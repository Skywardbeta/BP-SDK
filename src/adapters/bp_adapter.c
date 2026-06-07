#include "bp_adapter.h"
#include "bp_utils.h"

#include <string.h>

#define BP_ADAPTER_MAX 8

static const bp_adapter_t *g_adapters[BP_ADAPTER_MAX];
static size_t g_adapter_count;

extern const bp_adapter_t g_bp_ion_adapter;
extern const bp_adapter_t g_bp_ud3tn_adapter;
static int g_builtins_loaded;

int bp_adapter_register(const bp_adapter_t *adapter) {
    if (!adapter || !adapter->name) return BPSEC_ERR_INVALID_POLICY;
    for (size_t i = 0; i < g_adapter_count; i++) {
        if (strcmp(g_adapters[i]->name, adapter->name) == 0) {
            g_adapters[i] = adapter;
            return BPSEC_SUCCESS;
        }
    }
    if (g_adapter_count >= BP_ADAPTER_MAX) return BPSEC_ERR_INVALID_POLICY;
    g_adapters[g_adapter_count++] = adapter;
    return BPSEC_SUCCESS;
}

static void load_builtins(void) {
    if (g_builtins_loaded) return;
    g_builtins_loaded = 1;
    bp_adapter_register(&g_bp_ion_adapter);
    bp_adapter_register(&g_bp_ud3tn_adapter);
}

const bp_adapter_t *bp_adapter_find(const char *name) {
    if (!name) return NULL;
    load_builtins();
    for (size_t i = 0; i < g_adapter_count; i++)
        if (strcmp(g_adapters[i]->name, name) == 0) return g_adapters[i];
    return NULL;
}

static int is_hmac_ctx(bpsec_context_id_t c) {
    return c == BPSEC_CTX_HMAC_SHA2_256 || c == BPSEC_CTX_HMAC_SHA2_384 ||
           c == BPSEC_CTX_HMAC_SHA2_512;
}

static int is_aead_ctx(bpsec_context_id_t c) {
    return c == BPSEC_CTX_AES_GCM_128 || c == BPSEC_CTX_AES_GCM_256;
}

int bp_secure_policy_validate(const bp_security_policy_t *p) {
    if (!p) return BPSEC_ERR_INVALID_POLICY;
    switch (p->mode) {
    case BPSEC_MODE_NONE:
    case BPSEC_MODE_BIB_ONLY:
    case BPSEC_MODE_BCB_ONLY:
    case BPSEC_MODE_BIB_BCB:
        break;
    default:
        return BPSEC_ERR_INVALID_POLICY;
    }
    if (p->mode & BPSEC_MODE_BIB_ONLY) {
        if (!p->bib_key_ref || !*p->bib_key_ref) return BPSEC_ERR_INVALID_POLICY;
        if (!is_hmac_ctx(p->bib_context)) return BPSEC_ERR_INVALID_CONTEXT;
        if (p->bib_targets != BPSEC_TARGET_PAYLOAD) return BPSEC_ERR_INVALID_POLICY;
        if (p->bib_scope != BPSEC_SCOPE_BTSD_ONLY) return BPSEC_ERR_INVALID_POLICY;
    }
    if (p->mode & BPSEC_MODE_BCB_ONLY) {
        if (!p->bcb_key_ref || !*p->bcb_key_ref) return BPSEC_ERR_INVALID_POLICY;
        if (!is_aead_ctx(p->bcb_context)) return BPSEC_ERR_INVALID_CONTEXT;
        if (p->bcb_targets != BPSEC_TARGET_PAYLOAD) return BPSEC_ERR_INVALID_POLICY;
        if (p->bcb_scope != BPSEC_SCOPE_BTSD_ONLY) return BPSEC_ERR_INVALID_POLICY;
    }
    return BPSEC_SUCCESS;
}

struct bp_secure_link {
    const bp_adapter_t *adapter;
    void               *state;
    char               *source_eid;
    bp_security_policy_t policy;
    char               *bib_key_ref;
    char               *bcb_key_ref;
    int                 policy_set;
    char              **registered;
    size_t              registered_count;
    size_t              registered_cap;
};

bp_secure_link_t *bp_secure_link_open(const char *stack, const char *config) {
    const bp_adapter_t *adapter = bp_adapter_find(stack);
    if (!adapter) return NULL;

    bp_secure_link_t *link = bp_alloc(sizeof(*link));
    if (!link) return NULL;
    memset(link, 0, sizeof(*link));
    link->adapter = adapter;

    if (adapter->open && adapter->open(config, &link->state) != BPSEC_SUCCESS) {
        bp_free(link);
        return NULL;
    }
    return link;
}

int bp_secure_link_set_source(bp_secure_link_t *link, const char *source_eid) {
    if (!link || !source_eid || !*source_eid) return BPSEC_ERR_INVALID_POLICY;
    char *dup = bp_strdup(source_eid);
    if (!dup) return BPSEC_ERR_INTERNAL;
    bp_free(link->source_eid);
    link->source_eid = dup;

    for (size_t i = 0; i < link->registered_count; i++)
        bp_free(link->registered[i]);
    link->registered_count = 0;

    if (link->adapter->set_source)
        return link->adapter->set_source(link->state, source_eid);
    return BPSEC_SUCCESS;
}

int bp_secure_link_set_security(bp_secure_link_t *link,
                                const bp_security_policy_t *policy) {
    if (!link || !policy) return BPSEC_ERR_INVALID_POLICY;

    int rc = bp_secure_policy_validate(policy);
    if (rc != BPSEC_SUCCESS) return rc;
    if (link->adapter->validate_policy) {
        rc = link->adapter->validate_policy(policy);
        if (rc != BPSEC_SUCCESS) return rc;
    }

    char *bib = NULL, *bcb = NULL;
    if (policy->bib_key_ref) {
        bib = bp_strdup(policy->bib_key_ref);
        if (!bib) { rc = BPSEC_ERR_INTERNAL; goto fail; }
    }
    if (policy->bcb_key_ref) {
        bcb = bp_strdup(policy->bcb_key_ref);
        if (!bcb) { rc = BPSEC_ERR_INTERNAL; goto fail; }
    }

    bp_free(link->bib_key_ref);
    bp_free(link->bcb_key_ref);
    link->bib_key_ref = bib;
    link->bcb_key_ref = bcb;
    link->policy = *policy;
    link->policy.bib_key_ref = bib;
    link->policy.bcb_key_ref = bcb;
    link->policy_set = 1;

    for (size_t i = 0; i < link->registered_count; i++)
        bp_free(link->registered[i]);
    link->registered_count = 0;
    return BPSEC_SUCCESS;

fail:
    bp_free(bib);
    bp_free(bcb);
    return rc;
}

static int is_registered(const bp_secure_link_t *link, const char *dest) {
    for (size_t i = 0; i < link->registered_count; i++)
        if (strcmp(link->registered[i], dest) == 0) return 1;
    return 0;
}

static int remember_registered(bp_secure_link_t *link, const char *dest) {
    if (link->registered_count == link->registered_cap) {
        size_t ncap = link->registered_cap ? link->registered_cap * 2 : 4;
        char **n = bp_realloc(link->registered, ncap * sizeof(*n));
        if (!n) return BPSEC_ERR_INTERNAL;
        link->registered = n;
        link->registered_cap = ncap;
    }
    char *dup = bp_strdup(dest);
    if (!dup) return BPSEC_ERR_INTERNAL;
    link->registered[link->registered_count++] = dup;
    return BPSEC_SUCCESS;
}

int bp_secure_link_send(bp_secure_link_t *link, const char *dest_eid,
                        const uint8_t *data, size_t len,
                        const bp_delivery_opts_t *opts) {
    if (!link || !dest_eid || !data || len == 0) return BPSEC_ERR_INVALID_POLICY;
    if (!link->source_eid) return BPSEC_ERR_INVALID_POLICY;
    if (!link->adapter->send) return BPSEC_ERR_INTERNAL;

    if (link->policy_set && link->policy.mode != BPSEC_MODE_NONE &&
        !is_registered(link, dest_eid)) {
        if (!link->adapter->register_security) return BPSEC_ERR_INVALID_POLICY;
        int rc = link->adapter->register_security(link->state,
                                                  link->source_eid, dest_eid,
                                                  &link->policy);
        if (rc != BPSEC_SUCCESS) return rc;
        rc = remember_registered(link, dest_eid);
        if (rc != BPSEC_SUCCESS) return rc;
    }

    return link->adapter->send(link->state, link->source_eid, dest_eid,
                               data, len, opts);
}

int bp_secure_link_recv(bp_secure_link_t *link, uint8_t **out,
                        size_t *out_len, int timeout_ms) {
    if (!link || !out || !out_len) return BPSEC_ERR_INVALID_POLICY;
    if (!link->adapter->recv) return BPSEC_ERR_INTERNAL;
    return link->adapter->recv(link->state, link->source_eid, out, out_len,
                               timeout_ms);
}

const char *bp_secure_link_stack(const bp_secure_link_t *link) {
    return link ? link->adapter->name : NULL;
}

int bp_secure_link_close(bp_secure_link_t *link) {
    if (!link) return BPSEC_ERR_INVALID_POLICY;
    if (link->adapter->close) link->adapter->close(link->state);
    for (size_t i = 0; i < link->registered_count; i++)
        bp_free(link->registered[i]);
    bp_free(link->registered);
    bp_free(link->source_eid);
    bp_free(link->bib_key_ref);
    bp_free(link->bcb_key_ref);
    bp_free(link);
    return BPSEC_SUCCESS;
}
