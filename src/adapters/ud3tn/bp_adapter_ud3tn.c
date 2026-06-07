#include "bp_adapter_ud3tn.h"
#include "bp_aap.h"
#include "bp_utils.h"

#include <stdlib.h>
#include <string.h>

#define UD3TN_HOST_DEFAULT "127.0.0.1"
#define UD3TN_PORT_DEFAULT 4242

typedef struct {
    char            *host;
    uint16_t         port;
    char            *agent;
    char            *source_eid;
    bp_aap_client_t *client;
    int              registered;
} ud3tn_state_t;

static char *config_get(const char *config, const char *key) {
    if (!config) return NULL;
    size_t klen = strlen(key);
    const char *p = config;
    while (*p) {
        const char *eq = strchr(p, '=');
        const char *end = strchr(p, ';');
        if (!end) end = p + strlen(p);
        if (eq && eq < end && (size_t)(eq - p) == klen &&
            strncmp(p, key, klen) == 0) {
            size_t vlen = (size_t)(end - (eq + 1));
            char *v = bp_alloc(vlen + 1);
            if (!v) return NULL;
            memcpy(v, eq + 1, vlen);
            v[vlen] = '\0';
            return v;
        }
        p = (*end == ';') ? end + 1 : end;
    }
    return NULL;
}

static int ud3tn_open(const char *config, void **state_out) {
    ud3tn_state_t *st = bp_alloc(sizeof(*st));
    if (!st) return BPSEC_ERR_INTERNAL;
    memset(st, 0, sizeof(*st));

    char *host = config_get(config, "host");
    st->host = host ? host : bp_strdup(UD3TN_HOST_DEFAULT);
    if (!st->host) { bp_free(st); return BPSEC_ERR_INTERNAL; }

    char *port = config_get(config, "port");
    st->port = port ? (uint16_t)atoi(port) : UD3TN_PORT_DEFAULT;
    bp_free(port);
    if (st->port == 0) st->port = UD3TN_PORT_DEFAULT;

    st->agent = config_get(config, "agent");
    *state_out = st;
    return BPSEC_SUCCESS;
}

static void ud3tn_close(void *state) {
    ud3tn_state_t *st = state;
    if (!st) return;
    if (st->client) bp_aap_disconnect(st->client);
    bp_free(st->host);
    bp_free(st->agent);
    bp_free(st->source_eid);
    bp_free(st);
}

static int ud3tn_set_source(void *state, const char *source_eid) {
    ud3tn_state_t *st = state;
    if (!st || !source_eid) return BPSEC_ERR_INVALID_POLICY;
    char *dup = bp_strdup(source_eid);
    if (!dup) return BPSEC_ERR_INTERNAL;
    bp_free(st->source_eid);
    st->source_eid = dup;
    if (!st->agent) st->registered = 0;
    return BPSEC_SUCCESS;
}

static int scheme_is_ipn(const char *eid) {
    return eid && strncmp(eid, "ipn:", 4) == 0;
}

/* Sub-EID grammar from uD3TN eid.c: a dtn demux is non-empty with every byte in
 * 0x21..0x7E (eidstr_dtn_demux_is_valid); an ipn service number is decimal. */
static int agent_is_valid(const char *agent, int ipn) {
    if (!agent || !*agent) return 0;
    for (const char *p = agent; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (ipn ? (c < '0' || c > '9') : (c < 0x21 || c > 0x7E)) return 0;
    }
    return 1;
}

/* AAP REGISTER carries only the sub-EID (ud3tn_aap.md): the dtn demux part, or
 * the ipn service number string. Returns NULL for a missing or syntactically
 * invalid sub-EID, which uD3TN's agent_manager would reject anyway. */
static char *derive_agent(const char *eid) {
    if (!eid) return NULL;
    if (strncmp(eid, "dtn://", 6) == 0) {
        const char *slash = strchr(eid + 6, '/');
        if (!slash || !agent_is_valid(slash + 1, 0)) return NULL;
        return bp_strdup(slash + 1);
    }
    if (strncmp(eid, "ipn:", 4) == 0) {
        const char *dot = strchr(eid + 4, '.');
        if (!dot || !agent_is_valid(dot + 1, 1)) return NULL;
        return bp_strdup(dot + 1);
    }
    return NULL;
}

static int ensure_connected(ud3tn_state_t *st) {
    if (st->client && st->registered) return BPSEC_SUCCESS;

    char *derived = NULL;
    const char *agent = st->agent;
    if (agent) {
        if (!agent_is_valid(agent, scheme_is_ipn(st->source_eid)))
            return BPSEC_ERR_INVALID_POLICY;
    } else {
        derived = derive_agent(st->source_eid);
        if (!derived) return BPSEC_ERR_INVALID_POLICY;
        agent = derived;
    }

    if (!st->client) {
        st->client = bp_aap_connect(st->host, st->port);
        if (!st->client) { bp_free(derived); return BPSEC_ERR_BPA_REJECTED; }
    }

    int ok = (bp_aap_register(st->client, agent) == BP_AAP_OK);
    bp_free(derived);
    if (!ok) return BPSEC_ERR_BPA_REJECTED;
    st->registered = 1;
    return BPSEC_SUCCESS;
}

static int ud3tn_register_security(void *state,
                                   const char *source_eid, const char *dest_eid,
                                   const bp_security_policy_t *policy) {
    ud3tn_state_t *st = state;
    (void)dest_eid;
    if (!st) return BPSEC_ERR_INVALID_POLICY;
    if (!st->source_eid && source_eid) ud3tn_set_source(st, source_eid);

    int rc = ensure_connected(st);
    if (rc != BPSEC_SUCCESS) return rc;

    if (policy && policy->mode != BPSEC_MODE_NONE)
        BP_LOG_INFO("ud3tn: intent declared for %s -> %s; enforcement via node "
                    "BPSec configuration (AAP has no per-flow security API)",
                    source_eid ? source_eid : "?", dest_eid ? dest_eid : "?");
    return BPSEC_SUCCESS;
}

static int ud3tn_send(void *state,
                      const char *source_eid, const char *dest_eid,
                      const uint8_t *data, size_t len,
                      const bp_delivery_opts_t *opts) {
    ud3tn_state_t *st = state;
    (void)opts;
    if (!st || !dest_eid || !data || len == 0) return BPSEC_ERR_INVALID_POLICY;
    if (!st->source_eid && source_eid) ud3tn_set_source(st, source_eid);

    int rc = ensure_connected(st);
    if (rc != BPSEC_SUCCESS) return rc;

    if (bp_aap_send_bundle(st->client, dest_eid, data, len) != BP_AAP_OK)
        return BPSEC_ERR_BPA_REJECTED;
    return BPSEC_SUCCESS;
}

static int ud3tn_recv(void *state, const char *local_eid,
                      uint8_t **out, size_t *out_len, int timeout_ms) {
    ud3tn_state_t *st = state;
    (void)local_eid;
    if (!st || !out || !out_len) return BPSEC_ERR_INVALID_POLICY;
    *out = NULL;
    *out_len = 0;

    int rc = ensure_connected(st);
    if (rc != BPSEC_SUCCESS) return rc;

    for (;;) {
        bp_aap_msg_t msg = {0};
        if (bp_aap_recv(st->client, &msg, timeout_ms) != BP_AAP_OK)
            return BPSEC_ERR_TIMEOUT;
        if (msg.type == BP_AAP_RECVBUNDLE) {
            *out = msg.payload;
            *out_len = msg.payload_len;
            msg.payload = NULL;
            bp_aap_msg_free(&msg);
            return BPSEC_SUCCESS;
        }
        bp_aap_msg_free(&msg);
    }
}

const bp_adapter_t g_bp_ud3tn_adapter = {
    .name              = "ud3tn",
    .open              = ud3tn_open,
    .close             = ud3tn_close,
    .set_source        = ud3tn_set_source,
    .register_security = ud3tn_register_security,
    .send              = ud3tn_send,
    .recv              = ud3tn_recv,
};
