#include "bp_ion_policy.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define BP_ION_MAX_EID_LEN 256
#define BP_ION_MAX_KEY_LEN 64
#define BP_ION_MAX_ES_LEN  64

static int hmac_scid(bpsec_context_id_t ctx) {
    switch (ctx) {
    case BPSEC_CTX_HMAC_SHA2_256:
    case BPSEC_CTX_HMAC_SHA2_384:
    case BPSEC_CTX_HMAC_SHA2_512:
        return BP_ION_SCID_BIB_HMAC_SHA2;
    default:
        return -1;
    }
}

static int aes_scid(bpsec_context_id_t ctx) {
    switch (ctx) {
    case BPSEC_CTX_AES_GCM_128:
    case BPSEC_CTX_AES_GCM_256:
        return BP_ION_SCID_BCB_AES_GCM;
    default:
        return -1;
    }
}

/* Reject tokens that could break out of the JSON rule string (injection). */
static int token_is_safe(const char *s, size_t max_len) {
    if (!s || !*s) return 0;
    for (size_t i = 0; i <= max_len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\0') return 1;
        if (c < 0x20 || c == '"' || c == '\\') return 0;
    }
    return 0;
}

int bp_ion_policy_validate(const bp_security_policy_t *p) {
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
        if (!token_is_safe(p->bib_key_ref, BP_ION_MAX_KEY_LEN))
            return BPSEC_ERR_INVALID_POLICY;
        if (p->bib_context != BPSEC_CTX_HMAC_SHA2_256)
            return BPSEC_ERR_INVALID_CONTEXT;
        if (p->bib_targets != BPSEC_TARGET_PAYLOAD) return BPSEC_ERR_INVALID_POLICY;
        if (p->bib_scope != BPSEC_SCOPE_BTSD_ONLY) return BPSEC_ERR_INVALID_POLICY;
    }
    if (p->mode & BPSEC_MODE_BCB_ONLY) {
        if (!token_is_safe(p->bcb_key_ref, BP_ION_MAX_KEY_LEN))
            return BPSEC_ERR_INVALID_POLICY;
        if (p->bcb_context != BPSEC_CTX_AES_GCM_256)
            return BPSEC_ERR_INVALID_CONTEXT;
        if (p->bcb_targets != BPSEC_TARGET_PAYLOAD) return BPSEC_ERR_INVALID_POLICY;
        if (p->bcb_scope != BPSEC_SCOPE_BTSD_ONLY) return BPSEC_ERR_INVALID_POLICY;
    }
    return BPSEC_SUCCESS;
}

static int append(char *out, size_t out_size, size_t *off, const char *fmt, ...) {
    if (*off >= out_size) return -1;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *off, out_size - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= out_size - *off) return -1;
    *off += (size_t)n;
    return 0;
}

static int emit_rule(char *out, size_t out_size, size_t *off,
                     const char *desc, uint16_t rule_id, const char *svc,
                     int scid, const char *src, const char *dest,
                     const char *key_ref, const char *es) {
    return append(out, out_size, off,
        "a {\"policyrule\":{\"desc\":\"%s\","
        "\"filter\":{\"rule_id\":%u,\"role\":\"s\",\"src\":\"%s\","
        "\"dest\":\"%s\",\"tgt\":%d,\"sc_id\":%d},"
        "\"spec\":{\"svc\":\"%s\",\"sc_id\":%d,"
        "\"sc_parms\":[{\"key_name\":\"%s\"}]},"
        "\"es_ref\":\"%s\"}}\n",
        desc, (unsigned)rule_id, src, dest,
        BP_ION_BLOCK_TYPE_PAYLOAD, scid, svc, scid, key_ref, es);
}

int bp_ion_policy_lower(const bp_security_policy_t *policy,
                        const char *source_eid, const char *dest_eid,
                        const char *eventset_name, uint16_t rule_id_base,
                        char *out, size_t out_size) {
    int rc = bp_ion_policy_validate(policy);
    if (rc != BPSEC_SUCCESS) return rc;

    if (!out || out_size == 0) return BPSEC_ERR_INTERNAL;
    if (!token_is_safe(source_eid, BP_ION_MAX_EID_LEN) ||
        !token_is_safe(dest_eid, BP_ION_MAX_EID_LEN) ||
        !token_is_safe(eventset_name, BP_ION_MAX_ES_LEN))
        return BPSEC_ERR_INVALID_POLICY;

    size_t off = 0;
    if (append(out, out_size, &off,
               "a {\"event_set\":{\"name\":\"%s\",\"desc\":\"bp-sdk\"}}\n",
               eventset_name) < 0)
        return BPSEC_ERR_INTERNAL;

    if (policy->mode & BPSEC_MODE_BIB_ONLY) {
        if (emit_rule(out, out_size, &off, "bp-sdk integrity", rule_id_base,
                      "bib-integrity", hmac_scid(policy->bib_context),
                      source_eid, dest_eid, policy->bib_key_ref,
                      eventset_name) < 0)
            return BPSEC_ERR_INTERNAL;
    }
    if (policy->mode & BPSEC_MODE_BCB_ONLY) {
        if (emit_rule(out, out_size, &off, "bp-sdk confidentiality",
                      (uint16_t)(rule_id_base + 1), "bcb-confidentiality",
                      aes_scid(policy->bcb_context), source_eid, dest_eid,
                      policy->bcb_key_ref, eventset_name) < 0)
            return BPSEC_ERR_INTERNAL;
    }

    return (int)off;
}
