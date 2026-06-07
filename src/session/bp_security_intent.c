/*
 * bp_security_intent.c - Intent-to-policy lowering.
 *
 * A thin, pure mapping layer above bp_session_set_security: it never
 * touches crypto, keys, or session state directly. Each entry point
 * converts a bp_security_intent_t into a bp_security_policy_t with RFC
 * 9173 default contexts and scope, then defers to the existing policy
 * API so all validation and crypto-context handling stay in one place.
 */
#include "bp_security_intent.h"

#include <string.h>

int bp_security_intent_to_policy(const bp_security_intent_t *intent,
                                 bp_security_policy_t *out) {
    if (!intent || !out) return BPSEC_ERR_INVALID_POLICY;

    memset(out, 0, sizeof(*out));

    if (intent->service == BP_SEC_INTENT_NONE) {
        out->mode = BPSEC_MODE_NONE;
        return BPSEC_SUCCESS;
    }

    if (intent->target != BP_SEC_TARGET_PAYLOAD) return BPSEC_ERR_INVALID_POLICY;
    if (!intent->key_ref || !*intent->key_ref) return BPSEC_ERR_INVALID_POLICY;

    switch (intent->service) {
    case BP_SEC_INTENT_INTEGRITY:
        out->mode        = BPSEC_MODE_BIB_ONLY;
        out->bib_context = BPSEC_CTX_HMAC_SHA2_256;
        out->bib_targets = BPSEC_TARGET_PAYLOAD;
        out->bib_scope   = BPSEC_SCOPE_BTSD_ONLY;
        out->bib_key_ref = intent->key_ref;
        return BPSEC_SUCCESS;
    case BP_SEC_INTENT_CONFIDENTIAL:
    case BP_SEC_INTENT_INTEGRITY_AND_CONFIDENTIAL:
        out->mode        = BPSEC_MODE_BCB_ONLY;
        out->bcb_context = BPSEC_CTX_AES_GCM_256;
        out->bcb_targets = BPSEC_TARGET_PAYLOAD;
        out->bcb_scope   = BPSEC_SCOPE_BTSD_ONLY;
        out->bcb_key_ref = intent->key_ref;
        return BPSEC_SUCCESS;
    default:
        return BPSEC_ERR_INVALID_POLICY;
    }
}

int bp_session_set_security_intent(bp_session_t *s,
                                   const bp_security_intent_t *intent) {
    if (!s || !intent) return BPSEC_ERR_INVALID_POLICY;
    bp_security_policy_t policy;
    int rc = bp_security_intent_to_policy(intent, &policy);
    if (rc != BPSEC_SUCCESS) return rc;
    return bp_session_set_security(s, &policy);
}
