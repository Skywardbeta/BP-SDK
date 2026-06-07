/*
 * bp_security_intent.h - High-level declarative security intent.
 *
 * The intent layer is the recommended developer surface: an application
 * states *what* protection it wants (integrity, confidentiality, or both)
 * for a target and which key to use, and BP-SDK fills in the RFC 9173
 * wire-level choices (security context, scope) with safe defaults. This
 * keeps wire-level vocabulary out of application code.
 *
 * Defaults applied by the conversion:
 *   INTEGRITY                -> BIB-HMAC-SHA-256, BTSD-only scope.
 *   CONFIDENTIAL             -> BCB-AES-GCM-256,  BTSD-only scope.
 *   INTEGRITY_AND_CONFIDENTIAL -> BCB-AES-GCM-256 alone; the GCM tag
 *                                 carries integrity (RFC 9172 3.9).
 *
 * bp_security_policy_t (in bp_session.h) remains the low-level interface
 * for callers that need a non-default context or scope. Intent is the
 * high-level API; policy is the advanced one.
 */
#ifndef BP_SECURITY_INTENT_H
#define BP_SECURITY_INTENT_H

#include "bp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BP_SEC_INTENT_NONE                       = 0,
    BP_SEC_INTENT_INTEGRITY                  = 1,
    BP_SEC_INTENT_CONFIDENTIAL               = 2,
    BP_SEC_INTENT_INTEGRITY_AND_CONFIDENTIAL = 3
} bp_security_service_t;

typedef enum {
    BP_SEC_TARGET_PAYLOAD = 1
} bp_security_target_t;

typedef struct {
    bp_security_service_t service;
    bp_security_target_t  target;
    const char           *key_ref;
} bp_security_intent_t;

/* Fill *out with the policy the intent lowers to. out borrows intent->key_ref. */
int bp_security_intent_to_policy(const bp_security_intent_t *intent,
                                 bp_security_policy_t *out);

int bp_session_set_security_intent(bp_session_t *s,
                                   const bp_security_intent_t *intent);

#ifdef __cplusplus
}
#endif

#endif
