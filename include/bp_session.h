/*
 * bp_session.h - Declarative BPSec session API.
 *
 * A bp_session_t is the runtime engine handle: applications declare
 * security intent through a policy and SecurityService takes care of
 * cached crypto contexts, IV uniqueness, key expiry enforcement, and
 * BIB / BCB construction on send and verification / decryption on
 * receive. Sends and receives on the same session are serialised so
 * the cached HMAC / AES-GCM contexts stay consistent.
 *
 * Phase 1 scope:
 *   - Targets: BPSEC_TARGET_PAYLOAD only (anything else is rejected).
 *   - Scopes:  BPSEC_SCOPE_BTSD_ONLY only (anything else is rejected).
 *   - BIB:     RFC 9173 BIB-HMAC-SHA-256.
 *   - BCB:     RFC 9173 BCB-AES-GCM-256.
 *   - IV:      8-byte CSPRNG session salt || 4-byte atomic counter.
 *   - When BIB and BCB both target the payload, BCB is generated alone
 *     and the GCM tag carries integrity (RFC 9172 §3.9 simplified case).
 */
#ifndef BP_SESSION_H
#define BP_SESSION_H

#include <stdint.h>
#include <stddef.h>

#include "bp_sdk.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BPSEC_MODE_NONE     = 0,
    BPSEC_MODE_BIB_ONLY = 1,
    BPSEC_MODE_BCB_ONLY = 2,
    BPSEC_MODE_BIB_BCB  = 3
} bpsec_mode_t;

typedef enum {
    BPSEC_CTX_HMAC_SHA2_256 = 1,
    BPSEC_CTX_HMAC_SHA2_384 = 2,
    BPSEC_CTX_HMAC_SHA2_512 = 3,
    BPSEC_CTX_AES_GCM_128   = 10,
    BPSEC_CTX_AES_GCM_256   = 11,
    BPSEC_CTX_COSE          = 20
} bpsec_context_id_t;

typedef enum {
    BPSEC_TARGET_PAYLOAD       = (1 << 0),
    BPSEC_TARGET_PRIMARY       = (1 << 1),
    BPSEC_TARGET_PREVIOUS_NODE = (1 << 2),
    BPSEC_TARGET_BUNDLE_AGE    = (1 << 3),
    BPSEC_TARGET_HOP_COUNT     = (1 << 4),
    BPSEC_TARGET_ALL_EXT       = (1 << 5)
} bpsec_target_flags_t;

typedef enum {
    BPSEC_SCOPE_BTSD_ONLY       = 0x00,
    BPSEC_SCOPE_INCLUDE_PRIMARY = 0x01,
    BPSEC_SCOPE_INCLUDE_HEADER  = 0x02,
    BPSEC_SCOPE_INCLUDE_ALL     = 0x07
} bpsec_scope_flags_t;

typedef enum {
    BPSEC_SUCCESS               = 0,
    BPSEC_ERR_INVALID_POLICY    = -1,
    BPSEC_ERR_KEY_NOT_AVAILABLE = -2,
    BPSEC_ERR_KEY_EXPIRED       = -3,
    BPSEC_ERR_KEY_TTL_MISMATCH  = -4,
    BPSEC_ERR_CRYPTO_FAILURE    = -5,
    BPSEC_ERR_IV_EXHAUSTED      = -6,
    BPSEC_ERR_BPA_REJECTED      = -7,
    BPSEC_ERR_INVALID_CONTEXT   = -8,
    BPSEC_ERR_FRAGMENTATION     = -9,
    BPSEC_ERR_VERIFY            = -10,
    BPSEC_ERR_DECRYPT           = -11,
    BPSEC_ERR_INTERNAL          = -12,
    BPSEC_ERR_TIMEOUT           = -13
} bpsec_error_t;

typedef struct {
    bpsec_mode_t          mode;
    bpsec_context_id_t    bib_context;
    bpsec_context_id_t    bcb_context;
    bpsec_target_flags_t  bib_targets;
    bpsec_target_flags_t  bcb_targets;
    bpsec_scope_flags_t   bib_scope;
    bpsec_scope_flags_t   bcb_scope;
    const char           *bib_key_ref;
    const char           *bcb_key_ref;
} bp_security_policy_t;

typedef struct {
    const char *dest_eid;
    const char *source_eid;
    uint32_t    lifetime_ms;
    uint32_t    no_fragment;
} bp_delivery_opts_t;

typedef struct {
    uint64_t bundles_secured;
    uint64_t bundles_verified;
    uint64_t bundles_decrypted;
    uint64_t verify_failures;
    uint64_t decrypt_failures;
    uint64_t bytes_secured;
    uint64_t iv_counter;
} bp_session_stats_t;

typedef struct {
    int (*load)(void *ctx, const char *session_name,
                uint8_t salt[8], uint64_t *counter);
    int (*save)(void *ctx, const char *session_name,
                const uint8_t salt[8], uint64_t counter);
    void *ctx;
} bp_iv_state_provider_t;

typedef struct bp_session bp_session_t;

bp_session_t *bp_session_open(const char *session_name);
int           bp_session_close(bp_session_t *s);

int  bp_session_set_source(bp_session_t *s, const char *source_eid);
int  bp_session_set_security(bp_session_t *s, const bp_security_policy_t *policy);
int  bp_session_set_iv_state_provider(bp_session_t *s,
                                      const bp_iv_state_provider_t *provider);

int  bp_session_send(bp_session_t *s,
                     const uint8_t *data, size_t len,
                     const bp_delivery_opts_t *opts);

int  bp_session_secure_encode(bp_session_t *s,
                              const uint8_t *data, size_t len,
                              const bp_delivery_opts_t *opts,
                              uint8_t **out, size_t *out_len);

int  bp_session_recv(bp_session_t *s, bp_endpoint_t *endpoint,
                     bp_bundle_t **out, int timeout_ms);

int  bp_session_process_wire(bp_session_t *s,
                             const uint8_t *wire, size_t wire_len,
                             bp_bundle_t **out);

int  bp_session_get_stats(const bp_session_t *s, bp_session_stats_t *out);

const char *bp_session_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif
