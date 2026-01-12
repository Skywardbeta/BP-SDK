/*
 * bp_security.h - High-level BPSec security API
 * 
 * Provides one-call security automation for Bundle Protocol applications.
 * Internally manages keys, policies, and BIB/BCB block construction.
 */

#ifndef BP_SECURITY_H
#define BP_SECURITY_H

#include <stdint.h>
#include <stddef.h>
#include "bp_bundle.h"
#include "bp_bpsec.h"
#include "bp_bpsec_keys.h"
#include "bp_bpsec_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BP_SEC_OK = 0,
    BP_SEC_ERR_INIT,
    BP_SEC_ERR_NO_KEY,
    BP_SEC_ERR_NO_POLICY,
    BP_SEC_ERR_CRYPTO,
    BP_SEC_ERR_MEMORY,
    BP_SEC_ERR_INVALID,
    BP_SEC_ERR_VERIFY_FAIL,
    BP_SEC_ERR_DECRYPT_FAIL
} bp_security_status_t;

typedef struct bp_security_ctx bp_security_ctx_t;

typedef struct {
    bp_security_status_t status;
    int bib_verified;       /* 1 if verified, 0 if not present, -1 on failure */
    int bcb_decrypted;      /* 1 if decrypted, 0 if not present, -1 on failure */
    char key_id[64];
} bp_security_result_t;

bp_security_ctx_t *bp_security_init(void);
void bp_security_shutdown(bp_security_ctx_t *ctx);

bpsec_keystore_t *bp_security_get_keystore(bp_security_ctx_t *ctx);
bpsec_policy_ctx_t *bp_security_get_policy(bp_security_ctx_t *ctx);

/* Set local node identity for security source in BIB/BCB blocks */
void bp_security_set_local_eid(bp_security_ctx_t *ctx, uint64_t node, uint64_t service);

bp_security_status_t bp_security_apply(bp_security_ctx_t *ctx,
                                       bp_bundle_full_t *bundle,
                                       const char *source);

bp_security_status_t bp_security_process(bp_security_ctx_t *ctx,
                                         bp_bundle_full_t *bundle,
                                         bp_security_result_t *result);

bp_security_status_t bp_security_add_key(bp_security_ctx_t *ctx,
                                         const char *key_id,
                                         const char *bound_eid,
                                         const uint8_t *key_data,
                                         size_t key_len,
                                         uint8_t key_type);

bp_security_status_t bp_security_add_rule(bp_security_ctx_t *ctx,
                                          const char *dest_pattern,
                                          uint8_t requirements,
                                          uint8_t priority);

#ifdef __cplusplus
}
#endif

#endif
