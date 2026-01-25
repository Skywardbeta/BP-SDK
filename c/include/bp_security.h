/*
 * bp_security.h - BPSec Security Pipeline Integration
 * Integrates keystore and policy for automatic BIB/BCB processing on bundles.
 */
#ifndef BP_SECURITY_H
#define BP_SECURITY_H

#include "bp_bundle.h"
#include "bp_bpsec.h"
#include "bp_bpsec_keys.h"
#include "bp_bpsec_policy.h"
#include <stdint.h>
#include <stddef.h>

#define BP_SEC_OK               0
#define BP_SEC_ERR             -1
#define BP_SEC_ERR_NO_KEY      -2
#define BP_SEC_ERR_POLICY      -3
#define BP_SEC_ERR_VERIFY      -4
#define BP_SEC_ERR_DECRYPT     -5
#define BP_SEC_ERR_DROPPED     -6
#define BP_SEC_ERR_NO_ENTROPY  -7

typedef struct bp_security_ctx bp_security_ctx_t;

typedef void (*bp_sec_event_cb)(int event_type, const char *bundle_id, 
                                 const char *detail, void *user_data);

#define BP_SEC_EVENT_SIGNED      1
#define BP_SEC_EVENT_ENCRYPTED   2
#define BP_SEC_EVENT_VERIFIED    3
#define BP_SEC_EVENT_DECRYPTED   4
#define BP_SEC_EVENT_VERIFY_FAIL 5
#define BP_SEC_EVENT_DECRYPT_FAIL 6
#define BP_SEC_EVENT_DROPPED     7

bp_security_ctx_t *bp_security_ctx_create(void);
void bp_security_ctx_destroy(bp_security_ctx_t *ctx);

bpsec_keystore_t *bp_security_get_keystore(bp_security_ctx_t *ctx);
bpsec_policy_ctx_t *bp_security_get_policy(bp_security_ctx_t *ctx);

void bp_security_set_local_eid(bp_security_ctx_t *ctx, const char *eid);
void bp_security_set_event_callback(bp_security_ctx_t *ctx, bp_sec_event_cb cb, void *user_data);

int bp_security_apply(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle);
int bp_security_process(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle);

int bp_security_add_bib(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                        uint64_t target_block, const char *key_id);
int bp_security_add_bcb(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                        uint64_t target_block, const char *key_id);

int bp_security_verify_bib(bp_security_ctx_t *ctx, const bp_bundle_full_t *bundle,
                           const bp_block_t *bib_block);
int bp_security_verify_bib_with_key(bp_security_ctx_t *ctx, const bp_bundle_full_t *bundle,
                                    const bp_block_t *bib_block, const char *policy_key_id);
int bp_security_decrypt_bcb(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                            const bp_block_t *bcb_block);
int bp_security_decrypt_bcb_with_key(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                                     const bp_block_t *bcb_block, const char *policy_key_id);

#endif

