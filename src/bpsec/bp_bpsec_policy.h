/*
 * bp_bpsec_policy.h - BPSec Security Policy Engine
 * 
 * Per CCSDS 734.5-R-2: Defines security roles and policy rules
 * for automatic security block handling.
 * 
 * Security Roles:
 *   - SECURITY_SOURCE: Creates BIB/BCB blocks
 *   - SECURITY_VERIFIER: Validates blocks without removing
 *   - SECURITY_ACCEPTOR: Validates and removes blocks
 * 
 * Policy rules define:
 *   - Required security operations per destination
 *   - Actions on verification failure
 *   - Cipher suite preferences
 */
#ifndef BP_BPSEC_POLICY_H
#define BP_BPSEC_POLICY_H

#include <stdint.h>
#include <stddef.h>

#define BPSEC_ROLE_NONE       0
#define BPSEC_ROLE_SOURCE     1
#define BPSEC_ROLE_VERIFIER   2
#define BPSEC_ROLE_ACCEPTOR   3

#define BPSEC_ACTION_PASS     0
#define BPSEC_ACTION_DROP     1
#define BPSEC_ACTION_LOG      2
#define BPSEC_ACTION_FORWARD  3

#define BPSEC_REQUIRE_NONE      0x00
#define BPSEC_REQUIRE_SIGN      0x01
#define BPSEC_REQUIRE_ENCRYPT   0x02
#define BPSEC_REQUIRE_BOTH      0x03

#define BPSEC_POLICY_MAX_EID_LEN 128

typedef struct bpsec_policy_ctx bpsec_policy_ctx_t;

typedef struct {
    char dest_pattern[BPSEC_POLICY_MAX_EID_LEN];
    uint8_t requirements;
    uint8_t role;
    uint8_t on_verify_fail;
    uint8_t on_decrypt_fail;
    char sign_key_id[64];
    char encrypt_key_id[64];
    uint8_t priority;
} bpsec_policy_rule_t;

typedef struct {
    uint64_t bundles_signed;
    uint64_t bundles_encrypted;
    uint64_t bundles_verified;
    uint64_t bundles_decrypted;
    uint64_t verify_failures;
    uint64_t decrypt_failures;
    uint64_t policy_drops;
} bpsec_policy_stats_t;

bpsec_policy_ctx_t *bpsec_policy_create(void);
void bpsec_policy_destroy(bpsec_policy_ctx_t *ctx);

int bpsec_policy_add_rule(bpsec_policy_ctx_t *ctx,
                          const bpsec_policy_rule_t *rule);

int bpsec_policy_remove_rule(bpsec_policy_ctx_t *ctx,
                             const char *dest_pattern);

int bpsec_policy_lookup(bpsec_policy_ctx_t *ctx, const char *dest_eid,
                        bpsec_policy_rule_t *out);

int bpsec_policy_set_default(bpsec_policy_ctx_t *ctx,
                             const bpsec_policy_rule_t *rule);

int bpsec_policy_get_stats(bpsec_policy_ctx_t *ctx,
                           bpsec_policy_stats_t *out);

void bpsec_policy_reset_stats(bpsec_policy_ctx_t *ctx);

void bpsec_policy_inc_stat(bpsec_policy_ctx_t *ctx, int stat_type);

#define BPSEC_STAT_SIGNED      0
#define BPSEC_STAT_ENCRYPTED   1
#define BPSEC_STAT_VERIFIED    2
#define BPSEC_STAT_DECRYPTED   3
#define BPSEC_STAT_VERIFY_FAIL 4
#define BPSEC_STAT_DECRYPT_FAIL 5
#define BPSEC_STAT_DROP        6

size_t bpsec_policy_rule_count(bpsec_policy_ctx_t *ctx);

#endif

