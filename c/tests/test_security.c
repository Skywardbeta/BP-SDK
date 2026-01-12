/*
 * test_security.c - Tests for high-level security API
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bp_security.h"
#include "bp_bundle.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); \
    test_##name(); \
    tests_run++; \
} while(0)
#define PASS() do { tests_passed++; printf("OK\n"); return; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return; } while(0)
#define ASSERT(cond) do { if (!(cond)) FAIL(#cond); } while(0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) FAIL(#a " != " #b); } while(0)

TEST(init_shutdown) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    ASSERT(bp_security_get_keystore(ctx) != NULL);
    ASSERT(bp_security_get_policy(ctx) != NULL);
    
    bp_security_shutdown(ctx);
    PASS();
}

TEST(add_key) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    bp_security_status_t st = bp_security_add_key(ctx, "test-key", "ipn:1.*",
                                                   key, sizeof(key), BPSEC_KEY_TYPE_HMAC);
    ASSERT_EQ(st, BP_SEC_OK);
    
    bpsec_key_entry_t entry;
    int rc = bpsec_keystore_get(bp_security_get_keystore(ctx), "test-key", &entry);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(entry.data_len, 32);
    
    bp_security_shutdown(ctx);
    PASS();
}

TEST(add_rule) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    bp_security_status_t st = bp_security_add_rule(ctx, "ipn:1.*", BPSEC_REQUIRE_SIGN, 10);
    ASSERT_EQ(st, BP_SEC_OK);
    
    bpsec_policy_rule_t rule;
    int rc = bpsec_policy_lookup(bp_security_get_policy(ctx), "ipn:1.1", &rule);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(rule.requirements, BPSEC_REQUIRE_SIGN);
    
    bp_security_shutdown(ctx);
    PASS();
}

TEST(apply_sign) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    bp_security_add_key(ctx, "hmac-key", "ipn:1.1", key, sizeof(key), BPSEC_KEY_TYPE_HMAC);
    bp_security_add_rule(ctx, "ipn:1.*", BPSEC_REQUIRE_SIGN, 10);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 1;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 2;
    bundle.primary.source_ssp[1] = 1;
    
    uint8_t payload[] = "Test payload data";
    bundle.payload = malloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    bp_security_status_t st = bp_security_apply(ctx, &bundle, "ipn:2.1");
    ASSERT_EQ(st, BP_SEC_OK);
    ASSERT_EQ(bundle.block_count, 1);
    ASSERT_EQ(bundle.blocks[0].type, BP_BLOCK_BIB);
    
    free(bundle.payload);
    free(bundle.blocks[0].data);
    free(bundle.blocks);
    bp_security_shutdown(ctx);
    PASS();
}

TEST(apply_encrypt) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x10);
    bp_security_add_key(ctx, "aes-key", "ipn:2.1", key, sizeof(key), BPSEC_KEY_TYPE_AES);
    bp_security_add_rule(ctx, "ipn:2.*", BPSEC_REQUIRE_ENCRYPT, 10);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    
    uint8_t payload[] = "Secret payload data";
    bundle.payload = malloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    bp_security_status_t st = bp_security_apply(ctx, &bundle, "ipn:1.1");
    ASSERT_EQ(st, BP_SEC_OK);
    ASSERT_EQ(bundle.block_count, 1);
    ASSERT_EQ(bundle.blocks[0].type, BP_BLOCK_BCB);
    ASSERT(memcmp(bundle.payload, payload, sizeof(payload)) != 0);
    
    free(bundle.payload);
    free(bundle.blocks[0].data);
    free(bundle.blocks);
    bp_security_shutdown(ctx);
    PASS();
}

TEST(process_verify) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    /* Key bound to dest for apply, and source for process */
    bp_security_add_key(ctx, "hmac-key", "ipn:1.1", key, sizeof(key), BPSEC_KEY_TYPE_HMAC);
    bp_security_add_key(ctx, "hmac-key-src", "ipn:2.1", key, sizeof(key), BPSEC_KEY_TYPE_HMAC);
    bp_security_add_rule(ctx, "ipn:1.*", BPSEC_REQUIRE_SIGN, 10);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 1;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 2;
    bundle.primary.source_ssp[1] = 1;
    
    uint8_t payload[] = "Test payload";
    bundle.payload = malloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    bp_security_apply(ctx, &bundle, "ipn:2.1");
    
    bp_security_result_t result;
    bp_security_status_t st = bp_security_process(ctx, &bundle, &result);
    ASSERT_EQ(st, BP_SEC_OK);
    ASSERT_EQ(result.bib_verified, 1);
    
    free(bundle.payload);
    free(bundle.blocks[0].data);
    free(bundle.blocks);
    bp_security_shutdown(ctx);
    PASS();
}

TEST(process_decrypt) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x20);
    /* Key bound to dest for apply, and security source for process */
    bp_security_add_key(ctx, "aes-key", "ipn:3.1", key, sizeof(key), BPSEC_KEY_TYPE_AES);
    bp_security_add_key(ctx, "aes-key-src", "ipn:4.1", key, sizeof(key), BPSEC_KEY_TYPE_AES);
    bp_security_add_rule(ctx, "ipn:3.*", BPSEC_REQUIRE_ENCRYPT, 10);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 3;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 4;
    bundle.primary.source_ssp[1] = 1;
    
    uint8_t payload[] = "Secret message here";
    bundle.payload = malloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    /* Apply with security source matching key binding */
    bp_security_apply(ctx, &bundle, "ipn:4.1");
    
    bp_security_result_t result;
    bp_security_status_t st = bp_security_process(ctx, &bundle, &result);
    ASSERT_EQ(st, BP_SEC_OK);
    ASSERT_EQ(result.bcb_decrypted, 1);
    ASSERT(memcmp(bundle.payload, payload, sizeof(payload)) == 0);
    
    free(bundle.payload);
    free(bundle.blocks[0].data);
    free(bundle.blocks);
    bp_security_shutdown(ctx);
    PASS();
}

TEST(no_policy_no_security) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 99;
    bundle.primary.dest_ssp[1] = 1;
    
    uint8_t payload[] = "No security needed";
    bundle.payload = malloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    bp_security_status_t st = bp_security_apply(ctx, &bundle, "ipn:1.1");
    ASSERT_EQ(st, BP_SEC_OK);
    ASSERT_EQ(bundle.block_count, 0);
    
    free(bundle.payload);
    bp_security_shutdown(ctx);
    PASS();
}

TEST(missing_key_error) {
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT(ctx != NULL);
    
    bp_security_add_rule(ctx, "ipn:5.*", BPSEC_REQUIRE_SIGN, 10);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 5;
    bundle.primary.dest_ssp[1] = 1;
    
    uint8_t payload[] = "Test";
    bundle.payload = malloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    bp_security_status_t st = bp_security_apply(ctx, &bundle, "ipn:1.1");
    ASSERT_EQ(st, BP_SEC_ERR_NO_KEY);
    
    free(bundle.payload);
    bp_security_shutdown(ctx);
    PASS();
}

TEST(null_params) {
    ASSERT_EQ(bp_security_apply(NULL, NULL, NULL), BP_SEC_ERR_INVALID);
    
    bp_security_ctx_t *ctx = bp_security_init();
    ASSERT_EQ(bp_security_apply(ctx, NULL, NULL), BP_SEC_ERR_INVALID);
    ASSERT_EQ(bp_security_add_key(ctx, NULL, NULL, NULL, 0, 0), BP_SEC_ERR_INVALID);
    ASSERT_EQ(bp_security_add_rule(ctx, NULL, 0, 0), BP_SEC_ERR_INVALID);
    
    bp_security_shutdown(ctx);
    bp_security_shutdown(NULL);
    PASS();
}

int main(void) {
    printf("\n=== Security API Test Suite ===\n\n");
    
    printf("Initialization:\n");
    RUN_TEST(init_shutdown);
    RUN_TEST(add_key);
    RUN_TEST(add_rule);
    
    printf("\nApply Security:\n");
    RUN_TEST(apply_sign);
    RUN_TEST(apply_encrypt);
    
    printf("\nProcess Security:\n");
    RUN_TEST(process_verify);
    RUN_TEST(process_decrypt);
    
    printf("\nEdge Cases:\n");
    RUN_TEST(no_policy_no_security);
    RUN_TEST(missing_key_error);
    RUN_TEST(null_params);
    
    printf("\n=== Results: %d passed, %d failed ===\n\n", 
           tests_passed, tests_run - tests_passed);
    
    return (tests_passed == tests_run) ? 0 : 1;
}
