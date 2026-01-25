/*
 * test_security.c - Security hardening tests
 * Tests CRC validation, fragment limits, security pipeline, and transport.
 */
#include "bp_bundle.h"
#include "bp_fragment.h"
#include "bp_security.h"
#include "bp_bpsec.h"
#include "bp_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-50s", #name); \
    test_##name(); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

TEST(crc_valid_bundle_decodes) {
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.crc_type = BP_CRC_16;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 1;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.lifetime_ms = 3600000;
    
    uint8_t payload[] = "Test payload";
    bundle.payload = payload;
    bundle.payload_len = sizeof(payload) - 1;
    
    uint8_t wire[512];
    int wire_len = bp_bundle_encode(&bundle, wire, sizeof(wire));
    ASSERT(wire_len > 0);
    
    bp_bundle_full_t decoded = {0};
    int rc = bp_bundle_decode(wire, (size_t)wire_len, &decoded);
    ASSERT(rc == 0);
    ASSERT(decoded.payload_len == bundle.payload_len);
    
    bp_bundle_full_free(&decoded);
    PASS();
}

TEST(crc_corrupted_primary_rejected) {
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.crc_type = BP_CRC_16;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 1;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.lifetime_ms = 3600000;
    
    uint8_t wire[512];
    int wire_len = bp_bundle_encode(&bundle, wire, sizeof(wire));
    ASSERT(wire_len > 0);
    
    wire[10] ^= 0xFF;
    
    bp_bundle_full_t decoded = {0};
    int rc = bp_bundle_decode(wire, (size_t)wire_len, &decoded);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(fragment_limit_max_entries) {
    bp_fragment_config_t cfg = {
        .timeout_ms = 60000,
        .max_entries = 2,
        .max_total_bytes = 1024 * 1024
    };
    
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create(&cfg);
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t frag1 = {0};
    frag1.primary.flags = BP_FLAG_FRAGMENT;
    frag1.primary.creation_ts = 1000;
    frag1.primary.creation_seq = 1;
    frag1.primary.total_adu_len = 100;
    frag1.primary.fragment_offset = 0;
    uint8_t data1[50] = {0};
    frag1.payload = data1;
    frag1.payload_len = 50;
    
    bp_bundle_full_t frag2 = {0};
    frag2.primary.flags = BP_FLAG_FRAGMENT;
    frag2.primary.creation_ts = 2000;
    frag2.primary.creation_seq = 2;
    frag2.primary.total_adu_len = 100;
    frag2.primary.fragment_offset = 0;
    uint8_t data2[50] = {0};
    frag2.payload = data2;
    frag2.payload_len = 50;
    
    bp_bundle_full_t frag3 = {0};
    frag3.primary.flags = BP_FLAG_FRAGMENT;
    frag3.primary.creation_ts = 3000;
    frag3.primary.creation_seq = 3;
    frag3.primary.total_adu_len = 100;
    frag3.primary.fragment_offset = 0;
    uint8_t data3[50] = {0};
    frag3.payload = data3;
    frag3.payload_len = 50;
    
    bp_bundle_full_t complete = {0};
    
    int rc1 = bp_fragment_add(ctx, &frag1, &complete);
    ASSERT(rc1 == BP_FRAGMENT_OK);
    
    int rc2 = bp_fragment_add(ctx, &frag2, &complete);
    ASSERT(rc2 == BP_FRAGMENT_OK);
    
    int rc3 = bp_fragment_add(ctx, &frag3, &complete);
    ASSERT(rc3 == BP_FRAGMENT_ERR_LIMIT);
    
    bp_fragment_ctx_destroy(ctx);
    PASS();
}

TEST(fragment_limit_max_bytes) {
    bp_fragment_config_t cfg = {
        .timeout_ms = 60000,
        .max_entries = 100,
        .max_total_bytes = 200
    };
    
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create(&cfg);
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t frag1 = {0};
    frag1.primary.flags = BP_FLAG_FRAGMENT;
    frag1.primary.creation_ts = 1000;
    frag1.primary.creation_seq = 1;
    frag1.primary.total_adu_len = 150;
    frag1.primary.fragment_offset = 0;
    uint8_t data1[50] = {0};
    frag1.payload = data1;
    frag1.payload_len = 50;
    
    bp_bundle_full_t frag2 = {0};
    frag2.primary.flags = BP_FLAG_FRAGMENT;
    frag2.primary.creation_ts = 2000;
    frag2.primary.creation_seq = 2;
    frag2.primary.total_adu_len = 150;
    frag2.primary.fragment_offset = 0;
    uint8_t data2[50] = {0};
    frag2.payload = data2;
    frag2.payload_len = 50;
    
    bp_bundle_full_t complete = {0};
    
    int rc1 = bp_fragment_add(ctx, &frag1, &complete);
    ASSERT(rc1 == BP_FRAGMENT_OK);
    
    int rc2 = bp_fragment_add(ctx, &frag2, &complete);
    ASSERT(rc2 == BP_FRAGMENT_ERR_LIMIT);
    
    bp_fragment_ctx_destroy(ctx);
    PASS();
}

TEST(security_ctx_create_destroy) {
    bp_security_ctx_t *ctx = bp_security_ctx_create();
    ASSERT(ctx != NULL);
    
    bpsec_keystore_t *ks = bp_security_get_keystore(ctx);
    ASSERT(ks != NULL);
    
    bpsec_policy_ctx_t *pol = bp_security_get_policy(ctx);
    ASSERT(pol != NULL);
    
    bp_security_ctx_destroy(ctx);
    PASS();
}

TEST(security_add_bib) {
    bp_security_ctx_t *ctx = bp_security_ctx_create();
    ASSERT(ctx != NULL);
    
    bp_security_set_local_eid(ctx, "ipn:1.1");
    
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    bpsec_keystore_t *ks = bp_security_get_keystore(ctx);
    int rc = bpsec_keystore_add(ks, "test-key", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0);
    ASSERT(rc == 0);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    uint8_t payload[] = "Test payload data";
    bundle.payload = bp_alloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    rc = bp_security_add_bib(ctx, &bundle, 1, "test-key");
    ASSERT(rc == BP_SEC_OK);
    ASSERT(bundle.block_count == 1);
    ASSERT(bundle.blocks[0].type == BP_BLOCK_BIB);
    
    bp_free(bundle.payload);
    bp_free(bundle.blocks[0].data);
    bp_free(bundle.blocks);
    bp_security_ctx_destroy(ctx);
    PASS();
}

TEST(security_add_bcb) {
    bp_security_ctx_t *ctx = bp_security_ctx_create();
    ASSERT(ctx != NULL);
    
    bp_security_set_local_eid(ctx, "ipn:1.1");
    
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    bpsec_keystore_t *ks = bp_security_get_keystore(ctx);
    int rc = bpsec_keystore_add(ks, "aes-key", BPSEC_KEY_TYPE_AES, key, 32, NULL, 0);
    ASSERT(rc == 0);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    uint8_t payload[] = "Secret payload data";
    bundle.payload = bp_alloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    rc = bp_security_add_bcb(ctx, &bundle, 1, "aes-key");
    ASSERT(rc == BP_SEC_OK);
    ASSERT(bundle.block_count == 1);
    ASSERT(bundle.blocks[0].type == BP_BLOCK_BCB);
    ASSERT(memcmp(bundle.payload, payload, sizeof(payload)) != 0);
    
    bp_free(bundle.payload);
    bp_free(bundle.blocks[0].data);
    bp_free(bundle.blocks);
    bp_security_ctx_destroy(ctx);
    PASS();
}

TEST(security_policy_apply) {
    bp_security_ctx_t *ctx = bp_security_ctx_create();
    ASSERT(ctx != NULL);
    
    bp_security_set_local_eid(ctx, "ipn:1.1");
    
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    bpsec_keystore_t *ks = bp_security_get_keystore(ctx);
    bpsec_keystore_add(ks, "sign-key", BPSEC_KEY_TYPE_HMAC, key, 32, "ipn:2.1", 0);
    
    bpsec_policy_rule_t rule = {0};
    strcpy(rule.dest_pattern, "ipn:2.*");
    rule.requirements = BPSEC_REQUIRE_SIGN;
    rule.role = BPSEC_ROLE_SOURCE;
    strcpy(rule.sign_key_id, "sign-key");
    rule.priority = 10;
    
    bpsec_policy_ctx_t *pol = bp_security_get_policy(ctx);
    bpsec_policy_add_rule(pol, &rule);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    uint8_t payload[] = "Policy test payload";
    bundle.payload = bp_alloc(sizeof(payload));
    memcpy(bundle.payload, payload, sizeof(payload));
    bundle.payload_len = sizeof(payload);
    
    int rc = bp_security_apply(ctx, &bundle);
    ASSERT(rc == BP_SEC_OK);
    ASSERT(bundle.block_count == 1);
    ASSERT(bundle.blocks[0].type == BP_BLOCK_BIB);
    
    bp_free(bundle.payload);
    bp_free(bundle.blocks[0].data);
    bp_free(bundle.blocks);
    bp_security_ctx_destroy(ctx);
    PASS();
}

TEST(security_no_key_error) {
    bp_security_ctx_t *ctx = bp_security_ctx_create();
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    uint8_t payload[] = "Test";
    bundle.payload = payload;
    bundle.payload_len = sizeof(payload);
    
    int rc = bp_security_add_bib(ctx, &bundle, 1, "nonexistent-key");
    ASSERT(rc == BP_SEC_ERR_NO_KEY);
    
    bp_security_ctx_destroy(ctx);
    PASS();
}

int main(void) {
    printf("\n=== Security Hardening Test Suite ===\n\n");
    
    printf("CRC Validation Tests:\n");
    RUN_TEST(crc_valid_bundle_decodes);
    RUN_TEST(crc_corrupted_primary_rejected);
    
    printf("\nFragment Limit Tests:\n");
    RUN_TEST(fragment_limit_max_entries);
    RUN_TEST(fragment_limit_max_bytes);
    
    printf("\nSecurity Pipeline Tests:\n");
    RUN_TEST(security_ctx_create_destroy);
    RUN_TEST(security_add_bib);
    RUN_TEST(security_add_bcb);
    RUN_TEST(security_policy_apply);
    RUN_TEST(security_no_key_error);
    
    printf("\n=== Results: %d passed, %d failed ===\n\n", tests_passed, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

