/*
 * test_intent.c - Security intent lowering coverage.
 *
 * Covers the pure intent->policy mapping (defaults, validation, error
 * paths) and the bp_session_set_security_intent entry point end-to-end:
 * declaring intent must drive the same encode/decode roundtrip as the
 * equivalent hand-written policy.
 */
#include "bp_sdk.h"
#include "bp_session.h"
#include "bp_security_intent.h"
#include "bp_key_provider.h"
#include "bp_bpsec_keys.h"
#include "bp_utils.h"

#include "test_harness.h"

#include <stdint.h>
#include <string.h>

#define ASSERT_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { printf("FAIL\n    line %d: %lld != %lld\n", __LINE__, _a, _b); \
                    tests_failed++; return; } \
} while (0)

static const char *KEY_BCB = "intent-bcb-key";
static const char *KEY_BIB = "intent-bib-key";

static void install_keys(void) {
    uint8_t aes_key[32], hmac_key[32];
    for (size_t i = 0; i < sizeof(aes_key); i++)  aes_key[i]  = (uint8_t)(0x20 + i);
    for (size_t i = 0; i < sizeof(hmac_key); i++) hmac_key[i] = (uint8_t)(0x40 + i);
    bpsec_keystore_t *ks = bpsdk_default_keystore();
    bpsec_keystore_add(ks, KEY_BCB, BPSEC_KEY_TYPE_AES,  aes_key,  sizeof(aes_key),  NULL, 0);
    bpsec_keystore_add(ks, KEY_BIB, BPSEC_KEY_TYPE_HMAC, hmac_key, sizeof(hmac_key), NULL, 0);
}

static void test_to_policy_confidential(void) {
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_CONFIDENTIAL,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = KEY_BCB,
    };
    bp_security_policy_t p;
    ASSERT_EQ(bp_security_intent_to_policy(&in, &p), BPSEC_SUCCESS);
    ASSERT_EQ(p.mode, BPSEC_MODE_BCB_ONLY);
    ASSERT_EQ(p.bcb_context, BPSEC_CTX_AES_GCM_256);
    ASSERT_EQ(p.bcb_targets, BPSEC_TARGET_PAYLOAD);
    ASSERT_EQ(p.bcb_scope, BPSEC_SCOPE_BTSD_ONLY);
    ASSERT(p.bcb_key_ref == KEY_BCB);
    PASS();
}

static void test_to_policy_integrity(void) {
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_INTEGRITY,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = KEY_BIB,
    };
    bp_security_policy_t p;
    ASSERT_EQ(bp_security_intent_to_policy(&in, &p), BPSEC_SUCCESS);
    ASSERT_EQ(p.mode, BPSEC_MODE_BIB_ONLY);
    ASSERT_EQ(p.bib_context, BPSEC_CTX_HMAC_SHA2_256);
    ASSERT_EQ(p.bib_targets, BPSEC_TARGET_PAYLOAD);
    ASSERT_EQ(p.bib_scope, BPSEC_SCOPE_BTSD_ONLY);
    ASSERT(p.bib_key_ref == KEY_BIB);
    PASS();
}

static void test_to_policy_both_collapses_to_bcb(void) {
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_INTEGRITY_AND_CONFIDENTIAL,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = KEY_BCB,
    };
    bp_security_policy_t p;
    ASSERT_EQ(bp_security_intent_to_policy(&in, &p), BPSEC_SUCCESS);
    ASSERT_EQ(p.mode, BPSEC_MODE_BCB_ONLY);
    ASSERT_EQ(p.bcb_context, BPSEC_CTX_AES_GCM_256);
    ASSERT(p.bcb_key_ref == KEY_BCB);
    PASS();
}

static void test_to_policy_none(void) {
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_NONE,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = NULL,
    };
    bp_security_policy_t p;
    ASSERT_EQ(bp_security_intent_to_policy(&in, &p), BPSEC_SUCCESS);
    ASSERT_EQ(p.mode, BPSEC_MODE_NONE);
    PASS();
}

static void test_to_policy_zero_init_is_none(void) {
    bp_security_intent_t in = {0};
    bp_security_policy_t p;
    ASSERT_EQ(bp_security_intent_to_policy(&in, &p), BPSEC_SUCCESS);
    ASSERT_EQ(p.mode, BPSEC_MODE_NONE);
    PASS();
}

static void test_to_policy_rejects_bad_target(void) {
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_CONFIDENTIAL,
        .target  = (bp_security_target_t)0,
        .key_ref = KEY_BCB,
    };
    bp_security_policy_t p;
    ASSERT_EQ(bp_security_intent_to_policy(&in, &p), BPSEC_ERR_INVALID_POLICY);
    PASS();
}

static void test_to_policy_rejects_missing_key(void) {
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_CONFIDENTIAL,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = "",
    };
    bp_security_policy_t p;
    ASSERT_EQ(bp_security_intent_to_policy(&in, &p), BPSEC_ERR_INVALID_POLICY);
    PASS();
}

static void test_to_policy_null_args(void) {
    bp_security_policy_t p;
    bp_security_intent_t in = { .service = BP_SEC_INTENT_NONE, .target = BP_SEC_TARGET_PAYLOAD };
    ASSERT_EQ(bp_security_intent_to_policy(NULL, &p), BPSEC_ERR_INVALID_POLICY);
    ASSERT_EQ(bp_security_intent_to_policy(&in, NULL), BPSEC_ERR_INVALID_POLICY);
    ASSERT_EQ(bp_session_set_security_intent(NULL, &in), BPSEC_ERR_INVALID_POLICY);
    PASS();
}

static int roundtrip(bp_session_t *s, const char *msg) {
    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int rc = bp_session_secure_encode(s, (const uint8_t *)msg, strlen(msg),
                                      &opts, &wire, &wire_len);
    if (rc != BPSEC_SUCCESS) return rc;

    bp_bundle_t *out = NULL;
    rc = bp_session_process_wire(s, wire, wire_len, &out);
    bp_free(wire);
    if (rc != BPSEC_SUCCESS) return rc;

    int match = out && out->payload_len == strlen(msg)
                && memcmp(out->payload, msg, out->payload_len) == 0;
    bp_bundle_free(out);
    return match ? BPSEC_SUCCESS : BPSEC_ERR_DECRYPT;
}

static void test_session_confidential_roundtrip(void) {
    bp_session_t *s = bp_session_open("intent-conf");
    ASSERT(s);
    ASSERT_EQ(bp_session_set_source(s, "ipn:1.1"), BPSEC_SUCCESS);
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_CONFIDENTIAL,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = KEY_BCB,
    };
    ASSERT_EQ(bp_session_set_security_intent(s, &in), BPSEC_SUCCESS);
    ASSERT_EQ(roundtrip(s, "intent confidential payload"), BPSEC_SUCCESS);
    bp_session_close(s);
    PASS();
}

static void test_session_integrity_roundtrip(void) {
    bp_session_t *s = bp_session_open("intent-integ");
    ASSERT(s);
    ASSERT_EQ(bp_session_set_source(s, "ipn:1.1"), BPSEC_SUCCESS);
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_INTEGRITY,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = KEY_BIB,
    };
    ASSERT_EQ(bp_session_set_security_intent(s, &in), BPSEC_SUCCESS);
    ASSERT_EQ(roundtrip(s, "intent integrity payload"), BPSEC_SUCCESS);
    bp_session_close(s);
    PASS();
}

static void test_session_intent_rejects_missing_key(void) {
    bp_session_t *s = bp_session_open("intent-nokey");
    ASSERT(s);
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_CONFIDENTIAL,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = NULL,
    };
    ASSERT_EQ(bp_session_set_security_intent(s, &in), BPSEC_ERR_INVALID_POLICY);
    bp_session_close(s);
    PASS();
}

static void test_session_intent_unknown_key_not_armed(void) {
    bp_session_t *s = bp_session_open("intent-unknown");
    ASSERT(s);
    ASSERT_EQ(bp_session_set_source(s, "ipn:1.1"), BPSEC_SUCCESS);
    bp_security_intent_t in = {
        .service = BP_SEC_INTENT_CONFIDENTIAL,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = "missing-intent-key",
    };
    ASSERT_EQ(bp_session_set_security_intent(s, &in), BPSEC_ERR_KEY_NOT_AVAILABLE);
    bp_session_close(s);
    PASS();
}

int main(void) {
    if (bp_init("ipn:1.0", NULL) != BP_SUCCESS) return 2;
    install_keys();

    printf("\n=== bp_security_intent test suite ===\n\n");
    RUN_TEST(to_policy_confidential);
    RUN_TEST(to_policy_integrity);
    RUN_TEST(to_policy_both_collapses_to_bcb);
    RUN_TEST(to_policy_none);
    RUN_TEST(to_policy_zero_init_is_none);
    RUN_TEST(to_policy_rejects_bad_target);
    RUN_TEST(to_policy_rejects_missing_key);
    RUN_TEST(to_policy_null_args);
    RUN_TEST(session_confidential_roundtrip);
    RUN_TEST(session_integrity_roundtrip);
    RUN_TEST(session_intent_rejects_missing_key);
    RUN_TEST(session_intent_unknown_key_not_armed);

    TEST_SUMMARY();
    bp_shutdown();
    return tests_failed > 0 ? 1 : 0;
}
