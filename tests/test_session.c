/*
 * test_session.c - SecurityService Phase 1 coverage.
 *
 * Verifies the public API contracts: strict policy validation, key
 * expiry / TTL enforcement, IV uniqueness across many sends, encrypt
 * + verify roundtrip, tamper detection, and concurrent send safety.
 * Self-contained: combines bp_session_secure_encode with
 * bp_session_process_wire so no network is required.
 */
#include "bp_sdk.h"
#include "bp_session.h"
#include "bp_key_provider.h"
#include "bp_bpsec_keys.h"
#include "bp_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define THREAD_T HANDLE
#define THREAD_CREATE(t, fn, arg) (t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fn), (arg), 0, NULL)
#define THREAD_JOIN(t) WaitForSingleObject((t), INFINITE)
typedef DWORD thread_ret_t;
#else
#include <pthread.h>
#define THREAD_T pthread_t
#define THREAD_CREATE(t, fn, arg) pthread_create(&(t), NULL, (fn), (arg))
#define THREAD_JOIN(t) pthread_join((t), NULL)
typedef void *thread_ret_t;
#endif

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); fflush(stdout); test_##name(); \
} while(0)
#define ASSERT(cond) do { \
    if (!(cond)) { printf("FAIL\n    line %d: %s\n", __LINE__, #cond); tests_failed++; return; } \
} while(0)
#define ASSERT_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { printf("FAIL\n    line %d: %lld != %lld\n", __LINE__, _a, _b); tests_failed++; return; } \
} while(0)
#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

static const char *KEY_BCB = "test-bcb-key";
static const char *KEY_BIB = "test-bib-key";
static const char *KEY_BCB_EXPIRED = "test-bcb-expired";
static const char *KEY_BCB_SHORT_EXPIRY = "test-bcb-short";

static void install_keys(void) {
    uint8_t aes_key[32], hmac_key[32];
    for (size_t i = 0; i < sizeof(aes_key); i++) aes_key[i] = (uint8_t)(0x10 + i);
    for (size_t i = 0; i < sizeof(hmac_key); i++) hmac_key[i] = (uint8_t)(0x80 + i);

    bpsec_keystore_t *ks = bpsdk_default_keystore();
    bpsec_keystore_add(ks, KEY_BCB, BPSEC_KEY_TYPE_AES,  aes_key,  sizeof(aes_key),  NULL, 0);
    bpsec_keystore_add(ks, KEY_BIB, BPSEC_KEY_TYPE_HMAC, hmac_key, sizeof(hmac_key), NULL, 0);
    bpsec_keystore_add(ks, KEY_BCB_EXPIRED, BPSEC_KEY_TYPE_AES,
                       aes_key, sizeof(aes_key), NULL,
                       bp_time_now_dtn() > 100 ? bp_time_now_dtn() - 100 : 1);
    bpsec_keystore_add(ks, KEY_BCB_SHORT_EXPIRY, BPSEC_KEY_TYPE_AES,
                       aes_key, sizeof(aes_key), NULL,
                       bp_time_now_dtn() * 1000ULL + 100);
}

static int policy_bcb_only(bp_security_policy_t *p, const char *key) {
    memset(p, 0, sizeof(*p));
    p->mode        = BPSEC_MODE_BCB_ONLY;
    p->bcb_context = BPSEC_CTX_AES_GCM_256;
    p->bcb_targets = BPSEC_TARGET_PAYLOAD;
    p->bcb_scope   = BPSEC_SCOPE_BTSD_ONLY;
    p->bcb_key_ref = key;
    return 0;
}

static int policy_bib_only(bp_security_policy_t *p, const char *key) {
    memset(p, 0, sizeof(*p));
    p->mode        = BPSEC_MODE_BIB_ONLY;
    p->bib_context = BPSEC_CTX_HMAC_SHA2_256;
    p->bib_targets = BPSEC_TARGET_PAYLOAD;
    p->bib_scope   = BPSEC_SCOPE_BTSD_ONLY;
    p->bib_key_ref = key;
    return 0;
}

TEST(open_close_lifecycle) {
    bp_session_t *s = bp_session_open("session-a");
    ASSERT(s);
    ASSERT_EQ(bp_session_close(s), BPSEC_SUCCESS);
    PASS();
}

TEST(reject_target_other_than_payload) {
    bp_session_t *s = bp_session_open("policy-bad-target");
    ASSERT(s);
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    p.bcb_targets = BPSEC_TARGET_PAYLOAD | BPSEC_TARGET_PRIMARY;
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_ERR_INVALID_POLICY);
    bp_session_close(s);
    PASS();
}

TEST(reject_non_btsd_scope) {
    bp_session_t *s = bp_session_open("policy-bad-scope");
    ASSERT(s);
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    p.bcb_scope = BPSEC_SCOPE_INCLUDE_PRIMARY;
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_ERR_INVALID_POLICY);
    bp_session_close(s);
    PASS();
}

TEST(reject_unsupported_context) {
    bp_session_t *s = bp_session_open("policy-bad-ctx");
    ASSERT(s);
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    p.bcb_context = BPSEC_CTX_COSE;
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_ERR_INVALID_CONTEXT);
    bp_session_close(s);
    PASS();
}

TEST(reject_expired_key_at_set_security) {
    bp_session_t *s = bp_session_open("policy-expired");
    ASSERT(s);
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB_EXPIRED);
    int rc = bp_session_set_security(s, &p);
    ASSERT(rc == BPSEC_ERR_KEY_NOT_AVAILABLE || rc == BPSEC_ERR_KEY_EXPIRED);
    bp_session_close(s);
    PASS();
}

TEST(reject_lifetime_past_key_expiry) {
    bp_session_t *s = bp_session_open("policy-ttl");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");

    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB_SHORT_EXPIRY);
    int rc = bp_session_set_security(s, &p);
    if (rc == BPSEC_ERR_KEY_EXPIRED) { bp_session_close(s); PASS(); return; }
    ASSERT_EQ(rc, BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 3600000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    rc = bp_session_secure_encode(s, (const uint8_t *)"x", 1, &opts, &wire, &wire_len);
    ASSERT(rc == BPSEC_ERR_KEY_TTL_MISMATCH || rc == BPSEC_ERR_KEY_EXPIRED);
    if (wire) bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(bcb_encrypt_decrypt_roundtrip) {
    bp_session_t *s = bp_session_open("rt-bcb");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");

    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    const char *msg = "the eagle has landed";
    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)msg, strlen(msg),
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);
    ASSERT(wire_len > strlen(msg));

    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_SUCCESS);
    ASSERT(out);
    ASSERT_EQ(out->payload_len, strlen(msg));
    ASSERT_EQ(memcmp(out->payload, msg, strlen(msg)), 0);
    ASSERT(strcmp(out->source_eid, "ipn:1.1") == 0);

    bp_bundle_free(out);
    bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(bib_sign_verify_roundtrip) {
    bp_session_t *s = bp_session_open("rt-bib");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");

    bp_security_policy_t p;
    policy_bib_only(&p, KEY_BIB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    const char *msg = "integrity matters";
    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)msg, strlen(msg),
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);

    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_SUCCESS);
    ASSERT(out);
    ASSERT_EQ(out->payload_len, strlen(msg));
    ASSERT_EQ(memcmp(out->payload, msg, strlen(msg)), 0);

    bp_bundle_free(out);
    bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(bib_tamper_detected) {
    bp_session_t *s = bp_session_open("rt-bib-tamper");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bib_only(&p, KEY_BIB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t payload[64];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;

    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, payload, sizeof(payload),
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);
    int flipped = 0;
    for (size_t i = 0; i + sizeof(payload) <= wire_len; i++) {
        if (memcmp(wire + i, payload, sizeof(payload)) == 0) {
            wire[i + 7] ^= 0xff;
            flipped = 1;
            break;
        }
    }
    ASSERT(flipped);

    bp_bundle_t *out = NULL;
    int rc = bp_session_process_wire(s, wire, wire_len, &out);
    ASSERT_EQ(rc, BPSEC_ERR_VERIFY);

    bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(bcb_tamper_detected) {
    bp_session_t *s = bp_session_open("rt-bcb-tamper");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    const char *msg = "needs to stay confidential and tagged";
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)msg, strlen(msg),
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);
    ASSERT(wire_len > 16);
    wire[wire_len - 8] ^= 0x55;

    bp_bundle_t *out = NULL;
    int rc = bp_session_process_wire(s, wire, wire_len, &out);
    ASSERT_EQ(rc, BPSEC_ERR_DECRYPT);

    bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(iv_counter_monotonic_unique) {
    bp_session_t *s = bp_session_open("iv-uniq");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t payload[8] = "iv-test";
    uint64_t prev = 0;
    for (int i = 0; i < 100; i++) {
        uint8_t *wire = NULL; size_t wire_len = 0;
        ASSERT_EQ(bp_session_secure_encode(s, payload, sizeof(payload),
                                           &opts, &wire, &wire_len),
                  BPSEC_SUCCESS);
        bp_session_stats_t stats;
        bp_session_get_stats(s, &stats);
        ASSERT(stats.iv_counter > prev);
        prev = stats.iv_counter;
        bp_free(wire);
    }
    bp_session_close(s);
    PASS();
}

typedef struct {
    bp_session_t *session;
    int           iterations;
    int           failures;
} concurrent_arg_t;

static thread_ret_t concurrent_send_thread(void *arg) {
    concurrent_arg_t *a = arg;
    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t payload[32];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;

    for (int i = 0; i < a->iterations; i++) {
        uint8_t *wire = NULL; size_t wire_len = 0;
        int rc = bp_session_secure_encode(a->session, payload, sizeof(payload),
                                          &opts, &wire, &wire_len);
        if (rc != BPSEC_SUCCESS) { a->failures++; continue; }

        bp_bundle_t *out = NULL;
        rc = bp_session_process_wire(a->session, wire, wire_len, &out);
        if (rc != BPSEC_SUCCESS) a->failures++;
        if (out) bp_bundle_free(out);
        bp_free(wire);
    }
    return (thread_ret_t)0;
}

TEST(concurrent_send_safe) {
    bp_session_t *s = bp_session_open("concurrent");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    enum { N = 4, ITER = 50 };
    THREAD_T threads[N];
    concurrent_arg_t args[N];
    for (int i = 0; i < N; i++) {
        args[i].session = s;
        args[i].iterations = ITER;
        args[i].failures = 0;
        THREAD_CREATE(threads[i], concurrent_send_thread, &args[i]);
    }
    int total_failures = 0;
    for (int i = 0; i < N; i++) { THREAD_JOIN(threads[i]); total_failures += args[i].failures; }
    ASSERT_EQ(total_failures, 0);

    bp_session_stats_t stats;
    bp_session_get_stats(s, &stats);
    ASSERT_EQ(stats.bundles_secured,   (uint64_t)(N * ITER));
    ASSERT_EQ(stats.bundles_decrypted, (uint64_t)(N * ITER));
    ASSERT_EQ(stats.iv_counter,        (uint64_t)(N * ITER));

    bp_session_close(s);
    PASS();
}

TEST(missing_source_rejected) {
    bp_session_t *s = bp_session_open("no-source");
    ASSERT(s);
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"x", 1,
                                       &opts, &wire, &wire_len),
              BPSEC_ERR_INVALID_POLICY);
    if (wire) bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(opts_source_overrides_session) {
    bp_session_t *s = bp_session_open("override-src");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = {
        .dest_eid    = "ipn:2.1",
        .source_eid  = "ipn:9.9",
        .lifetime_ms = 60000,
    };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"hi", 2,
                                       &opts, &wire, &wire_len),
              BPSEC_SUCCESS);

    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_SUCCESS);
    ASSERT(strcmp(out->source_eid, "ipn:9.9") == 0);
    bp_bundle_free(out);
    bp_free(wire);
    bp_session_close(s);
    PASS();
}

int main(void) {
    if (bp_init("ipn:1.0", NULL) != BP_SUCCESS) {
        fprintf(stderr, "bp_init failed\n");
        return 2;
    }
    install_keys();

    printf("\n=== bp_session test suite ===\n\n");
    RUN_TEST(open_close_lifecycle);
    RUN_TEST(reject_target_other_than_payload);
    RUN_TEST(reject_non_btsd_scope);
    RUN_TEST(reject_unsupported_context);
    RUN_TEST(reject_expired_key_at_set_security);
    RUN_TEST(reject_lifetime_past_key_expiry);
    RUN_TEST(bcb_encrypt_decrypt_roundtrip);
    RUN_TEST(bib_sign_verify_roundtrip);
    RUN_TEST(bib_tamper_detected);
    RUN_TEST(bcb_tamper_detected);
    RUN_TEST(iv_counter_monotonic_unique);
    RUN_TEST(missing_source_rejected);
    RUN_TEST(opts_source_overrides_session);
    RUN_TEST(concurrent_send_safe);

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);

    bp_shutdown();
    return tests_failed > 0 ? 1 : 0;
}
