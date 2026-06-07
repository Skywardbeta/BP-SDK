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
    uint64_t now_s = bp_time_now_dtn();
    bpsec_keystore_add(ks, KEY_BCB_EXPIRED, BPSEC_KEY_TYPE_AES,
                       aes_key, sizeof(aes_key), NULL,
                       now_s > 100 ? now_s - 100 : 1);
    bpsec_keystore_add(ks, KEY_BCB_SHORT_EXPIRY, BPSEC_KEY_TYPE_AES,
                       aes_key, sizeof(aes_key), NULL, now_s + 1);
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

TEST(reject_empty_payload) {
    bp_session_t *s = bp_session_open("empty");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"x", 0,
                                       &opts, &wire, &wire_len),
              BPSEC_ERR_INVALID_POLICY);
    ASSERT(wire == NULL);
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

/* --- file provider parsing --- */

static char *write_temp_file(const char *body) {
    static char path[256];
#ifdef _WIN32
    char dir[256];
    DWORD n = GetTempPathA(sizeof(dir), dir);
    if (n == 0 || n >= sizeof(dir)) return NULL;
    snprintf(path, sizeof(path), "%sbp_kp_%lu.txt", dir, (unsigned long)GetCurrentProcessId());
#else
    snprintf(path, sizeof(path), "/tmp/bp_kp_%d.txt", (int)getpid());
#endif
    FILE *fp = fopen(path, "w");
    if (!fp) return NULL;
    fputs(body, fp);
    fclose(fp);
    return path;
}

TEST(file_provider_parses_hmac_and_aes) {
    const char *body =
        "# comment line\n"
        "k_hmac hmac 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "k_aes  aes  fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\n";
    char *path = write_temp_file(body);
    ASSERT(path);

    bp_key_provider_file_t *fp = bp_key_provider_file_create(path);
    ASSERT(fp);
    bp_key_provider_t prov = bp_key_provider_file_make(fp);

    uint8_t buf[32]; size_t blen = 0;
    ASSERT_EQ(prov.key_available(prov.provider_ctx, "k_hmac", BP_KEY_USAGE_HMAC), 0);
    ASSERT_EQ(prov.key_available(prov.provider_ctx, "k_hmac", BP_KEY_USAGE_AES),  -1);
    ASSERT_EQ(prov.get_key(prov.provider_ctx, "k_hmac", BP_KEY_USAGE_HMAC,
                           buf, sizeof(buf), &blen), 0);
    ASSERT_EQ(blen, 32);

    ASSERT_EQ(prov.key_available(prov.provider_ctx, "k_aes", BP_KEY_USAGE_AES),  0);
    ASSERT_EQ(prov.key_available(prov.provider_ctx, "k_aes", BP_KEY_USAGE_HMAC), -1);
    ASSERT_EQ(prov.get_key(prov.provider_ctx, "k_aes", BP_KEY_USAGE_AES,
                           buf, sizeof(buf), &blen), 0);
    ASSERT_EQ(blen, 32);

    bp_key_provider_file_destroy(fp);
    remove(path);
    PASS();
}

TEST(file_provider_rejects_missing_type_token) {
    const char *body =
        "k_x 0123456789abcdef0123456789abcdef\n";
    char *path = write_temp_file(body);
    ASSERT(path);

    bp_key_provider_file_t *fp = bp_key_provider_file_create(path);
    ASSERT(fp);
    bp_key_provider_t prov = bp_key_provider_file_make(fp);

    ASSERT_EQ(prov.key_available(prov.provider_ctx, "k_x", BP_KEY_USAGE_HMAC), -1);
    ASSERT_EQ(prov.key_available(prov.provider_ctx, "k_x", BP_KEY_USAGE_AES),  -1);

    bp_key_provider_file_destroy(fp);
    remove(path);
    PASS();
}

/* --- IV state provider --- */

typedef struct {
    int      have_state;
    uint8_t  salt[8];
    uint64_t counter;
    int      load_calls;
    int      save_calls;
} ivstate_t;

static int ivstate_load(void *ctx, const char *name, uint8_t salt[8], uint64_t *counter) {
    (void)name;
    ivstate_t *st = ctx;
    st->load_calls++;
    if (!st->have_state) return -1;
    memcpy(salt, st->salt, 8);
    *counter = st->counter;
    return 0;
}
static int ivstate_save(void *ctx, const char *name, const uint8_t salt[8], uint64_t counter) {
    (void)name;
    ivstate_t *st = ctx;
    st->save_calls++;
    memcpy(st->salt, salt, 8);
    st->counter = counter;
    st->have_state = 1;
    return 0;
}

TEST(iv_provider_load_after_set_security) {
    bp_session_t *s = bp_session_open("ivp-after");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    ivstate_t st = {0};
    st.have_state = 1;
    for (int i = 0; i < 8; i++) st.salt[i] = (uint8_t)(0xA0 + i);
    st.counter = 12345;

    bp_iv_state_provider_t prov = { .load = ivstate_load, .save = ivstate_save, .ctx = &st };
    ASSERT_EQ(bp_session_set_iv_state_provider(s, &prov), BPSEC_SUCCESS);
    ASSERT_EQ(st.load_calls, 1);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"x", 1,
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);

    bp_session_stats_t stats;
    bp_session_get_stats(s, &stats);
    ASSERT_EQ(stats.iv_counter, (uint64_t)12346);
    ASSERT_EQ(st.save_calls, 1);
    ASSERT_EQ(st.counter, (uint64_t)12346);

    bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(iv_provider_rejects_overflow_counter) {
    bp_session_t *s = bp_session_open("ivp-overflow");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    ivstate_t st = {0};
    st.have_state = 1;
    st.counter = 0x100000000ULL;
    bp_iv_state_provider_t prov = { .load = ivstate_load, .save = ivstate_save, .ctx = &st };
    ASSERT_EQ(bp_session_set_iv_state_provider(s, &prov), BPSEC_ERR_IV_EXHAUSTED);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"x", 1,
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);
    ASSERT(wire);
    bp_free(wire);

    bp_session_close(s);
    PASS();
}

/* --- malformed ASB rejection --- */

/*
 * Locate the BCB ASB params triple in the wire.
 *
 * The ASB content emitted by build_bcb_asb is:
 *   array(6) array(1) uint(payload=1) uint(ctx_id=2) uint(ctx_flags=1)
 *   <security_source_eid> array(3)
 *     array(2) uint(1) <bstr IV>           // IV pair
 *     array(2) uint(2) uint(3)             // variant pair
 *     array(2) uint(4) uint(0)             // scope pair
 *   array(1) array(1) array(2) uint(1) <bstr tag>
 *
 * `0x86 0x81 0x01 0x02 0x01` is unique to the ASB body. From there the
 * security source EID is variable-length, but the next `0x83` (params
 * array of 3) marks the start of the params block. After that:
 *   IV pair    starts at  +0  (variable length, contains a bstr)
 *   variant    starts at  +len(IV pair)
 *   scope      starts immediately after variant (always 3 bytes)
 *
 * For the patch tests we just scan forward from the ASB-body signature
 * to the literal variant pair `0x82 0x02 0x03` or scope pair
 * `0x82 0x04 0x00` and flip the pid byte. Because the search starts
 * inside the ASB body, the patch cannot land on a coincidental match
 * elsewhere in the bundle.
 */
static const uint8_t BCB_ASB_BODY_SIG[5] = {0x86, 0x81, 0x01, 0x02, 0x01};

static int find_asb_body(const uint8_t *wire, size_t wire_len, size_t *out_off) {
    for (size_t i = 0; i + sizeof(BCB_ASB_BODY_SIG) <= wire_len; i++) {
        if (memcmp(wire + i, BCB_ASB_BODY_SIG, sizeof(BCB_ASB_BODY_SIG)) == 0) {
            *out_off = i + sizeof(BCB_ASB_BODY_SIG);
            return 1;
        }
    }
    return 0;
}

static int patch_param_pid(uint8_t *wire, size_t wire_len,
                           const uint8_t pair[3], uint8_t new_pid) {
    size_t off = 0;
    if (!find_asb_body(wire, wire_len, &off)) return 0;
    for (size_t i = off; i + 3 <= wire_len; i++) {
        if (wire[i] == pair[0] && wire[i+1] == pair[1] && wire[i+2] == pair[2]) {
            wire[i+1] = new_pid;
            return 1;
        }
    }
    return 0;
}

TEST(asb_rejects_missing_variant) {
    bp_session_t *s = bp_session_open("asb-no-var");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"hello", 5,
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);

    uint8_t variant_pair[3] = {0x82, 0x02, 0x03};
    ASSERT(patch_param_pid(wire, wire_len, variant_pair, 0x09));

    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_ERR_DECRYPT);
    bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(asb_rejects_missing_scope) {
    bp_session_t *s = bp_session_open("asb-no-scope");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"hello", 5,
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);

    uint8_t scope_pair[3] = {0x82, 0x04, 0x00};
    ASSERT(patch_param_pid(wire, wire_len, scope_pair, 0x09));

    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_ERR_DECRYPT);
    bp_free(wire);
    bp_session_close(s);
    PASS();
}

/*
 * BCB ASB content layout (Phase 1 emitter):
 *   array(6) array(1) uint(payload=1) uint(ctx_id=2) uint(ctx_flags=1) ...
 * Bytes: 0x86 0x81 0x01 0x02 0x01 ...
 * That signature is unique to the ASB body; patching offset 4 changes
 * ctx_flags from 1 to anything else without disturbing the BCB block
 * header, where similar small ints appear as block number / flags.
 */
TEST(asb_rejects_extra_ctx_flags) {
    bp_session_t *s = bp_session_open("asb-ctx-flags");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"hi", 2,
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);

    int patched = 0;
    for (size_t i = 0; i + 5 <= wire_len; i++) {
        if (wire[i] == 0x86 && wire[i+1] == 0x81 && wire[i+2] == 0x01
            && wire[i+3] == 0x02 && wire[i+4] == 0x01) {
            wire[i+4] = 0x03;
            patched = 1;
            break;
        }
    }
    ASSERT(patched);

    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_ERR_DECRYPT);
    bp_free(wire);
    bp_session_close(s);
    PASS();
}

TEST(asb_rejects_mismatched_variant) {
    bp_session_t *s = bp_session_open("asb-variant");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");
    bp_security_policy_t p;
    policy_bcb_only(&p, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &p), BPSEC_SUCCESS);

    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"hello", 5,
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);

    size_t off = 0;
    ASSERT(find_asb_body(wire, wire_len, &off));
    int patched = 0;
    for (size_t i = off; i + 3 <= wire_len; i++) {
        if (wire[i] == 0x82 && wire[i+1] == 0x02 && wire[i+2] == 0x03) {
            wire[i+2] = 0x05;
            patched = 1;
            break;
        }
    }
    ASSERT(patched);

    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_ERR_DECRYPT);
    bp_free(wire);
    bp_session_close(s);
    PASS();
}

/*
 * Concurrent set_security: spawn N threads, each retries set_security
 * many times, alternating between a known-good policy and a policy
 * whose key was never installed. The good calls must always leave the
 * session armed; the bad calls must never tear it down. After joining
 * we verify a final secure_encode still works.
 */
typedef struct {
    bp_session_t *session;
    int           iters;
    int           good_failures;
} concurrent_setsec_arg_t;

static thread_ret_t concurrent_setsec_thread(void *arg) {
    concurrent_setsec_arg_t *a = arg;
    bp_security_policy_t good, bad;
    policy_bcb_only(&good, KEY_BCB);
    policy_bcb_only(&bad,  "unknown-key-id");
    for (int i = 0; i < a->iters; i++) {
        if ((i & 1) == 0) {
            if (bp_session_set_security(a->session, &good) != BPSEC_SUCCESS)
                a->good_failures++;
        } else {
            (void)bp_session_set_security(a->session, &bad);
        }
    }
    return (thread_ret_t)0;
}

TEST(concurrent_set_security_atomic) {
    bp_session_t *s = bp_session_open("setsec-race");
    ASSERT(s);
    bp_session_set_source(s, "ipn:1.1");

    bp_security_policy_t init;
    policy_bcb_only(&init, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &init), BPSEC_SUCCESS);

    enum { N = 4, ITER = 200 };
    THREAD_T threads[N];
    concurrent_setsec_arg_t args[N];
    for (int i = 0; i < N; i++) {
        args[i].session = s;
        args[i].iters = ITER;
        args[i].good_failures = 0;
        THREAD_CREATE(threads[i], concurrent_setsec_thread, &args[i]);
    }
    int total_failures = 0;
    for (int i = 0; i < N; i++) { THREAD_JOIN(threads[i]); total_failures += args[i].good_failures; }
    ASSERT_EQ(total_failures, 0);

    bp_security_policy_t good;
    policy_bcb_only(&good, KEY_BCB);
    ASSERT_EQ(bp_session_set_security(s, &good), BPSEC_SUCCESS);
    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };
    uint8_t *wire = NULL; size_t wire_len = 0;
    ASSERT_EQ(bp_session_secure_encode(s, (const uint8_t *)"x", 1,
                                       &opts, &wire, &wire_len), BPSEC_SUCCESS);
    bp_bundle_t *out = NULL;
    ASSERT_EQ(bp_session_process_wire(s, wire, wire_len, &out), BPSEC_SUCCESS);
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
    RUN_TEST(reject_empty_payload);
    RUN_TEST(file_provider_parses_hmac_and_aes);
    RUN_TEST(file_provider_rejects_missing_type_token);
    RUN_TEST(iv_provider_load_after_set_security);
    RUN_TEST(iv_provider_rejects_overflow_counter);
    RUN_TEST(asb_rejects_mismatched_variant);
    RUN_TEST(asb_rejects_missing_variant);
    RUN_TEST(asb_rejects_missing_scope);
    RUN_TEST(asb_rejects_extra_ctx_flags);
    RUN_TEST(concurrent_set_security_atomic);
    RUN_TEST(missing_source_rejected);
    RUN_TEST(opts_source_overrides_session);
    RUN_TEST(concurrent_send_safe);

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);

    bp_shutdown();
    return tests_failed > 0 ? 1 : 0;
}
