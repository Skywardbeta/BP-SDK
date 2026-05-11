/*
 * test_phase3a.c - BPSec Phase 3A Test Suite
 * 
 * Tests for key management, security policy, and security roles.
 * Includes thread safety verification.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bp_bpsec_keys.h"
#include "bp_bpsec_policy.h"
#include "bp_bpsec.h"
#include "bp_utils.h"

#ifdef _WIN32
#include <windows.h>
#define THREAD_T HANDLE
#define THREAD_CREATE(t, fn, arg) (t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fn), (arg), 0, NULL)
#define THREAD_JOIN(t) WaitForSingleObject((t), INFINITE)
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <pthread.h>
#include <unistd.h>
#define THREAD_T pthread_t
#define THREAD_CREATE(t, fn, arg) pthread_create(&(t), NULL, (fn), (arg))
#define THREAD_JOIN(t) pthread_join((t), NULL)
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); \
    test_##name(); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    Line %d: %s\n", __LINE__, #cond); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    Line %d: %s != %s\n", __LINE__, #a, #b); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

/* Key Management Tests */

TEST(keystore_create_destroy) {
    bpsec_keystore_t *ks = bpsec_keystore_create(0);
    ASSERT(ks != NULL);
    ASSERT_EQ(bpsec_keystore_count(ks), 0);
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(keystore_add_get) {
    bpsec_keystore_t *ks = bpsec_keystore_create(4);
    ASSERT(ks != NULL);
    
    uint8_t key_data[32];
    memset(key_data, 0xAB, sizeof(key_data));
    
    int rc = bpsec_keystore_add(ks, "test-key-1", BPSEC_KEY_TYPE_HMAC,
                                 key_data, 32, "ipn:1.1", 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bpsec_keystore_count(ks), 1);
    
    bpsec_key_entry_t entry;
    rc = bpsec_keystore_get(ks, "test-key-1", &entry);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(entry.type, BPSEC_KEY_TYPE_HMAC);
    ASSERT_EQ(entry.data_len, 32);
    ASSERT(memcmp(entry.data, key_data, 32) == 0);
    ASSERT(strcmp(entry.bound_eid, "ipn:1.1") == 0);
    
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(keystore_update_existing) {
    bpsec_keystore_t *ks = bpsec_keystore_create(4);
    
    uint8_t key1[32], key2[32];
    memset(key1, 0x11, sizeof(key1));
    memset(key2, 0x22, sizeof(key2));
    
    bpsec_keystore_add(ks, "key-1", BPSEC_KEY_TYPE_HMAC, key1, 32, NULL, 0);
    bpsec_keystore_add(ks, "key-1", BPSEC_KEY_TYPE_AES, key2, 32, "ipn:2.1", 0);
    
    ASSERT_EQ(bpsec_keystore_count(ks), 1);
    
    bpsec_key_entry_t entry;
    bpsec_keystore_get(ks, "key-1", &entry);
    ASSERT_EQ(entry.type, BPSEC_KEY_TYPE_AES);
    ASSERT(memcmp(entry.data, key2, 32) == 0);
    
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(keystore_remove) {
    bpsec_keystore_t *ks = bpsec_keystore_create(4);
    
    uint8_t key[32] = {0};
    bpsec_keystore_add(ks, "key-a", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0);
    bpsec_keystore_add(ks, "key-b", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0);
    bpsec_keystore_add(ks, "key-c", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0);
    
    ASSERT_EQ(bpsec_keystore_count(ks), 3);
    
    int rc = bpsec_keystore_remove(ks, "key-b");
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bpsec_keystore_count(ks), 2);
    
    bpsec_key_entry_t entry;
    rc = bpsec_keystore_get(ks, "key-b", &entry);
    ASSERT_EQ(rc, -1);
    
    rc = bpsec_keystore_get(ks, "key-a", &entry);
    ASSERT_EQ(rc, 0);
    rc = bpsec_keystore_get(ks, "key-c", &entry);
    ASSERT_EQ(rc, 0);
    
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(keystore_find_by_eid) {
    bpsec_keystore_t *ks = bpsec_keystore_create(4);
    
    uint8_t key1[32], key2[32];
    memset(key1, 0x11, sizeof(key1));
    memset(key2, 0x22, sizeof(key2));
    
    bpsec_keystore_add(ks, "hmac-node1", BPSEC_KEY_TYPE_HMAC, key1, 32, "ipn:1.1", 0);
    bpsec_keystore_add(ks, "aes-node2", BPSEC_KEY_TYPE_AES, key2, 32, "ipn:2.1", 0);
    bpsec_keystore_add(ks, "hmac-global", BPSEC_KEY_TYPE_HMAC, key1, 32, "", 0);
    
    bpsec_key_entry_t entry;
    
    int rc = bpsec_keystore_find_by_eid(ks, "ipn:1.1", BPSEC_KEY_TYPE_HMAC, &entry);
    ASSERT_EQ(rc, 0);
    ASSERT(strcmp(entry.id, "hmac-node1") == 0);
    
    rc = bpsec_keystore_find_by_eid(ks, "ipn:2.1", BPSEC_KEY_TYPE_AES, &entry);
    ASSERT_EQ(rc, 0);
    ASSERT(strcmp(entry.id, "aes-node2") == 0);
    
    rc = bpsec_keystore_find_by_eid(ks, "ipn:99.99", BPSEC_KEY_TYPE_HMAC, &entry);
    ASSERT_EQ(rc, 0);
    ASSERT(strcmp(entry.id, "hmac-global") == 0);
    
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(keystore_expiry) {
    bpsec_keystore_t *ks = bpsec_keystore_create(4);
    
    uint8_t key[32] = {0};
    uint64_t now = bp_time_now_dtn();
    
    bpsec_keystore_add(ks, "key-expired", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, now - 100);
    bpsec_keystore_add(ks, "key-valid", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, now + 10000);
    bpsec_keystore_add(ks, "key-no-expiry", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0);
    
    ASSERT_EQ(bpsec_keystore_count(ks), 3);
    
    size_t expired = bpsec_keystore_expire(ks, now);
    ASSERT_EQ(expired, 1);
    ASSERT_EQ(bpsec_keystore_count(ks), 2);
    
    bpsec_key_entry_t entry;
    int rc = bpsec_keystore_get(ks, "key-expired", &entry);
    ASSERT_EQ(rc, -1);
    
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(keystore_capacity_growth) {
    bpsec_keystore_t *ks = bpsec_keystore_create(2);
    
    uint8_t key[32] = {0};
    char id[32];
    
    for (int i = 0; i < 20; i++) {
        snprintf(id, sizeof(id), "key-%d", i);
        int rc = bpsec_keystore_add(ks, id, BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0);
        ASSERT_EQ(rc, 0);
    }
    
    ASSERT_EQ(bpsec_keystore_count(ks), 20);
    
    bpsec_key_entry_t entry;
    for (int i = 0; i < 20; i++) {
        snprintf(id, sizeof(id), "key-%d", i);
        int rc = bpsec_keystore_get(ks, id, &entry);
        ASSERT_EQ(rc, 0);
    }
    
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(keystore_null_params) {
    bpsec_keystore_t *ks = bpsec_keystore_create(4);
    uint8_t key[32] = {0};
    bpsec_key_entry_t entry;
    
    ASSERT_EQ(bpsec_keystore_add(NULL, "id", BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0), -1);
    ASSERT_EQ(bpsec_keystore_add(ks, NULL, BPSEC_KEY_TYPE_HMAC, key, 32, NULL, 0), -1);
    ASSERT_EQ(bpsec_keystore_add(ks, "id", BPSEC_KEY_TYPE_HMAC, NULL, 32, NULL, 0), -1);
    ASSERT_EQ(bpsec_keystore_add(ks, "id", BPSEC_KEY_TYPE_HMAC, key, 0, NULL, 0), -1);
    
    ASSERT_EQ(bpsec_keystore_get(NULL, "id", &entry), -1);
    ASSERT_EQ(bpsec_keystore_get(ks, NULL, &entry), -1);
    ASSERT_EQ(bpsec_keystore_get(ks, "id", NULL), -1);
    
    bpsec_keystore_destroy(ks);
    PASS();
}

/* Policy Engine Tests */

TEST(policy_create_destroy) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    ASSERT(ctx != NULL);
    ASSERT_EQ(bpsec_policy_rule_count(ctx), 0);
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_add_lookup) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    
    bpsec_policy_rule_t rule = {0};
    strncpy(rule.dest_pattern, "ipn:1.*", sizeof(rule.dest_pattern) - 1);
    rule.requirements = BPSEC_REQUIRE_SIGN;
    rule.role = BPSEC_ROLE_SOURCE;
    rule.on_verify_fail = BPSEC_ACTION_DROP;
    strncpy(rule.sign_key_id, "hmac-key-1", sizeof(rule.sign_key_id) - 1);
    rule.priority = 10;
    
    int rc = bpsec_policy_add_rule(ctx, &rule);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bpsec_policy_rule_count(ctx), 1);
    
    bpsec_policy_rule_t found;
    rc = bpsec_policy_lookup(ctx, "ipn:1.5", &found);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(found.requirements, BPSEC_REQUIRE_SIGN);
    ASSERT_EQ(found.role, BPSEC_ROLE_SOURCE);
    ASSERT(strcmp(found.sign_key_id, "hmac-key-1") == 0);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_priority_order) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    
    bpsec_policy_rule_t rule1 = {0};
    strncpy(rule1.dest_pattern, "ipn:*", sizeof(rule1.dest_pattern) - 1);
    rule1.requirements = BPSEC_REQUIRE_SIGN;
    rule1.priority = 5;
    
    bpsec_policy_rule_t rule2 = {0};
    strncpy(rule2.dest_pattern, "ipn:1.*", sizeof(rule2.dest_pattern) - 1);
    rule2.requirements = BPSEC_REQUIRE_BOTH;
    rule2.priority = 10;
    
    bpsec_policy_add_rule(ctx, &rule1);
    bpsec_policy_add_rule(ctx, &rule2);
    
    bpsec_policy_rule_t found;
    bpsec_policy_lookup(ctx, "ipn:1.5", &found);
    ASSERT_EQ(found.requirements, BPSEC_REQUIRE_BOTH);
    
    bpsec_policy_lookup(ctx, "ipn:2.5", &found);
    ASSERT_EQ(found.requirements, BPSEC_REQUIRE_SIGN);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_wildcard_match) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    
    bpsec_policy_rule_t rule = {0};
    strncpy(rule.dest_pattern, "*", sizeof(rule.dest_pattern) - 1);
    rule.requirements = BPSEC_REQUIRE_ENCRYPT;
    rule.priority = 1;
    
    bpsec_policy_add_rule(ctx, &rule);
    
    bpsec_policy_rule_t found;
    int rc = bpsec_policy_lookup(ctx, "ipn:1.1", &found);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(found.requirements, BPSEC_REQUIRE_ENCRYPT);
    
    rc = bpsec_policy_lookup(ctx, "dtn://node1/service", &found);
    ASSERT_EQ(rc, 0);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_prefix_match_edge_cases) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    
    bpsec_policy_rule_t rule = {0};
    strncpy(rule.dest_pattern, "ipn:1.*", sizeof(rule.dest_pattern) - 1);
    rule.requirements = BPSEC_REQUIRE_SIGN;
    rule.priority = 10;
    bpsec_policy_add_rule(ctx, &rule);
    
    bpsec_policy_rule_t found;
    
    int rc = bpsec_policy_lookup(ctx, "ipn:1.1", &found);
    ASSERT_EQ(rc, 0);
    
    rc = bpsec_policy_lookup(ctx, "ipn:1.999", &found);
    ASSERT_EQ(rc, 0);
    
    rc = bpsec_policy_lookup(ctx, "ipn:2.1", &found);
    ASSERT_EQ(rc, -1);
    
    rc = bpsec_policy_lookup(ctx, "ipn:", &found);
    ASSERT_EQ(rc, -1);
    
    rc = bpsec_policy_lookup(ctx, "ipn:1", &found);
    ASSERT_EQ(rc, -1);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_default_rule) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    
    bpsec_policy_rule_t def = {0};
    def.requirements = BPSEC_REQUIRE_NONE;
    def.on_verify_fail = BPSEC_ACTION_LOG;
    
    bpsec_policy_set_default(ctx, &def);
    
    bpsec_policy_rule_t found;
    int rc = bpsec_policy_lookup(ctx, "unknown:1.1", &found);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(found.requirements, BPSEC_REQUIRE_NONE);
    ASSERT_EQ(found.on_verify_fail, BPSEC_ACTION_LOG);
    
    bpsec_policy_set_default(ctx, NULL);
    rc = bpsec_policy_lookup(ctx, "unknown:1.1", &found);
    ASSERT_EQ(rc, -1);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_remove_rule) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    
    bpsec_policy_rule_t rule1 = {0};
    strncpy(rule1.dest_pattern, "ipn:1.*", sizeof(rule1.dest_pattern) - 1);
    rule1.priority = 10;
    
    bpsec_policy_rule_t rule2 = {0};
    strncpy(rule2.dest_pattern, "ipn:2.*", sizeof(rule2.dest_pattern) - 1);
    rule2.priority = 10;
    
    bpsec_policy_add_rule(ctx, &rule1);
    bpsec_policy_add_rule(ctx, &rule2);
    ASSERT_EQ(bpsec_policy_rule_count(ctx), 2);
    
    int rc = bpsec_policy_remove_rule(ctx, "ipn:1.*");
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bpsec_policy_rule_count(ctx), 1);
    
    bpsec_policy_rule_t found;
    rc = bpsec_policy_lookup(ctx, "ipn:1.1", &found);
    ASSERT_EQ(rc, -1);
    
    rc = bpsec_policy_lookup(ctx, "ipn:2.1", &found);
    ASSERT_EQ(rc, 0);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_statistics) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    
    bpsec_policy_inc_stat(ctx, BPSEC_STAT_SIGNED);
    bpsec_policy_inc_stat(ctx, BPSEC_STAT_SIGNED);
    bpsec_policy_inc_stat(ctx, BPSEC_STAT_VERIFIED);
    bpsec_policy_inc_stat(ctx, BPSEC_STAT_VERIFY_FAIL);
    
    bpsec_policy_stats_t stats;
    bpsec_policy_get_stats(ctx, &stats);
    
    ASSERT_EQ(stats.bundles_signed, 2);
    ASSERT_EQ(stats.bundles_verified, 1);
    ASSERT_EQ(stats.verify_failures, 1);
    ASSERT_EQ(stats.bundles_encrypted, 0);
    
    bpsec_policy_reset_stats(ctx);
    bpsec_policy_get_stats(ctx, &stats);
    ASSERT_EQ(stats.bundles_signed, 0);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

TEST(policy_null_params) {
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    bpsec_policy_rule_t rule = {0};
    
    ASSERT_EQ(bpsec_policy_add_rule(NULL, &rule), -1);
    ASSERT_EQ(bpsec_policy_add_rule(ctx, NULL), -1);
    ASSERT_EQ(bpsec_policy_lookup(NULL, "ipn:1.1", &rule), -1);
    ASSERT_EQ(bpsec_policy_lookup(ctx, NULL, &rule), -1);
    ASSERT_EQ(bpsec_policy_lookup(ctx, "ipn:1.1", NULL), -1);
    
    bpsec_policy_destroy(ctx);
    PASS();
}

/* Thread Safety Tests */

typedef struct {
    bpsec_keystore_t *ks;
    int thread_id;
    int iterations;
    int errors;
} keystore_thread_ctx_t;

#ifdef _WIN32
static DWORD WINAPI keystore_thread_fn(void *arg) {
#else
static void *keystore_thread_fn(void *arg) {
#endif
    keystore_thread_ctx_t *ctx = (keystore_thread_ctx_t *)arg;
    char key_id[64];
    uint8_t key_data[32];
    bpsec_key_entry_t entry;
    
    for (int i = 0; i < ctx->iterations; i++) {
        snprintf(key_id, sizeof(key_id), "thread-%d-key-%d", ctx->thread_id, i);
        memset(key_data, (uint8_t)(ctx->thread_id ^ i), sizeof(key_data));
        
        if (bpsec_keystore_add(ctx->ks, key_id, BPSEC_KEY_TYPE_HMAC,
                               key_data, 32, NULL, 0) != 0) {
            ctx->errors++;
        }
        
        if (bpsec_keystore_get(ctx->ks, key_id, &entry) != 0) {
            ctx->errors++;
        }
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

TEST(keystore_concurrent_access) {
    #define NUM_THREADS 8
    #define ITERATIONS 100
    
    bpsec_keystore_t *ks = bpsec_keystore_create(16);
    THREAD_T threads[NUM_THREADS];
    keystore_thread_ctx_t contexts[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++) {
        contexts[i].ks = ks;
        contexts[i].thread_id = i;
        contexts[i].iterations = ITERATIONS;
        contexts[i].errors = 0;
        THREAD_CREATE(threads[i], keystore_thread_fn, &contexts[i]);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    int total_errors = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        total_errors += contexts[i].errors;
    }
    
    ASSERT_EQ(total_errors, 0);
    ASSERT_EQ(bpsec_keystore_count(ks), NUM_THREADS * ITERATIONS);
    
    bpsec_keystore_destroy(ks);
    PASS();
    
    #undef NUM_THREADS
    #undef ITERATIONS
}

typedef struct {
    bpsec_policy_ctx_t *ctx;
    int thread_id;
    int iterations;
    int errors;
} policy_thread_ctx_t;

#ifdef _WIN32
static DWORD WINAPI policy_thread_fn(void *arg) {
#else
static void *policy_thread_fn(void *arg) {
#endif
    policy_thread_ctx_t *ctx = (policy_thread_ctx_t *)arg;
    bpsec_policy_rule_t rule = {0};
    
    for (int i = 0; i < ctx->iterations; i++) {
        snprintf(rule.dest_pattern, sizeof(rule.dest_pattern),
                 "ipn:%d.%d*", ctx->thread_id, i);
        rule.requirements = BPSEC_REQUIRE_SIGN;
        rule.priority = (uint8_t)(ctx->thread_id + i);
        
        if (bpsec_policy_add_rule(ctx->ctx, &rule) != 0) {
            ctx->errors++;
        }
        
        bpsec_policy_inc_stat(ctx->ctx, BPSEC_STAT_SIGNED);
        
        char eid[64];
        snprintf(eid, sizeof(eid), "ipn:%d.%d", ctx->thread_id, i);
        bpsec_policy_rule_t found;
        bpsec_policy_lookup(ctx->ctx, eid, &found);
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

TEST(policy_concurrent_access) {
    #define NUM_THREADS 8
    #define ITERATIONS 100
    
    bpsec_policy_ctx_t *ctx = bpsec_policy_create();
    THREAD_T threads[NUM_THREADS];
    policy_thread_ctx_t contexts[NUM_THREADS];
    
    for (int i = 0; i < NUM_THREADS; i++) {
        contexts[i].ctx = ctx;
        contexts[i].thread_id = i;
        contexts[i].iterations = ITERATIONS;
        contexts[i].errors = 0;
        THREAD_CREATE(threads[i], policy_thread_fn, &contexts[i]);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    int total_errors = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        total_errors += contexts[i].errors;
    }
    
    ASSERT_EQ(total_errors, 0);
    ASSERT_EQ(bpsec_policy_rule_count(ctx), NUM_THREADS * ITERATIONS);
    
    bpsec_policy_stats_t stats;
    bpsec_policy_get_stats(ctx, &stats);
    ASSERT_EQ(stats.bundles_signed, NUM_THREADS * ITERATIONS);
    
    bpsec_policy_destroy(ctx);
    PASS();
    
    #undef NUM_THREADS
    #undef ITERATIONS
}

/* Integration Test with existing BPSec */

TEST(integration_keystore_with_bpsec) {
    bpsec_keystore_t *ks = bpsec_keystore_create(4);
    
    uint8_t hmac_key[32];
    for (int i = 0; i < 32; i++) hmac_key[i] = (uint8_t)i;
    
    bpsec_keystore_add(ks, "test-hmac", BPSEC_KEY_TYPE_HMAC,
                       hmac_key, 32, "ipn:1.1", 0);
    
    bpsec_key_entry_t key;
    int rc = bpsec_keystore_find_by_eid(ks, "ipn:1.1", BPSEC_KEY_TYPE_HMAC, &key);
    ASSERT_EQ(rc, 0);
    
    const char *test_data = "Hello, BPSec!";
    uint8_t sig[32];
    size_t sig_len;
    
    rc = bpsec_sign_hmac_sha256(key.data, key.data_len,
                                 (const uint8_t *)test_data, strlen(test_data),
                                 sig, &sig_len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(sig_len, 32);
    
    rc = bpsec_verify_hmac_sha256(key.data, key.data_len,
                                   (const uint8_t *)test_data, strlen(test_data),
                                   sig, sig_len);
    ASSERT_EQ(rc, 0);
    
    bpsec_keystore_destroy(ks);
    PASS();
}

TEST(integration_policy_driven_security) {
    bpsec_policy_ctx_t *policy = bpsec_policy_create();
    bpsec_keystore_t *keys = bpsec_keystore_create(4);
    
    uint8_t hmac_key[32];
    memset(hmac_key, 0x42, sizeof(hmac_key));
    bpsec_keystore_add(keys, "secure-key", BPSEC_KEY_TYPE_HMAC,
                       hmac_key, 32, "ipn:2.*", 0);
    
    bpsec_policy_rule_t rule = {0};
    strncpy(rule.dest_pattern, "ipn:2.*", sizeof(rule.dest_pattern) - 1);
    rule.requirements = BPSEC_REQUIRE_SIGN;
    rule.role = BPSEC_ROLE_SOURCE;
    strncpy(rule.sign_key_id, "secure-key", sizeof(rule.sign_key_id) - 1);
    rule.priority = 10;
    bpsec_policy_add_rule(policy, &rule);
    
    bpsec_policy_rule_t found;
    int rc = bpsec_policy_lookup(policy, "ipn:2.5", &found);
    ASSERT_EQ(rc, 0);
    ASSERT(found.requirements & BPSEC_REQUIRE_SIGN);
    
    bpsec_key_entry_t key;
    rc = bpsec_keystore_get(keys, found.sign_key_id, &key);
    ASSERT_EQ(rc, 0);
    
    const char *payload = "Secure payload";
    uint8_t sig[32];
    size_t sig_len;
    rc = bpsec_sign_hmac_sha256(key.data, key.data_len,
                                 (const uint8_t *)payload, strlen(payload),
                                 sig, &sig_len);
    ASSERT_EQ(rc, 0);
    
    bpsec_policy_inc_stat(policy, BPSEC_STAT_SIGNED);
    
    bpsec_policy_stats_t stats;
    bpsec_policy_get_stats(policy, &stats);
    ASSERT_EQ(stats.bundles_signed, 1);
    
    bpsec_keystore_destroy(keys);
    bpsec_policy_destroy(policy);
    PASS();
}

int main(void) {
    printf("\n=== BP-SDK Phase 3A Test Suite ===\n\n");
    
    printf("Key Management Tests:\n");
    RUN_TEST(keystore_create_destroy);
    RUN_TEST(keystore_add_get);
    RUN_TEST(keystore_update_existing);
    RUN_TEST(keystore_remove);
    RUN_TEST(keystore_find_by_eid);
    RUN_TEST(keystore_expiry);
    RUN_TEST(keystore_capacity_growth);
    RUN_TEST(keystore_null_params);
    
    printf("\nPolicy Engine Tests:\n");
    RUN_TEST(policy_create_destroy);
    RUN_TEST(policy_add_lookup);
    RUN_TEST(policy_priority_order);
    RUN_TEST(policy_wildcard_match);
    RUN_TEST(policy_prefix_match_edge_cases);
    RUN_TEST(policy_default_rule);
    RUN_TEST(policy_remove_rule);
    RUN_TEST(policy_statistics);
    RUN_TEST(policy_null_params);
    
    printf("\nThread Safety Tests:\n");
    RUN_TEST(keystore_concurrent_access);
    RUN_TEST(policy_concurrent_access);
    
    printf("\nIntegration Tests:\n");
    RUN_TEST(integration_keystore_with_bpsec);
    RUN_TEST(integration_policy_driven_security);
    
    printf("\n=== Results: %d passed, %d failed ===\n\n", tests_passed, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

