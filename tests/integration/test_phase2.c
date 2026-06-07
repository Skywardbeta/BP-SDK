/*
 * test_phase2.c - Phase 2 Integration Tests
 * 
 * Tests for fragmentation timeout, streaming API, and large data transfers.
 */
#include "bp_sdk.h"
#include "bp_bundle.h"
#include "bp_fragment.h"
#include "bp_stream.h"
#include "bp_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-55s", #name); \
    fflush(stdout); \
    test_##name(); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    %s:%d: %lld != %lld\n", __FILE__, __LINE__, \
               (long long)(a), (long long)(b)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

TEST(fragment_expiry_init) {
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create_default();
    ASSERT(ctx != NULL);
    bp_fragment_ctx_destroy(ctx);
    
    bp_fragment_config_t cfg = {60000, BP_FRAGMENT_DEFAULT_MAX_ENTRIES, BP_FRAGMENT_DEFAULT_MAX_BYTES};
    ctx = bp_fragment_ctx_create(&cfg);
    ASSERT(ctx != NULL);
    bp_fragment_ctx_destroy(ctx);
    
    PASS();
}

TEST(fragment_expiry_basic) {
    bp_fragment_config_t cfg = {100, BP_FRAGMENT_DEFAULT_MAX_ENTRIES, BP_FRAGMENT_DEFAULT_MAX_BYTES};
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create(&cfg);
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t frag1;
    memset(&frag1, 0, sizeof(frag1));
    frag1.primary.version = 7;
    frag1.primary.flags = BP_FLAG_FRAGMENT;
    frag1.primary.creation_ts = 1000;
    frag1.primary.creation_seq = 1;
    frag1.primary.total_adu_len = 200;
    frag1.primary.fragment_offset = 0;
    frag1.primary.lifetime_ms = 100;
    
    uint8_t data[100];
    memset(data, 'A', sizeof(data));
    frag1.payload = data;
    frag1.payload_len = 100;
    
    bp_bundle_full_t complete;
    int rc = bp_fragment_add(ctx, &frag1, &complete);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bp_fragment_pending_count(ctx), 1);
    
    uint64_t now = (uint64_t)time(NULL) * 1000;
    size_t expired = bp_fragment_expire(ctx, now + 200);
    ASSERT_EQ(expired, 1);
    ASSERT_EQ(bp_fragment_pending_count(ctx), 0);
    
    bp_fragment_ctx_destroy(ctx);
    PASS();
}

TEST(fragment_pending_bytes) {
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create_default();
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t frag1;
    memset(&frag1, 0, sizeof(frag1));
    frag1.primary.version = 7;
    frag1.primary.flags = BP_FLAG_FRAGMENT;
    frag1.primary.creation_ts = 2000;
    frag1.primary.creation_seq = 1;
    frag1.primary.total_adu_len = 1000;
    frag1.primary.fragment_offset = 0;
    
    uint8_t data[500];
    memset(data, 'B', sizeof(data));
    frag1.payload = data;
    frag1.payload_len = 500;
    
    bp_bundle_full_t complete;
    bp_fragment_add(ctx, &frag1, &complete);
    
    ASSERT_EQ(bp_fragment_pending_bytes(ctx), 1000);
    
    bp_fragment_ctx_destroy(ctx);
    PASS();
}

TEST(stream_create_destroy) {
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", NULL);
    ASSERT(s != NULL);
    
    bp_stream_stats_t stats;
    int rc = bp_stream_get_stats(s, &stats);
    ASSERT_EQ(rc, BP_SUCCESS);
    ASSERT_EQ(stats.bytes_sent, 0);
    ASSERT_EQ(stats.bytes_received, 0);
    
    bp_stream_destroy(s);
    PASS();
}

TEST(stream_create_with_config) {
    bp_stream_config_t config = {
        .fragment_size = 1024,
        .max_in_flight = 4,
        .buffer_size = 8192,
        .timeout_ms = 5000
    };
    
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", &config);
    ASSERT(s != NULL);
    bp_stream_destroy(s);
    PASS();
}

TEST(stream_write_buffer) {
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", NULL);
    ASSERT(s != NULL);
    
    uint8_t data[1024];
    memset(data, 'X', sizeof(data));
    
    int rc = bp_stream_write(s, data, sizeof(data));
    ASSERT_EQ(rc, BP_SUCCESS);
    
    bp_stream_stats_t stats;
    bp_stream_get_stats(s, &stats);
    ASSERT_EQ(stats.bytes_pending, 1024);
    
    bp_stream_destroy(s);
    PASS();
}

TEST(stream_write_large) {
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", NULL);
    ASSERT(s != NULL);
    
    size_t size = 1024 * 1024;
    uint8_t *data = bp_alloc(size);
    ASSERT(data != NULL);
    
    for (size_t i = 0; i < size; i++) {
        data[i] = (uint8_t)(i & 0xFF);
    }
    
    int rc = bp_stream_write(s, data, size);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    bp_stream_stats_t stats;
    bp_stream_get_stats(s, &stats);
    ASSERT_EQ(stats.bytes_pending, size);
    
    bp_free(data);
    bp_stream_destroy(s);
    PASS();
}

TEST(stream_feed_simple) {
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", NULL);
    ASSERT(s != NULL);
    
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 1;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 2;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.lifetime_ms = 3600000;
    
    const char *payload = "Hello Stream";
    bundle.payload = (uint8_t *)payload;
    bundle.payload_len = strlen(payload);
    
    uint8_t encoded[512];
    int enc_len = bp_bundle_encode(&bundle, encoded, sizeof(encoded));
    ASSERT(enc_len > 0);
    
    int rc = bp_stream_feed(s, encoded, (size_t)enc_len);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    char buf[64];
    int n = bp_stream_read_available(s, buf, sizeof(buf));
    ASSERT_EQ(n, (int)strlen(payload));
    ASSERT(memcmp(buf, payload, (size_t)n) == 0);
    
    bp_stream_destroy(s);
    PASS();
}

TEST(stream_feed_fragments) {
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", NULL);
    ASSERT(s != NULL);
    
    size_t total = 300;
    uint8_t original[300];
    for (size_t i = 0; i < total; i++) {
        original[i] = (uint8_t)i;
    }
    
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 1;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 2;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.creation_ts = 5000;
    bundle.primary.creation_seq = 1;
    bundle.primary.lifetime_ms = 3600000;
    bundle.payload = original;
    bundle.payload_len = total;
    
    bp_bundle_full_t *frags = NULL;
    size_t frag_count = 0;
    int rc = bp_fragment_bundle(&bundle, 100, &frags, &frag_count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(frag_count, 3);
    
    for (size_t i = 0; i < frag_count; i++) {
        uint8_t encoded[512];
        int enc_len = bp_bundle_encode(&frags[i], encoded, sizeof(encoded));
        ASSERT(enc_len > 0);
        
        rc = bp_stream_feed(s, encoded, (size_t)enc_len);
        ASSERT_EQ(rc, BP_SUCCESS);
    }
    
    uint8_t received[300];
    int n = bp_stream_read_available(s, received, sizeof(received));
    ASSERT_EQ(n, (int)total);
    ASSERT(memcmp(received, original, total) == 0);
    
    bp_fragment_free_array(frags, frag_count);
    bp_stream_destroy(s);
    PASS();
}

TEST(stream_read_available_empty) {
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", NULL);
    ASSERT(s != NULL);
    
    char buf[64];
    int n = bp_stream_read_available(s, buf, sizeof(buf));
    ASSERT_EQ(n, 0);
    
    bp_stream_destroy(s);
    PASS();
}

TEST(stream_null_checks) {
    ASSERT(bp_stream_create(NULL, "ipn:2.1", NULL) == NULL);
    ASSERT(bp_stream_create("ipn:1.1", NULL, NULL) == NULL);
    
    ASSERT_EQ(bp_stream_write(NULL, "data", 4), BP_ERROR_INVALID_ARGS);
    ASSERT_EQ(bp_stream_flush(NULL), BP_ERROR_INVALID_ARGS);
    ASSERT_EQ(bp_stream_feed(NULL, "data", 4), BP_ERROR_INVALID_ARGS);
    ASSERT_EQ(bp_stream_get_stats(NULL, NULL), BP_ERROR_INVALID_ARGS);
    
    bp_stream_destroy(NULL);
    
    PASS();
}

TEST(large_fragment_reassembly) {
    size_t total_size = 100000;
    uint8_t *original = bp_alloc(total_size);
    ASSERT(original != NULL);
    
    for (size_t i = 0; i < total_size; i++) {
        original[i] = (uint8_t)(i * 7);
    }
    
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 1;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.creation_ts = 10000;
    bundle.primary.creation_seq = 1;
    bundle.primary.lifetime_ms = 3600000;
    bundle.payload = original;
    bundle.payload_len = total_size;
    
    bp_bundle_full_t *frags = NULL;
    size_t frag_count = 0;
    int rc = bp_fragment_bundle(&bundle, 10000, &frags, &frag_count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(frag_count, 10);
    
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create_default();
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t complete;
    int is_complete = 0;
    
    for (size_t i = 0; i < frag_count; i++) {
        rc = bp_fragment_add(ctx, &frags[i], &complete);
        ASSERT(rc >= 0);
        if (rc == 1) is_complete = 1;
    }
    
    ASSERT(is_complete);
    ASSERT_EQ(complete.payload_len, total_size);
    ASSERT(memcmp(complete.payload, original, total_size) == 0);
    
    bp_free(complete.payload);
    bp_free(complete.primary.dest_uri);
    bp_free(complete.primary.source_uri);
    bp_free(complete.primary.report_uri);
    bp_free(original);
    bp_fragment_free_array(frags, frag_count);
    bp_fragment_ctx_destroy(ctx);
    
    PASS();
}

TEST(stream_throughput_measurement) {
    bp_stream_t *s = bp_stream_create("ipn:1.1", "ipn:2.1", NULL);
    ASSERT(s != NULL);
    
    size_t chunk_size = 64 * 1024;
    size_t total_size = 1024 * 1024;
    uint8_t *chunk = bp_alloc(chunk_size);
    ASSERT(chunk != NULL);
    memset(chunk, 'T', chunk_size);
    
    clock_t start = clock();
    
    for (size_t sent = 0; sent < total_size; sent += chunk_size) {
        int rc = bp_stream_write(s, chunk, chunk_size);
        ASSERT_EQ(rc, BP_SUCCESS);
    }
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    
    bp_stream_stats_t stats;
    bp_stream_get_stats(s, &stats);
    ASSERT_EQ(stats.bytes_pending, total_size);
    
    if (elapsed > 0) {
        double mbps = ((double)total_size / (1024 * 1024)) / elapsed;
        printf("(%.1f MB/s) ", mbps);
    }
    
    bp_free(chunk);
    bp_stream_destroy(s);
    PASS();
}

TEST(multiple_concurrent_streams) {
    #define NUM_STREAMS 4
    bp_stream_t *streams[NUM_STREAMS];
    
    for (int i = 0; i < NUM_STREAMS; i++) {
        char local[32], remote[32];
        snprintf(local, sizeof(local), "ipn:1.%d", i);
        snprintf(remote, sizeof(remote), "ipn:2.%d", i);
        streams[i] = bp_stream_create(local, remote, NULL);
        ASSERT(streams[i] != NULL);
    }
    
    uint8_t data[1024];
    memset(data, 'M', sizeof(data));
    
    for (int i = 0; i < NUM_STREAMS; i++) {
        int rc = bp_stream_write(streams[i], data, sizeof(data));
        ASSERT_EQ(rc, BP_SUCCESS);
    }
    
    for (int i = 0; i < NUM_STREAMS; i++) {
        bp_stream_stats_t stats;
        bp_stream_get_stats(streams[i], &stats);
        ASSERT_EQ(stats.bytes_pending, sizeof(data));
    }
    
    for (int i = 0; i < NUM_STREAMS; i++) {
        bp_stream_destroy(streams[i]);
    }
    
    PASS();
    #undef NUM_STREAMS
}

TEST(fragment_loss_timeout) {
    bp_fragment_config_t cfg = {50, BP_FRAGMENT_DEFAULT_MAX_ENTRIES, BP_FRAGMENT_DEFAULT_MAX_BYTES};
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create(&cfg);
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t frag1, frag2;
    memset(&frag1, 0, sizeof(frag1));
    memset(&frag2, 0, sizeof(frag2));
    
    frag1.primary.version = 7;
    frag1.primary.flags = BP_FLAG_FRAGMENT;
    frag1.primary.creation_ts = 9000;
    frag1.primary.creation_seq = 1;
    frag1.primary.total_adu_len = 300;
    frag1.primary.fragment_offset = 0;
    frag1.primary.lifetime_ms = 50;
    
    uint8_t data1[100];
    memset(data1, 'A', sizeof(data1));
    frag1.payload = data1;
    frag1.payload_len = 100;
    
    bp_bundle_full_t complete;
    int rc = bp_fragment_add(ctx, &frag1, &complete);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bp_fragment_pending_count(ctx), 1);
    
    frag2.primary.version = 7;
    frag2.primary.flags = BP_FLAG_FRAGMENT;
    frag2.primary.creation_ts = 9000;
    frag2.primary.creation_seq = 1;
    frag2.primary.total_adu_len = 300;
    frag2.primary.fragment_offset = 100;
    frag2.primary.lifetime_ms = 50;
    
    uint8_t data2[100];
    memset(data2, 'B', sizeof(data2));
    frag2.payload = data2;
    frag2.payload_len = 100;
    
    rc = bp_fragment_add(ctx, &frag2, &complete);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bp_fragment_pending_count(ctx), 1);
    
    uint64_t now = (uint64_t)time(NULL) * 1000;
    size_t expired = bp_fragment_expire(ctx, now + 100);
    ASSERT_EQ(expired, 1);
    ASSERT_EQ(bp_fragment_pending_count(ctx), 0);
    
    bp_fragment_ctx_destroy(ctx);
    PASS();
}

TEST(large_data_10mb) {
    size_t total_size = 10 * 1024 * 1024;
    uint8_t *original = bp_alloc(total_size);
    ASSERT(original != NULL);
    
    for (size_t i = 0; i < total_size; i++) {
        original[i] = (uint8_t)(i ^ (i >> 8) ^ (i >> 16));
    }
    
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    bundle.primary.version = 7;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 1;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.creation_ts = 20000;
    bundle.primary.creation_seq = 1;
    bundle.primary.lifetime_ms = 3600000;
    bundle.payload = original;
    bundle.payload_len = total_size;
    
    bp_bundle_full_t *frags = NULL;
    size_t frag_count = 0;
    int rc = bp_fragment_bundle(&bundle, 64 * 1024, &frags, &frag_count);
    ASSERT_EQ(rc, 0);
    ASSERT(frag_count > 100);
    
    bp_fragment_ctx_t *ctx = bp_fragment_ctx_create_default();
    ASSERT(ctx != NULL);
    
    bp_bundle_full_t complete;
    int is_complete = 0;
    
    for (size_t i = 0; i < frag_count; i++) {
        rc = bp_fragment_add(ctx, &frags[i], &complete);
        ASSERT(rc >= 0);
        if (rc == 1) is_complete = 1;
    }
    
    ASSERT(is_complete);
    ASSERT_EQ(complete.payload_len, total_size);
    
    int match = 1;
    for (size_t i = 0; i < total_size && match; i++) {
        if (complete.payload[i] != original[i]) match = 0;
    }
    ASSERT(match);
    
    bp_free(complete.payload);
    bp_free(complete.primary.dest_uri);
    bp_free(complete.primary.source_uri);
    bp_free(complete.primary.report_uri);
    bp_free(original);
    bp_fragment_free_array(frags, frag_count);
    bp_fragment_ctx_destroy(ctx);
    
    PASS();
}

int main(void) {
    printf("\n=== BP-SDK Phase 2 Test Suite ===\n\n");
    
    printf("Fragment Expiration Tests:\n");
    RUN_TEST(fragment_expiry_init);
    RUN_TEST(fragment_expiry_basic);
    RUN_TEST(fragment_pending_bytes);
    
    printf("\nStream Creation Tests:\n");
    RUN_TEST(stream_create_destroy);
    RUN_TEST(stream_create_with_config);
    RUN_TEST(stream_null_checks);
    
    printf("\nStream Write Tests:\n");
    RUN_TEST(stream_write_buffer);
    RUN_TEST(stream_write_large);
    
    printf("\nStream Read Tests:\n");
    RUN_TEST(stream_feed_simple);
    RUN_TEST(stream_feed_fragments);
    RUN_TEST(stream_read_available_empty);
    
    printf("\nLarge Data Tests:\n");
    RUN_TEST(large_fragment_reassembly);
    RUN_TEST(stream_throughput_measurement);
    RUN_TEST(multiple_concurrent_streams);
    RUN_TEST(fragment_loss_timeout);
    RUN_TEST(large_data_10mb);
    
    printf("\n=== Results: %d passed, %d failed ===\n\n", tests_passed, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

