#include "bp_sdk.h"
#include "bp_bundle.h"
#include "bp_fragment.h"
#include "bp_storage.h"
#include "bp_tcpcl.h"
#include "bp_cbor.h"
#include "bp_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#include <pthread.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

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

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL\n    %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("FAIL\n    %s:%d: memory mismatch\n", __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

TEST(eid_parse_ipn) {
    uint8_t scheme;
    uint64_t ssp[2];
    char *uri = NULL;
    
    int rc = bp_eid_parse("ipn:1.1", &scheme, ssp, &uri);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(scheme, BP_EID_IPN);
    ASSERT_EQ(ssp[0], 1);
    ASSERT_EQ(ssp[1], 1);
    ASSERT(uri == NULL);
    
    rc = bp_eid_parse("ipn:42.99", &scheme, ssp, &uri);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ssp[0], 42);
    ASSERT_EQ(ssp[1], 99);
    
    PASS();
}

TEST(eid_parse_dtn) {
    uint8_t scheme;
    uint64_t ssp[2];
    char *uri = NULL;
    
    int rc = bp_eid_parse("dtn://node1/app", &scheme, ssp, &uri);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(scheme, BP_EID_DTN);
    ASSERT(uri != NULL);
    ASSERT_STR_EQ(uri, "//node1/app");
    bp_free(uri);
    
    PASS();
}

TEST(eid_parse_invalid) {
    uint8_t scheme;
    uint64_t ssp[2];
    
    ASSERT(bp_eid_parse(NULL, &scheme, ssp, NULL) < 0);
    ASSERT(bp_eid_parse("ipn:1.1", NULL, ssp, NULL) < 0);
    ASSERT(bp_eid_parse("ipn:1.1", &scheme, NULL, NULL) < 0);
    ASSERT(bp_eid_parse("invalid:1.1", &scheme, ssp, NULL) < 0);
    ASSERT(bp_eid_parse("ipn:bad", &scheme, ssp, NULL) < 0);
    
    PASS();
}

TEST(eid_format_ipn) {
    char buf[64];
    uint64_t ssp[2] = {1, 1};
    
    int len = bp_eid_format(BP_EID_IPN, ssp, NULL, buf, sizeof(buf));
    ASSERT(len > 0);
    ASSERT_STR_EQ(buf, "ipn:1.1");
    
    ssp[0] = 42; ssp[1] = 99;
    len = bp_eid_format(BP_EID_IPN, ssp, NULL, buf, sizeof(buf));
    ASSERT(len > 0);
    ASSERT_STR_EQ(buf, "ipn:42.99");
    
    PASS();
}

TEST(eid_roundtrip) {
    const char *original = "ipn:123.456";
    uint8_t scheme;
    uint64_t ssp[2];
    char buf[64];
    
    int rc = bp_eid_parse(original, &scheme, ssp, NULL);
    ASSERT_EQ(rc, 0);
    
    int len = bp_eid_format(scheme, ssp, NULL, buf, sizeof(buf));
    ASSERT(len > 0);
    ASSERT_STR_EQ(buf, original);
    
    PASS();
}

TEST(bundle_encode_minimal) {
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    
    bundle.primary.version = 7;
    bundle.primary.flags = 0;
    bundle.primary.crc_type = BP_CRC_NONE;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 1;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.report_ssp[0] = 1;
    bundle.primary.report_ssp[1] = 1;
    bundle.primary.creation_ts = 0;
    bundle.primary.creation_seq = 0;
    bundle.primary.lifetime_ms = 3600000;
    
    const char *payload_str = "Hello, DTN!";
    bundle.payload = (uint8_t *)payload_str;
    bundle.payload_len = strlen(payload_str);
    
    uint8_t buf[1024];
    int len = bp_bundle_encode(&bundle, buf, sizeof(buf));
    ASSERT(len > 0);
    ASSERT(len < 200);
    
    PASS();
}

TEST(bundle_encode_decode_roundtrip) {
    bp_bundle_full_t original;
    memset(&original, 0, sizeof(original));
    
    original.primary.version = 7;
    original.primary.flags = 0;
    original.primary.crc_type = BP_CRC_NONE;
    original.primary.dest_scheme = BP_EID_IPN;
    original.primary.dest_ssp[0] = 2;
    original.primary.dest_ssp[1] = 1;
    original.primary.source_scheme = BP_EID_IPN;
    original.primary.source_ssp[0] = 1;
    original.primary.source_ssp[1] = 1;
    original.primary.report_scheme = BP_EID_IPN;
    original.primary.report_ssp[0] = 1;
    original.primary.report_ssp[1] = 0;
    original.primary.creation_ts = 12345;
    original.primary.creation_seq = 1;
    original.primary.lifetime_ms = 7200000;
    
    const char *payload_str = "Test payload for roundtrip";
    size_t payload_len = strlen(payload_str);
    original.payload = bp_alloc(payload_len);
    ASSERT(original.payload != NULL);
    memcpy(original.payload, payload_str, payload_len);
    original.payload_len = payload_len;
    
    uint8_t buf[2048];
    int encoded_len = bp_bundle_encode(&original, buf, sizeof(buf));
    ASSERT(encoded_len > 0);
    
    bp_bundle_full_t decoded;
    int rc = bp_bundle_decode(buf, (size_t)encoded_len, &decoded);
    ASSERT_EQ(rc, 0);
    
    ASSERT_EQ(decoded.primary.version, 7);
    ASSERT_EQ(decoded.primary.dest_scheme, BP_EID_IPN);
    ASSERT_EQ(decoded.primary.dest_ssp[0], 2);
    ASSERT_EQ(decoded.primary.dest_ssp[1], 1);
    ASSERT_EQ(decoded.primary.source_scheme, BP_EID_IPN);
    ASSERT_EQ(decoded.primary.source_ssp[0], 1);
    ASSERT_EQ(decoded.primary.source_ssp[1], 1);
    ASSERT_EQ(decoded.primary.creation_ts, 12345);
    ASSERT_EQ(decoded.primary.creation_seq, 1);
    ASSERT_EQ(decoded.primary.lifetime_ms, 7200000);
    ASSERT_EQ(decoded.payload_len, payload_len);
    ASSERT_MEM_EQ(decoded.payload, payload_str, payload_len);
    
    bp_free(original.payload);
    bp_bundle_full_free(&decoded);
    
    PASS();
}

TEST(bundle_with_crc16) {
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    
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
    
    bundle.payload = (uint8_t *)"CRC test";
    bundle.payload_len = 8;
    
    uint8_t buf[1024];
    int len = bp_bundle_encode(&bundle, buf, sizeof(buf));
    ASSERT(len > 0);
    
    bp_bundle_full_t decoded;
    int rc = bp_bundle_decode(buf, (size_t)len, &decoded);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(decoded.primary.crc_type, BP_CRC_16);
    
    bp_bundle_full_free(&decoded);
    
    PASS();
}

TEST(bundle_with_crc32) {
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    
    bundle.primary.version = 7;
    bundle.primary.crc_type = BP_CRC_32;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 1;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.lifetime_ms = 3600000;
    
    bundle.payload = (uint8_t *)"CRC32 test payload";
    bundle.payload_len = 18;
    
    uint8_t buf[1024];
    int len = bp_bundle_encode(&bundle, buf, sizeof(buf));
    ASSERT(len > 0);
    
    bp_bundle_full_t decoded;
    int rc = bp_bundle_decode(buf, (size_t)len, &decoded);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(decoded.primary.crc_type, BP_CRC_32);
    
    bp_bundle_full_free(&decoded);
    
    PASS();
}

TEST(bundle_large_payload) {
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    
    bundle.primary.version = 7;
    bundle.primary.crc_type = BP_CRC_NONE;
    bundle.primary.dest_scheme = BP_EID_IPN;
    bundle.primary.dest_ssp[0] = 2;
    bundle.primary.dest_ssp[1] = 1;
    bundle.primary.source_scheme = BP_EID_IPN;
    bundle.primary.source_ssp[0] = 1;
    bundle.primary.source_ssp[1] = 1;
    bundle.primary.report_scheme = BP_EID_IPN;
    bundle.primary.lifetime_ms = 3600000;
    
    size_t payload_size = 10000;
    uint8_t *payload = bp_alloc(payload_size);
    ASSERT(payload != NULL);
    for (size_t i = 0; i < payload_size; i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }
    bundle.payload = payload;
    bundle.payload_len = payload_size;
    
    uint8_t *buf = bp_alloc(payload_size + 1024);
    ASSERT(buf != NULL);
    int len = bp_bundle_encode(&bundle, buf, payload_size + 1024);
    ASSERT(len > 0);
    
    bp_bundle_full_t decoded;
    int rc = bp_bundle_decode(buf, (size_t)len, &decoded);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(decoded.payload_len, payload_size);
    ASSERT_MEM_EQ(decoded.payload, payload, payload_size);
    
    bp_free(payload);
    bp_free(buf);
    bp_bundle_full_free(&decoded);
    
    PASS();
}

TEST(fragment_no_fragmentation_needed) {
    bp_bundle_full_t original;
    memset(&original, 0, sizeof(original));
    
    original.primary.version = 7;
    original.primary.dest_scheme = BP_EID_IPN;
    original.primary.dest_ssp[0] = 2;
    original.primary.dest_ssp[1] = 1;
    original.primary.source_scheme = BP_EID_IPN;
    original.primary.source_ssp[0] = 1;
    original.primary.source_ssp[1] = 1;
    original.primary.report_scheme = BP_EID_IPN;
    original.primary.lifetime_ms = 3600000;
    
    original.payload = (uint8_t *)"Small payload";
    original.payload_len = 13;
    
    bp_bundle_full_t *frags = NULL;
    size_t frag_count = 0;
    
    int rc = bp_fragment_bundle(&original, 1000, &frags, &frag_count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(frag_count, 1);
    ASSERT(frags != NULL);
    ASSERT_EQ(frags[0].payload_len, original.payload_len);
    ASSERT(!(frags[0].primary.flags & BP_FLAG_FRAGMENT));
    
    bp_fragment_free_array(frags, frag_count);
    
    PASS();
}

TEST(fragment_basic) {
    bp_bundle_full_t original;
    memset(&original, 0, sizeof(original));
    
    original.primary.version = 7;
    original.primary.dest_scheme = BP_EID_IPN;
    original.primary.dest_ssp[0] = 2;
    original.primary.dest_ssp[1] = 1;
    original.primary.source_scheme = BP_EID_IPN;
    original.primary.source_ssp[0] = 1;
    original.primary.source_ssp[1] = 1;
    original.primary.report_scheme = BP_EID_IPN;
    original.primary.creation_ts = 1000;
    original.primary.creation_seq = 5;
    original.primary.lifetime_ms = 3600000;
    
    size_t payload_size = 1000;
    uint8_t *payload = bp_alloc(payload_size);
    ASSERT(payload != NULL);
    for (size_t i = 0; i < payload_size; i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }
    original.payload = payload;
    original.payload_len = payload_size;
    
    bp_bundle_full_t *frags = NULL;
    size_t frag_count = 0;
    
    int rc = bp_fragment_bundle(&original, 300, &frags, &frag_count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(frag_count, 4);
    ASSERT(frags != NULL);
    
    size_t total_payload = 0;
    for (size_t i = 0; i < frag_count; i++) {
        ASSERT(frags[i].primary.flags & BP_FLAG_FRAGMENT);
        ASSERT_EQ(frags[i].primary.total_adu_len, payload_size);
        ASSERT_EQ(frags[i].primary.fragment_offset, total_payload);
        total_payload += frags[i].payload_len;
    }
    ASSERT_EQ(total_payload, payload_size);
    
    bp_free(payload);
    bp_fragment_free_array(frags, frag_count);
    
    PASS();
}

TEST(fragment_reassembly) {
    bp_bundle_full_t original;
    memset(&original, 0, sizeof(original));
    
    original.primary.version = 7;
    original.primary.dest_scheme = BP_EID_IPN;
    original.primary.dest_ssp[0] = 2;
    original.primary.dest_ssp[1] = 1;
    original.primary.source_scheme = BP_EID_IPN;
    original.primary.source_ssp[0] = 1;
    original.primary.source_ssp[1] = 1;
    original.primary.report_scheme = BP_EID_IPN;
    original.primary.creation_ts = 2000;
    original.primary.creation_seq = 10;
    original.primary.lifetime_ms = 3600000;
    
    size_t payload_size = 500;
    uint8_t *payload = bp_alloc(payload_size);
    ASSERT(payload != NULL);
    for (size_t i = 0; i < payload_size; i++) {
        payload[i] = (uint8_t)((i * 7) & 0xFF);
    }
    original.payload = payload;
    original.payload_len = payload_size;
    
    bp_bundle_full_t *frags = NULL;
    size_t frag_count = 0;
    int rc = bp_fragment_bundle(&original, 150, &frags, &frag_count);
    ASSERT_EQ(rc, 0);
    ASSERT(frag_count > 1);
    
    bp_fragment_ctx_t ctx;
    bp_fragment_ctx_init(&ctx);
    
    bp_bundle_full_t complete;
    int is_complete = 0;
    
    for (size_t i = 0; i < frag_count; i++) {
        rc = bp_fragment_add(&ctx, &frags[i], &complete);
        ASSERT(rc >= 0);
        if (rc == 1) {
            is_complete = 1;
            break;
        }
    }
    
    ASSERT(is_complete);
    ASSERT_EQ(complete.payload_len, payload_size);
    ASSERT_MEM_EQ(complete.payload, payload, payload_size);
    ASSERT(!(complete.primary.flags & BP_FLAG_FRAGMENT));
    
    bp_free(complete.payload);
    bp_free(complete.primary.dest_uri);
    bp_free(complete.primary.source_uri);
    bp_free(complete.primary.report_uri);
    bp_free(payload);
    bp_fragment_free_array(frags, frag_count);
    bp_fragment_ctx_free(&ctx);
    
    PASS();
}

TEST(fragment_out_of_order) {
    bp_bundle_full_t original;
    memset(&original, 0, sizeof(original));
    
    original.primary.version = 7;
    original.primary.dest_scheme = BP_EID_IPN;
    original.primary.dest_ssp[0] = 2;
    original.primary.dest_ssp[1] = 1;
    original.primary.source_scheme = BP_EID_IPN;
    original.primary.source_ssp[0] = 1;
    original.primary.source_ssp[1] = 1;
    original.primary.report_scheme = BP_EID_IPN;
    original.primary.creation_ts = 3000;
    original.primary.creation_seq = 15;
    original.primary.lifetime_ms = 3600000;
    
    size_t payload_size = 400;
    uint8_t *payload = bp_alloc(payload_size);
    ASSERT(payload != NULL);
    for (size_t i = 0; i < payload_size; i++) {
        payload[i] = (uint8_t)i;
    }
    original.payload = payload;
    original.payload_len = payload_size;
    
    bp_bundle_full_t *frags = NULL;
    size_t frag_count = 0;
    int rc = bp_fragment_bundle(&original, 100, &frags, &frag_count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(frag_count, 4);
    
    bp_fragment_ctx_t ctx;
    bp_fragment_ctx_init(&ctx);
    
    bp_bundle_full_t complete;
    size_t order[] = {2, 0, 3, 1};
    int is_complete = 0;
    
    for (size_t i = 0; i < frag_count; i++) {
        rc = bp_fragment_add(&ctx, &frags[order[i]], &complete);
        ASSERT(rc >= 0);
        if (rc == 1) {
            is_complete = 1;
        }
    }
    
    ASSERT(is_complete);
    ASSERT_EQ(complete.payload_len, payload_size);
    ASSERT_MEM_EQ(complete.payload, payload, payload_size);
    
    bp_free(complete.payload);
    bp_free(complete.primary.dest_uri);
    bp_free(complete.primary.source_uri);
    bp_free(complete.primary.report_uri);
    bp_free(payload);
    bp_fragment_free_array(frags, frag_count);
    bp_fragment_ctx_free(&ctx);
    
    PASS();
}

TEST(storage_basic) {
    bp_store_t store;
    int rc = bp_store_init(&store, 1024 * 1024);
    ASSERT_EQ(rc, 0);
    
    const uint8_t data1[] = "Bundle data 1";
    const uint8_t data2[] = "Bundle data 2 - longer";
    
    rc = bp_store_put(&store, "bundle-001", data1, sizeof(data1), 0xFFFFFFFF);
    ASSERT_EQ(rc, 0);
    
    rc = bp_store_put(&store, "bundle-002", data2, sizeof(data2), 0xFFFFFFFF);
    ASSERT_EQ(rc, 0);
    
    uint8_t *retrieved = NULL;
    size_t len = 0;
    rc = bp_store_get(&store, "bundle-001", &retrieved, &len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, sizeof(data1));
    ASSERT_MEM_EQ(retrieved, data1, len);
    bp_free(retrieved);
    
    rc = bp_store_get(&store, "bundle-002", &retrieved, &len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(len, sizeof(data2));
    ASSERT_MEM_EQ(retrieved, data2, len);
    bp_free(retrieved);
    
    bp_store_free(&store);
    
    PASS();
}

TEST(storage_delete) {
    bp_store_t store;
    bp_store_init(&store, 1024 * 1024);
    
    bp_store_put(&store, "to-delete", (uint8_t *)"data", 4, 0xFFFFFFFF);
    
    uint8_t *data = NULL;
    size_t len = 0;
    int rc = bp_store_get(&store, "to-delete", &data, &len);
    ASSERT_EQ(rc, 0);
    bp_free(data);
    
    rc = bp_store_delete(&store, "to-delete");
    ASSERT_EQ(rc, 0);
    
    rc = bp_store_get(&store, "to-delete", &data, &len);
    ASSERT(rc != 0);
    
    bp_store_free(&store);
    
    PASS();
}

TEST(storage_list) {
    bp_store_t store;
    bp_store_init(&store, 1024 * 1024);
    
    bp_store_put(&store, "id-1", (uint8_t *)"a", 1, 0xFFFFFFFF);
    bp_store_put(&store, "id-2", (uint8_t *)"b", 1, 0xFFFFFFFF);
    bp_store_put(&store, "id-3", (uint8_t *)"c", 1, 0xFFFFFFFF);
    
    char **ids = NULL;
    size_t count = 0;
    int rc = bp_store_list(&store, &ids, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 3);
    ASSERT(ids != NULL);
    
    for (size_t i = 0; i < count; i++) {
        bp_free(ids[i]);
    }
    bp_free(ids);
    bp_store_free(&store);
    
    PASS();
}

TEST(storage_update) {
    bp_store_t store;
    bp_store_init(&store, 1024 * 1024);
    
    bp_store_put(&store, "update-me", (uint8_t *)"original", 8, 0xFFFFFFFF);
    
    uint8_t *data = NULL;
    size_t len = 0;
    bp_store_get(&store, "update-me", &data, &len);
    ASSERT_EQ(len, 8);
    bp_free(data);
    
    bp_store_put(&store, "update-me", (uint8_t *)"updated-value", 13, 0xFFFFFFFF);
    
    bp_store_get(&store, "update-me", &data, &len);
    ASSERT_EQ(len, 13);
    ASSERT_MEM_EQ(data, "updated-value", 13);
    bp_free(data);
    
    bp_store_free(&store);
    
    PASS();
}

TEST(cbor_encode_uint) {
    uint8_t buf[16];
    cbor_encoder_t enc;
    
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_uint(&enc, 0);
    ASSERT_EQ(enc.len, 1);
    ASSERT_EQ(buf[0], 0x00);
    
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_uint(&enc, 23);
    ASSERT_EQ(enc.len, 1);
    ASSERT_EQ(buf[0], 0x17);
    
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_uint(&enc, 24);
    ASSERT_EQ(enc.len, 2);
    ASSERT_EQ(buf[0], 0x18);
    ASSERT_EQ(buf[1], 24);
    
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_uint(&enc, 256);
    ASSERT_EQ(enc.len, 3);
    ASSERT_EQ(buf[0], 0x19);
    
    PASS();
}

TEST(cbor_encode_decode_roundtrip) {
    uint8_t buf[64];
    cbor_encoder_t enc;
    cbor_decoder_t dec;
    
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_array(&enc, 3);
    cbor_encode_uint(&enc, 42);
    cbor_encode_uint(&enc, 1000);
    cbor_encode_bytes(&enc, (uint8_t *)"test", 4);
    ASSERT(!enc.error);
    
    cbor_decoder_init(&dec, buf, enc.len);
    
    size_t arr_len;
    int rc = cbor_decode_array(&dec, &arr_len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(arr_len, 3);
    
    uint64_t val;
    rc = cbor_decode_uint(&dec, &val);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(val, 42);
    
    rc = cbor_decode_uint(&dec, &val);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(val, 1000);
    
    const uint8_t *bytes;
    size_t bytes_len;
    rc = cbor_decode_bytes(&dec, &bytes, &bytes_len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(bytes_len, 4);
    ASSERT_MEM_EQ(bytes, "test", 4);
    
    PASS();
}

TEST(sdk_init_shutdown) {
    int rc = bp_init("ipn:1.0", NULL);
    ASSERT_EQ(rc, BP_SUCCESS);
    ASSERT(bp_is_initialized());
    
    rc = bp_shutdown();
    ASSERT_EQ(rc, BP_SUCCESS);
    ASSERT(!bp_is_initialized());
    
    PASS();
}

TEST(sdk_double_init) {
    int rc = bp_init("ipn:1.0", NULL);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    rc = bp_init("ipn:1.0", NULL);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    bp_shutdown();
    
    PASS();
}

TEST(sdk_endpoint_lifecycle) {
    bp_init("ipn:1.0", NULL);
    
    bp_endpoint_t *ep = NULL;
    int rc = bp_endpoint_create("ipn:1.1", &ep);
    ASSERT_EQ(rc, BP_SUCCESS);
    ASSERT(ep != NULL);
    
    rc = bp_endpoint_register(ep);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    rc = bp_endpoint_unregister(ep);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    rc = bp_endpoint_destroy(ep);
    ASSERT_EQ(rc, BP_SUCCESS);
    
    bp_shutdown();
    
    PASS();
}

TEST(sdk_error_messages) {
    ASSERT_STR_EQ(bp_strerror(BP_SUCCESS), "Success");
    ASSERT_STR_EQ(bp_strerror(BP_ERROR_INVALID_ARGS), "Invalid arguments");
    ASSERT_STR_EQ(bp_strerror(BP_ERROR_NOT_INITIALIZED), "Not initialized");
    ASSERT_STR_EQ(bp_strerror(BP_ERROR_MEMORY), "Memory allocation failed");
    ASSERT_STR_EQ(bp_strerror(BP_ERROR_TIMEOUT), "Operation timed out");
    
    PASS();
}

TEST(sdk_null_checks) {
    ASSERT_EQ(bp_init(NULL, NULL), BP_ERROR_INVALID_ARGS);
    ASSERT_EQ(bp_endpoint_create(NULL, NULL), BP_ERROR_INVALID_ARGS);
    ASSERT_EQ(bp_endpoint_destroy(NULL), BP_ERROR_INVALID_ARGS);
    ASSERT_EQ(bp_bundle_free(NULL), BP_ERROR_INVALID_ARGS);
    
    PASS();
}

TEST(crc16_basic) {
    uint8_t data[] = "123456789";
    uint16_t crc = bp_crc16(data, 9);
    ASSERT(crc != 0);
    
    uint16_t crc2 = bp_crc16(data, 9);
    ASSERT_EQ(crc, crc2);
    
    data[0] = '0';
    uint16_t crc3 = bp_crc16(data, 9);
    ASSERT(crc != crc3);
    
    PASS();
}

TEST(crc32c_basic) {
    uint8_t data[] = "123456789";
    uint32_t crc = bp_crc32c(data, 9);
    ASSERT(crc != 0);
    
    uint32_t crc2 = bp_crc32c(data, 9);
    ASSERT_EQ(crc, crc2);
    
    data[0] = '0';
    uint32_t crc3 = bp_crc32c(data, 9);
    ASSERT(crc != crc3);
    
    PASS();
}

TEST(time_conversion) {
    uint64_t unix_time = 1609459200;
    uint64_t dtn_time = bp_time_to_dtn(unix_time);
    uint64_t back = bp_time_from_dtn(dtn_time);
    ASSERT_EQ(back, unix_time);
    
    PASS();
}

int main(void) {
    printf("\n=== BP-SDK Phase 1 Test Suite ===\n\n");
    
    printf("EID Parsing Tests:\n");
    RUN_TEST(eid_parse_ipn);
    RUN_TEST(eid_parse_dtn);
    RUN_TEST(eid_parse_invalid);
    RUN_TEST(eid_format_ipn);
    RUN_TEST(eid_roundtrip);
    
    printf("\nBundle Encoding/Decoding Tests:\n");
    RUN_TEST(bundle_encode_minimal);
    RUN_TEST(bundle_encode_decode_roundtrip);
    RUN_TEST(bundle_with_crc16);
    RUN_TEST(bundle_with_crc32);
    RUN_TEST(bundle_large_payload);
    
    printf("\nFragmentation Tests:\n");
    RUN_TEST(fragment_no_fragmentation_needed);
    RUN_TEST(fragment_basic);
    RUN_TEST(fragment_reassembly);
    RUN_TEST(fragment_out_of_order);
    
    printf("\nStorage Tests:\n");
    RUN_TEST(storage_basic);
    RUN_TEST(storage_delete);
    RUN_TEST(storage_list);
    RUN_TEST(storage_update);
    
    printf("\nCBOR Tests:\n");
    RUN_TEST(cbor_encode_uint);
    RUN_TEST(cbor_encode_decode_roundtrip);
    
    printf("\nSDK Lifecycle Tests:\n");
    RUN_TEST(sdk_init_shutdown);
    RUN_TEST(sdk_double_init);
    RUN_TEST(sdk_endpoint_lifecycle);
    RUN_TEST(sdk_error_messages);
    RUN_TEST(sdk_null_checks);
    
    printf("\nUtility Tests:\n");
    RUN_TEST(crc16_basic);
    RUN_TEST(crc32c_basic);
    RUN_TEST(time_conversion);
    
    printf("\n=== Results: %d passed, %d failed ===\n\n", tests_passed, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

