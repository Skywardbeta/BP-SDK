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
        printf("FAIL\n    Assertion failed: %s\n    at %s:%d\n", #cond, __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    Expected %lld, got %lld\n    at %s:%d\n", \
               (long long)(b), (long long)(a), __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("FAIL\n    Memory mismatch at %s:%d\n", __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)

TEST(hmac_sha256_basic) {
    uint8_t key[] = "secret_key";
    uint8_t data[] = "Hello, World!";
    uint8_t sig[32];
    size_t sig_len;
    
    int rc = bpsec_sign_hmac_sha256(key, sizeof(key) - 1, data, sizeof(data) - 1, sig, &sig_len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(sig_len, 32);
    
    rc = bpsec_verify_hmac_sha256(key, sizeof(key) - 1, data, sizeof(data) - 1, sig, sig_len);
    ASSERT_EQ(rc, 0);
    
    PASS();
}

TEST(hmac_sha256_verify_fail_wrong_data) {
    uint8_t key[] = "secret_key";
    uint8_t data[] = "Hello, World!";
    uint8_t wrong_data[] = "Hello, World?";
    uint8_t sig[32];
    size_t sig_len;
    
    bpsec_sign_hmac_sha256(key, sizeof(key) - 1, data, sizeof(data) - 1, sig, &sig_len);
    
    int rc = bpsec_verify_hmac_sha256(key, sizeof(key) - 1, wrong_data, sizeof(wrong_data) - 1, sig, sig_len);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(hmac_sha256_verify_fail_wrong_key) {
    uint8_t key[] = "secret_key";
    uint8_t wrong_key[] = "wrong_key";
    uint8_t data[] = "Hello, World!";
    uint8_t sig[32];
    size_t sig_len;
    
    bpsec_sign_hmac_sha256(key, sizeof(key) - 1, data, sizeof(data) - 1, sig, &sig_len);
    
    int rc = bpsec_verify_hmac_sha256(wrong_key, sizeof(wrong_key) - 1, data, sizeof(data) - 1, sig, sig_len);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(hmac_sha256_empty_data) {
    uint8_t key[] = "key";
    uint8_t sig[32];
    size_t sig_len;
    
    int rc = bpsec_sign_hmac_sha256(key, 3, (uint8_t*)"", 0, sig, &sig_len);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(sig_len, 32);
    
    rc = bpsec_verify_hmac_sha256(key, 3, (uint8_t*)"", 0, sig, sig_len);
    ASSERT_EQ(rc, 0);
    
    PASS();
}

TEST(hmac_sha256_long_key) {
    uint8_t long_key[100];
    memset(long_key, 'A', sizeof(long_key));
    uint8_t data[] = "test data";
    uint8_t sig[32];
    size_t sig_len;
    
    int rc = bpsec_sign_hmac_sha256(long_key, sizeof(long_key), data, sizeof(data) - 1, sig, &sig_len);
    ASSERT_EQ(rc, 0);
    
    rc = bpsec_verify_hmac_sha256(long_key, sizeof(long_key), data, sizeof(data) - 1, sig, sig_len);
    ASSERT_EQ(rc, 0);
    
    PASS();
}

TEST(hmac_sha256_wrong_sig_len) {
    uint8_t key[] = "key";
    uint8_t data[] = "data";
    uint8_t sig[32] = {0};
    
    int rc = bpsec_verify_hmac_sha256(key, 3, data, 4, sig, 16);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(aes_gcm_encrypt_decrypt_basic) {
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    uint8_t plain[] = "Hello, AES-GCM!";
    uint8_t cipher[sizeof(plain)];
    uint8_t decrypted[sizeof(plain)];
    uint8_t tag[16];
    
    int rc = bpsec_encrypt_aes_gcm(key, sizeof(key), iv, plain, sizeof(plain) - 1, NULL, 0, cipher, tag);
    ASSERT_EQ(rc, 0);
    
    ASSERT(memcmp(cipher, plain, sizeof(plain) - 1) != 0);
    
    rc = bpsec_decrypt_aes_gcm(key, sizeof(key), iv, cipher, sizeof(plain) - 1, NULL, 0, tag, decrypted);
    ASSERT_EQ(rc, 0);
    ASSERT_MEM_EQ(decrypted, plain, sizeof(plain) - 1);
    
    PASS();
}

TEST(aes_gcm_with_aad) {
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    uint8_t iv[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    uint8_t plain[] = "Payload data";
    uint8_t aad[] = "Additional authenticated data";
    uint8_t cipher[sizeof(plain)];
    uint8_t decrypted[sizeof(plain)];
    uint8_t tag[16];
    
    int rc = bpsec_encrypt_aes_gcm(key, sizeof(key), iv, plain, sizeof(plain) - 1, aad, sizeof(aad) - 1, cipher, tag);
    ASSERT_EQ(rc, 0);
    
    rc = bpsec_decrypt_aes_gcm(key, sizeof(key), iv, cipher, sizeof(plain) - 1, aad, sizeof(aad) - 1, tag, decrypted);
    ASSERT_EQ(rc, 0);
    ASSERT_MEM_EQ(decrypted, plain, sizeof(plain) - 1);
    
    PASS();
}

TEST(aes_gcm_auth_fail_wrong_tag) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t plain[] = "test";
    uint8_t cipher[sizeof(plain)];
    uint8_t decrypted[sizeof(plain)];
    uint8_t tag[16];
    
    bpsec_encrypt_aes_gcm(key, sizeof(key), iv, plain, sizeof(plain) - 1, NULL, 0, cipher, tag);
    
    tag[0] ^= 0x01;
    int rc = bpsec_decrypt_aes_gcm(key, sizeof(key), iv, cipher, sizeof(plain) - 1, NULL, 0, tag, decrypted);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(aes_gcm_auth_fail_wrong_aad) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t plain[] = "test";
    uint8_t aad[] = "correct aad";
    uint8_t wrong_aad[] = "wrong aad!!";
    uint8_t cipher[sizeof(plain)];
    uint8_t decrypted[sizeof(plain)];
    uint8_t tag[16];
    
    bpsec_encrypt_aes_gcm(key, sizeof(key), iv, plain, sizeof(plain) - 1, aad, sizeof(aad) - 1, cipher, tag);
    
    int rc = bpsec_decrypt_aes_gcm(key, sizeof(key), iv, cipher, sizeof(plain) - 1, wrong_aad, sizeof(wrong_aad) - 1, tag, decrypted);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(aes_gcm_auth_fail_tampered_cipher) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t plain[] = "test data here";
    uint8_t cipher[sizeof(plain)];
    uint8_t decrypted[sizeof(plain)];
    uint8_t tag[16];
    
    bpsec_encrypt_aes_gcm(key, sizeof(key), iv, plain, sizeof(plain) - 1, NULL, 0, cipher, tag);
    
    cipher[5] ^= 0xff;
    int rc = bpsec_decrypt_aes_gcm(key, sizeof(key), iv, cipher, sizeof(plain) - 1, NULL, 0, tag, decrypted);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(aes_gcm_large_data) {
    uint8_t key[32];
    uint8_t iv[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i + 0x10);
    
    size_t data_len = 4096;
    uint8_t *plain = bp_alloc(data_len);
    uint8_t *cipher = bp_alloc(data_len);
    uint8_t *decrypted = bp_alloc(data_len);
    uint8_t tag[16];
    
    ASSERT(plain && cipher && decrypted);
    
    for (size_t i = 0; i < data_len; i++) plain[i] = (uint8_t)(i & 0xff);
    
    int rc = bpsec_encrypt_aes_gcm(key, sizeof(key), iv, plain, data_len, NULL, 0, cipher, tag);
    ASSERT_EQ(rc, 0);
    
    rc = bpsec_decrypt_aes_gcm(key, sizeof(key), iv, cipher, data_len, NULL, 0, tag, decrypted);
    ASSERT_EQ(rc, 0);
    ASSERT_MEM_EQ(decrypted, plain, data_len);
    
    bp_free(plain);
    bp_free(cipher);
    bp_free(decrypted);
    
    PASS();
}

TEST(aes_gcm_empty_plaintext) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[] = "only aad, no plaintext";
    uint8_t tag[16];
    uint8_t dummy[1];
    
    int rc = bpsec_encrypt_aes_gcm(key, sizeof(key), iv, NULL, 0, aad, sizeof(aad) - 1, dummy, tag);
    ASSERT_EQ(rc, 0);
    
    rc = bpsec_decrypt_aes_gcm(key, sizeof(key), iv, NULL, 0, aad, sizeof(aad) - 1, tag, dummy);
    ASSERT_EQ(rc, 0);
    
    PASS();
}

TEST(block_encode_decode_roundtrip) {
    bpsec_block_t block = {0};
    block.context_id = BPSEC_CTX_BIB_HMAC_SHA2;
    block.context_flags = BPSEC_FLAG_PARAMS_PRESENT;
    block.source_node = 1;
    block.source_service = 1;
    
    block.target_count = 2;
    block.targets = bp_alloc(sizeof(uint64_t) * 2);
    ASSERT(block.targets);
    block.targets[0] = 1;
    block.targets[1] = 2;
    
    block.result_count = 2;
    block.results = bp_alloc(sizeof(bpsec_result_t) * 2);
    ASSERT(block.results);
    
    uint8_t result1[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t result2[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    
    block.results[0].data = bp_alloc(sizeof(result1));
    block.results[0].len = sizeof(result1);
    memcpy(block.results[0].data, result1, sizeof(result1));
    
    block.results[1].data = bp_alloc(sizeof(result2));
    block.results[1].len = sizeof(result2);
    memcpy(block.results[1].data, result2, sizeof(result2));
    
    uint8_t buffer[256];
    int encoded_len = bpsec_block_encode(&block, buffer, sizeof(buffer));
    ASSERT(encoded_len > 0);
    
    bpsec_block_t decoded = {0};
    int rc = bpsec_block_decode(buffer, (size_t)encoded_len, &decoded);
    ASSERT_EQ(rc, 0);
    
    ASSERT_EQ(decoded.context_id, block.context_id);
    ASSERT_EQ(decoded.context_flags, block.context_flags);
    ASSERT_EQ(decoded.source_node, block.source_node);
    ASSERT_EQ(decoded.source_service, block.source_service);
    ASSERT_EQ(decoded.target_count, block.target_count);
    ASSERT_EQ(decoded.targets[0], block.targets[0]);
    ASSERT_EQ(decoded.targets[1], block.targets[1]);
    ASSERT_EQ(decoded.result_count, block.result_count);
    ASSERT_EQ(decoded.results[0].len, block.results[0].len);
    ASSERT_MEM_EQ(decoded.results[0].data, block.results[0].data, block.results[0].len);
    ASSERT_EQ(decoded.results[1].len, block.results[1].len);
    ASSERT_MEM_EQ(decoded.results[1].data, block.results[1].data, block.results[1].len);
    
    bpsec_block_free(&block);
    bpsec_block_free(&decoded);
    
    PASS();
}

TEST(block_encode_decode_single_target) {
    bpsec_block_t block = {0};
    block.context_id = BPSEC_CTX_BCB_AES_GCM;
    block.context_flags = 0;
    block.source_node = 42;
    block.source_service = 7;
    
    block.target_count = 1;
    block.targets = bp_alloc(sizeof(uint64_t));
    ASSERT(block.targets);
    block.targets[0] = 5;
    
    block.result_count = 1;
    block.results = bp_alloc(sizeof(bpsec_result_t));
    ASSERT(block.results);
    
    uint8_t hmac_result[32];
    for (int i = 0; i < 32; i++) hmac_result[i] = (uint8_t)i;
    
    block.results[0].data = bp_alloc(32);
    block.results[0].len = 32;
    memcpy(block.results[0].data, hmac_result, 32);
    
    uint8_t buffer[256];
    int encoded_len = bpsec_block_encode(&block, buffer, sizeof(buffer));
    ASSERT(encoded_len > 0);
    
    bpsec_block_t decoded = {0};
    int rc = bpsec_block_decode(buffer, (size_t)encoded_len, &decoded);
    ASSERT_EQ(rc, 0);
    
    ASSERT_EQ(decoded.context_id, BPSEC_CTX_BCB_AES_GCM);
    ASSERT_EQ(decoded.target_count, 1);
    ASSERT_EQ(decoded.targets[0], 5);
    ASSERT_EQ(decoded.source_node, 42);
    ASSERT_EQ(decoded.source_service, 7);
    ASSERT_EQ(decoded.result_count, 1);
    ASSERT_EQ(decoded.results[0].len, 32);
    ASSERT_MEM_EQ(decoded.results[0].data, hmac_result, 32);
    
    bpsec_block_free(&block);
    bpsec_block_free(&decoded);
    
    PASS();
}

TEST(block_free_null) {
    bpsec_block_free(NULL);
    PASS();
}

TEST(block_decode_invalid) {
    uint8_t bad_data[] = {0xFF, 0xFF, 0xFF};
    bpsec_block_t block = {0};
    
    int rc = bpsec_block_decode(bad_data, sizeof(bad_data), &block);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(block_encode_null_params) {
    uint8_t buffer[64];
    int rc = bpsec_block_encode(NULL, buffer, sizeof(buffer));
    ASSERT(rc == -1);
    
    bpsec_block_t block = {0};
    rc = bpsec_block_encode(&block, NULL, 64);
    ASSERT(rc == -1);
    
    PASS();
}

TEST(hmac_sha256_null_params) {
    uint8_t buf[32];
    size_t len;
    
    int rc = bpsec_sign_hmac_sha256(NULL, 1, (uint8_t*)"x", 1, buf, &len);
    ASSERT(rc != 0);
    
    rc = bpsec_sign_hmac_sha256((uint8_t*)"k", 1, NULL, 1, buf, &len);
    ASSERT(rc != 0);
    
    rc = bpsec_sign_hmac_sha256((uint8_t*)"k", 1, (uint8_t*)"d", 1, NULL, &len);
    ASSERT(rc != 0);
    
    rc = bpsec_sign_hmac_sha256((uint8_t*)"k", 1, (uint8_t*)"d", 1, buf, NULL);
    ASSERT(rc != 0);
    
    PASS();
}

TEST(aes_gcm_null_params) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t buf[16] = {0};
    uint8_t tag[16] = {0};
    
    int rc = bpsec_encrypt_aes_gcm(NULL, 32, iv, buf, 16, NULL, 0, buf, tag);
    ASSERT(rc != 0);
    
    rc = bpsec_encrypt_aes_gcm(key, 32, NULL, buf, 16, NULL, 0, buf, tag);
    ASSERT(rc != 0);
    
    rc = bpsec_encrypt_aes_gcm(key, 32, iv, buf, 16, NULL, 0, NULL, tag);
    ASSERT(rc != 0);
    
    rc = bpsec_encrypt_aes_gcm(key, 32, iv, buf, 16, NULL, 0, buf, NULL);
    ASSERT(rc != 0);
    
    /* Test invalid key length */
    rc = bpsec_encrypt_aes_gcm(key, 16, iv, buf, 16, NULL, 0, buf, tag);
    ASSERT(rc != 0);
    
    PASS();
}

int main(void) {
    printf("\n=== BPSec Test Suite ===\n\n");
    
    printf("HMAC-SHA256 Tests:\n");
    RUN_TEST(hmac_sha256_basic);
    RUN_TEST(hmac_sha256_verify_fail_wrong_data);
    RUN_TEST(hmac_sha256_verify_fail_wrong_key);
    RUN_TEST(hmac_sha256_empty_data);
    RUN_TEST(hmac_sha256_long_key);
    RUN_TEST(hmac_sha256_wrong_sig_len);
    RUN_TEST(hmac_sha256_null_params);
    
    printf("\nAES-GCM Tests:\n");
    RUN_TEST(aes_gcm_encrypt_decrypt_basic);
    RUN_TEST(aes_gcm_with_aad);
    RUN_TEST(aes_gcm_auth_fail_wrong_tag);
    RUN_TEST(aes_gcm_auth_fail_wrong_aad);
    RUN_TEST(aes_gcm_auth_fail_tampered_cipher);
    RUN_TEST(aes_gcm_large_data);
    RUN_TEST(aes_gcm_empty_plaintext);
    RUN_TEST(aes_gcm_null_params);
    
    printf("\nBlock Encode/Decode Tests:\n");
    RUN_TEST(block_encode_decode_roundtrip);
    RUN_TEST(block_encode_decode_single_target);
    RUN_TEST(block_free_null);
    RUN_TEST(block_decode_invalid);
    RUN_TEST(block_encode_null_params);
    
    printf("\n=== Results: %d passed, %d failed ===\n\n", tests_passed, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

