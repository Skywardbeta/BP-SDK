#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bp_sdk.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s\n", message); \
            return 0; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while(0)

int test_security_registration() {
    printf("\n=== Testing Security Registration ===\n");
    
    int result = bp_init("ipn:1.1", NULL);
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK initialization");
    
    bp_security_t *aes_security;
    result = bp_security_create_aes_gcm(&aes_security);
    TEST_ASSERT(result == BP_SUCCESS, "AES-GCM security creation");
    
    result = bp_security_register(aes_security);
    TEST_ASSERT(result == BP_SUCCESS, "Security registration");
    
    result = bp_security_register(aes_security);
    TEST_ASSERT(result == BP_ERROR_DUPLICATE, "Duplicate security registration");
    
    result = bp_security_unregister("aes-gcm");
    TEST_ASSERT(result == BP_SUCCESS, "Security unregistration");
    
    bp_security_destroy(aes_security);
    bp_shutdown();
    return 1;
}

int test_hmac_operations() {
    printf("\n=== Testing HMAC Operations ===\n");
    
    int result = bp_init("ipn:1.1", NULL);
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK initialization");
    
    bp_security_t *hmac_security;
    result = bp_security_create_hmac_sha256(&hmac_security);
    TEST_ASSERT(result == BP_SUCCESS, "HMAC-SHA256 security creation");
    
    result = bp_security_register(hmac_security);
    TEST_ASSERT(result == BP_SUCCESS, "HMAC security registration");
    
    const char *test_data = "Hello, BPSEC!";
    void *signature;
    size_t sig_len;
    
    result = bp_security_sign(test_data, strlen(test_data), &signature, &sig_len);
    TEST_ASSERT(result == BP_SUCCESS, "Data signing");
    TEST_ASSERT(signature != NULL, "Signature not NULL");
    TEST_ASSERT(sig_len > 0, "Signature length valid");
    
    result = bp_security_verify(test_data, strlen(test_data), signature, sig_len);
    TEST_ASSERT(result == BP_SUCCESS, "Signature verification");
    
    const char *wrong_data = "Wrong data";
    result = bp_security_verify(wrong_data, strlen(wrong_data), signature, sig_len);
    TEST_ASSERT(result != BP_SUCCESS, "Invalid signature rejection");
    
    free(signature);
    bp_security_unregister("hmac-sha256");
    bp_security_destroy(hmac_security);
    bp_shutdown();
    return 1;
}

int test_aes_operations() {
    printf("\n=== Testing AES Encryption ===\n");
    
    int result = bp_init("ipn:1.1", NULL);
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK initialization");
    
    bp_security_t *aes_security;
    result = bp_security_create_aes_gcm(&aes_security);
    TEST_ASSERT(result == BP_SUCCESS, "AES-GCM security creation");
    
    result = bp_security_register(aes_security);
    TEST_ASSERT(result == BP_SUCCESS, "AES security registration");
    
    const char *test_data = "Secret message for encryption!";
    void *encrypted;
    size_t encrypted_len;
    
    result = bp_security_encrypt(test_data, strlen(test_data), &encrypted, &encrypted_len);
    TEST_ASSERT(result == BP_SUCCESS, "Data encryption");
    TEST_ASSERT(encrypted != NULL, "Encrypted data not NULL");
    TEST_ASSERT(encrypted_len > strlen(test_data), "Encrypted data longer than original");
    
    void *decrypted;
    size_t decrypted_len;
    
    result = bp_security_decrypt(encrypted, encrypted_len, &decrypted, &decrypted_len);
    TEST_ASSERT(result == BP_SUCCESS, "Data decryption");
    TEST_ASSERT(decrypted != NULL, "Decrypted data not NULL");
    TEST_ASSERT(decrypted_len == strlen(test_data), "Decrypted length matches original");
    TEST_ASSERT(memcmp(decrypted, test_data, decrypted_len) == 0, "Decrypted data matches original");
    
    free(encrypted);
    free(decrypted);
    bp_security_unregister("aes-gcm");
    bp_security_destroy(aes_security);
    bp_shutdown();
    return 1;
}

int test_error_conditions() {
    printf("\n=== Testing Error Conditions ===\n");
    
    int result = bp_security_register(NULL);
    TEST_ASSERT(result == BP_ERROR_INVALID_ARGS, "NULL security registration");
    
    result = bp_security_unregister(NULL);
    TEST_ASSERT(result == BP_ERROR_INVALID_ARGS, "NULL security unregistration");
    
    result = bp_security_encrypt(NULL, 0, NULL, NULL);
    TEST_ASSERT(result == BP_ERROR_INVALID_ARGS, "NULL encryption parameters");
    
    result = bp_security_sign(NULL, 0, NULL, NULL);
    TEST_ASSERT(result == BP_ERROR_INVALID_ARGS, "NULL signing parameters");
    
    return 1;
}

int run_bpsec_tests() {
    printf("Running BPSEC Test Suite\n");
    printf("========================\n");
    
    int passed = 0;
    int total = 0;
    
    total++; if (test_security_registration()) passed++;
    total++; if (test_hmac_operations()) passed++;
    total++; if (test_aes_operations()) passed++;
    total++; if (test_error_conditions()) passed++;
    
    printf("\n=== BPSEC Test Results ===\n");
    printf("Passed: %d/%d tests\n", passed, total);
    
    if (passed == total) {
        printf("ALL BPSEC TESTS PASSED!\n");
        return 0;
    } else {
        printf("SOME BPSEC TESTS FAILED!\n");
        return 1;
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("BPSEC Test Suite\n");
        printf("Usage: %s [--help]\n", argv[0]);
        printf("\nThis test suite validates BPSEC functionality.\n");
        return 0;
    }
    
    return run_bpsec_tests();
} 