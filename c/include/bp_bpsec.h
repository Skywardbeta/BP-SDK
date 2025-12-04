/* bp_bpsec.h - BPSec (RFC 9172/9173) */
#ifndef BP_BPSEC_H
#define BP_BPSEC_H

#include <stdint.h>
#include <stddef.h>

#define BPSEC_CTX_BIB_HMAC_SHA2   1
#define BPSEC_CTX_BCB_AES_GCM     2

#define BP_BLOCK_BIB              11
#define BP_BLOCK_BCB              12

#define BPSEC_FLAG_PARAMS_PRESENT 0x01

typedef struct {
    uint8_t sha_variant;
    uint8_t *wrapped_key;
    size_t wrapped_key_len;
} bpsec_bib_params_t;

typedef struct {
    uint8_t aes_variant;
    uint8_t *wrapped_key;
    size_t wrapped_key_len;
    uint8_t iv[12];
} bpsec_bcb_params_t;

typedef struct {
    uint8_t *data;
    size_t len;
} bpsec_result_t;

typedef struct {
    uint8_t context_id;
    uint64_t context_flags;
    uint64_t *targets;
    size_t target_count;
    uint64_t source_node;
    uint64_t source_service;
    union {
        bpsec_bib_params_t bib;
        bpsec_bcb_params_t bcb;
    } params;
    bpsec_result_t *results;
    size_t result_count;
} bpsec_block_t;

typedef struct {
    char *key_id;
    uint8_t *key_data;
    size_t key_len;
} bpsec_key_t;

int bpsec_sign_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t *sig, size_t *sig_len);

int bpsec_verify_hmac_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             const uint8_t *sig, size_t sig_len);

int bpsec_encrypt_aes_gcm(const uint8_t *key, const uint8_t *iv,
                          const uint8_t *plain, size_t plain_len,
                          const uint8_t *aad, size_t aad_len,
                          uint8_t *cipher, uint8_t *tag);

int bpsec_decrypt_aes_gcm(const uint8_t *key, const uint8_t *iv,
                          const uint8_t *cipher, size_t cipher_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *tag, uint8_t *plain);

int bpsec_block_encode(const bpsec_block_t *block, uint8_t *out, size_t cap);
int bpsec_block_decode(const uint8_t *data, size_t len, bpsec_block_t *block);
void bpsec_block_free(bpsec_block_t *block);

#endif
