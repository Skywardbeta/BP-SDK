/*
 * bp_crypto_backend.h - Pluggable HMAC / AES-GCM provider.
 *
 * SecurityService delegates primitive operations through this contract so
 * the SDK can ship a default implementation while still letting integrators
 * substitute OpenSSL, libsodium, or hardware-accelerated providers.
 *
 * Backend implementations MUST be safe to call from multiple threads.
 * The opaque ctx returned from *_init is owned by the caller and need not
 * be thread-safe by itself; SecurityService serialises access to a given
 * ctx for the lifetime of the session.
 */
#ifndef BP_CRYPTO_BACKEND_H
#define BP_CRYPTO_BACKEND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BP_CRYPTO_HMAC_SHA256   5
#define BP_CRYPTO_HMAC_SHA384   6
#define BP_CRYPTO_HMAC_SHA512   7

#define BP_CRYPTO_AES_GCM_128   1
#define BP_CRYPTO_AES_GCM_256   3

#define BP_CRYPTO_AES_GCM_IV_LEN  12
#define BP_CRYPTO_AES_GCM_TAG_LEN 16
#define BP_CRYPTO_HMAC_SHA256_LEN 32
#define BP_CRYPTO_HMAC_SHA384_LEN 48
#define BP_CRYPTO_HMAC_SHA512_LEN 64

typedef struct {
    int  (*hmac_init)(void *backend_ctx, const uint8_t *key, size_t key_len,
                      int hash_variant, void **out_ctx);
    int  (*hmac_update)(void *backend_ctx, void *ctx,
                        const uint8_t *data, size_t len);
    int  (*hmac_final)(void *backend_ctx, void *ctx,
                       uint8_t *tag, size_t *tag_len);
    void (*hmac_free)(void *backend_ctx, void *ctx);

    int  (*aes_gcm_init)(void *backend_ctx, const uint8_t *key, size_t key_len,
                         int aes_variant, void **out_ctx);
    int  (*aes_gcm_encrypt)(void *backend_ctx, void *ctx,
                            const uint8_t *iv,  size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *ciphertext,
                            uint8_t *tag, size_t tag_len);
    int  (*aes_gcm_decrypt)(void *backend_ctx, void *ctx,
                            const uint8_t *iv,  size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *tag, size_t tag_len,
                            uint8_t *plaintext);
    void (*aes_gcm_free)(void *backend_ctx, void *ctx);

    void *backend_ctx;
} bp_crypto_backend_t;

/*
 * Install a backend globally. The struct is copied; the caller may pass a
 * stack-allocated value. The eight function pointers are required; this
 * call returns a negative value if any of them is NULL. Pass NULL to
 * revert to the in-tree default backend.
 */
int bpsdk_register_crypto_backend(const bp_crypto_backend_t *backend);

const bp_crypto_backend_t *bpsdk_get_crypto_backend(void);
const bp_crypto_backend_t *bpsdk_crypto_backend_default(void);

#ifdef __cplusplus
}
#endif

#endif
