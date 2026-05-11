/*
 * bp_crypto_backend.c - Default crypto backend wrapping bp_bpsec.c.
 *
 * The default backend keeps the SDK self-contained: it advertises support
 * for HMAC-SHA-256 and AES-GCM-256 only (the RFC 9173 default contexts).
 * For larger HMAC variants or AES-128 register a richer backend through
 * bpsdk_register_crypto_backend().
 *
 * The HMAC streaming API is implemented by buffering the IPPT in heap
 * memory until *_final, which keeps the implementation small enough to
 * audit. Replace the backend if you need true streaming HMAC for very
 * large bundles.
 */
#include "bp_crypto_backend.h"
#include "bp_bpsec.h"
#include "bp_utils.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION mutex_t;
typedef INIT_ONCE        once_t;
#define ONCE_INIT INIT_ONCE_STATIC_INIT
static BOOL CALLBACK once_thunk(PINIT_ONCE o, PVOID p, PVOID *c) {
    (void)o; (void)c;
    ((void (*)(void))p)();
    return TRUE;
}
static void run_once(once_t *o, void (*fn)(void)) {
    InitOnceExecuteOnce(o, once_thunk, (PVOID)fn, NULL);
}
#define mutex_init(m)    InitializeCriticalSection(m)
#define mutex_lock(m)    EnterCriticalSection(m)
#define mutex_unlock(m)  LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
typedef pthread_once_t  once_t;
#define ONCE_INIT PTHREAD_ONCE_INIT
static void run_once(once_t *o, void (*fn)(void)) { pthread_once(o, fn); }
#define mutex_init(m)    pthread_mutex_init(m, NULL)
#define mutex_lock(m)    pthread_mutex_lock(m)
#define mutex_unlock(m)  pthread_mutex_unlock(m)
#endif

#define HMAC_INITIAL_BUF 256
#define HMAC_MAX_KEY_LEN 64

typedef struct {
    int      variant;
    uint8_t  key[HMAC_MAX_KEY_LEN];
    size_t   key_len;
    uint8_t *buf;
    size_t   buf_len;
    size_t   buf_cap;
} default_hmac_ctx_t;

typedef struct {
    int     variant;
    uint8_t key[BPSEC_AES256_KEY_LEN];
    size_t  key_len;
} default_aes_gcm_ctx_t;

static int default_hmac_init(void *bx, const uint8_t *key, size_t key_len,
                             int variant, void **out_ctx) {
    (void)bx;
    if (!key || !out_ctx) return -1;
    if (key_len == 0 || key_len > HMAC_MAX_KEY_LEN) return -1;
    if (variant != BP_CRYPTO_HMAC_SHA256) return -1;

    default_hmac_ctx_t *c = bp_alloc(sizeof(*c));
    if (!c) return -1;
    memset(c, 0, sizeof(*c));
    c->variant = variant;
    c->key_len = key_len;
    memcpy(c->key, key, key_len);
    c->buf_cap = HMAC_INITIAL_BUF;
    c->buf = bp_alloc(c->buf_cap);
    if (!c->buf) {
        memset(c->key, 0, sizeof(c->key));
        bp_free(c);
        return -1;
    }
    *out_ctx = c;
    return 0;
}

static int default_hmac_update(void *bx, void *ctx,
                               const uint8_t *data, size_t len) {
    (void)bx;
    if (!ctx) return -1;
    if (len == 0) return 0;
    if (!data) return -1;
    default_hmac_ctx_t *c = ctx;
    if (c->buf_len + len > c->buf_cap) {
        size_t new_cap = c->buf_cap;
        while (new_cap < c->buf_len + len) new_cap *= 2;
        uint8_t *nb = bp_realloc(c->buf, new_cap);
        if (!nb) return -1;
        c->buf = nb;
        c->buf_cap = new_cap;
    }
    memcpy(c->buf + c->buf_len, data, len);
    c->buf_len += len;
    return 0;
}

static int default_hmac_final(void *bx, void *ctx,
                              uint8_t *tag, size_t *tag_len) {
    (void)bx;
    if (!ctx || !tag || !tag_len) return -1;
    if (*tag_len < BP_CRYPTO_HMAC_SHA256_LEN) return -1;
    default_hmac_ctx_t *c = ctx;
    size_t out_len = 0;
    int rc = bpsec_sign_hmac_sha256(c->key, c->key_len,
                                    c->buf, c->buf_len,
                                    tag, &out_len);
    if (c->buf_len > 0) memset(c->buf, 0, c->buf_len);
    c->buf_len = 0;
    if (rc != 0) return -1;
    *tag_len = out_len;
    return 0;
}

static void default_hmac_free(void *bx, void *ctx) {
    (void)bx;
    if (!ctx) return;
    default_hmac_ctx_t *c = ctx;
    if (c->buf) {
        memset(c->buf, 0, c->buf_cap);
        bp_free(c->buf);
    }
    memset(c->key, 0, sizeof(c->key));
    memset(c, 0, sizeof(*c));
    bp_free(c);
}

static int default_aes_gcm_init(void *bx, const uint8_t *key, size_t key_len,
                                int variant, void **out_ctx) {
    (void)bx;
    if (!key || !out_ctx) return -1;
    if (variant != BP_CRYPTO_AES_GCM_256) return -1;
    if (key_len != BPSEC_AES256_KEY_LEN) return -1;
    default_aes_gcm_ctx_t *c = bp_alloc(sizeof(*c));
    if (!c) return -1;
    memset(c, 0, sizeof(*c));
    c->variant = variant;
    c->key_len = key_len;
    memcpy(c->key, key, key_len);
    *out_ctx = c;
    return 0;
}

static int default_aes_gcm_encrypt(void *bx, void *ctx,
                                   const uint8_t *iv,  size_t iv_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t *ciphertext,
                                   uint8_t *tag, size_t tag_len) {
    (void)bx;
    if (!ctx || !iv || !tag) return -1;
    if (iv_len != BP_CRYPTO_AES_GCM_IV_LEN) return -1;
    if (tag_len != BP_CRYPTO_AES_GCM_TAG_LEN) return -1;
    if (pt_len > 0 && (!plaintext || !ciphertext)) return -1;
    default_aes_gcm_ctx_t *c = ctx;
    return bpsec_encrypt_aes_gcm(c->key, c->key_len, iv,
                                 plaintext, pt_len,
                                 aad, aad_len,
                                 ciphertext, tag);
}

static int default_aes_gcm_decrypt(void *bx, void *ctx,
                                   const uint8_t *iv,  size_t iv_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ciphertext, size_t ct_len,
                                   const uint8_t *tag, size_t tag_len,
                                   uint8_t *plaintext) {
    (void)bx;
    if (!ctx || !iv || !tag) return -1;
    if (iv_len != BP_CRYPTO_AES_GCM_IV_LEN) return -1;
    if (tag_len != BP_CRYPTO_AES_GCM_TAG_LEN) return -1;
    if (ct_len > 0 && (!ciphertext || !plaintext)) return -1;
    default_aes_gcm_ctx_t *c = ctx;
    return bpsec_decrypt_aes_gcm(c->key, c->key_len, iv,
                                 ciphertext, ct_len,
                                 aad, aad_len,
                                 tag, plaintext);
}

static void default_aes_gcm_free(void *bx, void *ctx) {
    (void)bx;
    if (!ctx) return;
    default_aes_gcm_ctx_t *c = ctx;
    memset(c->key, 0, sizeof(c->key));
    memset(c, 0, sizeof(*c));
    bp_free(c);
}

static const bp_crypto_backend_t k_default_backend = {
    .hmac_init       = default_hmac_init,
    .hmac_update     = default_hmac_update,
    .hmac_final      = default_hmac_final,
    .hmac_free       = default_hmac_free,
    .aes_gcm_init    = default_aes_gcm_init,
    .aes_gcm_encrypt = default_aes_gcm_encrypt,
    .aes_gcm_decrypt = default_aes_gcm_decrypt,
    .aes_gcm_free    = default_aes_gcm_free,
    .backend_ctx     = NULL,
};

static once_t              g_init_once = ONCE_INIT;
static mutex_t             g_mutex;
static bp_crypto_backend_t g_active;
static int                 g_active_set = 0;

static void init_globals(void) {
    mutex_init(&g_mutex);
}

static int validate_backend(const bp_crypto_backend_t *b) {
    if (!b->hmac_init || !b->hmac_update || !b->hmac_final || !b->hmac_free)
        return -1;
    if (!b->aes_gcm_init || !b->aes_gcm_encrypt || !b->aes_gcm_decrypt || !b->aes_gcm_free)
        return -1;
    return 0;
}

const bp_crypto_backend_t *bpsdk_crypto_backend_default(void) {
    return &k_default_backend;
}

int bpsdk_register_crypto_backend(const bp_crypto_backend_t *backend) {
    run_once(&g_init_once, init_globals);
    if (backend && validate_backend(backend) != 0) return -1;

    mutex_lock(&g_mutex);
    if (backend) {
        g_active = *backend;
        g_active_set = 1;
    } else {
        memset(&g_active, 0, sizeof(g_active));
        g_active_set = 0;
    }
    mutex_unlock(&g_mutex);
    return 0;
}

const bp_crypto_backend_t *bpsdk_get_crypto_backend(void) {
    run_once(&g_init_once, init_globals);
    mutex_lock(&g_mutex);
    int set = g_active_set;
    mutex_unlock(&g_mutex);
    return set ? &g_active : &k_default_backend;
}
