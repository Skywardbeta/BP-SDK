/*
 * bp_session.c - SecurityService session implementation.
 *
 * Threading model:
 *   Every public bp_session_* call acquires the session mutex for its
 *   entire critical section (policy access, key fetch, crypto context
 *   use, IV counter increment, statistics). Cached HMAC / AES-GCM
 *   contexts are therefore single-writer.
 *
 * IPPT and AAD construction:
 *   IPPT  = CBOR(scope_flags) || CBOR-byte-string-header(payload_len)
 *           || payload_bytes                                (RFC 9173 §3.7)
 *   AAD   = CBOR(scope_flags)                               (RFC 9173 §4.7.2)
 *   Phase 1 only honours BPSEC_SCOPE_BTSD_ONLY; any other value is
 *   rejected at set_security() time so the metadata in the ASB always
 *   matches the cryptographic input.
 *
 * IV scheme:
 *   12-byte AES-GCM IV = 8-byte CSPRNG salt || 4-byte counter (big-endian).
 *   Counter increments atomically; on overflow the send fails with
 *   BPSEC_ERR_IV_EXHAUSTED. An optional bp_iv_state_provider_t lets
 *   callers persist the (salt, counter) pair across restarts.
 *
 * BIB+BCB on the same payload (RFC 9172 §3.9 simplified case):
 *   BCB is generated alone and the GCM authentication tag carries
 *   integrity. BIB is suppressed.
 *
 * Wire-level extras:
 *   BCB blocks targeting the payload set bit 0x01 in block processing
 *   control flags ("Block must be replicated in every fragment"), per
 *   RFC 9172 §3.9 last paragraph.
 */
#include "bp_session.h"

#include "bp_backend.h"
#include "bp_bundle.h"
#include "bp_cbor.h"
#include "bp_crypto_backend.h"
#include "bp_key_provider.h"
#include "bp_sdk.h"
#include "bp_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
typedef CRITICAL_SECTION mutex_t;
#define mutex_init(m)    InitializeCriticalSection(m)
#define mutex_destroy(m) DeleteCriticalSection(m)
#define mutex_lock(m)    EnterCriticalSection(m)
#define mutex_unlock(m)  LeaveCriticalSection(m)
#else
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
typedef pthread_mutex_t mutex_t;
#define mutex_init(m)    pthread_mutex_init(m, NULL)
#define mutex_destroy(m) pthread_mutex_destroy(m)
#define mutex_lock(m)    pthread_mutex_lock(m)
#define mutex_unlock(m)  pthread_mutex_unlock(m)
#endif

#define BP_SESSION_NAME_MAX        64
#define BP_SESSION_KEYREF_MAX      128
#define BP_SESSION_EID_MAX         128
#define BPSEC_PAYLOAD_BLOCK_NUMBER 1
#define BPSEC_BIB_BLOCK_TYPE       11
#define BPSEC_BCB_BLOCK_TYPE       12
#define BPSEC_BCB_REPLICATED_FLAG  0x01
#define BPSEC_IV_SALT_LEN          8

struct bp_session {
    char                 name[BP_SESSION_NAME_MAX];
    bp_security_policy_t policy;
    char                 bib_key_ref[BP_SESSION_KEYREF_MAX];
    char                 bcb_key_ref[BP_SESSION_KEYREF_MAX];
    int                  policy_set;

    char                 source_eid[BP_SESSION_EID_MAX];
    uint8_t              source_scheme;
    uint64_t             source_ssp[2];
    char                *source_uri;

    void                *hmac_ctx;
    void                *aes_gcm_ctx;

    uint8_t              iv_salt[BPSEC_IV_SALT_LEN];
    uint32_t             iv_counter;

    bp_iv_state_provider_t iv_state;
    int                    iv_state_set;

    uint64_t             cached_key_expiry_ms;
    uint64_t             creation_seq;

    bp_session_stats_t   stats;

    mutex_t              mutex;
};

const char *bp_session_strerror(int code) {
    switch (code) {
    case BPSEC_SUCCESS:               return "success";
    case BPSEC_ERR_INVALID_POLICY:    return "invalid security policy";
    case BPSEC_ERR_KEY_NOT_AVAILABLE: return "key not available from provider";
    case BPSEC_ERR_KEY_EXPIRED:       return "key expired";
    case BPSEC_ERR_KEY_TTL_MISMATCH:  return "bundle TTL exceeds key expiry";
    case BPSEC_ERR_CRYPTO_FAILURE:    return "crypto backend failure";
    case BPSEC_ERR_IV_EXHAUSTED:      return "IV counter exhausted";
    case BPSEC_ERR_BPA_REJECTED:      return "BPA rejected the bundle";
    case BPSEC_ERR_INVALID_CONTEXT:   return "unsupported security context";
    case BPSEC_ERR_FRAGMENTATION:     return "fragmentation conflict";
    case BPSEC_ERR_VERIFY:            return "BIB verification failed";
    case BPSEC_ERR_DECRYPT:           return "BCB decryption failed";
    case BPSEC_ERR_TIMEOUT:           return "receive timed out";
    case BPSEC_ERR_INTERNAL:          return "internal error";
    default:                          return "unknown error";
    }
}

static int policy_uses_bib(const bp_security_policy_t *p) {
    return p->mode == BPSEC_MODE_BIB_ONLY || p->mode == BPSEC_MODE_BIB_BCB;
}
static int policy_uses_bcb(const bp_security_policy_t *p) {
    return p->mode == BPSEC_MODE_BCB_ONLY || p->mode == BPSEC_MODE_BIB_BCB;
}

static int hmac_variant(bpsec_context_id_t ctx, int *variant, size_t *tag_len) {
    switch (ctx) {
    case BPSEC_CTX_HMAC_SHA2_256:
        *variant = BP_CRYPTO_HMAC_SHA256; *tag_len = BP_CRYPTO_HMAC_SHA256_LEN; return 0;
    case BPSEC_CTX_HMAC_SHA2_384:
        *variant = BP_CRYPTO_HMAC_SHA384; *tag_len = BP_CRYPTO_HMAC_SHA384_LEN; return 0;
    case BPSEC_CTX_HMAC_SHA2_512:
        *variant = BP_CRYPTO_HMAC_SHA512; *tag_len = BP_CRYPTO_HMAC_SHA512_LEN; return 0;
    default: return -1;
    }
}

static int aes_variant(bpsec_context_id_t ctx, int *variant, size_t *key_len) {
    switch (ctx) {
    case BPSEC_CTX_AES_GCM_128: *variant = BP_CRYPTO_AES_GCM_128; *key_len = 16; return 0;
    case BPSEC_CTX_AES_GCM_256: *variant = BP_CRYPTO_AES_GCM_256; *key_len = 32; return 0;
    default: return -1;
    }
}

static uint64_t rfc9173_sha_variant_code(bpsec_context_id_t ctx) {
    switch (ctx) {
    case BPSEC_CTX_HMAC_SHA2_256: return 5;
    case BPSEC_CTX_HMAC_SHA2_384: return 6;
    case BPSEC_CTX_HMAC_SHA2_512: return 7;
    default: return 0;
    }
}

static uint64_t rfc9173_aes_variant_code(bpsec_context_id_t ctx) {
    switch (ctx) {
    case BPSEC_CTX_AES_GCM_128: return 1;
    case BPSEC_CTX_AES_GCM_256: return 3;
    default: return 0;
    }
}

static int os_random_bytes(uint8_t *out, size_t len) {
#ifdef _WIN32
    return BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, out + got, len - got);
        if (n <= 0) { close(fd); return -1; }
        got += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

static uint64_t now_dtn_ms(void) {
    return bp_time_now_dtn() * 1000ULL;
}

static int validate_policy(const bp_security_policy_t *p) {
    if (!p) return BPSEC_ERR_INVALID_POLICY;
    if (p->mode == BPSEC_MODE_NONE) return BPSEC_SUCCESS;

    if (policy_uses_bib(p)) {
        if (!p->bib_key_ref || !*p->bib_key_ref) return BPSEC_ERR_INVALID_POLICY;
        int v; size_t l;
        if (hmac_variant(p->bib_context, &v, &l) < 0) return BPSEC_ERR_INVALID_CONTEXT;
        if (p->bib_targets != BPSEC_TARGET_PAYLOAD) return BPSEC_ERR_INVALID_POLICY;
        if (p->bib_scope != BPSEC_SCOPE_BTSD_ONLY) return BPSEC_ERR_INVALID_POLICY;
    }
    if (policy_uses_bcb(p)) {
        if (!p->bcb_key_ref || !*p->bcb_key_ref) return BPSEC_ERR_INVALID_POLICY;
        int v; size_t l;
        if (aes_variant(p->bcb_context, &v, &l) < 0) return BPSEC_ERR_INVALID_CONTEXT;
        if (p->bcb_targets != BPSEC_TARGET_PAYLOAD) return BPSEC_ERR_INVALID_POLICY;
        if (p->bcb_scope != BPSEC_SCOPE_BTSD_ONLY) return BPSEC_ERR_INVALID_POLICY;
    }
    return BPSEC_SUCCESS;
}

static void free_cached_ctx_locked(bp_session_t *s) {
    const bp_crypto_backend_t *be = bpsdk_get_crypto_backend();
    if (s->hmac_ctx && be && be->hmac_free) be->hmac_free(be->backend_ctx, s->hmac_ctx);
    if (s->aes_gcm_ctx && be && be->aes_gcm_free) be->aes_gcm_free(be->backend_ctx, s->aes_gcm_ctx);
    s->hmac_ctx = NULL;
    s->aes_gcm_ctx = NULL;
}

static int init_hmac_ctx_locked(bp_session_t *s) {
    const bp_key_provider_t *kp = bpsdk_get_key_provider();
    const bp_crypto_backend_t *be = bpsdk_get_crypto_backend();
    if (!kp || !be) return BPSEC_ERR_INTERNAL;

    int variant; size_t tag_len;
    if (hmac_variant(s->policy.bib_context, &variant, &tag_len) < 0)
        return BPSEC_ERR_INVALID_CONTEXT;

    if (kp->key_available(kp->provider_ctx, s->bib_key_ref, BP_KEY_USAGE_HMAC) != 0)
        return BPSEC_ERR_KEY_NOT_AVAILABLE;

    uint8_t key[BP_KEY_PROVIDER_MAX_KEY_LEN];
    size_t key_len = 0;
    if (kp->get_key(kp->provider_ctx, s->bib_key_ref,
                    BP_KEY_USAGE_HMAC, key, sizeof(key), &key_len) != 0) {
        return BPSEC_ERR_KEY_NOT_AVAILABLE;
    }

    int rc = be->hmac_init(be->backend_ctx, key, key_len, variant, &s->hmac_ctx);
    memset(key, 0, sizeof(key));
    if (rc != 0) { s->hmac_ctx = NULL; return BPSEC_ERR_CRYPTO_FAILURE; }
    return BPSEC_SUCCESS;
}

static int init_aes_gcm_ctx_locked(bp_session_t *s) {
    const bp_key_provider_t *kp = bpsdk_get_key_provider();
    const bp_crypto_backend_t *be = bpsdk_get_crypto_backend();
    if (!kp || !be) return BPSEC_ERR_INTERNAL;

    int variant; size_t want_key_len;
    if (aes_variant(s->policy.bcb_context, &variant, &want_key_len) < 0)
        return BPSEC_ERR_INVALID_CONTEXT;

    if (kp->key_available(kp->provider_ctx, s->bcb_key_ref, BP_KEY_USAGE_AES) != 0)
        return BPSEC_ERR_KEY_NOT_AVAILABLE;

    uint8_t key[BP_KEY_PROVIDER_MAX_KEY_LEN];
    size_t key_len = 0;
    if (kp->get_key(kp->provider_ctx, s->bcb_key_ref,
                    BP_KEY_USAGE_AES, key, sizeof(key), &key_len) != 0) {
        return BPSEC_ERR_KEY_NOT_AVAILABLE;
    }
    if (key_len != want_key_len) {
        memset(key, 0, sizeof(key));
        return BPSEC_ERR_INVALID_POLICY;
    }

    int rc = be->aes_gcm_init(be->backend_ctx, key, key_len, variant, &s->aes_gcm_ctx);
    memset(key, 0, sizeof(key));
    if (rc != 0) { s->aes_gcm_ctx = NULL; return BPSEC_ERR_CRYPTO_FAILURE; }
    return BPSEC_SUCCESS;
}

static int parse_eid_into(const char *eid,
                          uint8_t *scheme, uint64_t ssp[2], char **uri) {
    *uri = NULL;
    return bp_eid_parse(eid, scheme, ssp, uri);
}

bp_session_t *bp_session_open(const char *session_name) {
    if (!session_name) return NULL;
    bp_session_t *s = bp_alloc(sizeof(*s));
    if (!s) return NULL;
    memset(s, 0, sizeof(*s));

    strncpy(s->name, session_name, sizeof(s->name) - 1);
    if (os_random_bytes(s->iv_salt, sizeof(s->iv_salt)) != 0) {
        bp_free(s);
        return NULL;
    }
    mutex_init(&s->mutex);
    return s;
}

int bp_session_close(bp_session_t *s) {
    if (!s) return BPSEC_ERR_INVALID_POLICY;
    mutex_lock(&s->mutex);
    free_cached_ctx_locked(s);
    bp_free(s->source_uri);
    s->source_uri = NULL;
    memset(&s->policy, 0, sizeof(s->policy));
    s->policy_set = 0;
    s->iv_counter = 0;
    memset(s->iv_salt, 0, sizeof(s->iv_salt));
    memset(s->bib_key_ref, 0, sizeof(s->bib_key_ref));
    memset(s->bcb_key_ref, 0, sizeof(s->bcb_key_ref));
    mutex_unlock(&s->mutex);
    mutex_destroy(&s->mutex);
    bp_free(s);
    return BPSEC_SUCCESS;
}

int bp_session_set_source(bp_session_t *s, const char *source_eid) {
    if (!s || !source_eid) return BPSEC_ERR_INVALID_POLICY;

    uint8_t scheme;
    uint64_t ssp[2];
    char *uri = NULL;
    if (bp_eid_parse(source_eid, &scheme, ssp, &uri) < 0) return BPSEC_ERR_INVALID_POLICY;

    mutex_lock(&s->mutex);
    bp_free(s->source_uri);
    s->source_scheme = scheme;
    s->source_ssp[0] = ssp[0];
    s->source_ssp[1] = ssp[1];
    s->source_uri    = uri;
    strncpy(s->source_eid, source_eid, sizeof(s->source_eid) - 1);
    s->source_eid[sizeof(s->source_eid) - 1] = '\0';
    mutex_unlock(&s->mutex);
    return BPSEC_SUCCESS;
}

int bp_session_set_iv_state_provider(bp_session_t *s,
                                     const bp_iv_state_provider_t *provider) {
    if (!s) return BPSEC_ERR_INVALID_POLICY;
    if (provider && (!provider->load || !provider->save)) return BPSEC_ERR_INVALID_POLICY;

    mutex_lock(&s->mutex);
    if (provider) {
        s->iv_state = *provider;
        s->iv_state_set = 1;
    } else {
        memset(&s->iv_state, 0, sizeof(s->iv_state));
        s->iv_state_set = 0;
    }
    mutex_unlock(&s->mutex);
    return BPSEC_SUCCESS;
}

int bp_session_set_security(bp_session_t *s, const bp_security_policy_t *policy) {
    if (!s || !policy) return BPSEC_ERR_INVALID_POLICY;
    int rc = validate_policy(policy);
    if (rc != BPSEC_SUCCESS) return rc;

    mutex_lock(&s->mutex);

    free_cached_ctx_locked(s);
    memset(s->bib_key_ref, 0, sizeof(s->bib_key_ref));
    memset(s->bcb_key_ref, 0, sizeof(s->bcb_key_ref));
    s->policy = *policy;
    if (policy->bib_key_ref) {
        strncpy(s->bib_key_ref, policy->bib_key_ref, sizeof(s->bib_key_ref) - 1);
        s->policy.bib_key_ref = s->bib_key_ref;
    }
    if (policy->bcb_key_ref) {
        strncpy(s->bcb_key_ref, policy->bcb_key_ref, sizeof(s->bcb_key_ref) - 1);
        s->policy.bcb_key_ref = s->bcb_key_ref;
    }

    if (policy_uses_bib(policy)) {
        rc = init_hmac_ctx_locked(s);
        if (rc != BPSEC_SUCCESS) goto out;
    }
    if (policy_uses_bcb(policy)) {
        rc = init_aes_gcm_ctx_locked(s);
        if (rc != BPSEC_SUCCESS) goto out;
    }

    s->cached_key_expiry_ms = 0;
    const bp_key_provider_t *kp = bpsdk_get_key_provider();
    if (kp && kp->get_key_expiry) {
        uint64_t exp = 0;
        if (policy_uses_bcb(policy)
            && kp->get_key_expiry(kp->provider_ctx, s->bcb_key_ref, &exp) == 0
            && exp > 0) {
            s->cached_key_expiry_ms = exp;
        }
        if (policy_uses_bib(policy)
            && kp->get_key_expiry(kp->provider_ctx, s->bib_key_ref, &exp) == 0
            && exp > 0
            && (s->cached_key_expiry_ms == 0 || exp < s->cached_key_expiry_ms)) {
            s->cached_key_expiry_ms = exp;
        }
    }

    if (s->cached_key_expiry_ms > 0
        && s->cached_key_expiry_ms <= now_dtn_ms()) {
        rc = BPSEC_ERR_KEY_EXPIRED;
        goto out;
    }

    if (s->iv_state_set) {
        uint8_t persisted_salt[BPSEC_IV_SALT_LEN];
        uint64_t persisted_counter = 0;
        memset(persisted_salt, 0, sizeof(persisted_salt));
        if (s->iv_state.load(s->iv_state.ctx, s->name,
                             persisted_salt, &persisted_counter) == 0) {
            int empty = 1;
            for (size_t i = 0; i < sizeof(persisted_salt); i++) {
                if (persisted_salt[i]) { empty = 0; break; }
            }
            if (!empty) memcpy(s->iv_salt, persisted_salt, sizeof(persisted_salt));
            s->iv_counter = (uint32_t)persisted_counter;
        }
    }

    s->policy_set = 1;
    rc = BPSEC_SUCCESS;

out:
    if (rc != BPSEC_SUCCESS) free_cached_ctx_locked(s);
    mutex_unlock(&s->mutex);
    return rc;
}

static int build_iv_locked(bp_session_t *s, uint8_t iv[12]) {
    if (s->iv_counter == 0xFFFFFFFFu) return BPSEC_ERR_IV_EXHAUSTED;
    s->iv_counter++;
    memcpy(iv, s->iv_salt, BPSEC_IV_SALT_LEN);
    iv[ 8] = (uint8_t)(s->iv_counter >> 24);
    iv[ 9] = (uint8_t)(s->iv_counter >> 16);
    iv[10] = (uint8_t)(s->iv_counter >>  8);
    iv[11] = (uint8_t)( s->iv_counter      );
    return BPSEC_SUCCESS;
}

static int encode_uint_inline(uint8_t *out, size_t cap, uint64_t v) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, out, cap);
    cbor_encode_uint(&e, v);
    return e.error ? -1 : (int)e.len;
}

static int encode_byte_string_header(uint8_t *out, size_t cap, size_t len) {
    if (len < 24) {
        if (cap < 1) return -1;
        out[0] = (uint8_t)(0x40 | len);
        return 1;
    }
    if (len <= 0xff) {
        if (cap < 2) return -1;
        out[0] = 0x58; out[1] = (uint8_t)len;
        return 2;
    }
    if (len <= 0xffff) {
        if (cap < 3) return -1;
        out[0] = 0x59; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)len;
        return 3;
    }
    if (len <= 0xffffffffULL) {
        if (cap < 5) return -1;
        out[0] = 0x5A;
        out[1] = (uint8_t)(len >> 24);
        out[2] = (uint8_t)(len >> 16);
        out[3] = (uint8_t)(len >>  8);
        out[4] = (uint8_t)( len      );
        return 5;
    }
    if (cap < 9) return -1;
    out[0] = 0x5B;
    for (int i = 0; i < 8; i++) out[1 + i] = (uint8_t)(len >> (56 - i * 8));
    return 9;
}

static int encode_security_source_eid(cbor_encoder_t *enc,
                                      uint8_t scheme, uint64_t ssp[2], const char *uri) {
    cbor_encode_array(enc, 2);
    cbor_encode_uint(enc, scheme);
    if (scheme == BP_EID_IPN) {
        cbor_encode_array(enc, 2);
        cbor_encode_uint(enc, ssp[0]);
        cbor_encode_uint(enc, ssp[1]);
    } else if (scheme == BP_EID_DTN && uri) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "//%s",
                 (uri[0] == '/' && uri[1] == '/') ? uri + 2 : uri);
        cbor_encode_text(enc, tmp);
    } else {
        cbor_encode_uint(enc, 0);
    }
    return enc->error ? -1 : 0;
}

static int build_bib_asb(uint8_t *out, size_t cap,
                         bpsec_context_id_t ctx,
                         bpsec_scope_flags_t scope,
                         uint8_t source_scheme, uint64_t source_ssp[2],
                         const char *source_uri,
                         const uint8_t *tag, size_t tag_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, out, cap);
    cbor_encode_array(&enc, 6);
    cbor_encode_array(&enc, 1);
    cbor_encode_uint(&enc, BPSEC_PAYLOAD_BLOCK_NUMBER);
    cbor_encode_uint(&enc, 1);
    cbor_encode_uint(&enc, 1);
    encode_security_source_eid(&enc, source_scheme, source_ssp, source_uri);
    cbor_encode_array(&enc, 2);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 1);
    cbor_encode_uint(&enc, rfc9173_sha_variant_code(ctx));
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 3);
    cbor_encode_uint(&enc, (uint64_t)scope);
    cbor_encode_array(&enc, 1);
    cbor_encode_array(&enc, 1);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 1);
    cbor_encode_bytes(&enc, tag, tag_len);
    return enc.error ? -1 : (int)enc.len;
}

static int build_bcb_asb(uint8_t *out, size_t cap,
                         bpsec_context_id_t ctx,
                         bpsec_scope_flags_t scope,
                         const uint8_t iv[12],
                         uint8_t source_scheme, uint64_t source_ssp[2],
                         const char *source_uri,
                         const uint8_t *tag, size_t tag_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, out, cap);
    cbor_encode_array(&enc, 6);
    cbor_encode_array(&enc, 1);
    cbor_encode_uint(&enc, BPSEC_PAYLOAD_BLOCK_NUMBER);
    cbor_encode_uint(&enc, 2);
    cbor_encode_uint(&enc, 1);
    encode_security_source_eid(&enc, source_scheme, source_ssp, source_uri);
    cbor_encode_array(&enc, 3);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 1);
    cbor_encode_bytes(&enc, iv, 12);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 2);
    cbor_encode_uint(&enc, rfc9173_aes_variant_code(ctx));
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 4);
    cbor_encode_uint(&enc, (uint64_t)scope);
    cbor_encode_array(&enc, 1);
    cbor_encode_array(&enc, 1);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 1);
    cbor_encode_bytes(&enc, tag, tag_len);
    return enc.error ? -1 : (int)enc.len;
}

/*
 * IPPT for a payload-target BIB with BTSD-only scope. The HMAC input is
 * fed to the backend in three update calls so we never have to allocate
 * a contiguous IPPT buffer for large payloads.
 */
static int hmac_payload_ippt_locked(bp_session_t *s,
                                    bpsec_scope_flags_t scope,
                                    const uint8_t *payload, size_t payload_len,
                                    uint8_t *tag, size_t *tag_len) {
    const bp_crypto_backend_t *be = bpsdk_get_crypto_backend();
    if (!be) return BPSEC_ERR_INTERNAL;

    uint8_t scope_buf[2];
    int scope_len = encode_uint_inline(scope_buf, sizeof(scope_buf), (uint64_t)scope);
    if (scope_len < 0) return BPSEC_ERR_INTERNAL;

    uint8_t hdr_buf[9];
    int hdr_len = encode_byte_string_header(hdr_buf, sizeof(hdr_buf), payload_len);
    if (hdr_len < 0) return BPSEC_ERR_INTERNAL;

    if (be->hmac_update(be->backend_ctx, s->hmac_ctx, scope_buf, (size_t)scope_len) != 0
        || be->hmac_update(be->backend_ctx, s->hmac_ctx, hdr_buf, (size_t)hdr_len) != 0
        || (payload_len > 0 &&
            be->hmac_update(be->backend_ctx, s->hmac_ctx, payload, payload_len) != 0)) {
        return BPSEC_ERR_CRYPTO_FAILURE;
    }
    if (be->hmac_final(be->backend_ctx, s->hmac_ctx, tag, tag_len) != 0)
        return BPSEC_ERR_CRYPTO_FAILURE;
    return BPSEC_SUCCESS;
}

static int do_secure_encode_locked(bp_session_t *s,
                                   const uint8_t *data, size_t len,
                                   const bp_delivery_opts_t *opts,
                                   uint8_t **out, size_t *out_len) {
    if (!s->policy_set) return BPSEC_ERR_INVALID_POLICY;
    if (!opts || !opts->dest_eid) return BPSEC_ERR_INVALID_POLICY;
    if (len > 0 && !data) return BPSEC_ERR_INVALID_POLICY;

    uint32_t lifetime = opts->lifetime_ms ? opts->lifetime_ms : 60000;
    if (s->cached_key_expiry_ms > 0) {
        uint64_t now_ms = now_dtn_ms();
        if (s->cached_key_expiry_ms <= now_ms) return BPSEC_ERR_KEY_EXPIRED;
        if (s->cached_key_expiry_ms - now_ms < (uint64_t)lifetime)
            return BPSEC_ERR_KEY_TTL_MISMATCH;
    }

    const char *src_eid = (opts->source_eid && *opts->source_eid)
                              ? opts->source_eid
                              : s->source_eid;
    if (!src_eid || !*src_eid) return BPSEC_ERR_INVALID_POLICY;

    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    bundle.primary.version = 7;
    bundle.primary.flags = opts->no_fragment ? BP_FLAG_NO_FRAGMENT : 0;
    bundle.primary.crc_type = BP_CRC_NONE;
    bundle.primary.creation_ts = now_dtn_ms();
    bundle.primary.creation_seq = s->creation_seq++;
    bundle.primary.lifetime_ms = lifetime;

    int rc = BPSEC_SUCCESS;
    uint8_t *bcb_ciphertext = NULL;
    uint8_t *bib_asb_buf = NULL;
    uint8_t *bcb_asb_buf = NULL;
    uint8_t *encoded = NULL;

    if (parse_eid_into(opts->dest_eid, &bundle.primary.dest_scheme,
                       bundle.primary.dest_ssp, &bundle.primary.dest_uri) < 0) {
        rc = BPSEC_ERR_INVALID_POLICY; goto done;
    }
    if (parse_eid_into(src_eid, &bundle.primary.source_scheme,
                       bundle.primary.source_ssp, &bundle.primary.source_uri) < 0) {
        rc = BPSEC_ERR_INVALID_POLICY; goto done;
    }
    bundle.primary.report_scheme = bundle.primary.source_scheme;
    bundle.primary.report_ssp[0] = bundle.primary.source_ssp[0];
    bundle.primary.report_ssp[1] = bundle.primary.source_ssp[1];
    if (bundle.primary.source_uri) {
        bundle.primary.report_uri = bp_strdup(bundle.primary.source_uri);
        if (!bundle.primary.report_uri) { rc = BPSEC_ERR_INTERNAL; goto done; }
    }

    int do_bib = policy_uses_bib(&s->policy);
    int do_bcb = policy_uses_bcb(&s->policy);
    if (do_bib && do_bcb) do_bib = 0;

    bundle.payload = (uint8_t *)data;
    bundle.payload_len = len;

    const bp_crypto_backend_t *be = bpsdk_get_crypto_backend();
    if (!be) { rc = BPSEC_ERR_INTERNAL; goto done; }

    uint8_t bcb_iv[12];
    uint8_t bcb_tag[BP_CRYPTO_AES_GCM_TAG_LEN];
    if (do_bcb) {
        rc = build_iv_locked(s, bcb_iv);
        if (rc != BPSEC_SUCCESS) goto done;

        bcb_ciphertext = bp_alloc(len > 0 ? len : 1);
        if (!bcb_ciphertext) { rc = BPSEC_ERR_INTERNAL; goto done; }

        uint8_t aad_buf[2];
        int aad_len = encode_uint_inline(aad_buf, sizeof(aad_buf),
                                         (uint64_t)s->policy.bcb_scope);
        if (aad_len < 0) { rc = BPSEC_ERR_INTERNAL; goto done; }

        if (be->aes_gcm_encrypt(be->backend_ctx, s->aes_gcm_ctx,
                                bcb_iv, sizeof(bcb_iv),
                                aad_buf, (size_t)aad_len,
                                data, len,
                                bcb_ciphertext,
                                bcb_tag, sizeof(bcb_tag)) != 0) {
            rc = BPSEC_ERR_CRYPTO_FAILURE; goto done;
        }
        bundle.payload = bcb_ciphertext;
        bundle.payload_len = len;
    }

    uint8_t bib_tag[BP_CRYPTO_HMAC_SHA512_LEN];
    size_t bib_tag_len = sizeof(bib_tag);
    if (do_bib) {
        rc = hmac_payload_ippt_locked(s, s->policy.bib_scope,
                                      bundle.payload, bundle.payload_len,
                                      bib_tag, &bib_tag_len);
        if (rc != BPSEC_SUCCESS) goto done;
    }

    size_t ext_count = (do_bib ? 1 : 0) + (do_bcb ? 1 : 0);
    if (ext_count > 0) {
        bundle.blocks = bp_alloc(ext_count * sizeof(bp_block_t));
        if (!bundle.blocks) { rc = BPSEC_ERR_INTERNAL; goto done; }
        memset(bundle.blocks, 0, ext_count * sizeof(bp_block_t));
    }

    size_t asb_cap = 256 + bib_tag_len + sizeof(bcb_tag);

    if (do_bib) {
        bib_asb_buf = bp_alloc(asb_cap);
        if (!bib_asb_buf) { rc = BPSEC_ERR_INTERNAL; goto done; }
        int n = build_bib_asb(bib_asb_buf, asb_cap,
                              s->policy.bib_context, s->policy.bib_scope,
                              bundle.primary.source_scheme,
                              bundle.primary.source_ssp,
                              bundle.primary.source_uri,
                              bib_tag, bib_tag_len);
        if (n < 0) { rc = BPSEC_ERR_INTERNAL; goto done; }
        bp_block_t *blk = &bundle.blocks[bundle.block_count++];
        blk->type = BPSEC_BIB_BLOCK_TYPE;
        blk->number = 2;
        blk->flags = 0;
        blk->crc_type = BP_CRC_NONE;
        blk->data = bib_asb_buf;
        blk->data_len = (size_t)n;
    }
    if (do_bcb) {
        bcb_asb_buf = bp_alloc(asb_cap);
        if (!bcb_asb_buf) { rc = BPSEC_ERR_INTERNAL; goto done; }
        int n = build_bcb_asb(bcb_asb_buf, asb_cap,
                              s->policy.bcb_context, s->policy.bcb_scope, bcb_iv,
                              bundle.primary.source_scheme,
                              bundle.primary.source_ssp,
                              bundle.primary.source_uri,
                              bcb_tag, sizeof(bcb_tag));
        if (n < 0) { rc = BPSEC_ERR_INTERNAL; goto done; }
        bp_block_t *blk = &bundle.blocks[bundle.block_count++];
        blk->type = BPSEC_BCB_BLOCK_TYPE;
        blk->number = do_bib ? 3 : 2;
        blk->flags = BPSEC_BCB_REPLICATED_FLAG;
        blk->crc_type = BP_CRC_NONE;
        blk->data = bcb_asb_buf;
        blk->data_len = (size_t)n;
    }

    size_t encode_cap = 1024 + bundle.payload_len;
    for (size_t i = 0; i < bundle.block_count; i++) {
        encode_cap += 64 + bundle.blocks[i].data_len;
    }
    encoded = bp_alloc(encode_cap);
    if (!encoded) { rc = BPSEC_ERR_INTERNAL; goto done; }

    int enc_len = bp_bundle_encode(&bundle, encoded, encode_cap);
    if (enc_len < 0) { rc = BPSEC_ERR_INTERNAL; goto done; }

    if (do_bcb && s->iv_state_set) {
        if (s->iv_state.save(s->iv_state.ctx, s->name,
                             s->iv_salt, (uint64_t)s->iv_counter) != 0) {
            rc = BPSEC_ERR_IV_EXHAUSTED;
            goto done;
        }
    }

    *out = encoded;
    *out_len = (size_t)enc_len;
    encoded = NULL;

    s->stats.bundles_secured++;
    s->stats.bytes_secured += len;
    s->stats.iv_counter = s->iv_counter;

done:
    bp_free(bundle.primary.dest_uri);
    bp_free(bundle.primary.source_uri);
    bp_free(bundle.primary.report_uri);
    bp_free(bundle.blocks);
    bp_free(bib_asb_buf);
    bp_free(bcb_asb_buf);
    bp_free(bcb_ciphertext);
    bp_free(encoded);
    return rc;
}

int bp_session_secure_encode(bp_session_t *s,
                             const uint8_t *data, size_t len,
                             const bp_delivery_opts_t *opts,
                             uint8_t **out, size_t *out_len) {
    if (!s || !out || !out_len) return BPSEC_ERR_INVALID_POLICY;
    mutex_lock(&s->mutex);
    int rc = do_secure_encode_locked(s, data, len, opts, out, out_len);
    mutex_unlock(&s->mutex);
    return rc;
}

int bp_session_send(bp_session_t *s,
                    const uint8_t *data, size_t len,
                    const bp_delivery_opts_t *opts) {
    if (!bp_is_initialized()) return BPSEC_ERR_INTERNAL;

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    int rc = bp_session_secure_encode(s, data, len, opts, &bytes, &bytes_len);
    if (rc != BPSEC_SUCCESS) return rc;

    int srv = bp_send_raw(bytes, bytes_len);
    bp_free(bytes);
    return srv == BP_SUCCESS ? BPSEC_SUCCESS : BPSEC_ERR_BPA_REJECTED;
}

/*
 * Minimal ASB decoder for the [targets, ctx_id, ctx_flags, source, params,
 * results] layout that build_*_asb() emits. Returns the parameters and
 * the first result tuple; that is all that Phase 1 verification and
 * decryption need.
 */
typedef struct {
    int      have_iv;
    uint8_t  iv[12];
    int      have_scope;
    uint64_t scope;
    int      have_variant;
    uint64_t variant;
    int      have_tag;
    const uint8_t *tag;
    size_t   tag_len;
    uint64_t target_block;
} asb_view_t;

static int decode_asb_view(const uint8_t *data, size_t len, asb_view_t *out) {
    memset(out, 0, sizeof(*out));
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, data, len);

    size_t arr;
    if (cbor_decode_array(&dec, &arr) < 0 || arr != 6) return -1;

    size_t targets;
    if (cbor_decode_array(&dec, &targets) < 0 || targets < 1) return -1;
    if (cbor_decode_uint(&dec, &out->target_block) < 0) return -1;
    for (size_t i = 1; i < targets; i++) {
        if (cbor_skip(&dec) < 0) return -1;
    }

    uint64_t ctx_id, ctx_flags;
    if (cbor_decode_uint(&dec, &ctx_id) < 0) return -1;
    if (cbor_decode_uint(&dec, &ctx_flags) < 0) return -1;

    if (cbor_skip(&dec) < 0) return -1;

    if (ctx_flags & 1) {
        size_t param_count;
        if (cbor_decode_array(&dec, &param_count) < 0) return -1;
        for (size_t i = 0; i < param_count; i++) {
            size_t pair_len;
            if (cbor_decode_array(&dec, &pair_len) < 0 || pair_len != 2) return -1;
            uint64_t pid;
            if (cbor_decode_uint(&dec, &pid) < 0) return -1;

            if (pid == 1 && ctx_id == 2) {
                const uint8_t *iv_bytes;
                size_t iv_len;
                if (cbor_decode_bytes(&dec, &iv_bytes, &iv_len) < 0) return -1;
                if (iv_len != 12) return -1;
                memcpy(out->iv, iv_bytes, 12);
                out->have_iv = 1;
            } else if (pid == 1 && ctx_id == 1) {
                if (cbor_decode_uint(&dec, &out->variant) < 0) return -1;
                out->have_variant = 1;
            } else if (pid == 2 && ctx_id == 2) {
                if (cbor_decode_uint(&dec, &out->variant) < 0) return -1;
                out->have_variant = 1;
            } else if ((pid == 3 && ctx_id == 1) || (pid == 4 && ctx_id == 2)) {
                if (cbor_decode_uint(&dec, &out->scope) < 0) return -1;
                out->have_scope = 1;
            } else {
                if (cbor_skip(&dec) < 0) return -1;
            }
        }
    }

    size_t result_targets;
    if (cbor_decode_array(&dec, &result_targets) < 0 || result_targets < 1) return -1;
    size_t inner;
    if (cbor_decode_array(&dec, &inner) < 0 || inner < 1) return -1;
    size_t pair_len;
    if (cbor_decode_array(&dec, &pair_len) < 0 || pair_len != 2) return -1;
    uint64_t rid;
    if (cbor_decode_uint(&dec, &rid) < 0) return -1;
    if (cbor_decode_bytes(&dec, &out->tag, &out->tag_len) < 0) return -1;
    out->have_tag = 1;
    return 0;
}

static int hmac_verify_locked(bp_session_t *s,
                              bpsec_scope_flags_t scope,
                              const uint8_t *payload, size_t payload_len,
                              const uint8_t *expected_tag, size_t expected_len) {
    uint8_t got[BP_CRYPTO_HMAC_SHA512_LEN];
    size_t got_len = sizeof(got);
    int rc = hmac_payload_ippt_locked(s, scope, payload, payload_len, got, &got_len);
    if (rc != BPSEC_SUCCESS) return rc;
    if (got_len != expected_len) return BPSEC_ERR_VERIFY;
    uint8_t diff = 0;
    for (size_t i = 0; i < got_len; i++) diff |= got[i] ^ expected_tag[i];
    return diff ? BPSEC_ERR_VERIFY : BPSEC_SUCCESS;
}

static int do_process_locked(bp_session_t *s,
                             const uint8_t *wire, size_t wire_len,
                             bp_bundle_t **out) {
    if (!s->policy_set) return BPSEC_ERR_INVALID_POLICY;
    if (!wire || wire_len == 0 || !out) return BPSEC_ERR_INVALID_POLICY;

    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    if (bp_bundle_decode(wire, wire_len, &bundle) < 0) return BPSEC_ERR_INTERNAL;

    int rc = BPSEC_SUCCESS;
    int saw_bcb = 0, saw_bib = 0;

    for (size_t i = 0; i < bundle.block_count; i++) {
        bp_block_t *b = &bundle.blocks[i];
        if (b->type != BPSEC_BCB_BLOCK_TYPE) continue;
        if (!policy_uses_bcb(&s->policy)) continue;

        asb_view_t view;
        if (decode_asb_view(b->data, b->data_len, &view) < 0
            || view.target_block != BPSEC_PAYLOAD_BLOCK_NUMBER
            || !view.have_iv || !view.have_tag) {
            rc = BPSEC_ERR_DECRYPT; goto done;
        }

        const bp_crypto_backend_t *be = bpsdk_get_crypto_backend();
        uint8_t aad_buf[2];
        int aad_len = encode_uint_inline(aad_buf, sizeof(aad_buf),
                                         view.have_scope ? view.scope
                                                         : (uint64_t)s->policy.bcb_scope);
        if (aad_len < 0) { rc = BPSEC_ERR_INTERNAL; goto done; }

        uint8_t *plaintext = bp_alloc(bundle.payload_len > 0 ? bundle.payload_len : 1);
        if (!plaintext) { rc = BPSEC_ERR_INTERNAL; goto done; }

        if (be->aes_gcm_decrypt(be->backend_ctx, s->aes_gcm_ctx,
                                view.iv, sizeof(view.iv),
                                aad_buf, (size_t)aad_len,
                                bundle.payload, bundle.payload_len,
                                view.tag, view.tag_len,
                                plaintext) != 0) {
            bp_free(plaintext);
            s->stats.decrypt_failures++;
            rc = BPSEC_ERR_DECRYPT;
            goto done;
        }
        bp_free(bundle.payload);
        bundle.payload = plaintext;
        s->stats.bundles_decrypted++;
        saw_bcb = 1;
        break;
    }

    for (size_t i = 0; i < bundle.block_count; i++) {
        bp_block_t *b = &bundle.blocks[i];
        if (b->type != BPSEC_BIB_BLOCK_TYPE) continue;
        if (!policy_uses_bib(&s->policy) && !saw_bcb) continue;

        asb_view_t view;
        if (decode_asb_view(b->data, b->data_len, &view) < 0
            || view.target_block != BPSEC_PAYLOAD_BLOCK_NUMBER
            || !view.have_tag) {
            rc = BPSEC_ERR_VERIFY; goto done;
        }
        if (!policy_uses_bib(&s->policy)) continue;

        rc = hmac_verify_locked(s,
                                view.have_scope ? (bpsec_scope_flags_t)view.scope
                                                : s->policy.bib_scope,
                                bundle.payload, bundle.payload_len,
                                view.tag, view.tag_len);
        if (rc != BPSEC_SUCCESS) {
            s->stats.verify_failures++;
            goto done;
        }
        s->stats.bundles_verified++;
        saw_bib = 1;
        break;
    }

    if (policy_uses_bib(&s->policy) && !saw_bib && !saw_bcb) {
        rc = BPSEC_ERR_VERIFY; goto done;
    }
    if (policy_uses_bcb(&s->policy) && !saw_bcb) {
        rc = BPSEC_ERR_DECRYPT; goto done;
    }

    bp_bundle_t *flat = calloc(1, sizeof(*flat));
    if (!flat) { rc = BPSEC_ERR_INTERNAL; goto done; }

    char eid_buf[256];
    bp_eid_format(bundle.primary.source_scheme, bundle.primary.source_ssp,
                  bundle.primary.source_uri, eid_buf, sizeof(eid_buf));
    flat->source_eid = bp_strdup(eid_buf);
    bp_eid_format(bundle.primary.dest_scheme, bundle.primary.dest_ssp,
                  bundle.primary.dest_uri, eid_buf, sizeof(eid_buf));
    flat->dest_eid = bp_strdup(eid_buf);
    if (!flat->source_eid || !flat->dest_eid) {
        free(flat->source_eid); free(flat->dest_eid); free(flat);
        rc = BPSEC_ERR_INTERNAL; goto done;
    }

    if (bundle.payload_len > 0) {
        flat->payload = bp_alloc(bundle.payload_len);
        if (!flat->payload) {
            free(flat->source_eid); free(flat->dest_eid); free(flat);
            rc = BPSEC_ERR_INTERNAL; goto done;
        }
        memcpy(flat->payload, bundle.payload, bundle.payload_len);
    }
    flat->payload_len = bundle.payload_len;
    flat->ttl = (uint32_t)(bundle.primary.lifetime_ms / 1000);
    *out = flat;

done:
    bp_bundle_full_free(&bundle);
    return rc;
}

int bp_session_process_wire(bp_session_t *s,
                            const uint8_t *wire, size_t wire_len,
                            bp_bundle_t **out) {
    if (!s) return BPSEC_ERR_INVALID_POLICY;
    mutex_lock(&s->mutex);
    int rc = do_process_locked(s, wire, wire_len, out);
    mutex_unlock(&s->mutex);
    return rc;
}

int bp_session_recv(bp_session_t *s, bp_endpoint_t *endpoint,
                    bp_bundle_t **out, int timeout_ms) {
    if (!s || !endpoint || !endpoint->endpoint_id || !out)
        return BPSEC_ERR_INVALID_POLICY;
    if (!bp_is_initialized()) return BPSEC_ERR_INTERNAL;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int rc = bp_recv_raw(endpoint->endpoint_id, &wire, &wire_len, timeout_ms);
    if (rc == BP_ERROR_TIMEOUT) return BPSEC_ERR_TIMEOUT;
    if (rc != BP_SUCCESS || !wire) return BPSEC_ERR_INTERNAL;

    int prc = bp_session_process_wire(s, wire, wire_len, out);
    bp_free(wire);
    return prc;
}

int bp_session_get_stats(const bp_session_t *s, bp_session_stats_t *out) {
    if (!s || !out) return BPSEC_ERR_INVALID_POLICY;
    bp_session_t *m = (bp_session_t *)s;
    mutex_lock(&m->mutex);
    *out = s->stats;
    out->iv_counter = s->iv_counter;
    mutex_unlock(&m->mutex);
    return BPSEC_SUCCESS;
}
