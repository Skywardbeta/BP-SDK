/*
 * bp_security.c - BPSec Security Pipeline Integration
 * Implements automatic security block application and processing.
 */
#include "bp_security.h"
#include "bp_utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#define MUTEX_T CRITICAL_SECTION
#define MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#define MUTEX_T pthread_mutex_t
#define MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#endif

struct bp_security_ctx {
    bpsec_keystore_t *keystore;
    bpsec_policy_ctx_t *policy;
    char local_eid[256];
    uint8_t local_eid_scheme;
    uint64_t local_eid_ssp[2];
    char *local_eid_uri;
    bp_sec_event_cb event_cb;
    void *event_user_data;
    uint64_t iv_counter;
    MUTEX_T mutex;
};

static int generate_iv(bp_security_ctx_t *ctx, uint8_t iv[12]) {
    (void)ctx;
#ifdef _WIN32
    HCRYPTPROV prov;
    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BOOL ok = CryptGenRandom(prov, 12, iv);
        CryptReleaseContext(prov, 0);
        if (ok) return 0;
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, iv, 12);
        close(fd);
        if (n == 12) return 0;
    }
#endif
    return -1;
}

static void fire_event(bp_security_ctx_t *ctx, int event, const char *detail) {
    if (ctx->event_cb) {
        ctx->event_cb(event, ctx->local_eid, detail, ctx->event_user_data);
    }
}

bp_security_ctx_t *bp_security_ctx_create(void) {
    bp_security_ctx_t *ctx = bp_alloc(sizeof(bp_security_ctx_t));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->keystore = bpsec_keystore_create(16);
    if (!ctx->keystore) {
        bp_free(ctx);
        return NULL;
    }
    
    ctx->policy = bpsec_policy_create();
    if (!ctx->policy) {
        bpsec_keystore_destroy(ctx->keystore);
        bp_free(ctx);
        return NULL;
    }
    
    MUTEX_INIT(ctx->mutex);
    return ctx;
}

void bp_security_ctx_destroy(bp_security_ctx_t *ctx) {
    if (!ctx) return;
    MUTEX_LOCK(ctx->mutex);
    bpsec_keystore_destroy(ctx->keystore);
    bpsec_policy_destroy(ctx->policy);
    bp_free(ctx->local_eid_uri);
    ctx->keystore = NULL;
    ctx->policy = NULL;
    ctx->local_eid_uri = NULL;
    MUTEX_UNLOCK(ctx->mutex);
    MUTEX_DESTROY(ctx->mutex);
    bp_free(ctx);
}

bpsec_keystore_t *bp_security_get_keystore(bp_security_ctx_t *ctx) {
    return ctx ? ctx->keystore : NULL;
}

bpsec_policy_ctx_t *bp_security_get_policy(bp_security_ctx_t *ctx) {
    return ctx ? ctx->policy : NULL;
}

void bp_security_set_local_eid(bp_security_ctx_t *ctx, const char *eid) {
    if (!ctx || !eid) return;
    MUTEX_LOCK(ctx->mutex);
    strncpy(ctx->local_eid, eid, sizeof(ctx->local_eid) - 1);
    ctx->local_eid[sizeof(ctx->local_eid) - 1] = '\0';
    
    bp_free(ctx->local_eid_uri);
    ctx->local_eid_uri = NULL;
    ctx->local_eid_scheme = 0;
    ctx->local_eid_ssp[0] = 0;
    ctx->local_eid_ssp[1] = 0;
    
    char *uri = NULL;
    if (bp_eid_parse(eid, &ctx->local_eid_scheme, ctx->local_eid_ssp, &uri) == 0) {
        ctx->local_eid_uri = uri;
    }
    MUTEX_UNLOCK(ctx->mutex);
}

void bp_security_set_event_callback(bp_security_ctx_t *ctx, bp_sec_event_cb cb, void *user_data) {
    if (!ctx) return;
    MUTEX_LOCK(ctx->mutex);
    ctx->event_cb = cb;
    ctx->event_user_data = user_data;
    MUTEX_UNLOCK(ctx->mutex);
}

static uint64_t find_max_block_number(const bp_bundle_full_t *bundle) {
    uint64_t max_num = 1;
    for (size_t i = 0; i < bundle->block_count; i++) {
        if (bundle->blocks[i].number > max_num) {
            max_num = bundle->blocks[i].number;
        }
    }
    return max_num;
}

static int add_block_to_bundle(bp_bundle_full_t *bundle, const bp_block_t *new_block) {
    size_t new_count = bundle->block_count + 1;
    bp_block_t *new_blocks = bp_realloc(bundle->blocks, new_count * sizeof(bp_block_t));
    if (!new_blocks) return -1;
    bundle->blocks = new_blocks;
    bundle->blocks[bundle->block_count] = *new_block;
    bundle->block_count = new_count;
    return 0;
}

static void set_security_source(bp_security_ctx_t *ctx, bpsec_block_t *sec_block) {
    if (ctx->local_eid_scheme == BP_EID_IPN) {
        sec_block->source_node = ctx->local_eid_ssp[0];
        sec_block->source_service = ctx->local_eid_ssp[1];
    } else if (ctx->local_eid_scheme == BP_EID_DTN && ctx->local_eid_uri) {
        sec_block->source_node = 0;
        sec_block->source_service = 0;
    }
}

static int format_source_eid_from_sec(const bpsec_block_t *sec, char *buf, size_t buf_len) {
    if (sec->source_node != 0 || sec->source_service != 0) {
        snprintf(buf, buf_len, "ipn:%llu.%llu",
                 (unsigned long long)sec->source_node,
                 (unsigned long long)sec->source_service);
        return 0;
    }
    return -1;
}

static int format_source_eid_from_bundle(const bp_bundle_full_t *bundle, char *buf, size_t buf_len) {
    if (bundle->primary.source_scheme == BP_EID_IPN) {
        snprintf(buf, buf_len, "ipn:%llu.%llu",
                 (unsigned long long)bundle->primary.source_ssp[0],
                 (unsigned long long)bundle->primary.source_ssp[1]);
        return 0;
    } else if (bundle->primary.source_scheme == BP_EID_DTN && bundle->primary.source_uri) {
        snprintf(buf, buf_len, "dtn:%s", bundle->primary.source_uri);
        return 0;
    }
    return -1;
}

int bp_security_add_bib(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                        uint64_t target_block, const char *key_id) {
    if (!ctx || !bundle || !key_id) return BP_SEC_ERR;
    
    MUTEX_LOCK(ctx->mutex);
    
    bpsec_key_entry_t key;
    if (bpsec_keystore_get(ctx->keystore, key_id, &key) < 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR_NO_KEY;
    }
    
    const uint8_t *target_data = NULL;
    size_t target_len = 0;
    
    if (target_block == 1) {
        target_data = bundle->payload;
        target_len = bundle->payload_len;
    } else {
        for (size_t i = 0; i < bundle->block_count; i++) {
            if (bundle->blocks[i].number == target_block) {
                target_data = bundle->blocks[i].data;
                target_len = bundle->blocks[i].data_len;
                break;
            }
        }
    }
    
    if (!target_data || target_len == 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    uint8_t sig[32];
    size_t sig_len;
    if (bpsec_sign_hmac_sha256(key.data, key.data_len, target_data, target_len, sig, &sig_len) < 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    bpsec_block_t sec_block = {0};
    sec_block.context_id = BPSEC_CTX_BIB_HMAC_SHA2;
    sec_block.context_flags = 0;
    sec_block.target_count = 1;
    sec_block.targets = bp_alloc(sizeof(uint64_t));
    if (!sec_block.targets) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    sec_block.targets[0] = target_block;
    set_security_source(ctx, &sec_block);
    
    sec_block.result_count = 1;
    sec_block.results = bp_alloc(sizeof(bpsec_result_t));
    if (!sec_block.results) {
        bp_free(sec_block.targets);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    sec_block.results[0].len = sig_len;
    sec_block.results[0].data = bp_alloc(sig_len);
    if (!sec_block.results[0].data) {
        bp_free(sec_block.targets);
        bp_free(sec_block.results);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    memcpy(sec_block.results[0].data, sig, sig_len);
    
    uint8_t encoded[512];
    int encoded_len = bpsec_block_encode(&sec_block, encoded, sizeof(encoded));
    bpsec_block_free(&sec_block);
    
    if (encoded_len < 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    bp_block_t bib = {0};
    bib.type = BP_BLOCK_BIB;
    bib.number = find_max_block_number(bundle) + 1;
    bib.flags = 0;
    bib.crc_type = BP_CRC_NONE;
    bib.data = bp_alloc((size_t)encoded_len);
    if (!bib.data) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    memcpy(bib.data, encoded, (size_t)encoded_len);
    bib.data_len = (size_t)encoded_len;
    
    if (add_block_to_bundle(bundle, &bib) < 0) {
        bp_free(bib.data);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_SIGNED);
    fire_event(ctx, BP_SEC_EVENT_SIGNED, key_id);
    
    MUTEX_UNLOCK(ctx->mutex);
    return BP_SEC_OK;
}

int bp_security_add_bcb(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                        uint64_t target_block, const char *key_id) {
    if (!ctx || !bundle || !key_id) return BP_SEC_ERR;
    
    MUTEX_LOCK(ctx->mutex);
    
    bpsec_key_entry_t key;
    if (bpsec_keystore_get(ctx->keystore, key_id, &key) < 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR_NO_KEY;
    }
    
    if (key.data_len != BPSEC_AES256_KEY_LEN) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR_NO_KEY;
    }
    
    uint8_t *target_data = NULL;
    size_t target_len = 0;
    size_t target_idx = (size_t)-1;
    
    if (target_block == 1) {
        target_data = bundle->payload;
        target_len = bundle->payload_len;
    } else {
        for (size_t i = 0; i < bundle->block_count; i++) {
            if (bundle->blocks[i].number == target_block) {
                target_data = bundle->blocks[i].data;
                target_len = bundle->blocks[i].data_len;
                target_idx = i;
                break;
            }
        }
    }
    
    if (!target_data || target_len == 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    uint8_t iv[12];
    if (generate_iv(ctx, iv) < 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR_NO_ENTROPY;
    }
    
    uint8_t *cipher = bp_alloc(target_len);
    if (!cipher) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    uint8_t tag[16];
    if (bpsec_encrypt_aes_gcm(key.data, key.data_len, iv, target_data, target_len,
                              NULL, 0, cipher, tag) < 0) {
        bp_free(cipher);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    bpsec_block_t sec_block = {0};
    sec_block.context_id = BPSEC_CTX_BCB_AES_GCM;
    sec_block.context_flags = BPSEC_FLAG_PARAMS_PRESENT;
    sec_block.target_count = 1;
    sec_block.targets = bp_alloc(sizeof(uint64_t));
    if (!sec_block.targets) {
        bp_free(cipher);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    sec_block.targets[0] = target_block;
    memcpy(sec_block.params.bcb.iv, iv, 12);
    sec_block.params.bcb.aes_variant = 3;
    set_security_source(ctx, &sec_block);
    
    sec_block.result_count = 1;
    sec_block.results = bp_alloc(sizeof(bpsec_result_t));
    if (!sec_block.results) {
        bp_free(sec_block.targets);
        bp_free(cipher);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    sec_block.results[0].len = 16;
    sec_block.results[0].data = bp_alloc(16);
    if (!sec_block.results[0].data) {
        bp_free(sec_block.targets);
        bp_free(sec_block.results);
        bp_free(cipher);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    memcpy(sec_block.results[0].data, tag, 16);
    
    uint8_t encoded[512];
    int encoded_len = bpsec_block_encode(&sec_block, encoded, sizeof(encoded));
    bpsec_block_free(&sec_block);
    
    if (encoded_len < 0) {
        bp_free(cipher);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    bp_block_t bcb = {0};
    bcb.type = BP_BLOCK_BCB;
    bcb.number = find_max_block_number(bundle) + 1;
    bcb.flags = 0;
    bcb.crc_type = BP_CRC_NONE;
    bcb.data = bp_alloc((size_t)encoded_len);
    if (!bcb.data) {
        bp_free(cipher);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    memcpy(bcb.data, encoded, (size_t)encoded_len);
    bcb.data_len = (size_t)encoded_len;
    
    if (add_block_to_bundle(bundle, &bcb) < 0) {
        bp_free(bcb.data);
        bp_free(cipher);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    if (target_block == 1) {
        bp_free(bundle->payload);
        bundle->payload = cipher;
        bundle->payload_len = target_len;
    } else {
        bp_free(bundle->blocks[target_idx].data);
        bundle->blocks[target_idx].data = cipher;
        bundle->blocks[target_idx].data_len = target_len;
    }
    
    bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_ENCRYPTED);
    fire_event(ctx, BP_SEC_EVENT_ENCRYPTED, key_id);
    
    MUTEX_UNLOCK(ctx->mutex);
    return BP_SEC_OK;
}

static int find_key_for_verify(bp_security_ctx_t *ctx, const bpsec_block_t *sec, 
                               const bp_bundle_full_t *bundle,
                               const char *policy_key_id, bpsec_key_entry_t *key) {
    if (policy_key_id && policy_key_id[0]) {
        if (bpsec_keystore_get(ctx->keystore, policy_key_id, key) == 0) {
            return 0;
        }
    }
    char source_eid[128];
    if (format_source_eid_from_sec(sec, source_eid, sizeof(source_eid)) == 0) {
        if (bpsec_keystore_find_by_eid(ctx->keystore, source_eid, BPSEC_KEY_TYPE_HMAC, key) == 0) {
            return 0;
        }
    }
    if (format_source_eid_from_bundle(bundle, source_eid, sizeof(source_eid)) == 0) {
        if (bpsec_keystore_find_by_eid(ctx->keystore, source_eid, BPSEC_KEY_TYPE_HMAC, key) == 0) {
            return 0;
        }
    }
    return -1;
}

static int find_key_for_decrypt(bp_security_ctx_t *ctx, const bpsec_block_t *sec,
                                const bp_bundle_full_t *bundle,
                                const char *policy_key_id, bpsec_key_entry_t *key) {
    if (policy_key_id && policy_key_id[0]) {
        if (bpsec_keystore_get(ctx->keystore, policy_key_id, key) == 0 &&
            key->data_len == BPSEC_AES256_KEY_LEN) {
            return 0;
        }
    }
    char source_eid[128];
    if (format_source_eid_from_sec(sec, source_eid, sizeof(source_eid)) == 0) {
        if (bpsec_keystore_find_by_eid(ctx->keystore, source_eid, BPSEC_KEY_TYPE_AES, key) == 0 &&
            key->data_len == BPSEC_AES256_KEY_LEN) {
            return 0;
        }
    }
    if (format_source_eid_from_bundle(bundle, source_eid, sizeof(source_eid)) == 0) {
        if (bpsec_keystore_find_by_eid(ctx->keystore, source_eid, BPSEC_KEY_TYPE_AES, key) == 0 &&
            key->data_len == BPSEC_AES256_KEY_LEN) {
            return 0;
        }
    }
    return -1;
}

int bp_security_verify_bib(bp_security_ctx_t *ctx, const bp_bundle_full_t *bundle,
                           const bp_block_t *bib_block) {
    return bp_security_verify_bib_with_key(ctx, bundle, bib_block, NULL);
}

int bp_security_verify_bib_with_key(bp_security_ctx_t *ctx, const bp_bundle_full_t *bundle,
                                    const bp_block_t *bib_block, const char *policy_key_id) {
    if (!ctx || !bundle || !bib_block) return BP_SEC_ERR;
    if (bib_block->type != BP_BLOCK_BIB) return BP_SEC_ERR;
    
    MUTEX_LOCK(ctx->mutex);
    
    bpsec_block_t sec;
    if (bpsec_block_decode(bib_block->data, bib_block->data_len, &sec) < 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    if (sec.context_id != BPSEC_CTX_BIB_HMAC_SHA2 || sec.target_count == 0 || sec.result_count == 0) {
        bpsec_block_free(&sec);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    bpsec_key_entry_t key;
    if (find_key_for_verify(ctx, &sec, bundle, policy_key_id, &key) < 0) {
        bpsec_block_free(&sec);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR_NO_KEY;
    }
    
    char source_eid[128] = {0};
    if (format_source_eid_from_sec(&sec, source_eid, sizeof(source_eid)) < 0) {
        format_source_eid_from_bundle(bundle, source_eid, sizeof(source_eid));
    }
    
    for (size_t t = 0; t < sec.target_count && t < sec.result_count; t++) {
        uint64_t target = sec.targets[t];
        const uint8_t *target_data = NULL;
        size_t target_len = 0;
        
        if (target == 1) {
            target_data = bundle->payload;
            target_len = bundle->payload_len;
        } else {
            for (size_t i = 0; i < bundle->block_count; i++) {
                if (bundle->blocks[i].number == target) {
                    target_data = bundle->blocks[i].data;
                    target_len = bundle->blocks[i].data_len;
                    break;
                }
            }
        }
        
        if (!target_data) {
            bpsec_block_free(&sec);
            MUTEX_UNLOCK(ctx->mutex);
            return BP_SEC_ERR;
        }
        
        if (bpsec_verify_hmac_sha256(key.data, key.data_len, target_data, target_len,
                                     sec.results[t].data, sec.results[t].len) < 0) {
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_VERIFY_FAIL);
            fire_event(ctx, BP_SEC_EVENT_VERIFY_FAIL, source_eid);
            bpsec_block_free(&sec);
            MUTEX_UNLOCK(ctx->mutex);
            return BP_SEC_ERR_VERIFY;
        }
    }
    
    bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_VERIFIED);
    fire_event(ctx, BP_SEC_EVENT_VERIFIED, source_eid);
    bpsec_block_free(&sec);
    MUTEX_UNLOCK(ctx->mutex);
    return BP_SEC_OK;
}

int bp_security_decrypt_bcb(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                            const bp_block_t *bcb_block) {
    return bp_security_decrypt_bcb_with_key(ctx, bundle, bcb_block, NULL);
}

int bp_security_decrypt_bcb_with_key(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle,
                                     const bp_block_t *bcb_block, const char *policy_key_id) {
    if (!ctx || !bundle || !bcb_block) return BP_SEC_ERR;
    if (bcb_block->type != BP_BLOCK_BCB) return BP_SEC_ERR;
    
    MUTEX_LOCK(ctx->mutex);
    
    bpsec_block_t sec;
    if (bpsec_block_decode(bcb_block->data, bcb_block->data_len, &sec) < 0) {
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    if (sec.context_id != BPSEC_CTX_BCB_AES_GCM || sec.target_count == 0 || sec.result_count == 0) {
        bpsec_block_free(&sec);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR;
    }
    
    bpsec_key_entry_t key;
    if (find_key_for_decrypt(ctx, &sec, bundle, policy_key_id, &key) < 0) {
        bpsec_block_free(&sec);
        MUTEX_UNLOCK(ctx->mutex);
        return BP_SEC_ERR_NO_KEY;
    }
    
    char source_eid[128] = {0};
    if (format_source_eid_from_sec(&sec, source_eid, sizeof(source_eid)) < 0) {
        format_source_eid_from_bundle(bundle, source_eid, sizeof(source_eid));
    }
    
    for (size_t t = 0; t < sec.target_count && t < sec.result_count; t++) {
        uint64_t target = sec.targets[t];
        uint8_t *cipher_data = NULL;
        size_t cipher_len = 0;
        size_t target_idx = (size_t)-1;
        
        if (target == 1) {
            cipher_data = bundle->payload;
            cipher_len = bundle->payload_len;
        } else {
            for (size_t i = 0; i < bundle->block_count; i++) {
                if (bundle->blocks[i].number == target) {
                    cipher_data = bundle->blocks[i].data;
                    cipher_len = bundle->blocks[i].data_len;
                    target_idx = i;
                    break;
                }
            }
        }
        
        if (!cipher_data) {
            bpsec_block_free(&sec);
            MUTEX_UNLOCK(ctx->mutex);
            return BP_SEC_ERR;
        }
        
        if (sec.results[t].len != 16) {
            bpsec_block_free(&sec);
            MUTEX_UNLOCK(ctx->mutex);
            return BP_SEC_ERR;
        }
        
        uint8_t *plain = bp_alloc(cipher_len);
        if (!plain) {
            bpsec_block_free(&sec);
            MUTEX_UNLOCK(ctx->mutex);
            return BP_SEC_ERR;
        }
        
        if (bpsec_decrypt_aes_gcm(key.data, key.data_len, sec.params.bcb.iv,
                                  cipher_data, cipher_len, NULL, 0,
                                  sec.results[t].data, plain) < 0) {
            bp_free(plain);
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DECRYPT_FAIL);
            fire_event(ctx, BP_SEC_EVENT_DECRYPT_FAIL, source_eid);
            bpsec_block_free(&sec);
            MUTEX_UNLOCK(ctx->mutex);
            return BP_SEC_ERR_DECRYPT;
        }
        
        if (target == 1) {
            bp_free(bundle->payload);
            bundle->payload = plain;
            bundle->payload_len = cipher_len;
        } else {
            bp_free(bundle->blocks[target_idx].data);
            bundle->blocks[target_idx].data = plain;
            bundle->blocks[target_idx].data_len = cipher_len;
        }
    }
    
    bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DECRYPTED);
    fire_event(ctx, BP_SEC_EVENT_DECRYPTED, source_eid);
    bpsec_block_free(&sec);
    MUTEX_UNLOCK(ctx->mutex);
    return BP_SEC_OK;
}

int bp_security_apply(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle) {
    if (!ctx || !bundle) return BP_SEC_ERR;
    
    char dest_eid[256];
    if (bundle->primary.dest_scheme == BP_EID_IPN) {
        snprintf(dest_eid, sizeof(dest_eid), "ipn:%llu.%llu",
                 (unsigned long long)bundle->primary.dest_ssp[0],
                 (unsigned long long)bundle->primary.dest_ssp[1]);
    } else if (bundle->primary.dest_uri) {
        snprintf(dest_eid, sizeof(dest_eid), "dtn:%s", bundle->primary.dest_uri);
    } else {
        return BP_SEC_OK;
    }
    
    bpsec_policy_rule_t rule;
    if (bpsec_policy_lookup(ctx->policy, dest_eid, &rule) < 0) {
        return BP_SEC_OK;
    }
    
    if (rule.role != BPSEC_ROLE_SOURCE) {
        return BP_SEC_OK;
    }
    
    int rc = BP_SEC_OK;
    
    if (rule.requirements & BPSEC_REQUIRE_SIGN) {
        const char *key_id = rule.sign_key_id[0] ? rule.sign_key_id : NULL;
        if (!key_id) {
            bpsec_key_entry_t key;
            if (bpsec_keystore_find_by_eid(ctx->keystore, dest_eid, BPSEC_KEY_TYPE_HMAC, &key) == 0) {
                key_id = key.id;
            }
        }
        if (key_id) {
            rc = bp_security_add_bib(ctx, bundle, 1, key_id);
            if (rc < 0) return rc;
        }
    }
    
    if (rule.requirements & BPSEC_REQUIRE_ENCRYPT) {
        const char *key_id = rule.encrypt_key_id[0] ? rule.encrypt_key_id : NULL;
        if (!key_id) {
            bpsec_key_entry_t key;
            if (bpsec_keystore_find_by_eid(ctx->keystore, dest_eid, BPSEC_KEY_TYPE_AES, &key) == 0) {
                key_id = key.id;
            }
        }
        if (key_id) {
            rc = bp_security_add_bcb(ctx, bundle, 1, key_id);
            if (rc < 0) return rc;
        }
    }
    
    return rc;
}

int bp_security_process(bp_security_ctx_t *ctx, bp_bundle_full_t *bundle) {
    if (!ctx || !bundle) return BP_SEC_ERR;
    
    char dest_eid[256];
    if (bundle->primary.dest_scheme == BP_EID_IPN) {
        snprintf(dest_eid, sizeof(dest_eid), "ipn:%llu.%llu",
                 (unsigned long long)bundle->primary.dest_ssp[0],
                 (unsigned long long)bundle->primary.dest_ssp[1]);
    } else if (bundle->primary.dest_uri) {
        snprintf(dest_eid, sizeof(dest_eid), "dtn:%s", bundle->primary.dest_uri);
    } else {
        dest_eid[0] = '\0';
    }
    
    bpsec_policy_rule_t rule;
    int have_rule = (bpsec_policy_lookup(ctx->policy, dest_eid, &rule) == 0);
    
    const char *verify_key_id = (have_rule && rule.sign_key_id[0]) ? rule.sign_key_id : NULL;
    const char *decrypt_key_id = (have_rule && rule.encrypt_key_id[0]) ? rule.encrypt_key_id : NULL;
    
    for (size_t i = 0; i < bundle->block_count; i++) {
        bp_block_t *blk = &bundle->blocks[i];
        int rc;
        
        if (blk->type == BP_BLOCK_BIB) {
            rc = bp_security_verify_bib_with_key(ctx, bundle, blk, verify_key_id);
            if (rc == BP_SEC_ERR_VERIFY && have_rule) {
                if (rule.on_verify_fail == BPSEC_ACTION_DROP) {
                    bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DROP);
                    fire_event(ctx, BP_SEC_EVENT_DROPPED, "verify_fail");
                    return BP_SEC_ERR_DROPPED;
                }
            }
        } else if (blk->type == BP_BLOCK_BCB) {
            rc = bp_security_decrypt_bcb_with_key(ctx, bundle, blk, decrypt_key_id);
            if (rc == BP_SEC_ERR_DECRYPT && have_rule) {
                if (rule.on_decrypt_fail == BPSEC_ACTION_DROP) {
                    bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DROP);
                    fire_event(ctx, BP_SEC_EVENT_DROPPED, "decrypt_fail");
                    return BP_SEC_ERR_DROPPED;
                }
            }
        }
    }
    
    return BP_SEC_OK;
}

