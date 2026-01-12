/*
 * bp_security.c - High-level BPSec security automation
 *
 * RFC 9172 order: Sign plaintext -> Encrypt (outbound), Decrypt -> Verify (inbound)
 * Keys are looked up by policy key ID first, then by EID binding.
 * Security source: ipn: EIDs use numeric node/service; dtn: EIDs leave source_node=0
 * so inbound key lookup falls back to the original source_eid string.
 */

#include "bp_security.h"
#include "bp_utils.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

struct bp_security_ctx {
    bpsec_keystore_t *keystore;
    bpsec_policy_ctx_t *policy;
    uint64_t local_node;
    uint64_t local_service;
};

bp_security_ctx_t *bp_security_init(void) {
    bp_security_ctx_t *ctx = bp_alloc(sizeof(bp_security_ctx_t));
    if (!ctx) return NULL;
    
    ctx->keystore = bpsec_keystore_create(64);
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
    
    ctx->local_node = 0;
    ctx->local_service = 0;
    
    return ctx;
}

void bp_security_shutdown(bp_security_ctx_t *ctx) {
    if (!ctx) return;
    bpsec_keystore_destroy(ctx->keystore);
    bpsec_policy_destroy(ctx->policy);
    bp_free(ctx);
}

bpsec_keystore_t *bp_security_get_keystore(bp_security_ctx_t *ctx) {
    return ctx ? ctx->keystore : NULL;
}

bpsec_policy_ctx_t *bp_security_get_policy(bp_security_ctx_t *ctx) {
    return ctx ? ctx->policy : NULL;
}

void bp_security_set_local_eid(bp_security_ctx_t *ctx, uint64_t node, uint64_t service) {
    if (ctx) {
        ctx->local_node = node;
        ctx->local_service = service;
    }
}

bp_security_status_t bp_security_add_key(bp_security_ctx_t *ctx,
                                         const char *key_id,
                                         const char *bound_eid,
                                         const uint8_t *key_data,
                                         size_t key_len,
                                         uint8_t key_type) {
    if (!ctx) return BP_SEC_ERR_INVALID;
    if (!key_id || strlen(key_id) == 0) return BP_SEC_ERR_INVALID;
    if (!key_data || key_len == 0) return BP_SEC_ERR_INVALID;
    if (key_len > BPSEC_KEY_MAX_DATA_LEN) return BP_SEC_ERR_INVALID;
    
    int rc = bpsec_keystore_add(ctx->keystore, key_id, key_type, 
                                key_data, key_len, bound_eid, 0);
    return (rc == 0) ? BP_SEC_OK : BP_SEC_ERR_MEMORY;
}

bp_security_status_t bp_security_add_rule(bp_security_ctx_t *ctx,
                                          const char *dest_pattern,
                                          uint8_t requirements,
                                          uint8_t priority) {
    if (!ctx || !dest_pattern) return BP_SEC_ERR_INVALID;
    
    bpsec_policy_rule_t rule = {0};
    size_t len = strlen(dest_pattern);
    if (len >= sizeof(rule.dest_pattern)) {
        len = sizeof(rule.dest_pattern) - 1;
    }
    memcpy(rule.dest_pattern, dest_pattern, len);
    rule.dest_pattern[len] = '\0';
    
    rule.requirements = requirements;
    rule.role = BPSEC_ROLE_SOURCE;
    rule.on_verify_fail = BPSEC_ACTION_DROP;
    rule.on_decrypt_fail = BPSEC_ACTION_DROP;
    rule.priority = priority;
    
    int rc = bpsec_policy_add_rule(ctx->policy, &rule);
    return (rc == 0) ? BP_SEC_OK : BP_SEC_ERR_MEMORY;
}

static int build_eid_string(uint8_t scheme, uint64_t ssp[2], const char *uri,
                            char *out, size_t cap) {
    if (scheme == BP_EID_IPN) {
        return snprintf(out, cap, "ipn:%llu.%llu",
                       (unsigned long long)ssp[0],
                       (unsigned long long)ssp[1]);
    } else if (uri) {
        return snprintf(out, cap, "dtn:%s", uri);
    }
    out[0] = '\0';
    return -1;
}

static int generate_random_iv(uint8_t *iv, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    BOOL ok = CryptGenRandom(hProv, (DWORD)len, iv);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        uint64_t ts = bp_time_now_dtn();
        static uint32_t counter = 0;
        memcpy(iv, &ts, 8);
        counter++;
        memcpy(iv + 8, &counter, 4);
        return 0;
    }
    ssize_t n = read(fd, iv, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
#endif
}

static uint64_t find_max_block_number(bp_bundle_full_t *bundle) {
    uint64_t max_num = 1;
    for (size_t i = 0; i < bundle->block_count; i++) {
        if (bundle->blocks[i].number > max_num) {
            max_num = bundle->blocks[i].number;
        }
    }
    return max_num;
}

static int parse_source_eid(const char *source, uint64_t *node, uint64_t *service) {
    if (!source || source[0] == '\0') return -1;
    
    if (strncmp(source, "ipn:", 4) == 0) {
        unsigned long long n, s;
        if (sscanf(source + 4, "%llu.%llu", &n, &s) == 2) {
            *node = n;
            *service = s;
            return 0;
        }
    }
    return -1;
}

static bp_security_status_t add_bib_block(bp_bundle_full_t *bundle,
                                          const bpsec_key_entry_t *key,
                                          uint64_t sec_node, uint64_t sec_service) {
    if (!bundle->payload || bundle->payload_len == 0) return BP_SEC_OK;
    
    uint8_t signature[32];
    size_t sig_len = 32;
    int rc = bpsec_sign_hmac_sha256(key->data, key->data_len,
                                    bundle->payload, bundle->payload_len,
                                    signature, &sig_len);
    if (rc != 0) return BP_SEC_ERR_CRYPTO;
    
    bpsec_block_t bib = {0};
    bib.context_id = BPSEC_CTX_BIB_HMAC_SHA2;
    bib.source_node = sec_node;
    bib.source_service = sec_service;
    
    uint64_t target = 1;
    bib.targets = &target;
    bib.target_count = 1;
    
    bpsec_result_t result = {0};
    result.data = signature;
    result.len = sig_len;
    bib.results = &result;
    bib.result_count = 1;
    
    uint8_t bib_data[256];
    int bib_len = bpsec_block_encode(&bib, bib_data, sizeof(bib_data));
    if (bib_len <= 0) return BP_SEC_ERR_CRYPTO;
    
    uint8_t *block_data = bp_alloc((size_t)bib_len);
    if (!block_data) return BP_SEC_ERR_MEMORY;
    
    size_t new_count = bundle->block_count + 1;
    bp_block_t *new_blocks = bp_realloc(bundle->blocks, new_count * sizeof(bp_block_t));
    if (!new_blocks) {
        bp_free(block_data);
        return BP_SEC_ERR_MEMORY;
    }
    
    memcpy(block_data, bib_data, (size_t)bib_len);
    
    bundle->blocks = new_blocks;
    bp_block_t *blk = &bundle->blocks[bundle->block_count];
    memset(blk, 0, sizeof(*blk));
    blk->type = BP_BLOCK_BIB;
    blk->number = find_max_block_number(bundle) + 1;
    blk->data = block_data;
    blk->data_len = (size_t)bib_len;
    bundle->block_count = new_count;
    
    return BP_SEC_OK;
}

static bp_security_status_t add_bcb_block(bp_bundle_full_t *bundle,
                                          const bpsec_key_entry_t *key,
                                          uint64_t sec_node, uint64_t sec_service) {
    if (!bundle->payload || bundle->payload_len == 0) return BP_SEC_OK;
    if (key->data_len != BPSEC_AES256_KEY_LEN) return BP_SEC_ERR_INVALID;
    
    uint8_t iv[12];
    if (generate_random_iv(iv, sizeof(iv)) < 0) {
        return BP_SEC_ERR_CRYPTO;
    }
    
    uint8_t *cipher = bp_alloc(bundle->payload_len);
    if (!cipher) return BP_SEC_ERR_MEMORY;
    
    uint8_t tag[16];
    int rc = bpsec_encrypt_aes_gcm(key->data, key->data_len, iv,
                                   bundle->payload, bundle->payload_len,
                                   NULL, 0, cipher, tag);
    if (rc != 0) {
        bp_free(cipher);
        return BP_SEC_ERR_CRYPTO;
    }
    
    bpsec_block_t bcb = {0};
    bcb.context_id = BPSEC_CTX_BCB_AES_GCM;
    bcb.source_node = sec_node;
    bcb.source_service = sec_service;
    
    uint64_t target = 1;
    bcb.targets = &target;
    bcb.target_count = 1;
    
    bpsec_result_t results[2] = {0};
    results[0].data = iv;
    results[0].len = 12;
    results[1].data = tag;
    results[1].len = 16;
    bcb.results = results;
    bcb.result_count = 2;
    
    uint8_t bcb_data[256];
    int bcb_len = bpsec_block_encode(&bcb, bcb_data, sizeof(bcb_data));
    if (bcb_len <= 0) {
        bp_free(cipher);
        return BP_SEC_ERR_CRYPTO;
    }
    
    uint8_t *block_data = bp_alloc((size_t)bcb_len);
    if (!block_data) {
        bp_free(cipher);
        return BP_SEC_ERR_MEMORY;
    }
    
    size_t new_count = bundle->block_count + 1;
    bp_block_t *new_blocks = bp_realloc(bundle->blocks, new_count * sizeof(bp_block_t));
    if (!new_blocks) {
        bp_free(cipher);
        bp_free(block_data);
        return BP_SEC_ERR_MEMORY;
    }
    
    memcpy(block_data, bcb_data, (size_t)bcb_len);
    
    bp_free(bundle->payload);
    bundle->payload = cipher;
    
    bundle->blocks = new_blocks;
    bp_block_t *blk = &bundle->blocks[bundle->block_count];
    memset(blk, 0, sizeof(*blk));
    blk->type = BP_BLOCK_BCB;
    blk->number = find_max_block_number(bundle) + 1;
    blk->data = block_data;
    blk->data_len = (size_t)bcb_len;
    bundle->block_count = new_count;
    
    return BP_SEC_OK;
}

bp_security_status_t bp_security_apply(bp_security_ctx_t *ctx,
                                       bp_bundle_full_t *bundle,
                                       const char *source) {
    if (!ctx || !bundle) return BP_SEC_ERR_INVALID;
    
    char dest_eid[256];
    if (build_eid_string(bundle->primary.dest_scheme, bundle->primary.dest_ssp,
                         bundle->primary.dest_uri, dest_eid, sizeof(dest_eid)) < 0) {
        return BP_SEC_ERR_INVALID;
    }
    
    bpsec_policy_rule_t rule = {0};
    if (bpsec_policy_lookup(ctx->policy, dest_eid, &rule) != 0) {
        return BP_SEC_OK;
    }
    
    if (rule.requirements == BPSEC_REQUIRE_NONE) return BP_SEC_OK;
    
    uint64_t sec_node = ctx->local_node;
    uint64_t sec_service = ctx->local_service;
    if (source && source[0] != '\0') {
        uint64_t parsed_node, parsed_service;
        if (parse_source_eid(source, &parsed_node, &parsed_service) == 0) {
            sec_node = parsed_node;
            sec_service = parsed_service;
        }
    }
    
    if (rule.requirements & BPSEC_REQUIRE_SIGN) {
        bpsec_key_entry_t key;
        int found = -1;
        if (rule.sign_key_id[0] != '\0') {
            found = bpsec_keystore_get(ctx->keystore, rule.sign_key_id, &key);
        }
        if (found != 0) {
            found = bpsec_keystore_find_by_eid(ctx->keystore, dest_eid, 
                                                BPSEC_KEY_TYPE_HMAC, &key);
        }
        if (found != 0) return BP_SEC_ERR_NO_KEY;
        
        bp_security_status_t st = add_bib_block(bundle, &key, sec_node, sec_service);
        if (st != BP_SEC_OK) return st;
        bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_SIGNED);
    }
    
    if (rule.requirements & BPSEC_REQUIRE_ENCRYPT) {
        bpsec_key_entry_t key;
        int found = -1;
        if (rule.encrypt_key_id[0] != '\0') {
            found = bpsec_keystore_get(ctx->keystore, rule.encrypt_key_id, &key);
        }
        if (found != 0) {
            found = bpsec_keystore_find_by_eid(ctx->keystore, dest_eid,
                                                BPSEC_KEY_TYPE_AES, &key);
        }
        if (found != 0) return BP_SEC_ERR_NO_KEY;
        
        bp_security_status_t st = add_bcb_block(bundle, &key, sec_node, sec_service);
        if (st != BP_SEC_OK) return st;
        bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_ENCRYPTED);
    }
    
    return BP_SEC_OK;
}

static bp_block_t *find_security_block(bp_bundle_full_t *bundle, uint8_t type) {
    for (size_t i = 0; i < bundle->block_count; i++) {
        if (bundle->blocks[i].type == type) {
            return &bundle->blocks[i];
        }
    }
    return NULL;
}

static void remove_security_block(bp_bundle_full_t *bundle, uint8_t type) {
    for (size_t i = 0; i < bundle->block_count; i++) {
        if (bundle->blocks[i].type == type) {
            bp_free(bundle->blocks[i].data);
            for (size_t j = i; j < bundle->block_count - 1; j++) {
                bundle->blocks[j] = bundle->blocks[j + 1];
            }
            bundle->block_count--;
            return;
        }
    }
}

static int lookup_key_for_block(bp_security_ctx_t *ctx,
                                const bpsec_policy_rule_t *rule,
                                const char *policy_key_id,
                                const char *eid_for_lookup,
                                uint8_t key_type,
                                bpsec_key_entry_t *key_out) {
    if (rule && policy_key_id[0] != '\0') {
        if (bpsec_keystore_get(ctx->keystore, policy_key_id, key_out) == 0) {
            return 0;
        }
    }
    return bpsec_keystore_find_by_eid(ctx->keystore, eid_for_lookup, key_type, key_out);
}

static void build_key_lookup_eid(const bpsec_block_t *block, const char *source_eid,
                                  char *out, size_t cap) {
    if (block->source_node != 0) {
        snprintf(out, cap, "ipn:%llu.%llu",
                (unsigned long long)block->source_node,
                (unsigned long long)block->source_service);
    } else if (source_eid[0] != '\0') {
        size_t len = strlen(source_eid);
        if (len >= cap) len = cap - 1;
        memcpy(out, source_eid, len);
        out[len] = '\0';
    } else {
        out[0] = '\0';
    }
}

bp_security_status_t bp_security_process(bp_security_ctx_t *ctx,
                                         bp_bundle_full_t *bundle,
                                         bp_security_result_t *result) {
    if (!ctx || !bundle || !result) return BP_SEC_ERR_INVALID;
    
    memset(result, 0, sizeof(*result));
    result->status = BP_SEC_OK;
    
    char source_eid[256];
    if (build_eid_string(bundle->primary.source_scheme, bundle->primary.source_ssp,
                         bundle->primary.source_uri, source_eid, sizeof(source_eid)) < 0) {
        source_eid[0] = '\0';
    }
    
    char dest_eid[256];
    int has_dest = (build_eid_string(bundle->primary.dest_scheme, bundle->primary.dest_ssp,
                                      bundle->primary.dest_uri, dest_eid, sizeof(dest_eid)) >= 0);
    
    bpsec_policy_rule_t rule = {0};
    int has_policy = (has_dest && bpsec_policy_lookup(ctx->policy, dest_eid, &rule) == 0);
    const bpsec_policy_rule_t *rule_ptr = has_policy ? &rule : NULL;
    
    bp_block_t *bcb_blk = find_security_block(bundle, BP_BLOCK_BCB);
    
    if (bcb_blk && bcb_blk->data) {
        bpsec_block_t bcb;
        if (bpsec_block_decode(bcb_blk->data, bcb_blk->data_len, &bcb) < 0) {
            result->bcb_decrypted = -1;
            result->status = BP_SEC_ERR_DECRYPT_FAIL;
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DECRYPT_FAIL);
            if (has_policy && rule.on_decrypt_fail == BPSEC_ACTION_DROP) {
                bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DROP);
            }
            return result->status;
        }
        
        char key_eid[256];
        build_key_lookup_eid(&bcb, source_eid, key_eid, sizeof(key_eid));
        
        if (key_eid[0] == '\0') {
            result->bcb_decrypted = -1;
            result->status = BP_SEC_ERR_NO_KEY;
            bpsec_block_free(&bcb);
            return result->status;
        }
        
        bpsec_key_entry_t key;
        const char *policy_key = has_policy ? rule.encrypt_key_id : "";
        if (lookup_key_for_block(ctx, rule_ptr, policy_key, key_eid, BPSEC_KEY_TYPE_AES, &key) != 0 ||
            key.data_len != BPSEC_AES256_KEY_LEN) {
            result->bcb_decrypted = -1;
            result->status = BP_SEC_ERR_NO_KEY;
            bpsec_block_free(&bcb);
            return result->status;
        }
        
        if (bcb.result_count < 2 || 
            !bcb.results[0].data || bcb.results[0].len != 12 ||
            !bcb.results[1].data || bcb.results[1].len != 16) {
            result->bcb_decrypted = -1;
            result->status = BP_SEC_ERR_DECRYPT_FAIL;
            bpsec_block_free(&bcb);
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DECRYPT_FAIL);
            return result->status;
        }
        
        uint8_t *plain = bp_alloc(bundle->payload_len);
        if (!plain) {
            result->bcb_decrypted = -1;
            result->status = BP_SEC_ERR_MEMORY;
            bpsec_block_free(&bcb);
            return result->status;
        }
        
        int rc = bpsec_decrypt_aes_gcm(key.data, key.data_len,
                                       bcb.results[0].data,
                                       bundle->payload, bundle->payload_len,
                                       NULL, 0,
                                       bcb.results[1].data, plain);
        bpsec_block_free(&bcb);
        
        if (rc != 0) {
            bp_free(plain);
            result->bcb_decrypted = -1;
            result->status = BP_SEC_ERR_DECRYPT_FAIL;
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DECRYPT_FAIL);
            if (has_policy && rule.on_decrypt_fail == BPSEC_ACTION_DROP) {
                bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DROP);
            }
            return result->status;
        }
        
        bp_free(bundle->payload);
        bundle->payload = plain;
        result->bcb_decrypted = 1;
        strncpy(result->key_id, key.id, sizeof(result->key_id) - 1);
        bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DECRYPTED);
        
        if (has_policy && rule.role == BPSEC_ROLE_ACCEPTOR) {
            remove_security_block(bundle, BP_BLOCK_BCB);
        }
    }
    
    bp_block_t *bib_blk = find_security_block(bundle, BP_BLOCK_BIB);
    
    if (bib_blk && bib_blk->data) {
        bpsec_block_t bib;
        if (bpsec_block_decode(bib_blk->data, bib_blk->data_len, &bib) < 0) {
            result->bib_verified = -1;
            result->status = BP_SEC_ERR_VERIFY_FAIL;
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_VERIFY_FAIL);
            if (has_policy && rule.on_verify_fail == BPSEC_ACTION_DROP) {
                bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DROP);
            }
            return result->status;
        }
        
        char key_eid[256];
        build_key_lookup_eid(&bib, source_eid, key_eid, sizeof(key_eid));
        
        if (key_eid[0] == '\0') {
            result->bib_verified = -1;
            result->status = BP_SEC_ERR_NO_KEY;
            bpsec_block_free(&bib);
            return result->status;
        }
        
        bpsec_key_entry_t key;
        const char *policy_key = has_policy ? rule.sign_key_id : "";
        if (lookup_key_for_block(ctx, rule_ptr, policy_key, key_eid, BPSEC_KEY_TYPE_HMAC, &key) != 0) {
            result->bib_verified = -1;
            result->status = BP_SEC_ERR_NO_KEY;
            bpsec_block_free(&bib);
            return result->status;
        }
        
        if (bib.result_count < 1 || !bib.results[0].data || bib.results[0].len != 32) {
            result->bib_verified = -1;
            result->status = BP_SEC_ERR_VERIFY_FAIL;
            bpsec_block_free(&bib);
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_VERIFY_FAIL);
            return result->status;
        }
        
        int rc = bpsec_verify_hmac_sha256(key.data, key.data_len,
                                          bundle->payload, bundle->payload_len,
                                          bib.results[0].data, bib.results[0].len);
        bpsec_block_free(&bib);
        
        if (rc != 0) {
            result->bib_verified = -1;
            result->status = BP_SEC_ERR_VERIFY_FAIL;
            bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_VERIFY_FAIL);
            if (has_policy && rule.on_verify_fail == BPSEC_ACTION_DROP) {
                bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_DROP);
            }
            return result->status;
        }
        
        result->bib_verified = 1;
        strncpy(result->key_id, key.id, sizeof(result->key_id) - 1);
        bpsec_policy_inc_stat(ctx->policy, BPSEC_STAT_VERIFIED);
        
        if (has_policy && rule.role == BPSEC_ROLE_ACCEPTOR) {
            remove_security_block(bundle, BP_BLOCK_BIB);
        }
    }
    
    return BP_SEC_OK;
}
