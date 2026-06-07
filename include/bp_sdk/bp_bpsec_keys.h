/*
 * bp_bpsec_keys.h - BPSec Key Management Interface
 * 
 * Thread-safe key storage and retrieval for BPSec operations.
 * Implements CCSDS 734.5-R-2 managed parameters for cipher suite keys.
 * 
 * Keys are stored by ID and can be looked up by EID for automatic
 * security block generation.
 */
#ifndef BP_BPSEC_KEYS_H
#define BP_BPSEC_KEYS_H

#include <stdint.h>
#include <stddef.h>

#define BPSEC_KEY_MAX_ID_LEN    64
#define BPSEC_KEY_MAX_DATA_LEN  64
#define BPSEC_KEY_TYPE_HMAC     1
#define BPSEC_KEY_TYPE_AES      2

typedef struct bpsec_keystore bpsec_keystore_t;

typedef struct {
    char id[BPSEC_KEY_MAX_ID_LEN];
    uint8_t type;
    uint8_t data[BPSEC_KEY_MAX_DATA_LEN];
    size_t data_len;
    char bound_eid[128];
    uint64_t expires_at;
    uint64_t created_at;
} bpsec_key_entry_t;

bpsec_keystore_t *bpsec_keystore_create(size_t initial_capacity);
void bpsec_keystore_destroy(bpsec_keystore_t *ks);

int bpsec_keystore_add(bpsec_keystore_t *ks, const char *key_id,
                       uint8_t key_type, const uint8_t *key_data,
                       size_t key_len, const char *bound_eid,
                       uint64_t expires_at);

int bpsec_keystore_remove(bpsec_keystore_t *ks, const char *key_id);

int bpsec_keystore_get(bpsec_keystore_t *ks, const char *key_id,
                       bpsec_key_entry_t *out);

int bpsec_keystore_find_by_eid(bpsec_keystore_t *ks, const char *eid,
                                uint8_t key_type, bpsec_key_entry_t *out);

size_t bpsec_keystore_expire(bpsec_keystore_t *ks, uint64_t current_time);

size_t bpsec_keystore_count(bpsec_keystore_t *ks);

#endif

