/* bp_storage.h - Bundle Storage */
#ifndef BP_STORAGE_H
#define BP_STORAGE_H

#include "bp_bundle.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    char *bundle_id;
    uint8_t *data;
    size_t len;
    uint64_t expiry;
    int pending_forward;
    int delivered;
} bp_store_entry_t;

typedef struct {
    bp_store_entry_t *entries;
    size_t count;
    size_t capacity;
    size_t max_size;
    size_t current_size;
} bp_store_t;

int bp_store_init(bp_store_t *store, size_t max_size);
void bp_store_free(bp_store_t *store);

int bp_bundle_id(const bp_primary_t *primary, char *out, size_t cap);

int bp_store_put(bp_store_t *store, const char *id, const uint8_t *data, size_t len, uint64_t expiry);
int bp_store_get(bp_store_t *store, const char *id, uint8_t **data, size_t *len);
int bp_store_delete(bp_store_t *store, const char *id);
int bp_store_list(bp_store_t *store, char ***ids, size_t *count);
int bp_store_expire(bp_store_t *store);

#endif
