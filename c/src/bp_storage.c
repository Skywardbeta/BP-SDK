/* bp_storage.c - In-Memory Bundle Storage */
#include "bp_storage.h"
#include "bp_utils.h"
#include <string.h>
#include <stdio.h>

int bp_store_init(bp_store_t *store, size_t max_size) {
    memset(store, 0, sizeof(*store));
    store->max_size = max_size;
    return 0;
}

void bp_store_free(bp_store_t *store) {
    for (size_t i = 0; i < store->count; i++) {
        bp_free(store->entries[i].bundle_id);
        bp_free(store->entries[i].data);
    }
    bp_free(store->entries);
    memset(store, 0, sizeof(*store));
}

int bp_bundle_id(const bp_primary_t *p, char *out, size_t cap) {
    return snprintf(out, cap, "ipn:%llu.%llu-%llu-%llu",
                    (unsigned long long)p->source_ssp[0], (unsigned long long)p->source_ssp[1],
                    (unsigned long long)p->creation_ts, (unsigned long long)p->creation_seq);
}

static bp_store_entry_t *find_entry(bp_store_t *store, const char *id) {
    for (size_t i = 0; i < store->count; i++)
        if (strcmp(store->entries[i].bundle_id, id) == 0) return &store->entries[i];
    return NULL;
}

int bp_store_put(bp_store_t *store, const char *id, const uint8_t *data, size_t len, uint64_t expiry) {
    if (store->current_size + len > store->max_size) {
        bp_store_expire(store);
        if (store->current_size + len > store->max_size) return -1;
    }

    bp_store_entry_t *e = find_entry(store, id);
    if (e) {
        store->current_size -= e->len;
        bp_free(e->data);
    } else {
        if (store->count >= store->capacity) {
            store->capacity = store->capacity ? store->capacity * 2 : 16;
            store->entries = bp_realloc(store->entries, store->capacity * sizeof(bp_store_entry_t));
        }
        e = &store->entries[store->count++];
        memset(e, 0, sizeof(*e));
        e->bundle_id = bp_strdup(id);
    }

    e->data = bp_alloc(len);
    memcpy(e->data, data, len);
    e->len = len;
    e->expiry = expiry;
    store->current_size += len;
    return 0;
}

int bp_store_get(bp_store_t *store, const char *id, uint8_t **data, size_t *len) {
    bp_store_entry_t *e = find_entry(store, id);
    if (!e) return -1;
    *data = bp_alloc(e->len);
    memcpy(*data, e->data, e->len);
    *len = e->len;
    return 0;
}

int bp_store_delete(bp_store_t *store, const char *id) {
    for (size_t i = 0; i < store->count; i++) {
        if (strcmp(store->entries[i].bundle_id, id) == 0) {
            store->current_size -= store->entries[i].len;
            bp_free(store->entries[i].bundle_id);
            bp_free(store->entries[i].data);
            store->entries[i] = store->entries[--store->count];
            return 0;
        }
    }
    return -1;
}

int bp_store_list(bp_store_t *store, char ***ids, size_t *count) {
    *count = store->count;
    *ids = bp_alloc(store->count * sizeof(char *));
    for (size_t i = 0; i < store->count; i++)
        (*ids)[i] = bp_strdup(store->entries[i].bundle_id);
    return 0;
}

int bp_store_expire(bp_store_t *store) {
    uint64_t now = bp_time_now_dtn();
    size_t removed = 0;
    for (size_t i = 0; i < store->count; ) {
        if (store->entries[i].expiry < now) {
            store->current_size -= store->entries[i].len;
            bp_free(store->entries[i].bundle_id);
            bp_free(store->entries[i].data);
            store->entries[i] = store->entries[--store->count];
            removed++;
        } else i++;
    }
    if (removed) BP_LOG_DEBUG("Expired %zu bundles", removed);
    return (int)removed;
}
