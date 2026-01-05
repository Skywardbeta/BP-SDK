#include "bp_storage.h"
#include "bp_utils.h"
#include <string.h>
#include <stdio.h>

int bp_store_init(bp_store_t *store, size_t max_size) {
    if (!store) return -1;
    memset(store, 0, sizeof(*store));
    store->max_size = max_size;
    return 0;
}

void bp_store_free(bp_store_t *store) {
    if (!store) return;
    for (size_t i = 0; i < store->count; i++) {
        bp_free(store->entries[i].bundle_id);
        bp_free(store->entries[i].data);
    }
    bp_free(store->entries);
    memset(store, 0, sizeof(*store));
}

int bp_bundle_id(const bp_primary_t *p, char *out, size_t cap) {
    if (!p || !out || cap == 0) return -1;
    return snprintf(out, cap, "ipn:%llu.%llu-%llu-%llu",
                    (unsigned long long)p->source_ssp[0], (unsigned long long)p->source_ssp[1],
                    (unsigned long long)p->creation_ts, (unsigned long long)p->creation_seq);
}

static bp_store_entry_t *find_entry(bp_store_t *store, const char *id) {
    if (!store || !id) return NULL;
    for (size_t i = 0; i < store->count; i++) {
        if (store->entries[i].bundle_id && strcmp(store->entries[i].bundle_id, id) == 0)
            return &store->entries[i];
    }
    return NULL;
}

int bp_store_put(bp_store_t *store, const char *id, const uint8_t *data, size_t len, uint64_t expiry) {
    if (!store || !id) return -1;
    if (len > 0 && !data) return -1;

    if (store->current_size + len > store->max_size) {
        bp_store_expire(store);
        if (store->current_size + len > store->max_size) return -1;
    }

    bp_store_entry_t *e = find_entry(store, id);
    if (e) {
        store->current_size -= e->len;
        bp_free(e->data);
        e->data = NULL;
    } else {
        if (store->count >= store->capacity) {
            size_t new_cap = store->capacity ? store->capacity * 2 : 16;
            bp_store_entry_t *new_entries = bp_realloc(store->entries, new_cap * sizeof(bp_store_entry_t));
            if (!new_entries) return -1;
            store->entries = new_entries;
            store->capacity = new_cap;
        }
        e = &store->entries[store->count++];
        memset(e, 0, sizeof(*e));
        e->bundle_id = bp_strdup(id);
        if (!e->bundle_id) {
            store->count--;
            return -1;
        }
    }

    if (len > 0) {
        e->data = bp_alloc(len);
        if (!e->data) {
            if (e == &store->entries[store->count - 1]) {
                bp_free(e->bundle_id);
                store->count--;
            }
            return -1;
        }
        memcpy(e->data, data, len);
    }
    e->len = len;
    e->expiry = expiry;
    store->current_size += len;
    return 0;
}

int bp_store_get(bp_store_t *store, const char *id, uint8_t **data, size_t *len) {
    if (!store || !id || !data || !len) return -1;
    
    *data = NULL;
    *len = 0;
    
    bp_store_entry_t *e = find_entry(store, id);
    if (!e) return -1;
    
    if (e->len > 0) {
        *data = bp_alloc(e->len);
        if (!*data) return -1;
        memcpy(*data, e->data, e->len);
    }
    *len = e->len;
    return 0;
}

int bp_store_delete(bp_store_t *store, const char *id) {
    if (!store || !id) return -1;
    
    for (size_t i = 0; i < store->count; i++) {
        if (store->entries[i].bundle_id && strcmp(store->entries[i].bundle_id, id) == 0) {
            store->current_size -= store->entries[i].len;
            bp_free(store->entries[i].bundle_id);
            bp_free(store->entries[i].data);
            if (i < store->count - 1) {
                store->entries[i] = store->entries[store->count - 1];
            }
            store->count--;
            return 0;
        }
    }
    return -1;
}

int bp_store_list(bp_store_t *store, char ***ids, size_t *count) {
    if (!store || !ids || !count) return -1;
    
    *count = store->count;
    if (store->count == 0) {
        *ids = NULL;
        return 0;
    }
    
    *ids = bp_alloc(store->count * sizeof(char *));
    if (!*ids) return -1;
    
    for (size_t i = 0; i < store->count; i++) {
        (*ids)[i] = bp_strdup(store->entries[i].bundle_id);
        if (!(*ids)[i]) {
            for (size_t j = 0; j < i; j++) bp_free((*ids)[j]);
            bp_free(*ids);
            *ids = NULL;
            *count = 0;
            return -1;
        }
    }
    return 0;
}

int bp_store_expire(bp_store_t *store) {
    if (!store) return -1;
    
    uint64_t now = bp_time_now_dtn();
    size_t removed = 0;
    
    for (size_t i = 0; i < store->count; ) {
        if (store->entries[i].expiry < now) {
            store->current_size -= store->entries[i].len;
            bp_free(store->entries[i].bundle_id);
            bp_free(store->entries[i].data);
            if (i < store->count - 1) {
                store->entries[i] = store->entries[store->count - 1];
            }
            store->count--;
            removed++;
        } else {
            i++;
        }
    }
    
    if (removed > 0) {
        BP_LOG_DEBUG("Expired %zu bundles", removed);
    }
    return (int)removed;
}
