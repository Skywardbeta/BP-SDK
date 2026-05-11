/*
 * bp_bpsec_keys.c - BPSec Key Management Implementation
 * 
 * Thread-safe keystore using mutex protection for all operations.
 * Keys are stored in a dynamic array with O(n) lookup by ID or EID.
 */
#include "bp_bpsec_keys.h"
#include "bp_utils.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define MUTEX_T CRITICAL_SECTION
#define MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#include <pthread.h>
#define MUTEX_T pthread_mutex_t
#define MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#endif

struct bpsec_keystore {
    bpsec_key_entry_t *entries;
    size_t count;
    size_t capacity;
    MUTEX_T mutex;
};

bpsec_keystore_t *bpsec_keystore_create(size_t initial_capacity) {
    if (initial_capacity == 0) initial_capacity = 16;
    
    bpsec_keystore_t *ks = bp_alloc(sizeof(bpsec_keystore_t));
    if (!ks) return NULL;
    
    ks->entries = bp_alloc(sizeof(bpsec_key_entry_t) * initial_capacity);
    if (!ks->entries) {
        bp_free(ks);
        return NULL;
    }
    
    ks->count = 0;
    ks->capacity = initial_capacity;
    MUTEX_INIT(ks->mutex);
    
    return ks;
}

void bpsec_keystore_destroy(bpsec_keystore_t *ks) {
    if (!ks) return;
    
    MUTEX_LOCK(ks->mutex);
    for (size_t i = 0; i < ks->count; i++) {
        memset(ks->entries[i].data, 0, sizeof(ks->entries[i].data));
    }
    bp_free(ks->entries);
    ks->entries = NULL;
    ks->count = 0;
    MUTEX_UNLOCK(ks->mutex);
    
    MUTEX_DESTROY(ks->mutex);
    bp_free(ks);
}

static int find_key_index(bpsec_keystore_t *ks, const char *key_id) {
    for (size_t i = 0; i < ks->count; i++) {
        if (strcmp(ks->entries[i].id, key_id) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int bpsec_keystore_add(bpsec_keystore_t *ks, const char *key_id,
                       uint8_t key_type, const uint8_t *key_data,
                       size_t key_len, const char *bound_eid,
                       uint64_t expires_at) {
    if (!ks || !key_id || !key_data) return -1;
    if (key_len == 0 || key_len > BPSEC_KEY_MAX_DATA_LEN) return -1;
    if (strlen(key_id) >= BPSEC_KEY_MAX_ID_LEN) return -1;
    
    MUTEX_LOCK(ks->mutex);
    
    int existing = find_key_index(ks, key_id);
    if (existing >= 0) {
        bpsec_key_entry_t *e = &ks->entries[existing];
        e->type = key_type;
        memcpy(e->data, key_data, key_len);
        e->data_len = key_len;
        if (bound_eid && strlen(bound_eid) < sizeof(e->bound_eid)) {
            strncpy(e->bound_eid, bound_eid, sizeof(e->bound_eid) - 1);
            e->bound_eid[sizeof(e->bound_eid) - 1] = '\0';
        } else {
            e->bound_eid[0] = '\0';
        }
        e->expires_at = expires_at;
        MUTEX_UNLOCK(ks->mutex);
        return 0;
    }
    
    if (ks->count >= ks->capacity) {
        size_t new_cap = ks->capacity * 2;
        bpsec_key_entry_t *new_entries = bp_realloc(ks->entries,
                                                     sizeof(bpsec_key_entry_t) * new_cap);
        if (!new_entries) {
            MUTEX_UNLOCK(ks->mutex);
            return -1;
        }
        ks->entries = new_entries;
        ks->capacity = new_cap;
    }
    
    bpsec_key_entry_t *e = &ks->entries[ks->count];
    memset(e, 0, sizeof(*e));
    
    strncpy(e->id, key_id, sizeof(e->id) - 1);
    e->type = key_type;
    memcpy(e->data, key_data, key_len);
    e->data_len = key_len;
    
    if (bound_eid && strlen(bound_eid) < sizeof(e->bound_eid)) {
        strncpy(e->bound_eid, bound_eid, sizeof(e->bound_eid) - 1);
        e->bound_eid[sizeof(e->bound_eid) - 1] = '\0';
    }
    
    e->expires_at = expires_at;
    e->created_at = bp_time_now_dtn();
    
    ks->count++;
    
    MUTEX_UNLOCK(ks->mutex);
    return 0;
}

int bpsec_keystore_remove(bpsec_keystore_t *ks, const char *key_id) {
    if (!ks || !key_id) return -1;
    
    MUTEX_LOCK(ks->mutex);
    
    int idx = find_key_index(ks, key_id);
    if (idx < 0) {
        MUTEX_UNLOCK(ks->mutex);
        return -1;
    }
    
    memset(ks->entries[idx].data, 0, sizeof(ks->entries[idx].data));
    
    if ((size_t)idx < ks->count - 1) {
        memmove(&ks->entries[idx], &ks->entries[idx + 1],
                sizeof(bpsec_key_entry_t) * (ks->count - (size_t)idx - 1));
    }
    ks->count--;
    
    MUTEX_UNLOCK(ks->mutex);
    return 0;
}

int bpsec_keystore_get(bpsec_keystore_t *ks, const char *key_id,
                       bpsec_key_entry_t *out) {
    if (!ks || !key_id || !out) return -1;
    
    MUTEX_LOCK(ks->mutex);
    
    int idx = find_key_index(ks, key_id);
    if (idx < 0) {
        MUTEX_UNLOCK(ks->mutex);
        return -1;
    }
    
    *out = ks->entries[idx];
    
    MUTEX_UNLOCK(ks->mutex);
    return 0;
}

int bpsec_keystore_find_by_eid(bpsec_keystore_t *ks, const char *eid,
                                uint8_t key_type, bpsec_key_entry_t *out) {
    if (!ks || !eid || !out) return -1;
    
    MUTEX_LOCK(ks->mutex);
    
    uint64_t now = bp_time_now_dtn();
    
    for (size_t i = 0; i < ks->count; i++) {
        bpsec_key_entry_t *e = &ks->entries[i];
        
        if (e->type != key_type) continue;
        if (e->expires_at > 0 && e->expires_at < now) continue;
        if (e->bound_eid[0] == '\0' || strcmp(e->bound_eid, eid) == 0) {
            *out = *e;
            MUTEX_UNLOCK(ks->mutex);
            return 0;
        }
    }
    
    MUTEX_UNLOCK(ks->mutex);
    return -1;
}

size_t bpsec_keystore_expire(bpsec_keystore_t *ks, uint64_t current_time) {
    if (!ks) return 0;
    
    MUTEX_LOCK(ks->mutex);
    
    size_t expired = 0;
    size_t i = 0;
    
    while (i < ks->count) {
        if (ks->entries[i].expires_at > 0 && 
            ks->entries[i].expires_at < current_time) {
            memset(ks->entries[i].data, 0, sizeof(ks->entries[i].data));
            
            if (i < ks->count - 1) {
                memmove(&ks->entries[i], &ks->entries[i + 1],
                        sizeof(bpsec_key_entry_t) * (ks->count - i - 1));
            }
            ks->count--;
            expired++;
        } else {
            i++;
        }
    }
    
    MUTEX_UNLOCK(ks->mutex);
    return expired;
}

size_t bpsec_keystore_count(bpsec_keystore_t *ks) {
    if (!ks) return 0;
    
    MUTEX_LOCK(ks->mutex);
    size_t count = ks->count;
    MUTEX_UNLOCK(ks->mutex);
    
    return count;
}

