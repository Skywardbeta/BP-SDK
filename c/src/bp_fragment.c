/*
 * bp_fragment.c - Bundle Fragmentation/Reassembly
 * Thread-safe with mutex protection and configurable DoS limits.
 */
#include "bp_fragment.h"
#include "bp_utils.h"
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define FRAG_MUTEX_T CRITICAL_SECTION
#define FRAG_MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define FRAG_MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define FRAG_MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define FRAG_MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#include <pthread.h>
#define FRAG_MUTEX_T pthread_mutex_t
#define FRAG_MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define FRAG_MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define FRAG_MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define FRAG_MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#endif

struct bp_fragment_ctx {
    bp_fragment_entry_t *entries;
    size_t count;
    size_t capacity;
    uint64_t default_timeout_ms;
    size_t max_entries;
    size_t max_total_bytes;
    size_t current_total_bytes;
    FRAG_MUTEX_T mutex;
};

static uint64_t get_time_ms(void) {
    return (uint64_t)time(NULL) * 1000;
}

static int copy_primary(bp_primary_t *dst, const bp_primary_t *src) {
    *dst = *src;
    dst->dest_uri = NULL;
    dst->source_uri = NULL;
    dst->report_uri = NULL;
    
    if (src->dest_uri) {
        dst->dest_uri = bp_strdup(src->dest_uri);
        if (!dst->dest_uri) goto fail;
    }
    if (src->source_uri) {
        dst->source_uri = bp_strdup(src->source_uri);
        if (!dst->source_uri) goto fail;
    }
    if (src->report_uri) {
        dst->report_uri = bp_strdup(src->report_uri);
        if (!dst->report_uri) goto fail;
    }
    return 0;

fail:
    bp_free(dst->dest_uri);
    bp_free(dst->source_uri);
    bp_free(dst->report_uri);
    dst->dest_uri = NULL;
    dst->source_uri = NULL;
    dst->report_uri = NULL;
    return -1;
}

int bp_fragment_bundle(const bp_bundle_full_t *original, size_t max_size,
                       bp_bundle_full_t **frags, size_t *count) {
    if (!original || !frags || !count || max_size < BP_FRAGMENT_MIN_SIZE) return -1;
    
    *frags = NULL;
    *count = 0;
    
    if (original->payload_len <= max_size) {
        bp_bundle_full_t *f = bp_alloc(sizeof(bp_bundle_full_t));
        if (!f) return -1;
        memset(f, 0, sizeof(*f));
        
        if (copy_primary(&f->primary, &original->primary) < 0) {
            bp_free(f);
            return -1;
        }
        
        if (original->payload_len > 0) {
            f->payload = bp_alloc(original->payload_len);
            if (!f->payload) {
                bp_free(f->primary.dest_uri);
                bp_free(f->primary.source_uri);
                bp_free(f->primary.report_uri);
                bp_free(f);
                return -1;
            }
            memcpy(f->payload, original->payload, original->payload_len);
        }
        f->payload_len = original->payload_len;
        
        *frags = f;
        *count = 1;
        return 0;
    }

    size_t n = (original->payload_len + max_size - 1) / max_size;
    bp_bundle_full_t *arr = bp_alloc(n * sizeof(bp_bundle_full_t));
    if (!arr) return -1;
    memset(arr, 0, n * sizeof(bp_bundle_full_t));

    for (size_t i = 0; i < n; i++) {
        size_t offset = i * max_size;
        size_t len = (i == n - 1) ? (original->payload_len - offset) : max_size;

        bp_bundle_full_t *f = &arr[i];
        if (copy_primary(&f->primary, &original->primary) < 0) {
            bp_fragment_free_array(arr, i);
            return -1;
        }
        
        f->primary.flags |= BP_FLAG_FRAGMENT;
        f->primary.fragment_offset = offset;
        f->primary.total_adu_len = original->payload_len;
        
        f->payload = bp_alloc(len);
        if (!f->payload) {
            bp_free(f->primary.dest_uri);
            bp_free(f->primary.source_uri);
            bp_free(f->primary.report_uri);
            bp_fragment_free_array(arr, i);
            return -1;
        }
        memcpy(f->payload, original->payload + offset, len);
        f->payload_len = len;
        f->blocks = NULL;
        f->block_count = 0;
    }
    
    *frags = arr;
    *count = n;
    return 0;
}

void bp_fragment_free_array(bp_bundle_full_t *frags, size_t count) {
    if (!frags) return;
    for (size_t i = 0; i < count; i++) {
        bp_free(frags[i].primary.dest_uri);
        bp_free(frags[i].primary.source_uri);
        bp_free(frags[i].primary.report_uri);
        bp_free(frags[i].payload);
        bp_free(frags[i].blocks);
    }
    bp_free(frags);
}

bp_fragment_ctx_t *bp_fragment_ctx_create_default(void) {
    return bp_fragment_ctx_create(NULL);
}

bp_fragment_ctx_t *bp_fragment_ctx_create(const bp_fragment_config_t *cfg) {
    bp_fragment_ctx_t *ctx = bp_alloc(sizeof(bp_fragment_ctx_t));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(*ctx));
    
    if (cfg) {
        ctx->default_timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : BP_FRAGMENT_DEFAULT_TIMEOUT_MS;
        ctx->max_entries = cfg->max_entries > 0 ? cfg->max_entries : BP_FRAGMENT_DEFAULT_MAX_ENTRIES;
        ctx->max_total_bytes = cfg->max_total_bytes > 0 ? cfg->max_total_bytes : BP_FRAGMENT_DEFAULT_MAX_BYTES;
    } else {
        ctx->default_timeout_ms = BP_FRAGMENT_DEFAULT_TIMEOUT_MS;
        ctx->max_entries = BP_FRAGMENT_DEFAULT_MAX_ENTRIES;
        ctx->max_total_bytes = BP_FRAGMENT_DEFAULT_MAX_BYTES;
    }
    
    FRAG_MUTEX_INIT(ctx->mutex);
    return ctx;
}

static size_t entry_bytes(const bp_fragment_entry_t *e) {
    if (!e || !e->assembled) return 0;
    size_t bitmap_size = ((size_t)e->total_len + 7) / 8;
    return (size_t)e->total_len + bitmap_size;
}

static void free_entry(bp_fragment_entry_t *e) {
    bp_free(e->assembled);
    bp_free(e->bitmap);
    memset(e, 0, sizeof(*e));
}

void bp_fragment_ctx_destroy(bp_fragment_ctx_t *ctx) {
    if (!ctx) return;
    FRAG_MUTEX_LOCK(ctx->mutex);
    for (size_t i = 0; i < ctx->count; i++) {
        free_entry(&ctx->entries[i]);
    }
    bp_free(ctx->entries);
    ctx->entries = NULL;
    ctx->count = 0;
    ctx->current_total_bytes = 0;
    FRAG_MUTEX_UNLOCK(ctx->mutex);
    FRAG_MUTEX_DESTROY(ctx->mutex);
    bp_free(ctx);
}

static bp_fragment_entry_t *find_entry(bp_fragment_ctx_t *ctx, const bp_bundle_full_t *frag) {
    for (size_t i = 0; i < ctx->count; i++) {
        bp_fragment_entry_t *e = &ctx->entries[i];
        if (e->assembled && 
            e->creation_ts == frag->primary.creation_ts && 
            e->creation_seq == frag->primary.creation_seq) {
            return e;
        }
    }
    return NULL;
}

static size_t active_entry_count(const bp_fragment_ctx_t *ctx) {
    size_t active = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->entries[i].assembled) active++;
    }
    return active;
}

static bp_fragment_entry_t *alloc_entry(bp_fragment_ctx_t *ctx) {
    for (size_t i = 0; i < ctx->count; i++) {
        if (!ctx->entries[i].assembled) {
            return &ctx->entries[i];
        }
    }
    
    if (active_entry_count(ctx) >= ctx->max_entries) {
        return NULL;
    }
    
    if (ctx->count >= ctx->capacity) {
        size_t new_cap = ctx->capacity ? ctx->capacity * 2 : 4;
        if (new_cap > ctx->max_entries) new_cap = ctx->max_entries;
        bp_fragment_entry_t *new_entries = bp_realloc(ctx->entries, 
                                                       new_cap * sizeof(bp_fragment_entry_t));
        if (!new_entries) return NULL;
        ctx->entries = new_entries;
        ctx->capacity = new_cap;
        memset(&ctx->entries[ctx->count], 0, (new_cap - ctx->count) * sizeof(bp_fragment_entry_t));
    }
    
    return &ctx->entries[ctx->count++];
}

int bp_fragment_add(bp_fragment_ctx_t *ctx, const bp_bundle_full_t *frag, bp_bundle_full_t *complete) {
    if (!ctx || !frag || !complete) return BP_FRAGMENT_ERR;
    
    if (!(frag->primary.flags & BP_FLAG_FRAGMENT)) {
        memset(complete, 0, sizeof(*complete));
        if (copy_primary(&complete->primary, &frag->primary) < 0) return BP_FRAGMENT_ERR;
        if (frag->payload_len > 0 && frag->payload) {
            complete->payload = bp_alloc(frag->payload_len);
            if (!complete->payload) {
                bp_free(complete->primary.dest_uri);
                bp_free(complete->primary.source_uri);
                bp_free(complete->primary.report_uri);
                return BP_FRAGMENT_ERR;
            }
            memcpy(complete->payload, frag->payload, frag->payload_len);
        }
        complete->payload_len = frag->payload_len;
        return BP_FRAGMENT_COMPLETE;
    }

    if (frag->primary.total_adu_len == 0) return BP_FRAGMENT_ERR;
    if (frag->payload_len > 0 && !frag->payload) return BP_FRAGMENT_ERR;
    
    size_t off = (size_t)frag->primary.fragment_offset;
    size_t len = frag->payload_len;
    
    if (off + len > frag->primary.total_adu_len) return BP_FRAGMENT_ERR;

    FRAG_MUTEX_LOCK(ctx->mutex);

    bp_fragment_entry_t *e = find_entry(ctx, frag);
    if (!e) {
        size_t needed = (size_t)frag->primary.total_adu_len;
        size_t bitmap_size = (needed + 7) / 8;
        size_t new_bytes = needed + bitmap_size;
        
        if (ctx->current_total_bytes + new_bytes > ctx->max_total_bytes) {
            FRAG_MUTEX_UNLOCK(ctx->mutex);
            return BP_FRAGMENT_ERR_LIMIT;
        }
        
        e = alloc_entry(ctx);
        if (!e) {
            FRAG_MUTEX_UNLOCK(ctx->mutex);
            return BP_FRAGMENT_ERR_LIMIT;
        }
        
        memset(e, 0, sizeof(*e));
        e->creation_ts = frag->primary.creation_ts;
        e->creation_seq = frag->primary.creation_seq;
        e->total_len = frag->primary.total_adu_len;
        
        uint64_t timeout = frag->primary.lifetime_ms > 0 ? 
                           frag->primary.lifetime_ms : ctx->default_timeout_ms;
        e->expiry_time = get_time_ms() + timeout;
        
        e->assembled = bp_alloc(needed);
        if (!e->assembled) {
            memset(e, 0, sizeof(*e));
            FRAG_MUTEX_UNLOCK(ctx->mutex);
            return BP_FRAGMENT_ERR;
        }
        memset(e->assembled, 0, needed);
        
        e->bitmap = bp_alloc(bitmap_size);
        if (!e->bitmap) {
            bp_free(e->assembled);
            memset(e, 0, sizeof(*e));
            FRAG_MUTEX_UNLOCK(ctx->mutex);
            return BP_FRAGMENT_ERR;
        }
        memset(e->bitmap, 0, bitmap_size);
        e->bytes_received = 0;
        ctx->current_total_bytes += new_bytes;
    }

    if (frag->payload && len > 0) {
        for (size_t i = off; i < off + len; i++) {
            if (!(e->bitmap[i / 8] & (1 << (i % 8)))) {
                e->bytes_received++;
            }
        }
        
        memcpy(e->assembled + off, frag->payload, len);
        
        for (size_t i = off; i < off + len; i++) {
            e->bitmap[i / 8] |= (uint8_t)(1 << (i % 8));
        }
    }

    if (e->bytes_received == e->total_len) {
        memset(complete, 0, sizeof(*complete));
        if (copy_primary(&complete->primary, &frag->primary) < 0) {
            FRAG_MUTEX_UNLOCK(ctx->mutex);
            return BP_FRAGMENT_ERR;
        }
        complete->primary.flags &= ~BP_FLAG_FRAGMENT;
        complete->primary.fragment_offset = 0;
        complete->primary.total_adu_len = 0;
        complete->payload = e->assembled;
        complete->payload_len = (size_t)e->total_len;
        
        ctx->current_total_bytes -= entry_bytes(e);
        e->assembled = NULL;
        free_entry(e);
        FRAG_MUTEX_UNLOCK(ctx->mutex);
        return BP_FRAGMENT_COMPLETE;
    }
    
    FRAG_MUTEX_UNLOCK(ctx->mutex);
    return BP_FRAGMENT_OK;
}

size_t bp_fragment_expire(bp_fragment_ctx_t *ctx, uint64_t current_time_ms) {
    if (!ctx) return 0;
    
    FRAG_MUTEX_LOCK(ctx->mutex);
    size_t expired = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        bp_fragment_entry_t *e = &ctx->entries[i];
        if (e->assembled && current_time_ms >= e->expiry_time) {
            ctx->current_total_bytes -= entry_bytes(e);
            free_entry(e);
            expired++;
        }
    }
    FRAG_MUTEX_UNLOCK(ctx->mutex);
    return expired;
}

size_t bp_fragment_pending_count(bp_fragment_ctx_t *ctx) {
    if (!ctx) return 0;
    FRAG_MUTEX_LOCK(ctx->mutex);
    size_t count = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->entries[i].assembled) count++;
    }
    FRAG_MUTEX_UNLOCK(ctx->mutex);
    return count;
}

size_t bp_fragment_pending_bytes(bp_fragment_ctx_t *ctx) {
    if (!ctx) return 0;
    FRAG_MUTEX_LOCK(ctx->mutex);
    size_t bytes = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->entries[i].assembled) {
            bytes += (size_t)ctx->entries[i].total_len;
        }
    }
    FRAG_MUTEX_UNLOCK(ctx->mutex);
    return bytes;
}
