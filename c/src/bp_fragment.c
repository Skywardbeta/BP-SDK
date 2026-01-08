/*
 * bp_fragment.c - Bundle Fragmentation/Reassembly with Timeout Support
 */
#include "bp_fragment.h"
#include "bp_utils.h"
#include <string.h>
#include <time.h>

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

void bp_fragment_ctx_init(bp_fragment_ctx_t *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->default_timeout_ms = BP_FRAGMENT_DEFAULT_TIMEOUT_MS;
}

void bp_fragment_ctx_init_with_timeout(bp_fragment_ctx_t *ctx, uint64_t timeout_ms) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->default_timeout_ms = timeout_ms > 0 ? timeout_ms : BP_FRAGMENT_DEFAULT_TIMEOUT_MS;
}

static void free_entry(bp_fragment_entry_t *e) {
    bp_free(e->assembled);
    bp_free(e->bitmap);
    memset(e, 0, sizeof(*e));
}

void bp_fragment_ctx_free(bp_fragment_ctx_t *ctx) {
    if (!ctx) return;
    for (size_t i = 0; i < ctx->count; i++) {
        free_entry(&ctx->entries[i]);
    }
    bp_free(ctx->entries);
    memset(ctx, 0, sizeof(*ctx));
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

static bp_fragment_entry_t *alloc_entry(bp_fragment_ctx_t *ctx) {
    for (size_t i = 0; i < ctx->count; i++) {
        if (!ctx->entries[i].assembled) {
            return &ctx->entries[i];
        }
    }
    
    if (ctx->count >= ctx->capacity) {
        size_t new_cap = ctx->capacity ? ctx->capacity * 2 : 4;
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
    if (!ctx || !frag || !complete) return -1;
    
    if (!(frag->primary.flags & BP_FLAG_FRAGMENT)) {
        memset(complete, 0, sizeof(*complete));
        if (copy_primary(&complete->primary, &frag->primary) < 0) return -1;
        if (frag->payload_len > 0 && frag->payload) {
            complete->payload = bp_alloc(frag->payload_len);
            if (!complete->payload) {
                bp_free(complete->primary.dest_uri);
                bp_free(complete->primary.source_uri);
                bp_free(complete->primary.report_uri);
                return -1;
            }
            memcpy(complete->payload, frag->payload, frag->payload_len);
        }
        complete->payload_len = frag->payload_len;
        return 1;
    }

    if (frag->primary.total_adu_len == 0) return -1;
    
    size_t off = frag->primary.fragment_offset;
    size_t len = frag->payload_len;
    
    if (off + len > frag->primary.total_adu_len) return -1;

    bp_fragment_entry_t *e = find_entry(ctx, frag);
    if (!e) {
        e = alloc_entry(ctx);
        if (!e) return -1;
        
        memset(e, 0, sizeof(*e));
        e->creation_ts = frag->primary.creation_ts;
        e->creation_seq = frag->primary.creation_seq;
        e->total_len = frag->primary.total_adu_len;
        
        uint64_t timeout = frag->primary.lifetime_ms > 0 ? 
                           frag->primary.lifetime_ms : ctx->default_timeout_ms;
        e->expiry_time = get_time_ms() + timeout;
        
        e->assembled = bp_alloc((size_t)e->total_len);
        if (!e->assembled) {
            memset(e, 0, sizeof(*e));
            return -1;
        }
        memset(e->assembled, 0, (size_t)e->total_len);
        
        size_t bitmap_size = ((size_t)e->total_len + 7) / 8;
        e->bitmap = bp_alloc(bitmap_size);
        if (!e->bitmap) {
            bp_free(e->assembled);
            memset(e, 0, sizeof(*e));
            return -1;
        }
        memset(e->bitmap, 0, bitmap_size);
        e->bytes_received = 0;
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
            return -1;
        }
        complete->primary.flags &= ~BP_FLAG_FRAGMENT;
        complete->primary.fragment_offset = 0;
        complete->primary.total_adu_len = 0;
        complete->payload = e->assembled;
        complete->payload_len = (size_t)e->total_len;
        
        e->assembled = NULL;
        free_entry(e);
        return 1;
    }
    return 0;
}

size_t bp_fragment_expire(bp_fragment_ctx_t *ctx, uint64_t current_time_ms) {
    if (!ctx) return 0;
    
    size_t expired = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        bp_fragment_entry_t *e = &ctx->entries[i];
        if (e->assembled && current_time_ms >= e->expiry_time) {
            BP_LOG_DEBUG("Fragment expired: ts=%llu seq=%llu (received %llu/%llu bytes)",
                         (unsigned long long)e->creation_ts,
                         (unsigned long long)e->creation_seq,
                         (unsigned long long)e->bytes_received,
                         (unsigned long long)e->total_len);
            free_entry(e);
            expired++;
        }
    }
    return expired;
}

size_t bp_fragment_pending_count(const bp_fragment_ctx_t *ctx) {
    if (!ctx) return 0;
    size_t count = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->entries[i].assembled) count++;
    }
    return count;
}

size_t bp_fragment_pending_bytes(const bp_fragment_ctx_t *ctx) {
    if (!ctx) return 0;
    size_t bytes = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->entries[i].assembled) {
            bytes += (size_t)ctx->entries[i].total_len;
        }
    }
    return bytes;
}
