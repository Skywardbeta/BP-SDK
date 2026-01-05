/* bp_fragment.c - Bundle Fragmentation/Reassembly */
#include "bp_fragment.h"
#include "bp_utils.h"
#include <string.h>

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
    if (!original || !frags || !count || max_size < 100) return -1;
    
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

void bp_fragment_ctx_init(bp_fragment_ctx_t *ctx) { memset(ctx, 0, sizeof(*ctx)); }

void bp_fragment_ctx_free(bp_fragment_ctx_t *ctx) {
    for (size_t i = 0; i < ctx->count; i++) {
        bp_free(ctx->entries[i].source_eid);
        bp_free(ctx->entries[i].assembled);
        bp_free(ctx->entries[i].bitmap);
    }
    bp_free(ctx->entries);
    memset(ctx, 0, sizeof(*ctx));
}

static bp_fragment_entry_t *find_entry(bp_fragment_ctx_t *ctx, const bp_bundle_full_t *frag) {
    for (size_t i = 0; i < ctx->count; i++) {
        bp_fragment_entry_t *e = &ctx->entries[i];
        if (e->creation_ts == frag->primary.creation_ts && e->creation_seq == frag->primary.creation_seq)
            return e;
    }
    return NULL;
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
        if (ctx->count >= ctx->capacity) {
            size_t new_cap = ctx->capacity ? ctx->capacity * 2 : 4;
            bp_fragment_entry_t *new_entries = bp_realloc(ctx->entries, 
                                                           new_cap * sizeof(bp_fragment_entry_t));
            if (!new_entries) return -1;
            ctx->entries = new_entries;
            ctx->capacity = new_cap;
        }
        
        e = &ctx->entries[ctx->count];
        memset(e, 0, sizeof(*e));
        e->creation_ts = frag->primary.creation_ts;
        e->creation_seq = frag->primary.creation_seq;
        e->total_len = frag->primary.total_adu_len;
        
        e->assembled = bp_alloc(e->total_len);
        if (!e->assembled) return -1;
        memset(e->assembled, 0, e->total_len);
        
        size_t bitmap_size = (e->total_len + 7) / 8;
        e->bitmap = bp_alloc(bitmap_size);
        if (!e->bitmap) {
            bp_free(e->assembled);
            e->assembled = NULL;
            return -1;
        }
        memset(e->bitmap, 0, bitmap_size);
        e->assembled_len = 0;
        
        ctx->count++;
    }

    if (frag->payload && len > 0) {
        memcpy(e->assembled + off, frag->payload, len);
        
        for (size_t i = off; i < off + len; i++) {
            e->bitmap[i / 8] |= (uint8_t)(1 << (i % 8));
        }
    }

    int complete_flag = 1;
    for (size_t i = 0; i < e->total_len; i++) {
        if (!(e->bitmap[i / 8] & (1 << (i % 8)))) {
            complete_flag = 0;
            break;
        }
    }

    if (complete_flag) {
        memset(complete, 0, sizeof(*complete));
        if (copy_primary(&complete->primary, &frag->primary) < 0) {
            return -1;
        }
        complete->primary.flags &= ~BP_FLAG_FRAGMENT;
        complete->primary.fragment_offset = 0;
        complete->primary.total_adu_len = 0;
        complete->payload = e->assembled;
        complete->payload_len = e->total_len;
        e->assembled = NULL;
        return 1;
    }
    return 0;
}
