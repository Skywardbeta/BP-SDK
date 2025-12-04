/* bp_fragment.c - Bundle Fragmentation/Reassembly */
#include "bp_fragment.h"
#include "bp_utils.h"
#include <string.h>

int bp_fragment_bundle(const bp_bundle_full_t *original, size_t max_size,
                       bp_bundle_full_t **frags, size_t *count) {
    if (!original || !frags || !count || max_size < 100) return -1;
    if (original->payload_len <= max_size) {
        *frags = bp_alloc(sizeof(bp_bundle_full_t));
        memcpy(*frags, original, sizeof(bp_bundle_full_t));
        (*frags)->payload = bp_alloc(original->payload_len);
        memcpy((*frags)->payload, original->payload, original->payload_len);
        *count = 1;
        return 0;
    }

    size_t n = (original->payload_len + max_size - 1) / max_size;
    *frags = bp_alloc(n * sizeof(bp_bundle_full_t));
    *count = n;

    for (size_t i = 0; i < n; i++) {
        size_t offset = i * max_size;
        size_t len = (i == n - 1) ? (original->payload_len - offset) : max_size;

        bp_bundle_full_t *f = &(*frags)[i];
        memcpy(&f->primary, &original->primary, sizeof(bp_primary_t));
        f->primary.flags |= BP_FLAG_FRAGMENT;
        f->primary.fragment_offset = offset;
        f->primary.total_adu_len = original->payload_len;
        f->payload = bp_alloc(len);
        memcpy(f->payload, original->payload + offset, len);
        f->payload_len = len;
        f->blocks = NULL;
        f->block_count = 0;
    }
    return 0;
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
    if (!(frag->primary.flags & BP_FLAG_FRAGMENT)) {
        memcpy(complete, frag, sizeof(*complete));
        return 1;
    }

    bp_fragment_entry_t *e = find_entry(ctx, frag);
    if (!e) {
        if (ctx->count >= ctx->capacity) {
            ctx->capacity = ctx->capacity ? ctx->capacity * 2 : 4;
            ctx->entries = bp_realloc(ctx->entries, ctx->capacity * sizeof(bp_fragment_entry_t));
        }
        e = &ctx->entries[ctx->count++];
        memset(e, 0, sizeof(*e));
        e->creation_ts = frag->primary.creation_ts;
        e->creation_seq = frag->primary.creation_seq;
        e->total_len = frag->primary.total_adu_len;
        e->assembled = bp_alloc(e->total_len);
        e->bitmap = bp_alloc((e->total_len + 7) / 8);
        memset(e->bitmap, 0, (e->total_len + 7) / 8);
    }

    size_t off = frag->primary.fragment_offset;
    size_t len = frag->payload_len;
    memcpy(e->assembled + off, frag->payload, len);

    for (size_t i = off; i < off + len; i++)
        e->bitmap[i / 8] |= (1 << (i % 8));

    int complete_flag = 1;
    for (size_t i = 0; i < e->total_len && complete_flag; i++)
        if (!(e->bitmap[i / 8] & (1 << (i % 8)))) complete_flag = 0;

    if (complete_flag) {
        memset(complete, 0, sizeof(*complete));
        memcpy(&complete->primary, &frag->primary, sizeof(bp_primary_t));
        complete->primary.flags &= ~BP_FLAG_FRAGMENT;
        complete->payload = e->assembled;
        complete->payload_len = e->total_len;
        e->assembled = NULL;
        return 1;
    }
    return 0;
}
