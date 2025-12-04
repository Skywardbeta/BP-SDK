/* bp_fragment.h - Bundle Fragmentation/Reassembly */
#ifndef BP_FRAGMENT_H
#define BP_FRAGMENT_H

#include "bp_bundle.h"
#include <stdint.h>
#include <stddef.h>

int bp_fragment_bundle(const bp_bundle_full_t *original, size_t max_fragment_size,
                       bp_bundle_full_t **fragments, size_t *fragment_count);

typedef struct {
    uint64_t creation_ts;
    uint64_t creation_seq;
    char *source_eid;
    uint64_t total_len;
    uint8_t *assembled;
    size_t assembled_len;
    uint8_t *bitmap;
} bp_fragment_entry_t;

typedef struct {
    bp_fragment_entry_t *entries;
    size_t count;
    size_t capacity;
} bp_fragment_ctx_t;

void bp_fragment_ctx_init(bp_fragment_ctx_t *ctx);
void bp_fragment_ctx_free(bp_fragment_ctx_t *ctx);
int bp_fragment_add(bp_fragment_ctx_t *ctx, const bp_bundle_full_t *frag,
                    bp_bundle_full_t *complete);

#endif
