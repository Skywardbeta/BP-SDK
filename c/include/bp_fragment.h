/*
 * bp_fragment.h - Bundle Fragmentation/Reassembly with Timeout Support
 * 
 * Provides fragmentation of large bundles and reassembly of fragments
 * with expiration tracking for incomplete reassembly contexts.
 */
#ifndef BP_FRAGMENT_H
#define BP_FRAGMENT_H

#include "bp_bundle.h"
#include <stdint.h>
#include <stddef.h>

#define BP_FRAGMENT_DEFAULT_TIMEOUT_MS  300000  /* 5 minutes */
#define BP_FRAGMENT_MIN_SIZE            100

int bp_fragment_bundle(const bp_bundle_full_t *original, size_t max_fragment_size,
                       bp_bundle_full_t **fragments, size_t *fragment_count);

typedef struct {
    uint64_t creation_ts;
    uint64_t creation_seq;
    uint64_t total_len;
    uint64_t expiry_time;
    uint64_t bytes_received;
    uint8_t *assembled;
    uint8_t *bitmap;
} bp_fragment_entry_t;

typedef struct {
    bp_fragment_entry_t *entries;
    size_t count;
    size_t capacity;
    uint64_t default_timeout_ms;
} bp_fragment_ctx_t;

void bp_fragment_ctx_init(bp_fragment_ctx_t *ctx);
void bp_fragment_ctx_init_with_timeout(bp_fragment_ctx_t *ctx, uint64_t timeout_ms);
void bp_fragment_ctx_free(bp_fragment_ctx_t *ctx);

int bp_fragment_add(bp_fragment_ctx_t *ctx, const bp_bundle_full_t *frag,
                    bp_bundle_full_t *complete);

size_t bp_fragment_expire(bp_fragment_ctx_t *ctx, uint64_t current_time_ms);

size_t bp_fragment_pending_count(const bp_fragment_ctx_t *ctx);
size_t bp_fragment_pending_bytes(const bp_fragment_ctx_t *ctx);

void bp_fragment_free_array(bp_bundle_full_t *frags, size_t count);

#endif
