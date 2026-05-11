/*
 * bp_fragment.h - Bundle Fragmentation/Reassembly
 * Thread-safe with configurable limits. Use opaque handle for thread safety.
 */
#ifndef BP_FRAGMENT_H
#define BP_FRAGMENT_H

#include "bp_bundle.h"
#include <stdint.h>
#include <stddef.h>

#define BP_FRAGMENT_DEFAULT_TIMEOUT_MS  300000
#define BP_FRAGMENT_MIN_SIZE            100
#define BP_FRAGMENT_DEFAULT_MAX_ENTRIES 64
#define BP_FRAGMENT_DEFAULT_MAX_BYTES   (64 * 1024 * 1024)

#define BP_FRAGMENT_OK          0
#define BP_FRAGMENT_COMPLETE    1
#define BP_FRAGMENT_ERR        -1
#define BP_FRAGMENT_ERR_LIMIT  -2

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

typedef struct bp_fragment_ctx bp_fragment_ctx_t;

typedef struct {
    uint64_t timeout_ms;
    size_t max_entries;
    size_t max_total_bytes;
} bp_fragment_config_t;

bp_fragment_ctx_t *bp_fragment_ctx_create(const bp_fragment_config_t *cfg);
bp_fragment_ctx_t *bp_fragment_ctx_create_default(void);
void bp_fragment_ctx_destroy(bp_fragment_ctx_t *ctx);

int bp_fragment_add(bp_fragment_ctx_t *ctx, const bp_bundle_full_t *frag,
                    bp_bundle_full_t *complete);

size_t bp_fragment_expire(bp_fragment_ctx_t *ctx, uint64_t current_time_ms);
size_t bp_fragment_pending_count(bp_fragment_ctx_t *ctx);
size_t bp_fragment_pending_bytes(bp_fragment_ctx_t *ctx);
void bp_fragment_free_array(bp_bundle_full_t *frags, size_t count);

#endif
