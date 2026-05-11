/*
 * bp_stream.h - Streaming Data Transfer API
 * 
 * High-level API for streaming large data over DTN with automatic
 * fragmentation, flow control, and reassembly.
 */
#ifndef BP_STREAM_H
#define BP_STREAM_H

#include "bp_sdk.h"
#include "bp_fragment.h"
#include <stdint.h>
#include <stddef.h>

#define BP_STREAM_DEFAULT_FRAGMENT_SIZE   (64 * 1024)
#define BP_STREAM_DEFAULT_MAX_IN_FLIGHT   16
#define BP_STREAM_DEFAULT_BUFFER_SIZE     (1024 * 1024)

typedef struct {
    size_t fragment_size;
    size_t max_in_flight;
    size_t buffer_size;
    uint32_t timeout_ms;
} bp_stream_config_t;

#define BP_STREAM_CONFIG_DEFAULT { \
    .fragment_size = BP_STREAM_DEFAULT_FRAGMENT_SIZE, \
    .max_in_flight = BP_STREAM_DEFAULT_MAX_IN_FLIGHT, \
    .buffer_size = BP_STREAM_DEFAULT_BUFFER_SIZE, \
    .timeout_ms = 30000 \
}

typedef struct bp_stream bp_stream_t;

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t fragments_sent;
    uint64_t fragments_received;
    uint64_t bytes_pending;
    size_t in_flight;
} bp_stream_stats_t;

bp_stream_t *bp_stream_create(const char *local_eid, const char *remote_eid,
                               const bp_stream_config_t *config);
void bp_stream_destroy(bp_stream_t *stream);

int bp_stream_write(bp_stream_t *stream, const void *data, size_t len);
int bp_stream_flush(bp_stream_t *stream);

int bp_stream_read(bp_stream_t *stream, void *buf, size_t len, int timeout_ms);
int bp_stream_read_available(bp_stream_t *stream, void *buf, size_t max_len);

int bp_stream_feed(bp_stream_t *stream, const void *bundle_data, size_t bundle_len);

int bp_stream_get_stats(bp_stream_t *stream, bp_stream_stats_t *stats);
int bp_stream_is_complete(bp_stream_t *stream);

int bp_stream_send_file(bp_stream_t *stream, const char *filepath);
int bp_stream_recv_file(bp_stream_t *stream, const char *filepath, size_t expected_size, int timeout_ms);

#endif

