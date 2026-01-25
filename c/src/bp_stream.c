/*
 * bp_stream.c - Streaming Data Transfer Implementation
 * 
 * Handles large data transfers via automatic fragmentation with
 * configurable flow control and buffering.
 */
#include "bp_stream.h"
#include "bp_bundle.h"
#include "bp_utils.h"
#include "bp_sdk.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define MUTEX_T CRITICAL_SECTION
#define MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <pthread.h>
#include <unistd.h>
#define MUTEX_T pthread_mutex_t
#define MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

struct bp_stream {
    char *local_eid;
    char *remote_eid;
    bp_stream_config_t config;
    
    uint8_t *send_buf;
    size_t send_len;
    size_t send_cap;
    
    uint8_t *recv_buf;
    size_t recv_len;
    size_t recv_cap;
    size_t recv_pos;
    
    bp_fragment_ctx_t *frag_ctx;
    
    uint64_t transfer_id;
    size_t in_flight;
    
    bp_stream_stats_t stats;
    
    MUTEX_T mutex;
    int closed;
};

bp_stream_t *bp_stream_create(const char *local_eid, const char *remote_eid,
                               const bp_stream_config_t *config) {
    if (!local_eid || !remote_eid) return NULL;
    
    bp_stream_t *s = bp_alloc(sizeof(bp_stream_t));
    if (!s) return NULL;
    memset(s, 0, sizeof(*s));
    
    s->local_eid = bp_strdup(local_eid);
    s->remote_eid = bp_strdup(remote_eid);
    if (!s->local_eid || !s->remote_eid) goto fail;
    
    if (config) {
        s->config = *config;
    } else {
        s->config.fragment_size = BP_STREAM_DEFAULT_FRAGMENT_SIZE;
        s->config.max_in_flight = BP_STREAM_DEFAULT_MAX_IN_FLIGHT;
        s->config.buffer_size = BP_STREAM_DEFAULT_BUFFER_SIZE;
        s->config.timeout_ms = 30000;
    }
    
    /* Validate config to prevent infinite loops/hangs */
    if (s->config.fragment_size == 0) s->config.fragment_size = BP_STREAM_DEFAULT_FRAGMENT_SIZE;
    if (s->config.max_in_flight == 0) s->config.max_in_flight = BP_STREAM_DEFAULT_MAX_IN_FLIGHT;
    if (s->config.buffer_size == 0) s->config.buffer_size = BP_STREAM_DEFAULT_BUFFER_SIZE;
    
    s->send_cap = s->config.buffer_size;
    s->send_buf = bp_alloc(s->send_cap);
    if (!s->send_buf) goto fail;
    
    s->recv_cap = s->config.buffer_size;
    s->recv_buf = bp_alloc(s->recv_cap);
    if (!s->recv_buf) goto fail;
    
    bp_fragment_config_t frag_cfg = {
        .timeout_ms = s->config.timeout_ms,
        .max_entries = BP_FRAGMENT_DEFAULT_MAX_ENTRIES,
        .max_total_bytes = BP_FRAGMENT_DEFAULT_MAX_BYTES
    };
    s->frag_ctx = bp_fragment_ctx_create(&frag_cfg);
    if (!s->frag_ctx) goto fail;
    
    MUTEX_INIT(s->mutex);
    
    return s;

fail:
    bp_fragment_ctx_destroy(s->frag_ctx);
    bp_free(s->local_eid);
    bp_free(s->remote_eid);
    bp_free(s->send_buf);
    bp_free(s->recv_buf);
    bp_free(s);
    return NULL;
}

void bp_stream_destroy(bp_stream_t *stream) {
    if (!stream) return;
    
    MUTEX_LOCK(stream->mutex);
    stream->closed = 1;
    MUTEX_UNLOCK(stream->mutex);
    
    MUTEX_DESTROY(stream->mutex);
    
    bp_fragment_ctx_destroy(stream->frag_ctx);
    bp_free(stream->local_eid);
    bp_free(stream->remote_eid);
    bp_free(stream->send_buf);
    bp_free(stream->recv_buf);
    bp_free(stream);
}

static int send_fragment(bp_stream_t *s, const uint8_t *data, size_t len,
                         uint64_t offset, uint64_t total_len,
                         uint64_t creation_ts, uint64_t creation_seq) {
    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    
    bundle.primary.version = 7;
    bundle.primary.flags = (total_len > len || offset > 0) ? BP_FLAG_FRAGMENT : 0;
    bundle.primary.crc_type = BP_CRC_NONE;
    
    uint8_t scheme;
    uint64_t ssp[2];
    if (bp_eid_parse(s->remote_eid, &scheme, ssp, NULL) == 0) {
        bundle.primary.dest_scheme = scheme;
        bundle.primary.dest_ssp[0] = ssp[0];
        bundle.primary.dest_ssp[1] = ssp[1];
    }
    if (bp_eid_parse(s->local_eid, &scheme, ssp, NULL) == 0) {
        bundle.primary.source_scheme = scheme;
        bundle.primary.source_ssp[0] = ssp[0];
        bundle.primary.source_ssp[1] = ssp[1];
        bundle.primary.report_scheme = scheme;
        bundle.primary.report_ssp[0] = ssp[0];
        bundle.primary.report_ssp[1] = ssp[1];
    }
    
    bundle.primary.creation_ts = creation_ts;
    bundle.primary.creation_seq = creation_seq;
    bundle.primary.lifetime_ms = s->config.timeout_ms;
    bundle.primary.fragment_offset = offset;
    bundle.primary.total_adu_len = total_len;
    
    bundle.payload = (uint8_t *)data;
    bundle.payload_len = len;
    
    size_t buf_size = len + 512;
    uint8_t *encoded = bp_alloc(buf_size);
    if (!encoded) return -1;
    
    int enc_len = bp_bundle_encode(&bundle, encoded, buf_size);
    if (enc_len <= 0) {
        bp_free(encoded);
        return -1;
    }
    
    int rc = bp_send_raw(encoded, (size_t)enc_len);
    
    bp_free(encoded);
    
    if (rc == BP_SUCCESS) {
        s->stats.bytes_sent += len;
        s->stats.fragments_sent++;
    }
    
    return rc;
}

int bp_stream_write(bp_stream_t *stream, const void *data, size_t len) {
    if (!stream || !data || len == 0) return BP_ERROR_INVALID_ARGS;
    
    MUTEX_LOCK(stream->mutex);
    
    if (stream->closed) {
        MUTEX_UNLOCK(stream->mutex);
        return BP_ERROR_INVALID_ARGS;
    }
    
    if (stream->send_len + len > stream->send_cap) {
        size_t new_cap = stream->send_cap * 2;
        while (new_cap < stream->send_len + len) new_cap *= 2;
        
        uint8_t *new_buf = bp_realloc(stream->send_buf, new_cap);
        if (!new_buf) {
            MUTEX_UNLOCK(stream->mutex);
            return BP_ERROR_MEMORY;
        }
        stream->send_buf = new_buf;
        stream->send_cap = new_cap;
    }
    
    memcpy(stream->send_buf + stream->send_len, data, len);
    stream->send_len += len;
    stream->stats.bytes_pending = stream->send_len;
    
    MUTEX_UNLOCK(stream->mutex);
    return BP_SUCCESS;
}

int bp_stream_flush(bp_stream_t *stream) {
    if (!stream) return BP_ERROR_INVALID_ARGS;
    
    MUTEX_LOCK(stream->mutex);
    
    if (stream->closed || stream->send_len == 0) {
        MUTEX_UNLOCK(stream->mutex);
        return BP_SUCCESS;
    }
    
    size_t total_len = stream->send_len;
    size_t offset = 0;
    size_t frag_size = stream->config.fragment_size;
    int rc = BP_SUCCESS;
    
    uint64_t creation_ts = bp_time_now_dtn();
    uint64_t creation_seq = stream->transfer_id++;
    
    while (offset < total_len && !stream->closed) {
        if (stream->closed) {
            rc = BP_ERROR_INVALID_ARGS;
            break;
        }
        
        size_t chunk = (total_len - offset > frag_size) ? frag_size : (total_len - offset);
        
        rc = send_fragment(stream, stream->send_buf + offset, chunk, 
                          offset, total_len, creation_ts, creation_seq);
        if (rc != BP_SUCCESS) break;
        
        offset += chunk;
    }
    
    stream->send_len = 0;
    stream->stats.bytes_pending = 0;
    
    MUTEX_UNLOCK(stream->mutex);
    return rc;
}

int bp_stream_feed(bp_stream_t *stream, const void *bundle_data, size_t bundle_len) {
    if (!stream || !bundle_data || bundle_len == 0) return BP_ERROR_INVALID_ARGS;
    
    bp_bundle_full_t decoded;
    if (bp_bundle_decode(bundle_data, bundle_len, &decoded) != 0) {
        return BP_ERROR_PROTOCOL;
    }
    
    MUTEX_LOCK(stream->mutex);
    
    bp_bundle_full_t complete;
    int rc = bp_fragment_add(stream->frag_ctx, &decoded, &complete);
    
    if (rc == 1) {
        if (stream->recv_len + complete.payload_len > stream->recv_cap) {
            size_t new_cap = stream->recv_cap * 2;
            while (new_cap < stream->recv_len + complete.payload_len) new_cap *= 2;
            
            uint8_t *new_buf = bp_realloc(stream->recv_buf, new_cap);
            if (!new_buf) {
                bp_free(complete.payload);
                bp_bundle_full_free(&decoded);
                MUTEX_UNLOCK(stream->mutex);
                return BP_ERROR_MEMORY;
            }
            stream->recv_buf = new_buf;
            stream->recv_cap = new_cap;
        }
        
        memcpy(stream->recv_buf + stream->recv_len, complete.payload, complete.payload_len);
        stream->recv_len += complete.payload_len;
        stream->stats.bytes_received += complete.payload_len;
        
        bp_free(complete.payload);
        bp_free(complete.primary.dest_uri);
        bp_free(complete.primary.source_uri);
        bp_free(complete.primary.report_uri);
    }
    
    if (rc >= 0) {
        stream->stats.fragments_received++;
    }
    
    bp_bundle_full_free(&decoded);
    
    MUTEX_UNLOCK(stream->mutex);
    return (rc >= 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_stream_read(bp_stream_t *stream, void *buf, size_t len, int timeout_ms) {
    if (!stream || !buf || len == 0) return BP_ERROR_INVALID_ARGS;
    
    uint64_t start = (uint64_t)time(NULL) * 1000;
    uint64_t deadline = (timeout_ms >= 0) ? start + (uint64_t)timeout_ms : UINT64_MAX;
    
    while (1) {
        MUTEX_LOCK(stream->mutex);
        
        if (stream->closed) {
            MUTEX_UNLOCK(stream->mutex);
            return BP_ERROR_INVALID_ARGS;
        }
        
        size_t available = stream->recv_len - stream->recv_pos;
        if (available >= len) {
            memcpy(buf, stream->recv_buf + stream->recv_pos, len);
            stream->recv_pos += len;
            
            if (stream->recv_pos == stream->recv_len) {
                stream->recv_pos = 0;
                stream->recv_len = 0;
            }
            
            MUTEX_UNLOCK(stream->mutex);
            return (int)len;
        }
        
        MUTEX_UNLOCK(stream->mutex);
        
        uint64_t now = (uint64_t)time(NULL) * 1000;
        if (now >= deadline) {
            return BP_ERROR_TIMEOUT;
        }
        
        SLEEP_MS(10);
    }
}

int bp_stream_read_available(bp_stream_t *stream, void *buf, size_t max_len) {
    if (!stream || !buf || max_len == 0) return 0;
    
    MUTEX_LOCK(stream->mutex);
    
    size_t available = stream->recv_len - stream->recv_pos;
    if (available == 0) {
        MUTEX_UNLOCK(stream->mutex);
        return 0;
    }
    
    size_t to_read = (available < max_len) ? available : max_len;
    memcpy(buf, stream->recv_buf + stream->recv_pos, to_read);
    stream->recv_pos += to_read;
    
    if (stream->recv_pos == stream->recv_len) {
        stream->recv_pos = 0;
        stream->recv_len = 0;
    }
    
    MUTEX_UNLOCK(stream->mutex);
    return (int)to_read;
}

int bp_stream_get_stats(bp_stream_t *stream, bp_stream_stats_t *stats) {
    if (!stream || !stats) return BP_ERROR_INVALID_ARGS;
    
    MUTEX_LOCK(stream->mutex);
    *stats = stream->stats;
    stats->in_flight = stream->in_flight;
    stats->bytes_pending = stream->send_len;
    MUTEX_UNLOCK(stream->mutex);
    
    return BP_SUCCESS;
}

int bp_stream_is_complete(bp_stream_t *stream) {
    if (!stream) return 0;
    
    MUTEX_LOCK(stream->mutex);
    int has_data = (stream->recv_len > stream->recv_pos);
    int no_pending = (bp_fragment_pending_count(stream->frag_ctx) == 0);
    MUTEX_UNLOCK(stream->mutex);
    
    /* Returns true only when data is available AND no fragments pending.
     * Note: Returns false after all data has been read, even if transfer completed.
     * Use bp_stream_read_available() to drain buffer, then check no_pending. */
    return has_data && no_pending;
}

int bp_stream_send_file(bp_stream_t *stream, const char *filepath) {
    if (!stream || !filepath) return BP_ERROR_INVALID_ARGS;
    
    FILE *f = fopen(filepath, "rb");
    if (!f) return BP_ERROR_NOT_FOUND;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0) {
        fclose(f);
        return BP_ERROR_INVALID_ARGS;
    }
    
    uint8_t *buf = bp_alloc((size_t)size);
    if (!buf) {
        fclose(f);
        return BP_ERROR_MEMORY;
    }
    
    size_t read = fread(buf, 1, (size_t)size, f);
    fclose(f);
    
    if (read != (size_t)size) {
        bp_free(buf);
        return BP_ERROR_PROTOCOL;
    }
    
    int rc = bp_stream_write(stream, buf, (size_t)size);
    bp_free(buf);
    
    if (rc != BP_SUCCESS) return rc;
    
    return bp_stream_flush(stream);
}

int bp_stream_recv_file(bp_stream_t *stream, const char *filepath, 
                         size_t expected_size, int timeout_ms) {
    if (!stream || !filepath || expected_size == 0) return BP_ERROR_INVALID_ARGS;
    
    uint8_t *buf = bp_alloc(expected_size);
    if (!buf) return BP_ERROR_MEMORY;
    
    size_t received = 0;
    uint64_t start = (uint64_t)time(NULL) * 1000;
    uint64_t deadline = (timeout_ms >= 0) ? start + (uint64_t)timeout_ms : UINT64_MAX;
    
    while (received < expected_size) {
        int n = bp_stream_read_available(stream, buf + received, expected_size - received);
        if (n > 0) {
            received += (size_t)n;
        }
        
        if (received < expected_size) {
            uint64_t now = (uint64_t)time(NULL) * 1000;
            if (now >= deadline) {
                bp_free(buf);
                return BP_ERROR_TIMEOUT;
            }
            SLEEP_MS(10);
        }
    }
    
    FILE *f = fopen(filepath, "wb");
    if (!f) {
        bp_free(buf);
        return BP_ERROR_STORAGE;
    }
    
    size_t written = fwrite(buf, 1, expected_size, f);
    fclose(f);
    bp_free(buf);
    
    return (written == expected_size) ? BP_SUCCESS : BP_ERROR_STORAGE;
}

