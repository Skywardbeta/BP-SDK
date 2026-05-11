/*
 * bp_sdk.h - BP-SDK core API.
 *
 * Bundle-level send/receive surface and the types shared with backends.
 * Higher-level features live in their own headers:
 *   - bp_session.h        BPSec sessions (declarative security policy)
 *   - bp_key_provider.h   Pluggable key sources
 *   - bp_crypto_backend.h Pluggable HMAC / AES-GCM providers
 *   - bp_bundle.h         BPv7 wire structures
 *   - bp_storage.h        In-memory bundle store
 *   - bp_admin.h          RFC 9171 §6 administrative records
 */
#ifndef BP_SDK_H
#define BP_SDK_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BP_SUCCESS               = 0,
    BP_ERROR_INVALID_ARGS    = -1,
    BP_ERROR_NOT_INITIALIZED = -2,
    BP_ERROR_MEMORY          = -3,
    BP_ERROR_TIMEOUT         = -4,
    BP_ERROR_NOT_FOUND       = -5,
    BP_ERROR_DUPLICATE       = -6,
    BP_ERROR_PROTOCOL        = -7,
    BP_ERROR_ROUTING         = -8,
    BP_ERROR_STORAGE         = -9,
    BP_ERROR_SECURITY        = -10
} bp_result_t;

typedef enum {
    BP_PRIORITY_BULK      = 0,
    BP_PRIORITY_STANDARD  = 1,
    BP_PRIORITY_EXPEDITED = 2
} bp_priority_t;

typedef enum {
    BP_CUSTODY_NONE     = 0,
    BP_CUSTODY_OPTIONAL = 1,
    BP_CUSTODY_REQUIRED = 2
} bp_custody_t;

typedef struct {
    uint64_t msec;
    uint32_t count;
} bp_timestamp_t;

typedef struct {
    char           *eid;
    bp_timestamp_t  creation_time;
    uint32_t        fragment_offset;
    uint32_t        ttl;
    bp_priority_t   priority;
    bp_custody_t    custody;
    uint8_t         status_reports;
    void           *payload;
    size_t          payload_len;
    char           *source_eid;
    char           *dest_eid;
    char           *report_to_eid;
} bp_bundle_t;

typedef struct {
    char *endpoint_id;
    void *context;
    int (*receive_callback)(bp_bundle_t *bundle, void *context);
    int (*status_callback)(const char *bundle_id, int status, void *context);
} bp_endpoint_t;

int bp_init(const char *node_id, const char *config_file);
int bp_shutdown(void);
int bp_is_initialized(void);

int bp_endpoint_create(const char *endpoint_id, bp_endpoint_t **endpoint);
int bp_endpoint_destroy(bp_endpoint_t *endpoint);
int bp_endpoint_register(bp_endpoint_t *endpoint);
int bp_endpoint_unregister(bp_endpoint_t *endpoint);

int bp_send(const char *source_eid, const char *dest_eid,
            const void *payload, size_t payload_len,
            bp_priority_t priority, bp_custody_t custody,
            uint32_t ttl, const char *report_to_eid);

int bp_send_raw(const void *wire_bundle, size_t wire_len);

int bp_receive(bp_endpoint_t *endpoint, bp_bundle_t **bundle, int timeout_ms);

int bp_recv_raw(const char *local_eid, uint8_t **out_wire,
                size_t *out_len, int timeout_ms);

int bp_bundle_free(bp_bundle_t *bundle);

const char *bp_strerror(bp_result_t result);

#ifdef __cplusplus
}
#endif

#endif
