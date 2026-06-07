/*
 * bp_sdk.c - BP-SDK facade.
 *
 * Thin dispatch over the active bp_backend_t. Higher-level functionality
 * (BPSec sessions, fragmentation, storage) lives in its own translation
 * units; this file only wires the bundle-level send/receive surface and
 * the SDK lifecycle.
 */
#include "bp_sdk.h"
#include "bp_backend.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define MUTEX_T          CRITICAL_SECTION
#define MUTEX_INIT(m)    InitializeCriticalSection(&(m))
#define MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define MUTEX_LOCK(m)    EnterCriticalSection(&(m))
#define MUTEX_UNLOCK(m)  LeaveCriticalSection(&(m))
#else
#include <pthread.h>
#define MUTEX_T          pthread_mutex_t
#define MUTEX_INIT(m)    pthread_mutex_init(&(m), NULL)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define MUTEX_LOCK(m)    pthread_mutex_lock(&(m))
#define MUTEX_UNLOCK(m)  pthread_mutex_unlock(&(m))
#endif

typedef struct {
    char         *node_id;
    int           initialized;
    MUTEX_T       mutex;
    bp_backend_t *backend;
} bp_context_t;

static bp_context_t g_ctx = {0};

static const char *g_error_messages[] = {
    "Success",
    "Invalid arguments",
    "Not initialized",
    "Memory allocation failed",
    "Operation timed out",
    "Not found",
    "Duplicate entry",
    "Protocol error",
    "Routing error",
    "Storage error",
    "Security error"
};

extern bp_backend_t g_posix_backend;
extern bp_backend_t g_bpsocket_backend;

static bp_backend_t *select_backend(const char *config) {
    if (config) {
        if (strstr(config, "bpsocket")) return &g_bpsocket_backend;
        if (strstr(config, "posix"))    return &g_posix_backend;
    }
    return &g_posix_backend;
}

int bp_init(const char *node_id, const char *config_file) {
    if (!node_id) return BP_ERROR_INVALID_ARGS;
    if (g_ctx.initialized) return BP_SUCCESS;

    MUTEX_INIT(g_ctx.mutex);

    g_ctx.node_id = strdup(node_id);
    if (!g_ctx.node_id) {
        MUTEX_DESTROY(g_ctx.mutex);
        return BP_ERROR_MEMORY;
    }

    g_ctx.backend = select_backend(config_file);

    if (g_ctx.backend && g_ctx.backend->init) {
        int rc = g_ctx.backend->init(config_file);
        if (rc != BP_SUCCESS) {
            free(g_ctx.node_id);
            g_ctx.node_id = NULL;
            MUTEX_DESTROY(g_ctx.mutex);
            return rc;
        }
    }

    g_ctx.initialized = 1;
    return BP_SUCCESS;
}

int bp_shutdown(void) {
    if (!g_ctx.initialized) return BP_ERROR_NOT_INITIALIZED;

    MUTEX_LOCK(g_ctx.mutex);
    if (g_ctx.backend && g_ctx.backend->shutdown)
        g_ctx.backend->shutdown();

    free(g_ctx.node_id);
    g_ctx.node_id     = NULL;
    g_ctx.initialized = 0;
    MUTEX_UNLOCK(g_ctx.mutex);
    MUTEX_DESTROY(g_ctx.mutex);
    return BP_SUCCESS;
}

int bp_is_initialized(void) {
    return g_ctx.initialized;
}

#define DELEGATE(fn, ...)                                              \
    do {                                                               \
        if (!g_ctx.initialized) return BP_ERROR_NOT_INITIALIZED;       \
        if (g_ctx.backend && g_ctx.backend->fn)                        \
            return g_ctx.backend->fn(__VA_ARGS__);                     \
        return BP_ERROR_PROTOCOL;                                      \
    } while (0)

int bp_send(const char *source_eid, const char *dest_eid,
            const void *payload, size_t payload_len,
            bp_priority_t priority, bp_custody_t custody,
            uint32_t ttl, const char *report_to_eid) {
    if (!source_eid || !dest_eid || !payload || payload_len == 0)
        return BP_ERROR_INVALID_ARGS;
    DELEGATE(send, source_eid, dest_eid, payload, payload_len,
             priority, custody, ttl, report_to_eid);
}

int bp_send_raw(const void *wire_bundle, size_t wire_len) {
    if (!wire_bundle || wire_len == 0) return BP_ERROR_INVALID_ARGS;
    DELEGATE(send_raw, wire_bundle, wire_len);
}

int bp_receive(bp_endpoint_t *endpoint, bp_bundle_t **bundle, int timeout_ms) {
    if (!endpoint || !bundle) return BP_ERROR_INVALID_ARGS;
    DELEGATE(receive, endpoint->endpoint_id, bundle, timeout_ms);
}

int bp_recv_raw(const char *local_eid, uint8_t **out_wire,
                size_t *out_len, int timeout_ms) {
    if (!local_eid || !out_wire || !out_len) return BP_ERROR_INVALID_ARGS;
    DELEGATE(receive_raw, local_eid, out_wire, out_len, timeout_ms);
}

int bp_bundle_free(bp_bundle_t *bundle) {
    if (!bundle) return BP_ERROR_INVALID_ARGS;
    if (g_ctx.backend && g_ctx.backend->bundle_free)
        return g_ctx.backend->bundle_free(bundle);
    free(bundle->eid);
    free(bundle->source_eid);
    free(bundle->dest_eid);
    free(bundle->report_to_eid);
    free(bundle->payload);
    free(bundle);
    return BP_SUCCESS;
}

int bp_endpoint_create(const char *endpoint_id, bp_endpoint_t **endpoint) {
    if (!endpoint_id || !endpoint) return BP_ERROR_INVALID_ARGS;
    if (!g_ctx.initialized)        return BP_ERROR_NOT_INITIALIZED;

    bp_endpoint_t *ep = calloc(1, sizeof(bp_endpoint_t));
    if (!ep) return BP_ERROR_MEMORY;
    ep->endpoint_id = strdup(endpoint_id);
    if (!ep->endpoint_id) { free(ep); return BP_ERROR_MEMORY; }
    *endpoint = ep;
    return BP_SUCCESS;
}

int bp_endpoint_destroy(bp_endpoint_t *endpoint) {
    if (!endpoint) return BP_ERROR_INVALID_ARGS;
    free(endpoint->endpoint_id);
    free(endpoint);
    return BP_SUCCESS;
}

int bp_endpoint_register(bp_endpoint_t *endpoint) {
    (void)endpoint;
    return g_ctx.initialized ? BP_SUCCESS : BP_ERROR_NOT_INITIALIZED;
}

int bp_endpoint_unregister(bp_endpoint_t *endpoint) {
    (void)endpoint;
    return g_ctx.initialized ? BP_SUCCESS : BP_ERROR_NOT_INITIALIZED;
}

const char *bp_strerror(bp_result_t result) {
    int idx = -((int)result);
    if (idx >= 0 &&
        idx < (int)(sizeof(g_error_messages) / sizeof(g_error_messages[0])))
        return g_error_messages[idx];
    return "Unknown error";
}
