/*
 * BP-SDK: Bundle Protocol SDK
 * Unified facade delegating to a pluggable backend (POSIX, ION, uD3TN, etc.)
 */
#include "bp_sdk.h"
#include "bp_backend.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct {
    char *node_id;
    int initialized;
    pthread_mutex_t mutex;
    bp_backend_t *backend;
} bp_context_t;

static bp_context_t g_ctx = {0};

static const char *g_error_messages[] = {
    "Success", "Invalid arguments", "Not initialized", "Memory allocation failed",
    "Operation timed out", "Not found", "Duplicate entry", "Protocol error",
    "Routing error", "Storage error", "Security error"
};

extern bp_backend_t g_posix_backend;
extern bp_backend_t g_bpsocket_backend;

static bp_backend_t *select_backend(const char *config) {
    if (config) {
        if (strstr(config, "bpsocket")) return &g_bpsocket_backend;
        if (strstr(config, "posix")) return &g_posix_backend;
    }
    return &g_posix_backend; // default
}

int bp_init(const char *node_id, const char *config_file) {
    if (!node_id) return BP_ERROR_INVALID_ARGS;
    if (g_ctx.initialized) return BP_SUCCESS;

    if (pthread_mutex_init(&g_ctx.mutex, NULL) != 0)
        return BP_ERROR_MEMORY;

    g_ctx.node_id = strdup(node_id);
    if (!g_ctx.node_id) {
        pthread_mutex_destroy(&g_ctx.mutex);
        return BP_ERROR_MEMORY;
    }

    g_ctx.backend = select_backend(config_file);

    if (g_ctx.backend && g_ctx.backend->init) {
        int rc = g_ctx.backend->init(config_file);
        if (rc != BP_SUCCESS) {
            free(g_ctx.node_id);
            pthread_mutex_destroy(&g_ctx.mutex);
            return rc;
        }
    }

    g_ctx.initialized = 1;
    return BP_SUCCESS;
}

int bp_shutdown(void) {
    if (!g_ctx.initialized) return BP_ERROR_NOT_INITIALIZED;

    pthread_mutex_lock(&g_ctx.mutex);
    if (g_ctx.backend && g_ctx.backend->shutdown)
        g_ctx.backend->shutdown();

    free(g_ctx.node_id);
    g_ctx.node_id = NULL;
    g_ctx.initialized = 0;
    pthread_mutex_unlock(&g_ctx.mutex);
    pthread_mutex_destroy(&g_ctx.mutex);
    return BP_SUCCESS;
}

int bp_is_initialized(void) {
    return g_ctx.initialized;
}

#define DELEGATE(fn, ...) \
    do { \
        if (!g_ctx.initialized) return BP_ERROR_NOT_INITIALIZED; \
        if (g_ctx.backend && g_ctx.backend->fn) \
            return g_ctx.backend->fn(__VA_ARGS__); \
        return BP_ERROR_PROTOCOL; \
    } while (0)

int bp_send(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len,
            bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid) {
    if (!source_eid || !dest_eid || !payload || payload_len == 0)
        return BP_ERROR_INVALID_ARGS;
    DELEGATE(send, source_eid, dest_eid, payload, payload_len, priority, custody, ttl, report_to_eid);
}

int bp_receive(bp_endpoint_t *endpoint, bp_bundle_t **bundle, int timeout_ms) {
    if (!endpoint || !bundle) return BP_ERROR_INVALID_ARGS;
    DELEGATE(receive, endpoint->endpoint_id, bundle, timeout_ms);
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
    if (!g_ctx.initialized) return BP_ERROR_NOT_INITIALIZED;

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

int bp_cla_register(bp_cla_t *cla) { DELEGATE(cla_register, cla); }
int bp_cla_unregister(const char *protocol_name) { DELEGATE(cla_unregister, protocol_name); }
int bp_cla_send(const char *protocol_name, const char *dest_addr, const void *data, size_t len) {
    DELEGATE(cla_send, protocol_name, dest_addr, data, len);
}
int bp_cla_list(char ***protocol_names, int *count) { DELEGATE(cla_list, protocol_names, count); }

int bp_routing_register(bp_routing_t *routing) { DELEGATE(routing_register, routing); }
int bp_routing_unregister(const char *algorithm_name) { DELEGATE(routing_unregister, algorithm_name); }
int bp_routing_compute(const char *dest_eid, bp_route_t **routes, int *route_count) {
    DELEGATE(routing_compute, dest_eid, routes, route_count);
}
int bp_routing_update_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate) {
    DELEGATE(routing_update_contact, neighbor_eid, start, end, rate);
}
int bp_routing_update_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt) {
    DELEGATE(routing_update_range, neighbor_eid, start, end, owlt);
}

int bp_storage_register(bp_storage_t *storage) { DELEGATE(storage_register, storage); }
int bp_storage_unregister(const char *storage_name) { DELEGATE(storage_unregister, storage_name); }
int bp_storage_store(const char *bundle_id, const void *data, size_t len) {
    DELEGATE(storage_store, bundle_id, data, len);
}
int bp_storage_retrieve(const char *bundle_id, void **data, size_t *len) {
    DELEGATE(storage_retrieve, bundle_id, data, len);
}
int bp_storage_delete(const char *bundle_id) { DELEGATE(storage_delete, bundle_id); }
int bp_storage_list(char ***bundle_ids, int *count) { DELEGATE(storage_list, bundle_ids, count); }

int bp_security_register(bp_security_t *security) { DELEGATE(security_register, security); }
int bp_security_unregister(const char *security_name) { DELEGATE(security_unregister, security_name); }
int bp_security_encrypt(const void *plain, size_t plain_len, void **cipher, size_t *cipher_len) {
    DELEGATE(security_encrypt, plain, plain_len, cipher, cipher_len);
}
int bp_security_decrypt(const void *cipher, size_t cipher_len, void **plain, size_t *plain_len) {
    DELEGATE(security_decrypt, cipher, cipher_len, plain, plain_len);
}
int bp_security_sign(const void *data, size_t data_len, void **signature, size_t *sig_len) {
    DELEGATE(security_sign, data, data_len, signature, sig_len);
}
int bp_security_verify(const void *data, size_t data_len, const void *signature, size_t sig_len) {
    DELEGATE(security_verify, data, data_len, signature, sig_len);
}

int bp_admin_add_plan(const char *dest_eid, uint32_t nominal_rate) {
    DELEGATE(admin_add_plan, dest_eid, nominal_rate);
}
int bp_admin_remove_plan(const char *dest_eid) { DELEGATE(admin_remove_plan, dest_eid); }
int bp_admin_add_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate) {
    DELEGATE(admin_add_contact, neighbor_eid, start, end, rate);
}
int bp_admin_remove_contact(const char *neighbor_eid, time_t start, time_t end) {
    DELEGATE(admin_remove_contact, neighbor_eid, start, end);
}
int bp_admin_add_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt) {
    DELEGATE(admin_add_range, neighbor_eid, start, end, owlt);
}
int bp_admin_remove_range(const char *neighbor_eid, time_t start, time_t end) {
    DELEGATE(admin_remove_range, neighbor_eid, start, end);
}

int bp_stats_get_bundles_sent(uint64_t *count) { if (count) *count = 0; return BP_SUCCESS; }
int bp_stats_get_bundles_received(uint64_t *count) { if (count) *count = 0; return BP_SUCCESS; }
int bp_stats_get_bundles_forwarded(uint64_t *count) { if (count) *count = 0; return BP_SUCCESS; }
int bp_stats_get_bundles_delivered(uint64_t *count) { if (count) *count = 0; return BP_SUCCESS; }
int bp_stats_get_bundles_deleted(uint64_t *count) { if (count) *count = 0; return BP_SUCCESS; }
int bp_stats_reset(void) { return BP_SUCCESS; }

const char *bp_strerror(bp_result_t result) {
    int idx = -result;
    if (idx >= 0 && idx < (int)(sizeof(g_error_messages) / sizeof(g_error_messages[0])))
        return g_error_messages[idx];
    return "Unknown error";
}
