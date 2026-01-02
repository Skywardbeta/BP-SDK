#include "bp_sdk.h"
#include "bp_backend.h"
#include "bp_utils.h"
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
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

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
    return &g_posix_backend;
}

int bp_init(const char *node_id, const char *config_file) {
    if (!node_id) return BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_init_mutex);
    if (g_ctx.initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return BP_SUCCESS;
    }

    if (pthread_mutex_init(&g_ctx.mutex, NULL) != 0) {
        pthread_mutex_unlock(&g_init_mutex);
        return BP_ERROR_MEMORY;
    }

    g_ctx.node_id = bp_strdup(node_id);
    if (!g_ctx.node_id) {
        pthread_mutex_destroy(&g_ctx.mutex);
        pthread_mutex_unlock(&g_init_mutex);
        return BP_ERROR_MEMORY;
    }

    g_ctx.backend = select_backend(config_file);

    if (g_ctx.backend && g_ctx.backend->init) {
        int rc = g_ctx.backend->init(config_file);
        if (rc != BP_SUCCESS) {
            bp_free(g_ctx.node_id);
            g_ctx.node_id = NULL;
            pthread_mutex_destroy(&g_ctx.mutex);
            pthread_mutex_unlock(&g_init_mutex);
            return rc;
        }
    }

    g_ctx.initialized = 1;
    pthread_mutex_unlock(&g_init_mutex);
    return BP_SUCCESS;
}

int bp_shutdown(void) {
    pthread_mutex_lock(&g_init_mutex);
    if (!g_ctx.initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return BP_ERROR_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&g_ctx.mutex);
    if (g_ctx.backend && g_ctx.backend->shutdown)
        g_ctx.backend->shutdown();

    bp_free(g_ctx.node_id);
    g_ctx.node_id = NULL;
    g_ctx.backend = NULL;
    g_ctx.initialized = 0;
    pthread_mutex_unlock(&g_ctx.mutex);
    pthread_mutex_destroy(&g_ctx.mutex);
    pthread_mutex_unlock(&g_init_mutex);
    return BP_SUCCESS;
}

int bp_is_initialized(void) {
    pthread_mutex_lock(&g_init_mutex);
    int result = g_ctx.initialized;
    pthread_mutex_unlock(&g_init_mutex);
    return result;
}

static int check_initialized(void) {
    pthread_mutex_lock(&g_init_mutex);
    int result = g_ctx.initialized;
    pthread_mutex_unlock(&g_init_mutex);
    return result;
}

#define DELEGATE(fn, ...) \
    do { \
        if (!check_initialized()) return BP_ERROR_NOT_INITIALIZED; \
        pthread_mutex_lock(&g_ctx.mutex); \
        int _rc = BP_ERROR_PROTOCOL; \
        if (g_ctx.backend && g_ctx.backend->fn) \
            _rc = g_ctx.backend->fn(__VA_ARGS__); \
        pthread_mutex_unlock(&g_ctx.mutex); \
        return _rc; \
    } while (0)

#define DELEGATE_NOLOCK(fn, ...) \
    do { \
        if (!check_initialized()) return BP_ERROR_NOT_INITIALIZED; \
        if (g_ctx.backend && g_ctx.backend->fn) \
            return g_ctx.backend->fn(__VA_ARGS__); \
        return BP_ERROR_PROTOCOL; \
    } while (0)

int bp_send(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len,
            bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid) {
    if (!source_eid || !dest_eid) return BP_ERROR_INVALID_ARGS;
    if (payload_len > 0 && !payload) return BP_ERROR_INVALID_ARGS;
    DELEGATE(send, source_eid, dest_eid, payload, payload_len, priority, custody, ttl, report_to_eid);
}

int bp_receive(bp_endpoint_t *endpoint, bp_bundle_t **bundle, int timeout_ms) {
    if (!endpoint || !bundle) return BP_ERROR_INVALID_ARGS;
    if (!endpoint->endpoint_id) return BP_ERROR_INVALID_ARGS;
    DELEGATE_NOLOCK(receive, endpoint->endpoint_id, bundle, timeout_ms);
}

int bp_bundle_free(bp_bundle_t *bundle) {
    if (!bundle) return BP_ERROR_INVALID_ARGS;
    
    pthread_mutex_lock(&g_init_mutex);
    int initialized = g_ctx.initialized;
    bp_backend_t *backend = initialized ? g_ctx.backend : NULL;
    pthread_mutex_unlock(&g_init_mutex);
    
    if (backend && backend->bundle_free)
        return backend->bundle_free(bundle);
    
    bp_free(bundle->eid);
    bp_free(bundle->source_eid);
    bp_free(bundle->dest_eid);
    bp_free(bundle->report_to_eid);
    bp_free(bundle->payload);
    bp_free(bundle);
    return BP_SUCCESS;
}

int bp_endpoint_create(const char *endpoint_id, bp_endpoint_t **endpoint) {
    if (!endpoint_id || !endpoint) return BP_ERROR_INVALID_ARGS;
    if (!check_initialized()) return BP_ERROR_NOT_INITIALIZED;

    bp_endpoint_t *ep = bp_alloc(sizeof(bp_endpoint_t));
    if (!ep) return BP_ERROR_MEMORY;
    memset(ep, 0, sizeof(*ep));
    ep->endpoint_id = bp_strdup(endpoint_id);
    if (!ep->endpoint_id) { 
        bp_free(ep); 
        return BP_ERROR_MEMORY; 
    }
    *endpoint = ep;
    return BP_SUCCESS;
}

int bp_endpoint_destroy(bp_endpoint_t *endpoint) {
    if (!endpoint) return BP_ERROR_INVALID_ARGS;
    bp_free(endpoint->endpoint_id);
    bp_free(endpoint);
    return BP_SUCCESS;
}

int bp_endpoint_register(bp_endpoint_t *endpoint) {
    if (!endpoint) return BP_ERROR_INVALID_ARGS;
    return check_initialized() ? BP_SUCCESS : BP_ERROR_NOT_INITIALIZED;
}

int bp_endpoint_unregister(bp_endpoint_t *endpoint) {
    if (!endpoint) return BP_ERROR_INVALID_ARGS;
    return check_initialized() ? BP_SUCCESS : BP_ERROR_NOT_INITIALIZED;
}

int bp_cla_register(bp_cla_t *cla) { 
    if (!cla) return BP_ERROR_INVALID_ARGS;
    DELEGATE(cla_register, cla); 
}

int bp_cla_unregister(const char *protocol_name) { 
    if (!protocol_name) return BP_ERROR_INVALID_ARGS;
    DELEGATE(cla_unregister, protocol_name); 
}

int bp_cla_send(const char *protocol_name, const char *dest_addr, const void *data, size_t len) {
    if (!protocol_name || !dest_addr) return BP_ERROR_INVALID_ARGS;
    if (len > 0 && !data) return BP_ERROR_INVALID_ARGS;
    DELEGATE(cla_send, protocol_name, dest_addr, data, len);
}

int bp_cla_list(char ***protocol_names, int *count) { 
    if (!protocol_names || !count) return BP_ERROR_INVALID_ARGS;
    DELEGATE(cla_list, protocol_names, count); 
}

int bp_routing_register(bp_routing_t *routing) { 
    if (!routing) return BP_ERROR_INVALID_ARGS;
    DELEGATE(routing_register, routing); 
}

int bp_routing_unregister(const char *algorithm_name) { 
    if (!algorithm_name) return BP_ERROR_INVALID_ARGS;
    DELEGATE(routing_unregister, algorithm_name); 
}

int bp_routing_compute(const char *dest_eid, bp_route_t **routes, int *route_count) {
    if (!dest_eid || !routes || !route_count) return BP_ERROR_INVALID_ARGS;
    DELEGATE(routing_compute, dest_eid, routes, route_count);
}

int bp_routing_update_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate) {
    if (!neighbor_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(routing_update_contact, neighbor_eid, start, end, rate);
}

int bp_routing_update_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt) {
    if (!neighbor_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(routing_update_range, neighbor_eid, start, end, owlt);
}

int bp_storage_register(bp_storage_t *storage) { 
    if (!storage) return BP_ERROR_INVALID_ARGS;
    DELEGATE(storage_register, storage); 
}

int bp_storage_unregister(const char *storage_name) { 
    if (!storage_name) return BP_ERROR_INVALID_ARGS;
    DELEGATE(storage_unregister, storage_name); 
}

int bp_storage_store(const char *bundle_id, const void *data, size_t len) {
    if (!bundle_id) return BP_ERROR_INVALID_ARGS;
    if (len > 0 && !data) return BP_ERROR_INVALID_ARGS;
    DELEGATE(storage_store, bundle_id, data, len);
}

int bp_storage_retrieve(const char *bundle_id, void **data, size_t *len) {
    if (!bundle_id || !data || !len) return BP_ERROR_INVALID_ARGS;
    DELEGATE(storage_retrieve, bundle_id, data, len);
}

int bp_storage_delete(const char *bundle_id) { 
    if (!bundle_id) return BP_ERROR_INVALID_ARGS;
    DELEGATE(storage_delete, bundle_id); 
}

int bp_storage_list(char ***bundle_ids, int *count) { 
    if (!bundle_ids || !count) return BP_ERROR_INVALID_ARGS;
    DELEGATE(storage_list, bundle_ids, count); 
}

int bp_security_register(bp_security_t *security) { 
    if (!security) return BP_ERROR_INVALID_ARGS;
    DELEGATE(security_register, security); 
}

int bp_security_unregister(const char *security_name) { 
    if (!security_name) return BP_ERROR_INVALID_ARGS;
    DELEGATE(security_unregister, security_name); 
}

int bp_security_encrypt(const void *plain, size_t plain_len, void **cipher, size_t *cipher_len) {
    if (!cipher || !cipher_len) return BP_ERROR_INVALID_ARGS;
    if (plain_len > 0 && !plain) return BP_ERROR_INVALID_ARGS;
    DELEGATE(security_encrypt, plain, plain_len, cipher, cipher_len);
}

int bp_security_decrypt(const void *cipher, size_t cipher_len, void **plain, size_t *plain_len) {
    if (!plain || !plain_len) return BP_ERROR_INVALID_ARGS;
    if (cipher_len > 0 && !cipher) return BP_ERROR_INVALID_ARGS;
    DELEGATE(security_decrypt, cipher, cipher_len, plain, plain_len);
}

int bp_security_sign(const void *data, size_t data_len, void **signature, size_t *sig_len) {
    if (!signature || !sig_len) return BP_ERROR_INVALID_ARGS;
    if (data_len > 0 && !data) return BP_ERROR_INVALID_ARGS;
    DELEGATE(security_sign, data, data_len, signature, sig_len);
}

int bp_security_verify(const void *data, size_t data_len, const void *signature, size_t sig_len) {
    if (data_len > 0 && !data) return BP_ERROR_INVALID_ARGS;
    if (sig_len > 0 && !signature) return BP_ERROR_INVALID_ARGS;
    DELEGATE(security_verify, data, data_len, signature, sig_len);
}

int bp_admin_add_plan(const char *dest_eid, uint32_t nominal_rate) {
    if (!dest_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(admin_add_plan, dest_eid, nominal_rate);
}

int bp_admin_remove_plan(const char *dest_eid) { 
    if (!dest_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(admin_remove_plan, dest_eid); 
}

int bp_admin_add_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate) {
    if (!neighbor_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(admin_add_contact, neighbor_eid, start, end, rate);
}

int bp_admin_remove_contact(const char *neighbor_eid, time_t start, time_t end) {
    if (!neighbor_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(admin_remove_contact, neighbor_eid, start, end);
}

int bp_admin_add_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt) {
    if (!neighbor_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(admin_add_range, neighbor_eid, start, end, owlt);
}

int bp_admin_remove_range(const char *neighbor_eid, time_t start, time_t end) {
    if (!neighbor_eid) return BP_ERROR_INVALID_ARGS;
    DELEGATE(admin_remove_range, neighbor_eid, start, end);
}

int bp_stats_get_bundles_sent(uint64_t *count) { 
    if (!count) return BP_ERROR_INVALID_ARGS;
    *count = 0; 
    return BP_SUCCESS; 
}

int bp_stats_get_bundles_received(uint64_t *count) { 
    if (!count) return BP_ERROR_INVALID_ARGS;
    *count = 0; 
    return BP_SUCCESS; 
}

int bp_stats_get_bundles_forwarded(uint64_t *count) { 
    if (!count) return BP_ERROR_INVALID_ARGS;
    *count = 0; 
    return BP_SUCCESS; 
}

int bp_stats_get_bundles_delivered(uint64_t *count) { 
    if (!count) return BP_ERROR_INVALID_ARGS;
    *count = 0; 
    return BP_SUCCESS; 
}

int bp_stats_get_bundles_deleted(uint64_t *count) { 
    if (!count) return BP_ERROR_INVALID_ARGS;
    *count = 0; 
    return BP_SUCCESS; 
}

int bp_stats_reset(void) { return BP_SUCCESS; }

const char *bp_strerror(bp_result_t result) {
    int idx = -result;
    if (idx >= 0 && idx < (int)(sizeof(g_error_messages) / sizeof(g_error_messages[0])))
        return g_error_messages[idx];
    return "Unknown error";
}
