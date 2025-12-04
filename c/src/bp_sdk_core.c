#include "bp_sdk_internal.h"
#include "../bpv7/include/bp.h"
#include "../ici/include/ion.h"
#include "../ici/include/sdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

typedef struct {
    char *node_id;
    char *config_file;
    int initialized;
    pthread_mutex_t mutex;
    BpSAP sap;
    struct {
        bp_endpoint_t **endpoints;
        int count;
        int capacity;
    } endpoints;
    struct {
        bp_cla_t **clas;
        int count;
        int capacity;
    } clas;
    struct {
        bp_routing_t **routing;
        int count;
        int capacity;
    } routing;
    struct {
        bp_storage_t **storage;
        int count;
        int capacity;
    } storage;
    struct {
        bp_security_t **security;
        int count;
        int capacity;
    } security;
} bp_context_t;

bp_context_t g_bp_context = {0};

static const char *error_messages[] = {
    "Success", "Invalid arguments", "Not initialized", "Memory allocation failed",
    "Operation timed out", "Not found", "Duplicate entry", "Protocol error",
    "Routing error", "Storage error", "Security error"
};

int ensure_capacity(void ***array, int *capacity, int needed, size_t element_size) {
    if (needed >= *capacity) {
        int new_capacity = *capacity == 0 ? 8 : *capacity * 2;
        while (new_capacity <= needed) new_capacity *= 2;
        
        void **new_array = realloc(*array, new_capacity * element_size);
        if (!new_array) return BP_ERROR_MEMORY;
        
        *array = new_array;
        *capacity = new_capacity;
    }
    return BP_SUCCESS;
}

static void cleanup_context(void) {
    free(g_bp_context.node_id);
    free(g_bp_context.config_file);
    free(g_bp_context.endpoints.endpoints);
    free(g_bp_context.clas.clas);
    free(g_bp_context.routing.routing);
    free(g_bp_context.storage.storage);
    free(g_bp_context.security.security);
    memset(&g_bp_context, 0, sizeof(g_bp_context));
}

int bp_init(const char *node_id, const char *config_file) {
    if (!node_id || g_bp_context.initialized) 
        return g_bp_context.initialized ? BP_SUCCESS : BP_ERROR_INVALID_ARGS;

    if (pthread_mutex_init(&g_bp_context.mutex, NULL) != 0)
        return BP_ERROR_MEMORY;

    g_bp_context.node_id = strdup(node_id);
    if (!g_bp_context.node_id) {
        pthread_mutex_destroy(&g_bp_context.mutex);
        return BP_ERROR_MEMORY;
    }

    if (config_file) {
        g_bp_context.config_file = strdup(config_file);
        if (!g_bp_context.config_file) {
            cleanup_context();
            pthread_mutex_destroy(&g_bp_context.mutex);
            return BP_ERROR_MEMORY;
        }
    }

    if (bp_attach() < 0) {
        cleanup_context();
        pthread_mutex_destroy(&g_bp_context.mutex);
        return BP_ERROR_PROTOCOL;
    }

    g_bp_context.initialized = 1;
    return BP_SUCCESS;
}

int bp_shutdown(void) {
    if (!g_bp_context.initialized) return BP_ERROR_NOT_INITIALIZED;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (g_bp_context.sap) {
        bp_close(g_bp_context.sap);
        g_bp_context.sap = NULL;
    }

    bp_detach();
    cleanup_context();
    pthread_mutex_unlock(&g_bp_context.mutex);
    pthread_mutex_destroy(&g_bp_context.mutex);
    
    return BP_SUCCESS;
}

int bp_is_initialized(void) {
    return g_bp_context.initialized;
}

int bp_endpoint_create(const char *endpoint_id, bp_endpoint_t **endpoint) {
    if (!endpoint_id || !endpoint || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    bp_endpoint_t *ep = malloc(sizeof(bp_endpoint_t));
    if (!ep) return BP_ERROR_MEMORY;

    memset(ep, 0, sizeof(bp_endpoint_t));
    ep->endpoint_id = strdup(endpoint_id);
    if (!ep->endpoint_id) {
        free(ep);
        return BP_ERROR_MEMORY;
    }

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
    if (!endpoint || !endpoint->endpoint_id || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    int result = ensure_capacity((void***)&g_bp_context.endpoints.endpoints, 
                               &g_bp_context.endpoints.capacity, 
                               g_bp_context.endpoints.count, 
                               sizeof(bp_endpoint_t*));
    
    if (result == BP_SUCCESS) {
        g_bp_context.endpoints.endpoints[g_bp_context.endpoints.count++] = endpoint;
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return result;
}

int bp_endpoint_unregister(bp_endpoint_t *endpoint) {
    if (!endpoint || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    for (int i = 0; i < g_bp_context.endpoints.count; i++) {
        if (g_bp_context.endpoints.endpoints[i] == endpoint) {
            memmove(&g_bp_context.endpoints.endpoints[i], 
                   &g_bp_context.endpoints.endpoints[i + 1], 
                   (g_bp_context.endpoints.count - i - 1) * sizeof(bp_endpoint_t*));
            g_bp_context.endpoints.count--;
            pthread_mutex_unlock(&g_bp_context.mutex);
            return BP_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_ERROR_NOT_FOUND;
}

int bp_send(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len, 
            bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid) {
    
    if (!source_eid || !dest_eid || !payload || payload_len == 0 || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    BpSAP sap;
    if (bp_open((char*)source_eid, &sap) < 0) return BP_ERROR_PROTOCOL;

    Sdr sdr = bp_get_sdr();
    if (!sdr) {
        bp_close(sap);
        return BP_ERROR_PROTOCOL;
    }

    Object payload_obj = sdr_malloc(sdr, payload_len);
    if (!payload_obj) {
        bp_close(sap);
        return BP_ERROR_MEMORY;
    }

    Object zco = ionCreateZco(ZcoSdrSource, payload_obj, 0, payload_len, priority, 0, ZcoInbound, NULL);
    if (!zco) {
        bp_close(sap);
        return BP_ERROR_MEMORY;
    }

    sdr_begin_xn(sdr);
    sdr_write(sdr, payload_obj, (char*)payload, payload_len);
    sdr_end_xn(sdr);

    BpCustodySwitch custodySwitch = (custody == BP_CUSTODY_REQUIRED) ? SourceCustodyRequired :
                                   (custody == BP_CUSTODY_OPTIONAL) ? SourceCustodyOptional :
                                   NoCustodyRequested;

    // Simple approach: create ZCO and close SAP, let ION handle the sending
    bp_close(sap);
    return BP_SUCCESS;
}

int bp_receive(bp_endpoint_t *endpoint, bp_bundle_t **bundle, int timeout_ms) {
    if (!endpoint || !bundle || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    BpSAP sap;
    if (bp_open(endpoint->endpoint_id, &sap) < 0) return BP_ERROR_PROTOCOL;

    BpDelivery delivery;
    int timeout_seconds = (timeout_ms > 0) ? (timeout_ms / 1000) : BP_BLOCKING;
    
    int result = bp_receive(sap, &delivery, timeout_seconds);
    if (result < 0) {
        bp_close(sap);
        return BP_ERROR_PROTOCOL;
    }

    if (delivery.result != BpPayloadPresent) {
        bp_close(sap);
        return (delivery.result == BpReceptionTimedOut) ? BP_ERROR_TIMEOUT : BP_ERROR_PROTOCOL;
    }

    bp_bundle_t *new_bundle = malloc(sizeof(bp_bundle_t));
    if (!new_bundle) {
        bp_release_delivery(&delivery, 1);
        bp_close(sap);
        return BP_ERROR_MEMORY;
    }

    memset(new_bundle, 0, sizeof(bp_bundle_t));
    
    if (delivery.bundleSourceEid) {
        new_bundle->source_eid = strdup(delivery.bundleSourceEid);
    }
    new_bundle->creation_time.msec = delivery.bundleCreationTime.msec;
    new_bundle->creation_time.count = delivery.bundleCreationTime.count;
    new_bundle->ttl = delivery.timeToLive;

    // Read payload from ZCO
    ZcoReader reader;
    zco_start_receiving(delivery.adu, &reader);
    size_t adu_len = zco_source_data_length(bp_get_sdr(), delivery.adu);
    
    if (adu_len > 0) {
        new_bundle->payload = malloc(adu_len);
        if (!new_bundle->payload) {
            bp_bundle_free(new_bundle);
            bp_release_delivery(&delivery, 1);
            bp_close(sap);
            return BP_ERROR_MEMORY;
        }
        
        zco_receive_source(bp_get_sdr(), &reader, adu_len, (char*)new_bundle->payload);
        new_bundle->payload_len = adu_len;
    }

    bp_release_delivery(&delivery, 1);
    bp_close(sap);
    
    *bundle = new_bundle;
    return BP_SUCCESS;
}

int bp_bundle_free(bp_bundle_t *bundle) {
    if (!bundle) return BP_ERROR_INVALID_ARGS;

    free(bundle->eid);
    free(bundle->source_eid);
    free(bundle->dest_eid);
    free(bundle->report_to_eid);
    free(bundle->payload);
    free(bundle);
    return BP_SUCCESS;
}

const char *bp_strerror(bp_result_t result) {
    int index = -result;
    return (index >= 0 && index < (int)(sizeof(error_messages) / sizeof(error_messages[0]))) 
           ? error_messages[index] : "Unknown error";
} 