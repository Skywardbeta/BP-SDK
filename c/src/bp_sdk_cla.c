#include "bp_sdk_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

extern bp_context_t g_bp_context;

static bp_cla_t *find_cla(const char *protocol_name) {
    if (!protocol_name) return NULL;
    
    for (int i = 0; i < g_bp_context.clas.count; i++) {
        if (strcmp(g_bp_context.clas.clas[i]->protocol_name, protocol_name) == 0) {
            return g_bp_context.clas.clas[i];
        }
    }
    return NULL;
}

static int validate_cla(bp_cla_t *cla) {
    return cla && cla->protocol_name && cla->send_callback && cla->receive_callback;
}

int bp_cla_register(bp_cla_t *cla) {
    if (!validate_cla(cla) || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (find_cla(cla->protocol_name)) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_DUPLICATE;
    }

    int result = ensure_capacity((void***)&g_bp_context.clas.clas, 
                               &g_bp_context.clas.capacity, 
                               g_bp_context.clas.count, 
                               sizeof(bp_cla_t*));
    
    if (result == BP_SUCCESS) {
        g_bp_context.clas.clas[g_bp_context.clas.count++] = cla;
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return result;
}

int bp_cla_unregister(const char *protocol_name) {
    if (!protocol_name || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    for (int i = 0; i < g_bp_context.clas.count; i++) {
        if (strcmp(g_bp_context.clas.clas[i]->protocol_name, protocol_name) == 0) {
            memmove(&g_bp_context.clas.clas[i], 
                   &g_bp_context.clas.clas[i + 1], 
                   (g_bp_context.clas.count - i - 1) * sizeof(bp_cla_t*));
            g_bp_context.clas.count--;
            pthread_mutex_unlock(&g_bp_context.mutex);
            return BP_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_ERROR_NOT_FOUND;
}

int bp_cla_send(const char *protocol_name, const char *dest_addr, const void *data, size_t len) {
    if (!protocol_name || !dest_addr || !data || len == 0 || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    bp_cla_t *cla = find_cla(protocol_name);
    
    if (!cla) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_NOT_FOUND;
    }

    int result = cla->send_callback(data, len, dest_addr, cla->context);
    pthread_mutex_unlock(&g_bp_context.mutex);
    
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_cla_list(char ***protocol_names, int *count) {
    if (!protocol_names || !count || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    *count = g_bp_context.clas.count;
    if (*count == 0) {
        *protocol_names = NULL;
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_SUCCESS;
    }

    *protocol_names = malloc(*count * sizeof(char*));
    if (!*protocol_names) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_MEMORY;
    }

    for (int i = 0; i < *count; i++) {
        (*protocol_names)[i] = strdup(g_bp_context.clas.clas[i]->protocol_name);
        if (!(*protocol_names)[i]) {
            // Cleanup on failure
            for (int j = 0; j < i; j++) free((*protocol_names)[j]);
            free(*protocol_names);
            pthread_mutex_unlock(&g_bp_context.mutex);
            return BP_ERROR_MEMORY;
        }
    }

    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_SUCCESS;
}

static bp_cla_t *create_cla_base(const char *protocol, const char *addr, uint16_t port, 
                                uint32_t max_payload, uint32_t rate) {
    bp_cla_t *cla = malloc(sizeof(bp_cla_t));
    if (!cla) return NULL;

    memset(cla, 0, sizeof(bp_cla_t));
    
    cla->protocol_name = strdup(protocol);
    if (!cla->protocol_name) {
        free(cla);
        return NULL;
    }

    char addr_str[256];
    snprintf(addr_str, sizeof(addr_str), "%s:%u", addr, port);
    cla->local_address = strdup(addr_str);
    if (!cla->local_address) {
        free(cla->protocol_name);
        free(cla);
        return NULL;
    }

    cla->max_payload_size = max_payload;
    cla->data_rate = rate;
    return cla;
}

int bp_cla_create_tcp(const char *local_addr, uint16_t local_port, bp_cla_t **cla) {
    if (!local_addr || !cla) return BP_ERROR_INVALID_ARGS;
    
    *cla = create_cla_base("tcp", local_addr, local_port, 65536, 1000000);
    return *cla ? BP_SUCCESS : BP_ERROR_MEMORY;
}

int bp_cla_create_udp(const char *local_addr, uint16_t local_port, bp_cla_t **cla) {
    if (!local_addr || !cla) return BP_ERROR_INVALID_ARGS;
    
    *cla = create_cla_base("udp", local_addr, local_port, 1472, 1000000);
    return *cla ? BP_SUCCESS : BP_ERROR_MEMORY;
}

int bp_cla_destroy(bp_cla_t *cla) {
    if (!cla) return BP_ERROR_INVALID_ARGS;

    free(cla->protocol_name);
    free(cla->local_address);
    free(cla->remote_address);
    free(cla);
    return BP_SUCCESS;
}

int bp_cla_handle_bundle_receive(bp_cla_t *cla, const void *data, size_t len, const char *source_eid) {
    if (!cla || !data || len == 0 || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    return cla->receive_callback ? 
           cla->receive_callback((void*)data, len, (char*)source_eid, cla->context) : 
           BP_SUCCESS;
} 