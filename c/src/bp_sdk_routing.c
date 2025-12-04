#include "bp_sdk_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

extern bp_context_t g_bp_context;

static bp_routing_t *find_routing(const char *algorithm_name) {
    if (!algorithm_name) return NULL;
    
    for (int i = 0; i < g_bp_context.routing.count; i++) {
        if (strcmp(g_bp_context.routing.routing[i]->algorithm_name, algorithm_name) == 0) {
            return g_bp_context.routing.routing[i];
        }
    }
    return NULL;
}

static int validate_routing(bp_routing_t *routing) {
    return routing && routing->algorithm_name && routing->compute_route;
}

int bp_routing_register(bp_routing_t *routing) {
    if (!validate_routing(routing) || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (find_routing(routing->algorithm_name)) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_DUPLICATE;
    }

    int result = ensure_capacity((void***)&g_bp_context.routing.routing, 
                               &g_bp_context.routing.capacity, 
                               g_bp_context.routing.count, 
                               sizeof(bp_routing_t*));
    
    if (result == BP_SUCCESS) {
        g_bp_context.routing.routing[g_bp_context.routing.count++] = routing;
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return result;
}

int bp_routing_unregister(const char *algorithm_name) {
    if (!algorithm_name || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    for (int i = 0; i < g_bp_context.routing.count; i++) {
        if (strcmp(g_bp_context.routing.routing[i]->algorithm_name, algorithm_name) == 0) {
            memmove(&g_bp_context.routing.routing[i], 
                   &g_bp_context.routing.routing[i + 1], 
                   (g_bp_context.routing.count - i - 1) * sizeof(bp_routing_t*));
            g_bp_context.routing.count--;
            pthread_mutex_unlock(&g_bp_context.mutex);
            return BP_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_ERROR_NOT_FOUND;
}

int bp_routing_compute(const char *dest_eid, bp_route_t **routes, int *route_count) {
    if (!dest_eid || !routes || !route_count || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    *routes = NULL;
    *route_count = 0;

    for (int i = 0; i < g_bp_context.routing.count; i++) {
        bp_routing_t *routing = g_bp_context.routing.routing[i];
        bp_route_t *alg_routes = NULL;
        int alg_count = 0;
        
        if (routing->compute_route(dest_eid, &alg_routes, &alg_count, routing->context) == 0 && alg_count > 0) {
            if (*routes == NULL) {
                *routes = malloc(alg_count * sizeof(bp_route_t));
                if (!*routes) {
                    pthread_mutex_unlock(&g_bp_context.mutex);
                    return BP_ERROR_MEMORY;
                }
                memcpy(*routes, alg_routes, alg_count * sizeof(bp_route_t));
                *route_count = alg_count;
            } else {
                bp_route_t *new_routes = realloc(*routes, (*route_count + alg_count) * sizeof(bp_route_t));
                if (!new_routes) {
                    free(*routes);
                    pthread_mutex_unlock(&g_bp_context.mutex);
                    return BP_ERROR_MEMORY;
                }
                *routes = new_routes;
                memcpy(*routes + *route_count, alg_routes, alg_count * sizeof(bp_route_t));
                *route_count += alg_count;
            }
        }
    }

    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_SUCCESS;
}

int bp_routing_update_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate) {
    if (!neighbor_eid || start >= end || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    for (int i = 0; i < g_bp_context.routing.count; i++) {
        bp_routing_t *routing = g_bp_context.routing.routing[i];
        if (routing->update_contact) {
            routing->update_contact(neighbor_eid, start, end, rate, routing->context);
        }
    }

    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_SUCCESS;
}

int bp_routing_update_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt) {
    if (!neighbor_eid || start >= end || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    for (int i = 0; i < g_bp_context.routing.count; i++) {
        bp_routing_t *routing = g_bp_context.routing.routing[i];
        if (routing->update_range) {
            routing->update_range(neighbor_eid, start, end, owlt, routing->context);
        }
    }

    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_SUCCESS;
}

static bp_routing_t *create_routing_base(const char *algorithm_name) {
    bp_routing_t *routing = malloc(sizeof(bp_routing_t));
    if (!routing) return NULL;

    memset(routing, 0, sizeof(bp_routing_t));
    
    routing->algorithm_name = strdup(algorithm_name);
    if (!routing->algorithm_name) {
        free(routing);
        return NULL;
    }
    
    return routing;
}

int bp_routing_create_cgr(bp_routing_t **routing) {
    if (!routing) return BP_ERROR_INVALID_ARGS;
    
    *routing = create_routing_base("cgr");
    return *routing ? BP_SUCCESS : BP_ERROR_MEMORY;
}

int bp_routing_create_static(bp_routing_t **routing) {
    if (!routing) return BP_ERROR_INVALID_ARGS;
    
    *routing = create_routing_base("static");
    return *routing ? BP_SUCCESS : BP_ERROR_MEMORY;
}

int bp_routing_destroy(bp_routing_t *routing) {
    if (!routing) return BP_ERROR_INVALID_ARGS;

    free(routing->algorithm_name);
    free(routing);
    return BP_SUCCESS;
}

int bp_route_create(const char *dest_eid, const char *next_hop, uint32_t cost, 
                   float confidence, time_t valid_until, bp_route_t **route) {
    if (!dest_eid || !next_hop || !route) return BP_ERROR_INVALID_ARGS;

    bp_route_t *new_route = malloc(sizeof(bp_route_t));
    if (!new_route) return BP_ERROR_MEMORY;

    memset(new_route, 0, sizeof(bp_route_t));
    
    new_route->dest_eid = strdup(dest_eid);
    if (!new_route->dest_eid) {
        free(new_route);
        return BP_ERROR_MEMORY;
    }

    new_route->next_hop = strdup(next_hop);
    if (!new_route->next_hop) {
        free(new_route->dest_eid);
        free(new_route);
        return BP_ERROR_MEMORY;
    }

    new_route->cost = cost;
    new_route->confidence = confidence;
    new_route->valid_until = valid_until;

    *route = new_route;
    return BP_SUCCESS;
}

int bp_route_destroy(bp_route_t *route) {
    if (!route) return BP_ERROR_INVALID_ARGS;

    free(route->dest_eid);
    free(route->next_hop);
    free(route);
    return BP_SUCCESS;
}

int bp_route_list_destroy(bp_route_t *routes, int count) {
    if (!routes || count <= 0) return BP_ERROR_INVALID_ARGS;

    for (int i = 0; i < count; i++) {
        free(routes[i].dest_eid);
        free(routes[i].next_hop);
    }
    free(routes);
    return BP_SUCCESS;
} 