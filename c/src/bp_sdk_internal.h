#ifndef BP_SDK_INTERNAL_H
#define BP_SDK_INTERNAL_H

#include "bp_sdk.h"
#include "../bpv7/include/bp.h"
#include "../ici/include/ion.h"
#include <pthread.h>

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

extern bp_context_t g_bp_context;

// Helper functions
int ensure_capacity(void ***array, int *capacity, int needed, size_t element_size);

// CLA functions
int bp_cla_create_tcp(const char *local_addr, uint16_t local_port, bp_cla_t **cla);
int bp_cla_create_udp(const char *local_addr, uint16_t local_port, bp_cla_t **cla);
int bp_cla_destroy(bp_cla_t *cla);
int bp_cla_handle_bundle_receive(bp_cla_t *cla, const void *data, size_t len, const char *source_eid);

// Routing functions
int bp_routing_create_cgr(bp_routing_t **routing);
int bp_routing_create_static(bp_routing_t **routing);
int bp_routing_destroy(bp_routing_t *routing);
int bp_route_create(const char *dest_eid, const char *next_hop, uint32_t cost, 
                   float confidence, time_t valid_until, bp_route_t **route);
int bp_route_destroy(bp_route_t *route);
int bp_route_list_destroy(bp_route_t *routes, int count);

// Security functions
int bp_security_create_aes_gcm(bp_security_t **security);
int bp_security_create_hmac_sha256(bp_security_t **security);
int bp_security_destroy(bp_security_t *security);

// Admin functions
int bp_admin_add_scheme(const char *scheme_name, const char *forwarder_cmd, const char *admin_cmd);
int bp_admin_remove_scheme(const char *scheme_name);
int bp_admin_add_endpoint(const char *endpoint_id, const char *recv_script);
int bp_admin_remove_endpoint(const char *endpoint_id);
int bp_admin_add_protocol(const char *protocol_name, int protocol_class);
int bp_admin_remove_protocol(const char *protocol_name);
int bp_admin_add_induct(const char *protocol_name, const char *duct_name, const char *cli_cmd);
int bp_admin_remove_induct(const char *protocol_name, const char *duct_name);
int bp_admin_add_outduct(const char *protocol_name, const char *duct_name, const char *clo_cmd, uint32_t max_payload_len);
int bp_admin_remove_outduct(const char *protocol_name, const char *duct_name);

#endif 