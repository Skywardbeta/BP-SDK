/* bp_backend.h - Backend Abstraction */
#ifndef BP_BACKEND_H
#define BP_BACKEND_H

#include "bp_sdk.h"
#include <stddef.h>
#include <time.h>

typedef struct {
    const char *name;
    int (*init)(const char *config);
    int (*shutdown)(void);
    
    int (*send)(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len, 
                bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid);
    int (*receive)(const char *local_eid, bp_bundle_t **bundle, int timeout_ms);
    int (*bundle_free)(bp_bundle_t *bundle);
    
    int (*cla_register)(bp_cla_t *cla);
    int (*cla_unregister)(const char *protocol_name);
    int (*cla_send)(const char *protocol_name, const char *dest_addr, const void *data, size_t len);
    int (*cla_list)(char ***protocol_names, int *count);

    int (*routing_register)(bp_routing_t *routing);
    int (*routing_unregister)(const char *algorithm_name);
    int (*routing_compute)(const char *dest_eid, bp_route_t **routes, int *route_count);
    int (*routing_update_contact)(const char *neighbor_eid, time_t start, time_t end, uint32_t rate);
    int (*routing_update_range)(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt);

    int (*storage_register)(bp_storage_t *storage);
    int (*storage_unregister)(const char *storage_name);
    int (*storage_store)(const char *bundle_id, const void *data, size_t len);
    int (*storage_retrieve)(const char *bundle_id, void **data, size_t *len);
    int (*storage_delete)(const char *bundle_id);
    int (*storage_list)(char ***bundle_ids, int *count);

    int (*security_register)(bp_security_t *security);
    int (*security_unregister)(const char *security_name);
    int (*security_encrypt)(const void *plain, size_t plain_len, void **cipher, size_t *cipher_len);
    int (*security_decrypt)(const void *cipher, size_t cipher_len, void **plain, size_t *plain_len);
    int (*security_sign)(const void *data, size_t data_len, void **signature, size_t *sig_len);
    int (*security_verify)(const void *data, size_t data_len, const void *signature, size_t sig_len);

    int (*admin_add_plan)(const char *dest_eid, uint32_t nominal_rate);
    int (*admin_remove_plan)(const char *dest_eid);
    int (*admin_add_contact)(const char *neighbor_eid, time_t start, time_t end, uint32_t rate);
    int (*admin_remove_contact)(const char *neighbor_eid, time_t start, time_t end);
    int (*admin_add_range)(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt);
    int (*admin_remove_range)(const char *neighbor_eid, time_t start, time_t end);
} bp_backend_t;

int bp_backend_register(bp_backend_t *backend);
bp_backend_t *bp_backend_get(void);

#endif
