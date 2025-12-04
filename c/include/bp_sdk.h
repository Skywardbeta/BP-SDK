#ifndef BP_SDK_H
#define BP_SDK_H

#include <stdint.h>
#include <time.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BP_SUCCESS = 0,
    BP_ERROR_INVALID_ARGS = -1,
    BP_ERROR_NOT_INITIALIZED = -2,
    BP_ERROR_MEMORY = -3,
    BP_ERROR_TIMEOUT = -4,
    BP_ERROR_NOT_FOUND = -5,
    BP_ERROR_DUPLICATE = -6,
    BP_ERROR_PROTOCOL = -7,
    BP_ERROR_ROUTING = -8,
    BP_ERROR_STORAGE = -9,
    BP_ERROR_SECURITY = -10
} bp_result_t;

typedef enum {
    BP_PRIORITY_BULK = 0,
    BP_PRIORITY_STANDARD = 1,
    BP_PRIORITY_EXPEDITED = 2
} bp_priority_t;

typedef enum {
    BP_CUSTODY_NONE = 0,
    BP_CUSTODY_OPTIONAL = 1,
    BP_CUSTODY_REQUIRED = 2
} bp_custody_t;

typedef struct {
    uint64_t msec;
    uint32_t count;
} bp_timestamp_t;

typedef struct {
    char *eid;
    bp_timestamp_t creation_time;
    uint32_t fragment_offset;
    uint32_t ttl;
    bp_priority_t priority;
    bp_custody_t custody;
    uint8_t status_reports;
    void *payload;
    size_t payload_len;
    char *source_eid;
    char *dest_eid;
    char *report_to_eid;
} bp_bundle_t;

typedef struct {
    char *endpoint_id;
    void *context;
    int (*receive_callback)(bp_bundle_t *bundle, void *context);
    int (*status_callback)(const char *bundle_id, int status, void *context);
} bp_endpoint_t;

typedef struct {
    char *protocol_name;
    char *local_address;
    char *remote_address;
    uint32_t max_payload_size;
    uint32_t data_rate;
    void *context;
    int (*send_callback)(const void *data, size_t len, const char *dest, void *context);
    int (*receive_callback)(void *data, size_t len, char *source, void *context);
    int (*connect_callback)(const char *remote, void *context);
    int (*disconnect_callback)(const char *remote, void *context);
} bp_cla_t;

typedef struct {
    char *dest_eid;
    char *next_hop;
    uint32_t cost;
    float confidence;
    time_t valid_until;
    void *routing_data;
} bp_route_t;

typedef struct {
    char *algorithm_name;
    void *context;
    int (*compute_route)(const char *dest_eid, bp_route_t **routes, int *route_count, void *context);
    int (*update_contact)(const char *neighbor_eid, time_t start, time_t end, uint32_t rate, void *context);
    int (*update_range)(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt, void *context);
} bp_routing_t;

typedef struct {
    char *storage_name;
    void *context;
    int (*store_bundle)(const char *bundle_id, const void *data, size_t len, void *context);
    int (*retrieve_bundle)(const char *bundle_id, void **data, size_t *len, void *context);
    int (*delete_bundle)(const char *bundle_id, void *context);
    int (*list_bundles)(char ***bundle_ids, int *count, void *context);
} bp_storage_t;

typedef struct {
    char *security_name;
    void *context;
    int (*encrypt)(const void *plain, size_t plain_len, void **cipher, size_t *cipher_len, void *context);
    int (*decrypt)(const void *cipher, size_t cipher_len, void **plain, size_t *plain_len, void *context);
    int (*sign)(const void *data, size_t data_len, void **signature, size_t *sig_len, void *context);
    int (*verify)(const void *data, size_t data_len, const void *signature, size_t sig_len, void *context);
} bp_security_t;

int bp_init(const char *node_id, const char *config_file);
int bp_shutdown(void);
int bp_is_initialized(void);

int bp_endpoint_create(const char *endpoint_id, bp_endpoint_t **endpoint);
int bp_endpoint_destroy(bp_endpoint_t *endpoint);
int bp_endpoint_register(bp_endpoint_t *endpoint);
int bp_endpoint_unregister(bp_endpoint_t *endpoint);

int bp_send(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len, 
            bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid);
int bp_receive(bp_endpoint_t *endpoint, bp_bundle_t **bundle, int timeout_ms);
int bp_bundle_free(bp_bundle_t *bundle);

int bp_cla_register(bp_cla_t *cla);
int bp_cla_unregister(const char *protocol_name);
int bp_cla_send(const char *protocol_name, const char *dest_addr, const void *data, size_t len);
int bp_cla_list(char ***protocol_names, int *count);

int bp_routing_register(bp_routing_t *routing);
int bp_routing_unregister(const char *algorithm_name);
int bp_routing_compute(const char *dest_eid, bp_route_t **routes, int *route_count);
int bp_routing_update_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate);
int bp_routing_update_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt);

int bp_storage_register(bp_storage_t *storage);
int bp_storage_unregister(const char *storage_name);
int bp_storage_store(const char *bundle_id, const void *data, size_t len);
int bp_storage_retrieve(const char *bundle_id, void **data, size_t *len);
int bp_storage_delete(const char *bundle_id);
int bp_storage_list(char ***bundle_ids, int *count);

int bp_security_register(bp_security_t *security);
int bp_security_unregister(const char *security_name);
int bp_security_encrypt(const void *plain, size_t plain_len, void **cipher, size_t *cipher_len);
int bp_security_decrypt(const void *cipher, size_t cipher_len, void **plain, size_t *plain_len);
int bp_security_sign(const void *data, size_t data_len, void **signature, size_t *sig_len);
int bp_security_verify(const void *data, size_t data_len, const void *signature, size_t sig_len);

int bp_admin_add_plan(const char *dest_eid, uint32_t nominal_rate);
int bp_admin_remove_plan(const char *dest_eid);
int bp_admin_add_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate);
int bp_admin_remove_contact(const char *neighbor_eid, time_t start, time_t end);
int bp_admin_add_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt);
int bp_admin_remove_range(const char *neighbor_eid, time_t start, time_t end);

int bp_stats_get_bundles_sent(uint64_t *count);
int bp_stats_get_bundles_received(uint64_t *count);
int bp_stats_get_bundles_forwarded(uint64_t *count);
int bp_stats_get_bundles_delivered(uint64_t *count);
int bp_stats_get_bundles_deleted(uint64_t *count);
int bp_stats_reset(void);

const char *bp_strerror(bp_result_t result);

#ifdef __cplusplus
}
#endif

#endif 