#include "bp_sdk_internal.h"
#include "../bpv7/library/bpP.h"
#include "../ici/include/ion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

extern bp_context_t g_bp_context;

static int validate_admin_args(const char *arg1, const char *arg2, int require_both) {
    return arg1 && (!require_both || arg2) && g_bp_context.initialized;
}

static int admin_wrapper(int (*func)(char*), const char *arg) {
    if (!validate_admin_args(arg, NULL, 0)) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;
    
    int result = func((char*)arg);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

static int admin_wrapper2(int (*func)(char*, char*), const char *arg1, const char *arg2) {
    if (!validate_admin_args(arg1, arg2, 1)) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;
    
    int result = func((char*)arg1, (char*)arg2);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_admin_add_plan(const char *dest_eid, uint32_t nominal_rate) {
    if (!dest_eid || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    int result = addPlan((char*)dest_eid, nominal_rate);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_admin_remove_plan(const char *dest_eid) {
    return admin_wrapper(removePlan, dest_eid);
}

int bp_admin_add_contact(const char *neighbor_eid, time_t start, time_t end, uint32_t rate) {
    if (!neighbor_eid || start >= end || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    uvast toNode = 0;
    if (sscanf(neighbor_eid, "ipn:%lu.%*u", &toNode) != 1) {
        return BP_ERROR_INVALID_ARGS;
    }

    IonContact contact = {
        .fromTime = start,
        .toTime = end,
        .fromNode = 0,
        .toNode = toNode,
        .xmitRate = rate,
        .confidence = 1.0,
        .type = CtScheduled
    };

    Sdr sdr = getIonsdr();
    if (!sdr) return BP_ERROR_PROTOCOL;

    sdr_begin_xn(sdr);
    Object contactObj = sdr_malloc(sdr, sizeof(IonContact));
    if (!contactObj) {
        sdr_cancel_xn(sdr);
        return BP_ERROR_MEMORY;
    }

    sdr_write(sdr, contactObj, (char*)&contact, sizeof(IonContact));
    
    Object iondbObj = getIonDbObject();
    if (!iondbObj) {
        sdr_cancel_xn(sdr);
        return BP_ERROR_PROTOCOL;
    }

    IonDB iondb;
    sdr_read(sdr, (char*)&iondb, iondbObj, sizeof(IonDB));
    sdr_list_insert_last(sdr, iondb.regions[0].contacts, contactObj);
    
    return (sdr_end_xn(sdr) < 0) ? BP_ERROR_PROTOCOL : BP_SUCCESS;
}

int bp_admin_remove_contact(const char *neighbor_eid, time_t start, time_t end) {
    if (!neighbor_eid || start >= end || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    uvast toNode = 0;
    if (sscanf(neighbor_eid, "ipn:%lu.%*u", &toNode) != 1) {
        return BP_ERROR_INVALID_ARGS;
    }

    Sdr sdr = getIonsdr();
    if (!sdr) return BP_ERROR_PROTOCOL;

    sdr_begin_xn(sdr);
    
    Object iondbObj = getIonDbObject();
    if (!iondbObj) {
        sdr_cancel_xn(sdr);
        return BP_ERROR_PROTOCOL;
    }

    IonDB iondb;
    sdr_read(sdr, (char*)&iondb, iondbObj, sizeof(IonDB));
    
    Object elt = sdr_list_first(sdr, iondb.regions[0].contacts);
    while (elt) {
        Object contactObj = sdr_list_data(sdr, elt);
        IonContact contact;
        sdr_read(sdr, (char*)&contact, contactObj, sizeof(IonContact));
        
        if (contact.toNode == toNode && contact.fromTime == start && contact.toTime == end) {
            sdr_list_delete(sdr, elt, NULL, NULL);
            sdr_free(sdr, contactObj);
            break;
        }
        
        elt = sdr_list_next(sdr, elt);
    }
    
    return (sdr_end_xn(sdr) < 0) ? BP_ERROR_PROTOCOL : BP_SUCCESS;
}

int bp_admin_add_range(const char *neighbor_eid, time_t start, time_t end, uint32_t owlt) {
    if (!neighbor_eid || start >= end || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    uvast toNode = 0;
    if (sscanf(neighbor_eid, "ipn:%lu.%*u", &toNode) != 1) {
        return BP_ERROR_INVALID_ARGS;
    }

    IonRange range = {
        .fromTime = start,
        .toTime = end,
        .fromNode = 0,
        .toNode = toNode,
        .owlt = owlt
    };

    Sdr sdr = getIonsdr();
    if (!sdr) return BP_ERROR_PROTOCOL;

    sdr_begin_xn(sdr);
    Object rangeObj = sdr_malloc(sdr, sizeof(IonRange));
    if (!rangeObj) {
        sdr_cancel_xn(sdr);
        return BP_ERROR_MEMORY;
    }

    sdr_write(sdr, rangeObj, (char*)&range, sizeof(IonRange));
    
    Object iondbObj = getIonDbObject();
    if (!iondbObj) {
        sdr_cancel_xn(sdr);
        return BP_ERROR_PROTOCOL;
    }

    IonDB iondb;
    sdr_read(sdr, (char*)&iondb, iondbObj, sizeof(IonDB));
    sdr_list_insert_last(sdr, iondb.ranges, rangeObj);
    
    return (sdr_end_xn(sdr) < 0) ? BP_ERROR_PROTOCOL : BP_SUCCESS;
}

int bp_admin_remove_range(const char *neighbor_eid, time_t start, time_t end) {
    if (!neighbor_eid || start >= end || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    uvast toNode = 0;
    if (sscanf(neighbor_eid, "ipn:%lu.%*u", &toNode) != 1) {
        return BP_ERROR_INVALID_ARGS;
    }

    Sdr sdr = getIonsdr();
    if (!sdr) return BP_ERROR_PROTOCOL;

    sdr_begin_xn(sdr);
    
    Object iondbObj = getIonDbObject();
    if (!iondbObj) {
        sdr_cancel_xn(sdr);
        return BP_ERROR_PROTOCOL;
    }

    IonDB iondb;
    sdr_read(sdr, (char*)&iondb, iondbObj, sizeof(IonDB));
    
    Object elt = sdr_list_first(sdr, iondb.ranges);
    while (elt) {
        Object rangeObj = sdr_list_data(sdr, elt);
        IonRange range;
        sdr_read(sdr, (char*)&range, rangeObj, sizeof(IonRange));
        
        if (range.toNode == toNode && range.fromTime == start && range.toTime == end) {
            sdr_list_delete(sdr, elt, NULL, NULL);
            sdr_free(sdr, rangeObj);
            break;
        }
        
        elt = sdr_list_next(sdr, elt);
    }
    
    return (sdr_end_xn(sdr) < 0) ? BP_ERROR_PROTOCOL : BP_SUCCESS;
}

int bp_stats_get_bundles_sent(uint64_t *count) {
    return (!count || !g_bp_context.initialized) ? 
           (!g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS) : 
           (*count = 0, BP_SUCCESS);
}

int bp_stats_get_bundles_received(uint64_t *count) {
    return bp_stats_get_bundles_sent(count);
}

int bp_stats_get_bundles_forwarded(uint64_t *count) {
    return bp_stats_get_bundles_sent(count);
}

int bp_stats_get_bundles_delivered(uint64_t *count) {
    return bp_stats_get_bundles_sent(count);
}

int bp_stats_get_bundles_deleted(uint64_t *count) {
    return bp_stats_get_bundles_sent(count);
}

int bp_stats_reset(void) {
    return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_SUCCESS;
}

int bp_admin_add_scheme(const char *scheme_name, const char *forwarder_cmd, const char *admin_cmd) {
    if (!scheme_name || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    int result = addScheme((char*)scheme_name, (char*)forwarder_cmd, (char*)admin_cmd);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_admin_remove_scheme(const char *scheme_name) {
    return admin_wrapper(removeScheme, scheme_name);
}

int bp_admin_add_endpoint(const char *endpoint_id, const char *recv_script) {
    if (!endpoint_id || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    int result = addEndpoint((char*)endpoint_id, EnqueueBundle, (char*)recv_script);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_admin_remove_endpoint(const char *endpoint_id) {
    return admin_wrapper(removeEndpoint, endpoint_id);
}

int bp_admin_add_protocol(const char *protocol_name, int protocol_class) {
    if (!protocol_name || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    int result = addProtocol((char*)protocol_name, protocol_class);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_admin_remove_protocol(const char *protocol_name) {
    return admin_wrapper(removeProtocol, protocol_name);
}

int bp_admin_add_induct(const char *protocol_name, const char *duct_name, const char *cli_cmd) {
    if (!protocol_name || !duct_name || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    int result = addInduct((char*)protocol_name, (char*)duct_name, (char*)cli_cmd);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_admin_remove_induct(const char *protocol_name, const char *duct_name) {
    return admin_wrapper2(removeInduct, protocol_name, duct_name);
}

int bp_admin_add_outduct(const char *protocol_name, const char *duct_name, const char *clo_cmd, uint32_t max_payload_len) {
    if (!protocol_name || !duct_name || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    int result = addOutduct((char*)protocol_name, (char*)duct_name, (char*)clo_cmd, max_payload_len);
    return (result == 0) ? BP_SUCCESS : BP_ERROR_PROTOCOL;
}

int bp_admin_remove_outduct(const char *protocol_name, const char *duct_name) {
    return admin_wrapper2(removeOutduct, protocol_name, duct_name);
} 