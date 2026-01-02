#include "bp_admin.h"
#include "bp_cbor.h"
#include "bp_utils.h"
#include <string.h>

#define ADMIN_PAYLOAD_MAX 512

int bp_create_status_report(const bp_bundle_full_t *subject, uint8_t status_flags, uint8_t reason,
                            bp_bundle_full_t *report) {
    if (!subject || !report) return -1;

    memset(report, 0, sizeof(*report));
    report->primary.version = 7;
    report->primary.flags = BP_FLAG_ADMIN_RECORD;
    report->primary.crc_type = BP_CRC_NONE;

    report->primary.dest_scheme = subject->primary.report_scheme;
    report->primary.dest_ssp[0] = subject->primary.report_ssp[0];
    report->primary.dest_ssp[1] = subject->primary.report_ssp[1];

    report->primary.source_scheme = subject->primary.dest_scheme;
    report->primary.source_ssp[0] = subject->primary.dest_ssp[0];
    report->primary.source_ssp[1] = 0;

    report->primary.creation_ts = bp_time_now_dtn();
    report->primary.lifetime_ms = 3600000;

    uint8_t payload[ADMIN_PAYLOAD_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, payload, sizeof(payload));

    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, BP_ADMIN_STATUS_REPORT);
    
    int has_frag = (subject->primary.flags & BP_FLAG_FRAGMENT) ? 1 : 0;
    cbor_encode_array(&enc, has_frag ? 8 : 6);
    
    cbor_encode_array(&enc, 4);
    cbor_encode_uint(&enc, (status_flags & BP_STATUS_RECEIVED) ? 1 : 0);
    cbor_encode_uint(&enc, (status_flags & BP_STATUS_FORWARDED) ? 1 : 0);
    cbor_encode_uint(&enc, (status_flags & BP_STATUS_DELIVERED) ? 1 : 0);
    cbor_encode_uint(&enc, (status_flags & BP_STATUS_DELETED) ? 1 : 0);
    
    cbor_encode_uint(&enc, reason);
    
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 2);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, subject->primary.source_ssp[0]);
    cbor_encode_uint(&enc, subject->primary.source_ssp[1]);
    
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, subject->primary.creation_ts);
    cbor_encode_uint(&enc, subject->primary.creation_seq);

    if (has_frag) {
        cbor_encode_uint(&enc, subject->primary.fragment_offset);
        cbor_encode_uint(&enc, subject->payload_len);
    }
    
    cbor_encode_uint(&enc, bp_time_now_dtn());

    if (enc.error) return -1;

    report->payload = bp_alloc(enc.len);
    if (!report->payload) return -1;
    memcpy(report->payload, payload, enc.len);
    report->payload_len = enc.len;
    return 0;
}

int bp_create_custody_signal(const bp_bundle_full_t *subject, int accepted, uint8_t reason,
                             bp_bundle_full_t *signal) {
    if (!subject || !signal) return -1;

    memset(signal, 0, sizeof(*signal));
    signal->primary.version = 7;
    signal->primary.flags = BP_FLAG_ADMIN_RECORD;
    signal->primary.crc_type = BP_CRC_NONE;

    signal->primary.dest_scheme = subject->primary.source_scheme;
    signal->primary.dest_ssp[0] = subject->primary.source_ssp[0];
    signal->primary.dest_ssp[1] = subject->primary.source_ssp[1];

    signal->primary.source_scheme = subject->primary.dest_scheme;
    signal->primary.source_ssp[0] = subject->primary.dest_ssp[0];
    signal->primary.source_ssp[1] = 0;

    signal->primary.creation_ts = bp_time_now_dtn();
    signal->primary.lifetime_ms = 3600000;

    uint8_t payload[ADMIN_PAYLOAD_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, payload, sizeof(payload));

    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, BP_ADMIN_CUSTODY_SIGNAL);
    cbor_encode_array(&enc, 4);
    cbor_encode_uint(&enc, accepted ? 1 : 0);
    cbor_encode_uint(&enc, reason);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, subject->primary.creation_ts);
    cbor_encode_uint(&enc, subject->primary.creation_seq);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 2);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, subject->primary.source_ssp[0]);
    cbor_encode_uint(&enc, subject->primary.source_ssp[1]);

    if (enc.error) return -1;

    signal->payload = bp_alloc(enc.len);
    if (!signal->payload) return -1;
    memcpy(signal->payload, payload, enc.len);
    signal->payload_len = enc.len;
    return 0;
}

int bp_parse_admin_record(const uint8_t *payload, size_t len, int *type, void *record) {
    if (!payload || len == 0 || !type) return -1;
    
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, payload, len);

    size_t arr_len;
    if (cbor_decode_array(&dec, &arr_len) < 0 || arr_len < 2) return -1;

    uint64_t t;
    if (cbor_decode_uint(&dec, &t) < 0) return -1;
    *type = (int)t;

    if (record && *type == BP_ADMIN_STATUS_REPORT) {
        bp_status_report_t *sr = (bp_status_report_t *)record;
        memset(sr, 0, sizeof(*sr));
        
        size_t inner_len;
        if (cbor_decode_array(&dec, &inner_len) < 0 || inner_len < 6) return -1;
        
        size_t status_len;
        if (cbor_decode_array(&dec, &status_len) < 0 || status_len != 4) return -1;
        
        uint64_t received, forwarded, delivered, deleted;
        if (cbor_decode_uint(&dec, &received) < 0) return -1;
        if (cbor_decode_uint(&dec, &forwarded) < 0) return -1;
        if (cbor_decode_uint(&dec, &delivered) < 0) return -1;
        if (cbor_decode_uint(&dec, &deleted) < 0) return -1;
        
        sr->status_flags = 0;
        if (received) sr->status_flags |= BP_STATUS_RECEIVED;
        if (forwarded) sr->status_flags |= BP_STATUS_FORWARDED;
        if (delivered) sr->status_flags |= BP_STATUS_DELIVERED;
        if (deleted) sr->status_flags |= BP_STATUS_DELETED;
        
        uint64_t reason;
        if (cbor_decode_uint(&dec, &reason) < 0) return -1;
        sr->reason_code = (uint8_t)reason;
        
        size_t eid_len;
        if (cbor_decode_array(&dec, &eid_len) < 0 || eid_len != 2) return -1;
        uint64_t scheme;
        if (cbor_decode_uint(&dec, &scheme) < 0) return -1;
        size_t ssp_len;
        if (cbor_decode_array(&dec, &ssp_len) < 0 || ssp_len != 2) return -1;
        if (cbor_decode_uint(&dec, &sr->bundle_source_node) < 0) return -1;
        if (cbor_decode_uint(&dec, &sr->bundle_source_service) < 0) return -1;
        
        size_t ts_len;
        if (cbor_decode_array(&dec, &ts_len) < 0 || ts_len != 2) return -1;
        if (cbor_decode_uint(&dec, &sr->bundle_creation_ts) < 0) return -1;
        if (cbor_decode_uint(&dec, &sr->bundle_creation_seq) < 0) return -1;
        
        if (inner_len >= 8) {
            if (cbor_decode_uint(&dec, &sr->fragment_offset) < 0) return -1;
            if (cbor_decode_uint(&dec, &sr->fragment_len) < 0) return -1;
        }
        
        if (cbor_decode_uint(&dec, &sr->status_time) < 0) return -1;
    }

    return 0;
}
