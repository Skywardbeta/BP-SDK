/* bp_admin.c - Administrative Records */
#include "bp_admin.h"
#include "bp_cbor.h"
#include "bp_utils.h"
#include <string.h>

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

    uint8_t payload[256];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, payload, sizeof(payload));

    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, BP_ADMIN_STATUS_REPORT);
    cbor_encode_array(&enc, 6);
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

    if (subject->primary.flags & BP_FLAG_FRAGMENT) {
        cbor_encode_uint(&enc, subject->primary.fragment_offset);
        cbor_encode_uint(&enc, subject->payload_len);
    }
    cbor_encode_uint(&enc, bp_time_now_dtn());

    report->payload = bp_alloc(enc.len);
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

    uint8_t payload[128];
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

    signal->payload = bp_alloc(enc.len);
    memcpy(signal->payload, payload, enc.len);
    signal->payload_len = enc.len;
    return 0;
}

int bp_parse_admin_record(const uint8_t *payload, size_t len, int *type, void *record) {
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, payload, len);

    size_t arr_len;
    if (cbor_decode_array(&dec, &arr_len) < 0 || arr_len < 2) return -1;

    uint64_t t;
    if (cbor_decode_uint(&dec, &t) < 0) return -1;
    *type = (int)t;
    (void)record;
    return 0;
}
