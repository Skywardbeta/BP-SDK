/* bp_admin.h - Administrative Records (RFC 9171 Section 6) */
#ifndef BP_ADMIN_H
#define BP_ADMIN_H

#include "bp_bundle.h"
#include <stdint.h>

#define BP_ADMIN_STATUS_REPORT    1
#define BP_ADMIN_CUSTODY_SIGNAL   2

#define BP_REASON_NO_INFO         0
#define BP_REASON_LIFETIME_EXPIRED 1
#define BP_REASON_FORWARDED       2
#define BP_REASON_BLOCK_UNINTELLIGIBLE 3
#define BP_REASON_HOP_LIMIT       4
#define BP_REASON_STORAGE_DEPLETED 5
#define BP_REASON_DEST_EID_UNINTELLIGIBLE 6
#define BP_REASON_NO_ROUTE        7
#define BP_REASON_NO_NEXT_NODE    8
#define BP_REASON_SECURITY_FAILED 9

#define BP_STATUS_RECEIVED        0x01
#define BP_STATUS_FORWARDED       0x04
#define BP_STATUS_DELIVERED       0x08
#define BP_STATUS_DELETED         0x10

typedef struct {
    uint8_t status_flags;
    uint8_t reason_code;
    uint64_t bundle_source_node;
    uint64_t bundle_source_service;
    uint64_t bundle_creation_ts;
    uint64_t bundle_creation_seq;
    uint64_t fragment_offset;
    uint64_t fragment_len;
    uint64_t status_time;
} bp_status_report_t;

typedef struct {
    int accepted;
    uint8_t reason_code;
    uint64_t bundle_source_node;
    uint64_t bundle_source_service;
    uint64_t bundle_creation_ts;
    uint64_t bundle_creation_seq;
} bp_custody_signal_t;

int bp_create_status_report(const bp_bundle_full_t *subject,
                            uint8_t status_flags, uint8_t reason,
                            bp_bundle_full_t *report);

int bp_create_custody_signal(const bp_bundle_full_t *subject,
                             int accepted, uint8_t reason,
                             bp_bundle_full_t *signal);

int bp_parse_admin_record(const uint8_t *payload, size_t len, int *type, void *record);

#endif
