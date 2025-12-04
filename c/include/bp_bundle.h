/* bp_bundle.h - BPv7 Bundle structures (RFC 9171) */
#ifndef BP_BUNDLE_H
#define BP_BUNDLE_H

#include <stdint.h>
#include <stddef.h>

#define BP_FLAG_FRAGMENT           (1 << 0)
#define BP_FLAG_ADMIN_RECORD       (1 << 1)
#define BP_FLAG_NO_FRAGMENT        (1 << 2)
#define BP_FLAG_ACK_REQUESTED      (1 << 5)
#define BP_FLAG_STATUS_TIME        (1 << 6)
#define BP_FLAG_REPORT_RECEPTION   (1 << 14)
#define BP_FLAG_REPORT_FORWARD     (1 << 16)
#define BP_FLAG_REPORT_DELIVERY    (1 << 17)
#define BP_FLAG_REPORT_DELETE      (1 << 18)

#define BP_BLOCK_PAYLOAD           1
#define BP_BLOCK_HOP_COUNT         10
#define BP_BLOCK_BUNDLE_AGE        7

#define BP_CRC_NONE                0
#define BP_CRC_16                  1
#define BP_CRC_32                  2

#define BP_EID_DTN                 1
#define BP_EID_IPN                 2

typedef struct {
    uint8_t version;
    uint64_t flags;
    uint8_t crc_type;
    uint8_t dest_scheme;
    uint64_t dest_ssp[2];
    char *dest_uri;
    uint8_t source_scheme;
    uint64_t source_ssp[2];
    char *source_uri;
    uint8_t report_scheme;
    uint64_t report_ssp[2];
    char *report_uri;
    uint64_t creation_ts;
    uint64_t creation_seq;
    uint64_t lifetime_ms;
    uint64_t fragment_offset;
    uint64_t total_adu_len;
} bp_primary_t;

typedef struct {
    uint8_t type;
    uint64_t number;
    uint64_t flags;
    uint8_t crc_type;
    uint8_t *data;
    size_t data_len;
} bp_block_t;

typedef struct {
    bp_primary_t primary;
    bp_block_t *blocks;
    size_t block_count;
    uint8_t *payload;
    size_t payload_len;
} bp_bundle_full_t;

int bp_bundle_encode(const bp_bundle_full_t *bundle, uint8_t *out, size_t cap);
int bp_bundle_decode(const uint8_t *data, size_t len, bp_bundle_full_t *bundle);
void bp_bundle_full_free(bp_bundle_full_t *bundle);

int bp_eid_parse(const char *eid, uint8_t *scheme, uint64_t ssp[2], char **uri);
int bp_eid_format(uint8_t scheme, uint64_t ssp[2], const char *uri, char *out, size_t cap);

#endif
