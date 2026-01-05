/*
 * bp_bundle.c - BPv7 Bundle encoding/decoding (RFC 9171)
 */
#include "bp_bundle.h"
#include "bp_cbor.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* CRC-16 ANSI (X.25) for BP_CRC_16 */
static uint16_t crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0x8408;
            else crc >>= 1;
        }
    }
    return crc ^ 0xFFFF;
}

/* CRC-32C (Castagnoli) for BP_CRC_32 */
static uint32_t crc32c(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0x82F63B78;
            else crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

int bp_eid_parse(const char *eid, uint8_t *scheme, uint64_t ssp[2], char **uri) {
    if (!eid || !scheme || !ssp) return -1;
    ssp[0] = ssp[1] = 0;
    if (uri) *uri = NULL;

    if (strncmp(eid, "ipn:", 4) == 0) {
        *scheme = BP_EID_IPN;
        if (sscanf(eid + 4, "%llu.%llu", (unsigned long long *)&ssp[0], (unsigned long long *)&ssp[1]) != 2)
            return -1;
    } else if (strncmp(eid, "dtn:", 4) == 0) {
        *scheme = BP_EID_DTN;
        if (uri) *uri = strdup(eid + 4);
    } else {
        return -1;
    }
    return 0;
}

int bp_eid_format(uint8_t scheme, uint64_t ssp[2], const char *uri, char *out, size_t cap) {
    if (scheme == BP_EID_IPN) {
        return snprintf(out, cap, "ipn:%llu.%llu", (unsigned long long)ssp[0], (unsigned long long)ssp[1]);
    } else if (scheme == BP_EID_DTN && uri) {
        return snprintf(out, cap, "dtn:%s", uri);
    }
    return -1;
}

/* Encode EID as CBOR array [scheme, ssp] */
static int encode_eid(cbor_encoder_t *enc, uint8_t scheme, uint64_t ssp[2], const char *uri) {
    cbor_encode_array(enc, 2);
    cbor_encode_uint(enc, scheme);
    if (scheme == BP_EID_IPN) {
        cbor_encode_array(enc, 2);
        cbor_encode_uint(enc, ssp[0]);
        cbor_encode_uint(enc, ssp[1]);
    } else if (scheme == BP_EID_DTN) {
        if (uri && uri[0] == '/' && uri[1] == '/') {
            cbor_encode_text(enc, uri);
        } else {
            cbor_encode_uint(enc, 0); /* dtn:none */
        }
    }
    return enc->error ? -1 : 0;
}

/* Encode Primary Block */
static int encode_primary(cbor_encoder_t *enc, const bp_primary_t *p) {
    int is_frag = (p->flags & BP_FLAG_FRAGMENT) ? 1 : 0;
    size_t arr_len = is_frag ? 11 : 9;
    if (p->crc_type != BP_CRC_NONE) arr_len++;

    size_t start = enc->len;
    cbor_encode_array(enc, arr_len);
    cbor_encode_uint(enc, p->version);
    cbor_encode_uint(enc, p->flags);
    cbor_encode_uint(enc, p->crc_type);
    encode_eid(enc, p->dest_scheme, (uint64_t *)p->dest_ssp, p->dest_uri);
    encode_eid(enc, p->source_scheme, (uint64_t *)p->source_ssp, p->source_uri);
    encode_eid(enc, p->report_scheme, (uint64_t *)p->report_ssp, p->report_uri);

    cbor_encode_array(enc, 2);
    cbor_encode_uint(enc, p->creation_ts);
    cbor_encode_uint(enc, p->creation_seq);

    cbor_encode_uint(enc, p->lifetime_ms);

    if (is_frag) {
        cbor_encode_uint(enc, p->fragment_offset);
        cbor_encode_uint(enc, p->total_adu_len);
    }

    /* CRC placeholder then compute */
    if (p->crc_type == BP_CRC_16) {
        size_t crc_pos = enc->len;
        cbor_encode_bytes(enc, (uint8_t[]){0, 0}, 2);
        uint16_t c = crc16(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (c >> 8) & 0xFF;
        enc->buf[crc_pos + 2] = c & 0xFF;
    } else if (p->crc_type == BP_CRC_32) {
        size_t crc_pos = enc->len;
        cbor_encode_bytes(enc, (uint8_t[]){0, 0, 0, 0}, 4);
        uint32_t c = crc32c(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (c >> 24) & 0xFF;
        enc->buf[crc_pos + 2] = (c >> 16) & 0xFF;
        enc->buf[crc_pos + 3] = (c >> 8) & 0xFF;
        enc->buf[crc_pos + 4] = c & 0xFF;
    }

    return enc->error ? -1 : 0;
}

static int encode_block(cbor_encoder_t *enc, const bp_block_t *b) {
    size_t arr_len = (b->crc_type != BP_CRC_NONE) ? 6 : 5;
    size_t start = enc->len;

    cbor_encode_array(enc, arr_len);
    cbor_encode_uint(enc, b->type);
    cbor_encode_uint(enc, b->number);
    cbor_encode_uint(enc, b->flags);
    cbor_encode_uint(enc, b->crc_type);
    cbor_encode_bytes(enc, b->data, b->data_len);

    if (b->crc_type == BP_CRC_16) {
        size_t crc_pos = enc->len;
        cbor_encode_bytes(enc, (uint8_t[]){0, 0}, 2);
        uint16_t c = crc16(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (c >> 8) & 0xFF;
        enc->buf[crc_pos + 2] = c & 0xFF;
    } else if (b->crc_type == BP_CRC_32) {
        size_t crc_pos = enc->len;
        cbor_encode_bytes(enc, (uint8_t[]){0, 0, 0, 0}, 4);
        uint32_t c = crc32c(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (c >> 24) & 0xFF;
        enc->buf[crc_pos + 2] = (c >> 16) & 0xFF;
        enc->buf[crc_pos + 3] = (c >> 8) & 0xFF;
        enc->buf[crc_pos + 4] = c & 0xFF;
    }

    return enc->error ? -1 : 0;
}

int bp_bundle_encode(const bp_bundle_full_t *bundle, uint8_t *out, size_t cap) {
    if (!bundle || !out) return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, out, cap);

    cbor_encode_indef_array_start(&enc);

    if (encode_primary(&enc, &bundle->primary) < 0) return -1;

    /* Extension blocks */
    for (size_t i = 0; i < bundle->block_count; i++) {
        if (encode_block(&enc, &bundle->blocks[i]) < 0) return -1;
    }

    /* Payload block (type=1, number=1) */
    if (bundle->payload && bundle->payload_len > 0) {
        bp_block_t payload_block = {
            .type = BP_BLOCK_PAYLOAD,
            .number = 1,
            .flags = 0,
            .crc_type = BP_CRC_NONE,
            .data = bundle->payload,
            .data_len = bundle->payload_len
        };
        if (encode_block(&enc, &payload_block) < 0) return -1;
    }

    cbor_encode_break(&enc);

    return enc.error ? -1 : (int)enc.len;
}

/* Decode EID from CBOR */
static int decode_eid(cbor_decoder_t *dec, uint8_t *scheme, uint64_t ssp[2], char **uri) {
    size_t arr_len;
    if (cbor_decode_array(dec, &arr_len) < 0 || arr_len != 2) return -1;

    uint64_t s;
    if (cbor_decode_uint(dec, &s) < 0) return -1;
    *scheme = (uint8_t)s;

    if (*scheme == BP_EID_IPN) {
        size_t inner_len;
        if (cbor_decode_array(dec, &inner_len) < 0 || inner_len != 2) return -1;
        if (cbor_decode_uint(dec, &ssp[0]) < 0) return -1;
        if (cbor_decode_uint(dec, &ssp[1]) < 0) return -1;
    } else if (*scheme == BP_EID_DTN) {
        int t = cbor_peek_type(dec);
        if (t == CBOR_TYPE_TEXT) {
            const char *str;
            size_t len;
            if (cbor_decode_text(dec, &str, &len) < 0) return -1;
            if (uri) {
                *uri = malloc(len + 1);
                memcpy(*uri, str, len);
                (*uri)[len] = '\0';
            }
        } else {
            uint64_t v;
            cbor_decode_uint(dec, &v); /* dtn:none */
        }
    }
    return 0;
}

int bp_bundle_decode(const uint8_t *data, size_t len, bp_bundle_full_t *bundle) {
    if (!data || !bundle) return -1;
    memset(bundle, 0, sizeof(*bundle));

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, data, len);

    if (cbor_decode_indef_array_start(&dec) < 0) return -1;

    size_t prim_len;
    if (cbor_decode_array(&dec, &prim_len) < 0) return -1;

    uint64_t tmp;
    if (cbor_decode_uint(&dec, &tmp) < 0) return -1;
    bundle->primary.version = (uint8_t)tmp;

    if (cbor_decode_uint(&dec, &bundle->primary.flags) < 0) return -1;
    if (cbor_decode_uint(&dec, &tmp) < 0) return -1;
    bundle->primary.crc_type = (uint8_t)tmp;

    if (decode_eid(&dec, &bundle->primary.dest_scheme, bundle->primary.dest_ssp, &bundle->primary.dest_uri) < 0) return -1;
    if (decode_eid(&dec, &bundle->primary.source_scheme, bundle->primary.source_ssp, &bundle->primary.source_uri) < 0) return -1;
    if (decode_eid(&dec, &bundle->primary.report_scheme, bundle->primary.report_ssp, &bundle->primary.report_uri) < 0) return -1;

    /* Creation timestamp */
    size_t ts_len;
    if (cbor_decode_array(&dec, &ts_len) < 0 || ts_len != 2) return -1;
    if (cbor_decode_uint(&dec, &bundle->primary.creation_ts) < 0) return -1;
    if (cbor_decode_uint(&dec, &bundle->primary.creation_seq) < 0) return -1;

    if (cbor_decode_uint(&dec, &bundle->primary.lifetime_ms) < 0) return -1;

    if (bundle->primary.flags & BP_FLAG_FRAGMENT) {
        if (cbor_decode_uint(&dec, &bundle->primary.fragment_offset) < 0) return -1;
        if (cbor_decode_uint(&dec, &bundle->primary.total_adu_len) < 0) return -1;
    }

    if (bundle->primary.crc_type != BP_CRC_NONE) {
        cbor_skip(&dec);
    }

    /* Decode blocks until break */
    bp_block_t *blocks = NULL;
    size_t block_cap = 0, block_cnt = 0;

    while (dec.buf[dec.pos] != CBOR_BREAK) {
        size_t blk_len;
        if (cbor_decode_array(&dec, &blk_len) < 0) break;

        bp_block_t blk = {0};
        if (cbor_decode_uint(&dec, &tmp) < 0) break;
        blk.type = (uint8_t)tmp;
        if (cbor_decode_uint(&dec, &blk.number) < 0) break;
        if (cbor_decode_uint(&dec, &blk.flags) < 0) break;
        if (cbor_decode_uint(&dec, &tmp) < 0) break;
        blk.crc_type = (uint8_t)tmp;

        const uint8_t *bdata;
        size_t blen;
        if (cbor_decode_bytes(&dec, &bdata, &blen) < 0) break;
        blk.data = malloc(blen);
        memcpy(blk.data, bdata, blen);
        blk.data_len = blen;

        if (blk.crc_type != BP_CRC_NONE) cbor_skip(&dec);

        if (blk.type == BP_BLOCK_PAYLOAD) {
            bundle->payload = blk.data;
            bundle->payload_len = blk.data_len;
        } else {
            if (block_cnt >= block_cap) {
                block_cap = block_cap ? block_cap * 2 : 4;
                blocks = realloc(blocks, block_cap * sizeof(bp_block_t));
            }
            blocks[block_cnt++] = blk;
        }
    }

    bundle->blocks = blocks;
    bundle->block_count = block_cnt;

    cbor_decode_break(&dec);
    return dec.error ? -1 : 0;
}

void bp_bundle_full_free(bp_bundle_full_t *bundle) {
    if (!bundle) return;
    free(bundle->primary.dest_uri);
    free(bundle->primary.source_uri);
    free(bundle->primary.report_uri);
    for (size_t i = 0; i < bundle->block_count; i++) {
        free(bundle->blocks[i].data);
    }
    free(bundle->blocks);
    free(bundle->payload);
    memset(bundle, 0, sizeof(*bundle));
}
