#include "bp_bundle.h"
#include "bp_cbor.h"
#include "bp_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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
        if (uri) {
            *uri = bp_strdup(eid + 4);
            if (!*uri) return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

int bp_eid_format(uint8_t scheme, uint64_t ssp[2], const char *uri, char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    if (scheme == BP_EID_IPN) {
        return snprintf(out, cap, "ipn:%llu.%llu", (unsigned long long)ssp[0], (unsigned long long)ssp[1]);
    } else if (scheme == BP_EID_DTN && uri) {
        return snprintf(out, cap, "dtn:%s", uri);
    }
    return -1;
}

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
            cbor_encode_uint(enc, 0);
        }
    }
    return enc->error ? -1 : 0;
}

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

    if (p->crc_type == BP_CRC_16) {
        size_t crc_pos = enc->len;
        uint8_t zero_crc[2] = {0, 0};
        cbor_encode_bytes(enc, zero_crc, 2);
        uint16_t c = bp_crc16(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (uint8_t)((c >> 8) & 0xFF);
        enc->buf[crc_pos + 2] = (uint8_t)(c & 0xFF);
    } else if (p->crc_type == BP_CRC_32) {
        size_t crc_pos = enc->len;
        uint8_t zero_crc[4] = {0, 0, 0, 0};
        cbor_encode_bytes(enc, zero_crc, 4);
        uint32_t c = bp_crc32c(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (uint8_t)((c >> 24) & 0xFF);
        enc->buf[crc_pos + 2] = (uint8_t)((c >> 16) & 0xFF);
        enc->buf[crc_pos + 3] = (uint8_t)((c >> 8) & 0xFF);
        enc->buf[crc_pos + 4] = (uint8_t)(c & 0xFF);
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
        uint8_t zero_crc[2] = {0, 0};
        cbor_encode_bytes(enc, zero_crc, 2);
        uint16_t c = bp_crc16(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (uint8_t)((c >> 8) & 0xFF);
        enc->buf[crc_pos + 2] = (uint8_t)(c & 0xFF);
    } else if (b->crc_type == BP_CRC_32) {
        size_t crc_pos = enc->len;
        uint8_t zero_crc[4] = {0, 0, 0, 0};
        cbor_encode_bytes(enc, zero_crc, 4);
        uint32_t c = bp_crc32c(enc->buf + start, enc->len - start);
        enc->buf[crc_pos + 1] = (uint8_t)((c >> 24) & 0xFF);
        enc->buf[crc_pos + 2] = (uint8_t)((c >> 16) & 0xFF);
        enc->buf[crc_pos + 3] = (uint8_t)((c >> 8) & 0xFF);
        enc->buf[crc_pos + 4] = (uint8_t)(c & 0xFF);
    }

    return enc->error ? -1 : 0;
}

int bp_bundle_encode(const bp_bundle_full_t *bundle, uint8_t *out, size_t cap) {
    if (!bundle || !out || cap == 0) return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, out, cap);

    cbor_encode_indef_array_start(&enc);

    if (encode_primary(&enc, &bundle->primary) < 0) return -1;

    for (size_t i = 0; i < bundle->block_count; i++) {
        if (encode_block(&enc, &bundle->blocks[i]) < 0) return -1;
    }

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
                *uri = bp_alloc(len + 1);
                if (!*uri) return -1;
                memcpy(*uri, str, len);
                (*uri)[len] = '\0';
            }
        } else {
            uint64_t v;
            cbor_decode_uint(dec, &v);
        }
    }
    return 0;
}

static void free_blocks(bp_block_t *blocks, size_t count) {
    if (!blocks) return;
    for (size_t i = 0; i < count; i++) {
        bp_free(blocks[i].data);
    }
    bp_free(blocks);
}

int bp_bundle_decode(const uint8_t *data, size_t len, bp_bundle_full_t *bundle) {
    if (!data || len == 0 || !bundle) return -1;
    memset(bundle, 0, sizeof(*bundle));

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, data, len);

    if (cbor_decode_indef_array_start(&dec) < 0) return -1;

    size_t prim_len;
    if (cbor_decode_array(&dec, &prim_len) < 0) return -1;

    uint64_t tmp;
    if (cbor_decode_uint(&dec, &tmp) < 0) return -1;
    bundle->primary.version = (uint8_t)tmp;

    if (cbor_decode_uint(&dec, &bundle->primary.flags) < 0) goto fail;
    if (cbor_decode_uint(&dec, &tmp) < 0) goto fail;
    bundle->primary.crc_type = (uint8_t)tmp;

    if (decode_eid(&dec, &bundle->primary.dest_scheme, bundle->primary.dest_ssp, &bundle->primary.dest_uri) < 0) goto fail;
    if (decode_eid(&dec, &bundle->primary.source_scheme, bundle->primary.source_ssp, &bundle->primary.source_uri) < 0) goto fail;
    if (decode_eid(&dec, &bundle->primary.report_scheme, bundle->primary.report_ssp, &bundle->primary.report_uri) < 0) goto fail;

    size_t ts_len;
    if (cbor_decode_array(&dec, &ts_len) < 0 || ts_len != 2) goto fail;
    if (cbor_decode_uint(&dec, &bundle->primary.creation_ts) < 0) goto fail;
    if (cbor_decode_uint(&dec, &bundle->primary.creation_seq) < 0) goto fail;

    if (cbor_decode_uint(&dec, &bundle->primary.lifetime_ms) < 0) goto fail;

    if (bundle->primary.flags & BP_FLAG_FRAGMENT) {
        if (cbor_decode_uint(&dec, &bundle->primary.fragment_offset) < 0) goto fail;
        if (cbor_decode_uint(&dec, &bundle->primary.total_adu_len) < 0) goto fail;
    }

    if (bundle->primary.crc_type != BP_CRC_NONE) {
        cbor_skip(&dec);
    }

    bp_block_t *blocks = NULL;
    size_t block_cap = 0, block_cnt = 0;

    while (dec.pos < dec.len && dec.buf[dec.pos] != CBOR_BREAK) {
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
        
        blk.data = bp_alloc(blen);
        if (!blk.data) {
            free_blocks(blocks, block_cnt);
            goto fail;
        }
        memcpy(blk.data, bdata, blen);
        blk.data_len = blen;

        if (blk.crc_type != BP_CRC_NONE) cbor_skip(&dec);

        if (blk.type == BP_BLOCK_PAYLOAD) {
            bundle->payload = blk.data;
            bundle->payload_len = blk.data_len;
        } else {
            if (block_cnt >= block_cap) {
                size_t new_cap = block_cap ? block_cap * 2 : 4;
                bp_block_t *new_blocks = bp_realloc(blocks, new_cap * sizeof(bp_block_t));
                if (!new_blocks) {
                    bp_free(blk.data);
                    free_blocks(blocks, block_cnt);
                    goto fail;
                }
                blocks = new_blocks;
                block_cap = new_cap;
            }
            blocks[block_cnt++] = blk;
        }
    }

    bundle->blocks = blocks;
    bundle->block_count = block_cnt;

    cbor_decode_break(&dec);
    return dec.error ? -1 : 0;

fail:
    bp_bundle_full_free(bundle);
    return -1;
}

void bp_bundle_full_free(bp_bundle_full_t *bundle) {
    if (!bundle) return;
    bp_free(bundle->primary.dest_uri);
    bp_free(bundle->primary.source_uri);
    bp_free(bundle->primary.report_uri);
    for (size_t i = 0; i < bundle->block_count; i++) {
        bp_free(bundle->blocks[i].data);
    }
    bp_free(bundle->blocks);
    bp_free(bundle->payload);
    memset(bundle, 0, sizeof(*bundle));
}
