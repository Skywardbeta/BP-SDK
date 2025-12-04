/* bp_cbor.c - CBOR encoder/decoder */
#include "bp_cbor.h"
#include <string.h>

static int enc_write(cbor_encoder_t *enc, const uint8_t *data, size_t len) {
    if (enc->error) return -1;
    if (enc->len + len > enc->cap) { enc->error = 1; return -1; }
    memcpy(enc->buf + enc->len, data, len);
    enc->len += len;
    return 0;
}

static int enc_head(cbor_encoder_t *enc, uint8_t type, uint64_t val) {
    uint8_t major = type << 5;
    uint8_t hdr[9];
    size_t hdr_len;

    if (val < 24) {
        hdr[0] = major | (uint8_t)val; hdr_len = 1;
    } else if (val <= 0xFF) {
        hdr[0] = major | 24; hdr[1] = (uint8_t)val; hdr_len = 2;
    } else if (val <= 0xFFFF) {
        hdr[0] = major | 25;
        hdr[1] = (uint8_t)(val >> 8); hdr[2] = (uint8_t)val; hdr_len = 3;
    } else if (val <= 0xFFFFFFFF) {
        hdr[0] = major | 26;
        hdr[1] = (uint8_t)(val >> 24); hdr[2] = (uint8_t)(val >> 16);
        hdr[3] = (uint8_t)(val >> 8); hdr[4] = (uint8_t)val; hdr_len = 5;
    } else {
        hdr[0] = major | 27;
        hdr[1] = (uint8_t)(val >> 56); hdr[2] = (uint8_t)(val >> 48);
        hdr[3] = (uint8_t)(val >> 40); hdr[4] = (uint8_t)(val >> 32);
        hdr[5] = (uint8_t)(val >> 24); hdr[6] = (uint8_t)(val >> 16);
        hdr[7] = (uint8_t)(val >> 8); hdr[8] = (uint8_t)val; hdr_len = 9;
    }
    return enc_write(enc, hdr, hdr_len);
}

void cbor_encoder_init(cbor_encoder_t *enc, uint8_t *buf, size_t cap) {
    enc->buf = buf; enc->cap = cap; enc->len = 0; enc->error = 0;
}

int cbor_encode_uint(cbor_encoder_t *enc, uint64_t val) { return enc_head(enc, CBOR_TYPE_UINT, val); }
int cbor_encode_negint(cbor_encoder_t *enc, uint64_t val) { return enc_head(enc, CBOR_TYPE_NEGINT, val); }

int cbor_encode_bytes(cbor_encoder_t *enc, const uint8_t *data, size_t len) {
    if (enc_head(enc, CBOR_TYPE_BYTES, len) < 0) return -1;
    return enc_write(enc, data, len);
}

int cbor_encode_text(cbor_encoder_t *enc, const char *str) {
    size_t len = str ? strlen(str) : 0;
    if (enc_head(enc, CBOR_TYPE_TEXT, len) < 0) return -1;
    return enc_write(enc, (const uint8_t *)str, len);
}

int cbor_encode_array(cbor_encoder_t *enc, size_t count) { return enc_head(enc, CBOR_TYPE_ARRAY, count); }
int cbor_encode_indef_array_start(cbor_encoder_t *enc) { uint8_t b = CBOR_INDEF_ARRAY; return enc_write(enc, &b, 1); }
int cbor_encode_break(cbor_encoder_t *enc) { uint8_t b = CBOR_BREAK; return enc_write(enc, &b, 1); }
int cbor_encode_null(cbor_encoder_t *enc) { uint8_t b = CBOR_NULL; return enc_write(enc, &b, 1); }

void cbor_decoder_init(cbor_decoder_t *dec, const uint8_t *buf, size_t len) {
    dec->buf = buf; dec->len = len; dec->pos = 0; dec->error = 0;
}

int cbor_peek_type(cbor_decoder_t *dec) {
    if (dec->error || dec->pos >= dec->len) return -1;
    return dec->buf[dec->pos] >> 5;
}

static int dec_head(cbor_decoder_t *dec, uint8_t *type, uint64_t *val) {
    if (dec->error || dec->pos >= dec->len) { dec->error = 1; return -1; }

    uint8_t first = dec->buf[dec->pos++];
    *type = first >> 5;
    uint8_t info = first & 0x1F;

    if (info < 24) { *val = info; }
    else if (info == 24) {
        if (dec->pos + 1 > dec->len) { dec->error = 1; return -1; }
        *val = dec->buf[dec->pos++];
    } else if (info == 25) {
        if (dec->pos + 2 > dec->len) { dec->error = 1; return -1; }
        *val = ((uint64_t)dec->buf[dec->pos] << 8) | dec->buf[dec->pos + 1];
        dec->pos += 2;
    } else if (info == 26) {
        if (dec->pos + 4 > dec->len) { dec->error = 1; return -1; }
        *val = ((uint64_t)dec->buf[dec->pos] << 24) | ((uint64_t)dec->buf[dec->pos + 1] << 16) |
               ((uint64_t)dec->buf[dec->pos + 2] << 8) | dec->buf[dec->pos + 3];
        dec->pos += 4;
    } else if (info == 27) {
        if (dec->pos + 8 > dec->len) { dec->error = 1; return -1; }
        *val = ((uint64_t)dec->buf[dec->pos] << 56) | ((uint64_t)dec->buf[dec->pos + 1] << 48) |
               ((uint64_t)dec->buf[dec->pos + 2] << 40) | ((uint64_t)dec->buf[dec->pos + 3] << 32) |
               ((uint64_t)dec->buf[dec->pos + 4] << 24) | ((uint64_t)dec->buf[dec->pos + 5] << 16) |
               ((uint64_t)dec->buf[dec->pos + 6] << 8) | dec->buf[dec->pos + 7];
        dec->pos += 8;
    } else if (info == 31) { *val = (uint64_t)-1; }
    else { dec->error = 1; return -1; }
    return 0;
}

int cbor_decode_uint(cbor_decoder_t *dec, uint64_t *val) {
    uint8_t type;
    if (dec_head(dec, &type, val) < 0) return -1;
    if (type != CBOR_TYPE_UINT) { dec->error = 1; return -1; }
    return 0;
}

int cbor_decode_bytes(cbor_decoder_t *dec, const uint8_t **data, size_t *len) {
    uint8_t type; uint64_t blen;
    if (dec_head(dec, &type, &blen) < 0) return -1;
    if (type != CBOR_TYPE_BYTES) { dec->error = 1; return -1; }
    if (dec->pos + blen > dec->len) { dec->error = 1; return -1; }
    *data = dec->buf + dec->pos; *len = (size_t)blen;
    dec->pos += blen;
    return 0;
}

int cbor_decode_text(cbor_decoder_t *dec, const char **str, size_t *len) {
    uint8_t type; uint64_t slen;
    if (dec_head(dec, &type, &slen) < 0) return -1;
    if (type != CBOR_TYPE_TEXT) { dec->error = 1; return -1; }
    if (dec->pos + slen > dec->len) { dec->error = 1; return -1; }
    *str = (const char *)(dec->buf + dec->pos); *len = (size_t)slen;
    dec->pos += slen;
    return 0;
}

int cbor_decode_array(cbor_decoder_t *dec, size_t *count) {
    uint8_t type; uint64_t cnt;
    if (dec_head(dec, &type, &cnt) < 0) return -1;
    if (type != CBOR_TYPE_ARRAY) { dec->error = 1; return -1; }
    *count = (cnt == (uint64_t)-1) ? (size_t)-1 : (size_t)cnt;
    return 0;
}

int cbor_decode_indef_array_start(cbor_decoder_t *dec) {
    if (dec->pos >= dec->len || dec->buf[dec->pos] != CBOR_INDEF_ARRAY) { dec->error = 1; return -1; }
    dec->pos++; return 0;
}

int cbor_decode_break(cbor_decoder_t *dec) {
    if (dec->pos >= dec->len || dec->buf[dec->pos] != CBOR_BREAK) { dec->error = 1; return -1; }
    dec->pos++; return 0;
}

int cbor_skip(cbor_decoder_t *dec) {
    if (dec->error || dec->pos >= dec->len) return -1;

    uint8_t first = dec->buf[dec->pos];
    if (first == CBOR_BREAK) return 0;

    uint8_t type; uint64_t val;
    if (dec_head(dec, &type, &val) < 0) return -1;

    switch (type) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT:
        case CBOR_TYPE_SPECIAL:
            break;
        case CBOR_TYPE_BYTES:
        case CBOR_TYPE_TEXT:
            if (dec->pos + val > dec->len) { dec->error = 1; return -1; }
            dec->pos += val;
            break;
        case CBOR_TYPE_ARRAY:
            if (val == (uint64_t)-1) {
                while (dec->buf[dec->pos] != CBOR_BREAK) { if (cbor_skip(dec) < 0) return -1; }
                dec->pos++;
            } else {
                for (uint64_t i = 0; i < val; i++) { if (cbor_skip(dec) < 0) return -1; }
            }
            break;
        case CBOR_TYPE_MAP:
            if (val == (uint64_t)-1) {
                while (dec->buf[dec->pos] != CBOR_BREAK) {
                    if (cbor_skip(dec) < 0) return -1;
                    if (cbor_skip(dec) < 0) return -1;
                }
                dec->pos++;
            } else {
                for (uint64_t i = 0; i < val * 2; i++) { if (cbor_skip(dec) < 0) return -1; }
            }
            break;
        case CBOR_TYPE_TAG:
            if (cbor_skip(dec) < 0) return -1;
            break;
        default:
            dec->error = 1; return -1;
    }
    return 0;
}
