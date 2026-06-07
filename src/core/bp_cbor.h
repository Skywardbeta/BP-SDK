/* bp_cbor.h - CBOR encoder/decoder (RFC 8949) */
#ifndef BP_CBOR_H
#define BP_CBOR_H

#include <stdint.h>
#include <stddef.h>

#define CBOR_TYPE_UINT     0
#define CBOR_TYPE_NEGINT   1
#define CBOR_TYPE_BYTES    2
#define CBOR_TYPE_TEXT     3
#define CBOR_TYPE_ARRAY    4
#define CBOR_TYPE_MAP      5
#define CBOR_TYPE_TAG      6
#define CBOR_TYPE_SPECIAL  7

#define CBOR_BREAK         0xFF
#define CBOR_NULL          0xF6
#define CBOR_INDEF_ARRAY   0x9F
#define CBOR_INDEF_BYTES   0x5F

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int error;
} cbor_encoder_t;

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    int error;
} cbor_decoder_t;

void cbor_encoder_init(cbor_encoder_t *enc, uint8_t *buf, size_t cap);
int cbor_encode_uint(cbor_encoder_t *enc, uint64_t val);
int cbor_encode_negint(cbor_encoder_t *enc, uint64_t val);
int cbor_encode_bytes(cbor_encoder_t *enc, const uint8_t *data, size_t len);
int cbor_encode_text(cbor_encoder_t *enc, const char *str);
int cbor_encode_array(cbor_encoder_t *enc, size_t count);
int cbor_encode_indef_array_start(cbor_encoder_t *enc);
int cbor_encode_break(cbor_encoder_t *enc);
int cbor_encode_null(cbor_encoder_t *enc);

void cbor_decoder_init(cbor_decoder_t *dec, const uint8_t *buf, size_t len);
int cbor_peek_type(cbor_decoder_t *dec);
int cbor_decode_uint(cbor_decoder_t *dec, uint64_t *val);
int cbor_decode_bytes(cbor_decoder_t *dec, const uint8_t **data, size_t *len);
int cbor_decode_text(cbor_decoder_t *dec, const char **str, size_t *len);
int cbor_decode_array(cbor_decoder_t *dec, size_t *count);
int cbor_decode_indef_array_start(cbor_decoder_t *dec);
int cbor_decode_break(cbor_decoder_t *dec);
int cbor_skip(cbor_decoder_t *dec);

#endif
