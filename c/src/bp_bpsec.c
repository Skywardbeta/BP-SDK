/* bp_bpsec.c - BPSec with software SHA256/HMAC */
#include "bp_bpsec.h"
#include "bp_cbor.h"
#include "bp_utils.h"
#include <string.h>
#include <stdlib.h>

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;

    for (int i = 0; i < 16; i++)
        w[i] = (data[i*4] << 24) | (data[i*4+1] << 16) | (data[i*4+2] << 8) | data[i*4+3];
    for (int i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t block[64];
    size_t i;

    for (i = 0; i + 64 <= len; i += 64) sha256_transform(state, data + i);

    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        sha256_transform(state, block);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    uint64_t bits = len * 8;
    for (int j = 0; j < 8; j++) block[56 + j] = (bits >> (56 - j*8)) & 0xFF;
    sha256_transform(state, block);

    for (int j = 0; j < 8; j++) {
        hash[j*4] = (state[j] >> 24) & 0xFF;
        hash[j*4+1] = (state[j] >> 16) & 0xFF;
        hash[j*4+2] = (state[j] >> 8) & 0xFF;
        hash[j*4+3] = state[j] & 0xFF;
    }
}

int bpsec_sign_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t *sig, size_t *sig_len) {
    uint8_t k_pad[64], o_pad[64], i_hash[32];

    memset(k_pad, 0, 64);
    if (key_len > 64) sha256(key, key_len, k_pad);
    else memcpy(k_pad, key, key_len);

    for (int i = 0; i < 64; i++) o_pad[i] = k_pad[i] ^ 0x5c;
    for (int i = 0; i < 64; i++) k_pad[i] ^= 0x36;

    uint8_t *inner = bp_alloc(64 + data_len);
    memcpy(inner, k_pad, 64);
    memcpy(inner + 64, data, data_len);
    sha256(inner, 64 + data_len, i_hash);
    bp_free(inner);

    uint8_t outer[96];
    memcpy(outer, o_pad, 64);
    memcpy(outer + 64, i_hash, 32);
    sha256(outer, 96, sig);
    *sig_len = 32;
    return 0;
}

int bpsec_verify_hmac_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             const uint8_t *sig, size_t sig_len) {
    if (sig_len != 32) return -1;
    uint8_t computed[32]; size_t clen;
    bpsec_sign_hmac_sha256(key, key_len, data, data_len, computed, &clen);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ sig[i];
    return diff ? -1 : 0;
}

int bpsec_encrypt_aes_gcm(const uint8_t *key, const uint8_t *iv,
                          const uint8_t *plain, size_t plain_len,
                          const uint8_t *aad, size_t aad_len,
                          uint8_t *cipher, uint8_t *tag) {
    (void)key; (void)iv; (void)aad; (void)aad_len;
    memcpy(cipher, plain, plain_len);
    memset(tag, 0, 16);
    BP_LOG_WARN("AES-GCM not implemented");
    return 0;
}

int bpsec_decrypt_aes_gcm(const uint8_t *key, const uint8_t *iv,
                          const uint8_t *cipher, size_t cipher_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *tag, uint8_t *plain) {
    (void)key; (void)iv; (void)aad; (void)aad_len; (void)tag;
    memcpy(plain, cipher, cipher_len);
    BP_LOG_WARN("AES-GCM not implemented");
    return 0;
}

int bpsec_block_encode(const bpsec_block_t *block, uint8_t *out, size_t cap) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, out, cap);

    cbor_encode_array(&enc, 5);
    cbor_encode_array(&enc, block->target_count);
    for (size_t i = 0; i < block->target_count; i++)
        cbor_encode_uint(&enc, block->targets[i]);
    cbor_encode_uint(&enc, block->context_id);
    cbor_encode_uint(&enc, block->context_flags);

    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 2);
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, block->source_node);
    cbor_encode_uint(&enc, block->source_service);

    cbor_encode_array(&enc, block->result_count);
    for (size_t i = 0; i < block->result_count; i++) {
        cbor_encode_array(&enc, 1);
        cbor_encode_array(&enc, 2);
        cbor_encode_uint(&enc, 1);
        cbor_encode_bytes(&enc, block->results[i].data, block->results[i].len);
    }

    return enc.error ? -1 : (int)enc.len;
}

int bpsec_block_decode(const uint8_t *data, size_t len, bpsec_block_t *block) {
    (void)data; (void)len; (void)block;
    return -1;
}

void bpsec_block_free(bpsec_block_t *block) {
    if (!block) return;
    bp_free(block->targets);
    for (size_t i = 0; i < block->result_count; i++) bp_free(block->results[i].data);
    bp_free(block->results);
    memset(block, 0, sizeof(*block));
}
