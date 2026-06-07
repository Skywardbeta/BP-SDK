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
        w[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) | 
               ((uint32_t)data[i*4+2] << 8) | data[i*4+3];
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
    for (int j = 0; j < 8; j++) block[56 + j] = (uint8_t)((bits >> (56 - j*8)) & 0xFF);
    sha256_transform(state, block);

    for (int j = 0; j < 8; j++) {
        hash[j*4] = (uint8_t)((state[j] >> 24) & 0xFF);
        hash[j*4+1] = (uint8_t)((state[j] >> 16) & 0xFF);
        hash[j*4+2] = (uint8_t)((state[j] >> 8) & 0xFF);
        hash[j*4+3] = (uint8_t)(state[j] & 0xFF);
    }
}

int bpsec_sign_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t *sig, size_t *sig_len) {
    if (!key || !data || !sig || !sig_len) return -1;
    
    uint8_t k_pad[64], o_pad[64], i_hash[32];

    memset(k_pad, 0, 64);
    if (key_len > 64) sha256(key, key_len, k_pad);
    else memcpy(k_pad, key, key_len);

    for (int i = 0; i < 64; i++) o_pad[i] = k_pad[i] ^ 0x5c;
    for (int i = 0; i < 64; i++) k_pad[i] ^= 0x36;

    uint8_t *inner = bp_alloc(64 + data_len);
    if (!inner) return -1;
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
    uint8_t computed[32]; 
    size_t clen;
    if (bpsec_sign_hmac_sha256(key, key_len, data, data_len, computed, &clen) != 0) return -1;
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ sig[i];
    return diff ? -1 : 0;
}

static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t AES_RCON[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void aes_key_expand(const uint8_t *key, uint32_t *w, int nk, int nr) {
    for (int i = 0; i < nk; i++) {
        w[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
               ((uint32_t)key[4*i+2] << 8) | key[4*i+3];
    }
    for (int i = nk; i < 4 * (nr + 1); i++) {
        uint32_t tmp = w[i - 1];
        if (i % nk == 0) {
            tmp = ((uint32_t)AES_SBOX[(tmp >> 16) & 0xff] << 24) |
                  ((uint32_t)AES_SBOX[(tmp >> 8) & 0xff] << 16) |
                  ((uint32_t)AES_SBOX[tmp & 0xff] << 8) |
                  AES_SBOX[(tmp >> 24) & 0xff];
            tmp ^= (uint32_t)AES_RCON[i / nk] << 24;
        } else if (nk > 6 && i % nk == 4) {
            tmp = ((uint32_t)AES_SBOX[(tmp >> 24) & 0xff] << 24) |
                  ((uint32_t)AES_SBOX[(tmp >> 16) & 0xff] << 16) |
                  ((uint32_t)AES_SBOX[(tmp >> 8) & 0xff] << 8) |
                  AES_SBOX[tmp & 0xff];
        }
        w[i] = w[i - nk] ^ tmp;
    }
}

static void aes_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t *w, int nr) {
    uint8_t s[16];
    memcpy(s, in, 16);
    
    for (int i = 0; i < 4; i++) {
        s[i*4]   ^= (uint8_t)(w[i] >> 24);
        s[i*4+1] ^= (uint8_t)(w[i] >> 16);
        s[i*4+2] ^= (uint8_t)(w[i] >> 8);
        s[i*4+3] ^= (uint8_t)w[i];
    }
    
    for (int round = 1; round <= nr; round++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = AES_SBOX[s[i]];
        
        uint8_t tmp = t[1]; t[1] = t[5]; t[5] = t[9]; t[9] = t[13]; t[13] = tmp;
        tmp = t[2]; t[2] = t[10]; t[10] = tmp; tmp = t[6]; t[6] = t[14]; t[14] = tmp;
        tmp = t[15]; t[15] = t[11]; t[11] = t[7]; t[7] = t[3]; t[3] = tmp;
        
        if (round < nr) {
            for (int i = 0; i < 4; i++) {
                uint8_t a0 = t[i*4], a1 = t[i*4+1], a2 = t[i*4+2], a3 = t[i*4+3];
                s[i*4]   = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
                s[i*4+1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
                s[i*4+2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
                s[i*4+3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
            }
        } else {
            memcpy(s, t, 16);
        }
        
        for (int i = 0; i < 4; i++) {
            s[i*4]   ^= (uint8_t)(w[round*4 + i] >> 24);
            s[i*4+1] ^= (uint8_t)(w[round*4 + i] >> 16);
            s[i*4+2] ^= (uint8_t)(w[round*4 + i] >> 8);
            s[i*4+3] ^= (uint8_t)w[round*4 + i];
        }
    }
    memcpy(out, s, 16);
}

static void gcm_gf_mul(uint8_t *x, const uint8_t *h) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16);
    
    for (int i = 0; i < 128; i++) {
        if ((x[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        }
        uint8_t lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = (v[j] >> 1) | (v[j-1] << 7);
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    memcpy(x, z, 16);
}

static void gcm_ghash(const uint8_t *h, const uint8_t *data, size_t len, uint8_t *out) {
    memset(out, 0, 16);
    size_t i = 0;
    for (; i + 16 <= len; i += 16) {
        for (int j = 0; j < 16; j++) out[j] ^= data[i + j];
        gcm_gf_mul(out, h);
    }
    if (i < len) {
        for (size_t j = 0; j < len - i; j++) out[j] ^= data[i + j];
        gcm_gf_mul(out, h);
    }
}

static void inc32(uint8_t *block) {
    for (int i = 15; i >= 12; i--) {
        if (++block[i]) break;
    }
}

int bpsec_encrypt_aes_gcm(const uint8_t *key, size_t key_len, const uint8_t *iv,
                          const uint8_t *plain, size_t plain_len,
                          const uint8_t *aad, size_t aad_len,
                          uint8_t *cipher, uint8_t *tag) {
    if (!key || !iv || !cipher || !tag) return -1;
    if (key_len != BPSEC_AES256_KEY_LEN) return -1;
    if (plain_len > 0 && !plain) return -1;
    
    uint32_t w[60];
    aes_key_expand(key, w, 8, 14);
    
    uint8_t h[16] = {0};
    aes_encrypt_block(h, h, w, 14);
    
    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    
    uint8_t ctr[16];
    memcpy(ctr, j0, 16);
    
    for (size_t i = 0; i < plain_len; i += 16) {
        inc32(ctr);
        uint8_t ks[16];
        aes_encrypt_block(ctr, ks, w, 14);
        size_t chunk = (plain_len - i < 16) ? plain_len - i : 16;
        for (size_t j = 0; j < chunk; j++) cipher[i + j] = plain[i + j] ^ ks[j];
    }
    
    size_t aad_padded = ((aad_len + 15) / 16) * 16;
    size_t ct_padded = ((plain_len + 15) / 16) * 16;
    size_t ghash_len = aad_padded + ct_padded + 16;
    
    uint8_t *ghash_input = bp_alloc(ghash_len);
    if (!ghash_input) return -1;
    memset(ghash_input, 0, ghash_len);
    
    if (aad && aad_len > 0) memcpy(ghash_input, aad, aad_len);
    if (plain_len > 0) memcpy(ghash_input + aad_padded, cipher, plain_len);
    
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = plain_len * 8;
    for (int i = 0; i < 8; i++) {
        ghash_input[ghash_len - 16 + i] = (uint8_t)(aad_bits >> (56 - i * 8));
        ghash_input[ghash_len - 8 + i] = (uint8_t)(ct_bits >> (56 - i * 8));
    }
    
    uint8_t s[16];
    gcm_ghash(h, ghash_input, ghash_len, s);
    bp_free(ghash_input);
    
    uint8_t ek_j0[16];
    aes_encrypt_block(j0, ek_j0, w, 14);
    for (int i = 0; i < 16; i++) tag[i] = s[i] ^ ek_j0[i];
    
    return 0;
}

int bpsec_decrypt_aes_gcm(const uint8_t *key, size_t key_len, const uint8_t *iv,
                          const uint8_t *cipher, size_t cipher_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *tag, uint8_t *plain) {
    if (!key || !iv || !tag || !plain) return -1;
    if (key_len != BPSEC_AES256_KEY_LEN) return -1;
    if (cipher_len > 0 && !cipher) return -1;
    
    uint32_t w[60];
    aes_key_expand(key, w, 8, 14);
    
    uint8_t h[16] = {0};
    aes_encrypt_block(h, h, w, 14);
    
    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    
    size_t aad_padded = ((aad_len + 15) / 16) * 16;
    size_t ct_padded = ((cipher_len + 15) / 16) * 16;
    size_t ghash_len = aad_padded + ct_padded + 16;
    
    uint8_t *ghash_input = bp_alloc(ghash_len);
    if (!ghash_input) return -1;
    memset(ghash_input, 0, ghash_len);
    
    if (aad && aad_len > 0) memcpy(ghash_input, aad, aad_len);
    if (cipher_len > 0) memcpy(ghash_input + aad_padded, cipher, cipher_len);
    
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = cipher_len * 8;
    for (int i = 0; i < 8; i++) {
        ghash_input[ghash_len - 16 + i] = (uint8_t)(aad_bits >> (56 - i * 8));
        ghash_input[ghash_len - 8 + i] = (uint8_t)(ct_bits >> (56 - i * 8));
    }
    
    uint8_t s[16];
    gcm_ghash(h, ghash_input, ghash_len, s);
    bp_free(ghash_input);
    
    uint8_t ek_j0[16];
    aes_encrypt_block(j0, ek_j0, w, 14);
    
    uint8_t computed_tag[16];
    for (int i = 0; i < 16; i++) computed_tag[i] = s[i] ^ ek_j0[i];
    
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    if (diff) return -1;
    
    uint8_t ctr[16];
    memcpy(ctr, j0, 16);
    
    for (size_t i = 0; i < cipher_len; i += 16) {
        inc32(ctr);
        uint8_t ks[16];
        aes_encrypt_block(ctr, ks, w, 14);
        size_t chunk = (cipher_len - i < 16) ? cipher_len - i : 16;
        for (size_t j = 0; j < chunk; j++) plain[i + j] = cipher[i + j] ^ ks[j];
    }
    
    return 0;
}

int bpsec_block_encode(const bpsec_block_t *block, uint8_t *out, size_t cap) {
    if (!block || !out) return -1;
    
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
    if (!data || !block) return -1;
    
    memset(block, 0, sizeof(*block));
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, data, len);
    
    size_t arr_len;
    if (cbor_decode_array(&dec, &arr_len) < 0 || arr_len != 5) return -1;
    
    size_t target_count;
    if (cbor_decode_array(&dec, &target_count) < 0) return -1;
    
    block->target_count = target_count;
    if (target_count > 0) {
        block->targets = bp_alloc(sizeof(uint64_t) * target_count);
        if (!block->targets) return -1;
        for (size_t i = 0; i < target_count; i++) {
            if (cbor_decode_uint(&dec, &block->targets[i]) < 0) {
                bp_free(block->targets);
                return -1;
            }
        }
    }
    
    uint64_t ctx_id;
    if (cbor_decode_uint(&dec, &ctx_id) < 0) {
        bp_free(block->targets);
        return -1;
    }
    block->context_id = (uint8_t)ctx_id;
    
    if (cbor_decode_uint(&dec, &block->context_flags) < 0) {
        bp_free(block->targets);
        return -1;
    }
    
    size_t source_arr_len;
    if (cbor_decode_array(&dec, &source_arr_len) < 0 || source_arr_len != 2) {
        bp_free(block->targets);
        return -1;
    }
    
    uint64_t source_type;
    if (cbor_decode_uint(&dec, &source_type) < 0 || source_type != 2) {
        bp_free(block->targets);
        return -1;
    }
    
    size_t eid_arr_len;
    if (cbor_decode_array(&dec, &eid_arr_len) < 0 || eid_arr_len != 2) {
        bp_free(block->targets);
        return -1;
    }
    
    if (cbor_decode_uint(&dec, &block->source_node) < 0) {
        bp_free(block->targets);
        return -1;
    }
    if (cbor_decode_uint(&dec, &block->source_service) < 0) {
        bp_free(block->targets);
        return -1;
    }
    
    size_t result_count;
    if (cbor_decode_array(&dec, &result_count) < 0) {
        bp_free(block->targets);
        return -1;
    }
    
    block->result_count = result_count;
    if (result_count > 0) {
        block->results = bp_alloc(sizeof(bpsec_result_t) * result_count);
        if (!block->results) {
            bp_free(block->targets);
            return -1;
        }
        memset(block->results, 0, sizeof(bpsec_result_t) * result_count);
        
        for (size_t i = 0; i < result_count; i++) {
            size_t res_arr_len;
            if (cbor_decode_array(&dec, &res_arr_len) < 0 || res_arr_len != 1) {
                bpsec_block_free(block);
                return -1;
            }
            
            size_t tuple_len;
            if (cbor_decode_array(&dec, &tuple_len) < 0 || tuple_len != 2) {
                bpsec_block_free(block);
                return -1;
            }
            
            uint64_t result_type;
            if (cbor_decode_uint(&dec, &result_type) < 0) {
                bpsec_block_free(block);
                return -1;
            }
            
            const uint8_t *bytes_data;
            size_t bytes_len;
            if (cbor_decode_bytes(&dec, &bytes_data, &bytes_len) < 0) {
                bpsec_block_free(block);
                return -1;
            }
            
            block->results[i].len = bytes_len;
            if (bytes_len > 0) {
                block->results[i].data = bp_alloc(bytes_len);
                if (!block->results[i].data) {
                    bpsec_block_free(block);
                    return -1;
                }
                memcpy(block->results[i].data, bytes_data, bytes_len);
            }
        }
    }
    
    return 0;
}

void bpsec_block_free(bpsec_block_t *block) {
    if (!block) return;
    bp_free(block->targets);
    for (size_t i = 0; i < block->result_count; i++) bp_free(block->results[i].data);
    bp_free(block->results);
    memset(block, 0, sizeof(*block));
}
