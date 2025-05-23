#ifndef AES_C_FULL_H
#define AES_C_FULL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define AES128KS 0x80
#define AES192KS 0xC0
#define AES256KS 0x100
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12
#define AES256_ROUNDS 14
#define AES_BLOCK_SIZE 16

typedef uint8_t byte;

/* ===================== PRNG (Mersenne Twister) ===================== */
#define PRNG_N 624
#define PRNG_M 397
#define PRNG_MATRIX_A 0x9908b0dfUL
#define PRNG_UPPER_MASK 0x80000000UL
#define PRNG_LOWER_MASK 0x7fffffffUL

typedef struct {
    uint32_t mt[PRNG_N];
    int mti;
} PRNG;

void prng_init(PRNG *prng, uint32_t seed) {
    prng->mt[0] = seed;
    for (prng->mti = 1; prng->mti < PRNG_N; prng->mti++) {
        prng->mt[prng->mti] = (1812433253UL * (prng->mt[prng->mti - 1] ^ (prng->mt[prng->mti - 1] >> 30)) + prng->mti);
    }
}

uint32_t prng_rand(PRNG *prng, uint32_t min, uint32_t max) {
    uint32_t y;
    static const uint32_t mag01[2] = {0x0UL, PRNG_MATRIX_A};
    int kk;

    if (prng->mti >= PRNG_N) {
        for (kk = 0; kk < PRNG_N - PRNG_M; kk++) {
            y = (prng->mt[kk] & PRNG_UPPER_MASK) | (prng->mt[kk + 1] & PRNG_LOWER_MASK);
            prng->mt[kk] = prng->mt[kk + PRNG_M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        for (; kk < PRNG_N - 1; kk++) {
            y = (prng->mt[kk] & PRNG_UPPER_MASK) | (prng->mt[kk + 1] & PRNG_LOWER_MASK);
            prng->mt[kk] = prng->mt[kk + (PRNG_M - PRNG_N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        y = (prng->mt[PRNG_N - 1] & PRNG_UPPER_MASK) | (prng->mt[0] & PRNG_LOWER_MASK);
        prng->mt[PRNG_N - 1] = prng->mt[PRNG_M - 1] ^ (y >> 1) ^ mag01[y & 0x1UL];
        prng->mti = 0;
    }
    y = prng->mt[prng->mti++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    return min + (y % (max - min + 1));
}

/* ===================== Galois Field & S-Box ===================== */
byte gf_mul(byte a, byte b) {
    byte p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        byte hiBitSet = a & 0x80;
        a <<= 1;
        if (hiBitSet) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

byte gf_inv(byte x) {
    byte y = x;
    for (int i = 0; i < 4; ++i) {
        y = gf_mul(y, y);
        y = gf_mul(y, x);
    }
    return y;
}

byte affine_transform(byte x) {
    byte result = 0x63;
    for (int i = 0; i < 8; ++i) {
        if ((x >> i) & 1)
            result ^= (0xF1 >> (7 - i)) & 0xFF;
    }
    return result;
}

byte sbox_entry(byte x) {
    return affine_transform(gf_inv(x));
}

void create_sbox(byte sbox[256]) {
    for (int i = 0; i < 256; ++i)
        sbox[i] = sbox_entry((byte)i);
}

void create_invsbox(const byte sbox[256], byte invsbox[256]) {
    for (int i = 0; i < 256; ++i)
        invsbox[sbox[i]] = (byte)i;
}

void create_rcon(byte rcon[256]) {
    byte c = 1;
    for (int i = 0; i < 256; ++i) {
        rcon[i] = c;
        c = gf_mul(c, 0x02);
    }
}

/* ===================== AES Context & Key Expansion ===================== */
typedef struct {
    int Nk, Nr, Nb;
    byte round_keys[240]; // supports up to AES-256
    byte sbox[256];
    byte inv_sbox[256];
    byte rcon[256];
} aes_ctx;

void aes_init(aes_ctx *ctx, int key_size) {
    ctx->Nb = 4;
    if (key_size == AES128KS)      { ctx->Nk = 4; ctx->Nr = 10; }
    else if (key_size == AES192KS) { ctx->Nk = 6; ctx->Nr = 12; }
    else if (key_size == AES256KS) { ctx->Nk = 8; ctx->Nr = 14; }
    else { ctx->Nk = 4; ctx->Nr = 10; }
    create_sbox(ctx->sbox);
    create_invsbox(ctx->sbox, ctx->inv_sbox);
    create_rcon(ctx->rcon);
}

void aes_key_expansion(aes_ctx *ctx, const byte *key) {
    int i = 0, Nk = ctx->Nk, Nb = ctx->Nb, Nr = ctx->Nr;
    byte temp[4];
    byte *w = ctx->round_keys;
    for (; i < Nk; ++i) {
        w[4*i+0] = key[4*i+0];
        w[4*i+1] = key[4*i+1];
        w[4*i+2] = key[4*i+2];
        w[4*i+3] = key[4*i+3];
    }
    for (; i < Nb*(Nr+1); ++i) {
        temp[0] = w[4*(i-1)+0];
        temp[1] = w[4*(i-1)+1];
        temp[2] = w[4*(i-1)+2];
        temp[3] = w[4*(i-1)+3];
        if (i % Nk == 0) {
            byte t = temp[0];
            temp[0] = ctx->sbox[temp[1]] ^ ctx->rcon[i/Nk];
            temp[1] = ctx->sbox[temp[2]];
            temp[2] = ctx->sbox[temp[3]];
            temp[3] = ctx->sbox[t];
        } else if (Nk > 6 && (i % Nk == 4)) {
            temp[0] = ctx->sbox[temp[0]];
            temp[1] = ctx->sbox[temp[1]];
            temp[2] = ctx->sbox[temp[2]];
            temp[3] = ctx->sbox[temp[3]];
        }
        w[4*i+0] = w[4*(i-Nk)+0] ^ temp[0];
        w[4*i+1] = w[4*(i-Nk)+1] ^ temp[1];
        w[4*i+2] = w[4*(i-Nk)+2] ^ temp[2];
        w[4*i+3] = w[4*(i-Nk)+3] ^ temp[3];
    }
}

/* ===================== Block Routines ===================== */
void aes_add_round_key(byte state[4][4], const byte *rk) {
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            state[r][c] ^= rk[4*c+r];
}

void aes_sub_bytes(byte state[4][4], const byte sbox[256]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = sbox[state[r][c]];
}

void aes_inv_sub_bytes(byte state[4][4], const byte invsbox[256]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = invsbox[state[r][c]];
}

void aes_shift_rows(byte state[4][4]) {
    byte t;
    // row 1
    t = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;
    // row 2
    t = state[2][0]; byte t2 = state[2][1];
    state[2][0] = state[2][2]; state[2][1] = state[2][3];
    state[2][2] = t; state[2][3] = t2;
    // row 3
    t = state[3][3];
    state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;
}

void aes_inv_shift_rows(byte state[4][4]) {
    byte t;
    // row 1
    t = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t;
    // row 2
    t = state[2][0]; byte t2 = state[2][1];
    state[2][0] = state[2][2]; state[2][1] = state[2][3];
    state[2][2] = t; state[2][3] = t2;
    // row 3
    t = state[3][0];
    state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t;
}

void aes_mix_columns(byte state[4][4]) {
    for (int c = 0; c < 4; ++c) {
        byte a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
        state[0][c] = gf_mul(a0,2) ^ gf_mul(a1,3) ^ a2 ^ a3;
        state[1][c] = a0 ^ gf_mul(a1,2) ^ gf_mul(a2,3) ^ a3;
        state[2][c] = a0 ^ a1 ^ gf_mul(a2,2) ^ gf_mul(a3,3);
        state[3][c] = gf_mul(a0,3) ^ a1 ^ a2 ^ gf_mul(a3,2);
    }
}

void aes_inv_mix_columns(byte state[4][4]) {
    for (int c = 0; c < 4; ++c) {
        byte a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
        state[0][c] = gf_mul(a0,0x0e) ^ gf_mul(a1,0x0b) ^ gf_mul(a2,0x0d) ^ gf_mul(a3,0x09);
        state[1][c] = gf_mul(a0,0x09) ^ gf_mul(a1,0x0e) ^ gf_mul(a2,0x0b) ^ gf_mul(a3,0x0d);
        state[2][c] = gf_mul(a0,0x0d) ^ gf_mul(a1,0x09) ^ gf_mul(a2,0x0e) ^ gf_mul(a3,0x0b);
        state[3][c] = gf_mul(a0,0x0b) ^ gf_mul(a1,0x0d) ^ gf_mul(a2,0x09) ^ gf_mul(a3,0x0e);
    }
}

void aes_encrypt_block(aes_ctx *ctx, const byte in[16], byte out[16]) {
    byte state[4][4];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = in[r + 4*c];
    aes_add_round_key(state, ctx->round_keys);
    for (int round = 1; round < ctx->Nr; ++round) {
        aes_sub_bytes(state, ctx->sbox);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, ctx->round_keys + 16*round);
    }
    aes_sub_bytes(state, ctx->sbox);
    aes_shift_rows(state);
    aes_add_round_key(state, ctx->round_keys + 16*ctx->Nr);
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[r + 4*c] = state[r][c];
}

void aes_decrypt_block(aes_ctx *ctx, const byte in[16], byte out[16]) {
    byte state[4][4];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = in[r + 4*c];
    aes_add_round_key(state, ctx->round_keys + 16*ctx->Nr);
    for (int round = ctx->Nr-1; round >= 1; --round) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state, ctx->inv_sbox);
        aes_add_round_key(state, ctx->round_keys + 16*round);
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state, ctx->inv_sbox);
    aes_add_round_key(state, ctx->round_keys);
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[r + 4*c] = state[r][c];
}

/* ===================== PKCS7 Padding ===================== */
size_t pkcs7_pad(byte *buf, size_t len, size_t block_size) {
    size_t pad = block_size - (len % block_size);
    for (size_t i = 0; i < pad; ++i)
        buf[len+i] = (byte)pad;
    return len+pad;
}
size_t pkcs7_unpad(byte *buf, size_t len) {
    if (!len) return 0;
    byte pad = buf[len-1];
    if (pad > AES_BLOCK_SIZE) return len;
    return len - pad;
}

/* ===================== Key/IV Generation ===================== */
void aes_gen_key(byte *key, size_t key_size) {
    PRNG prng; prng_init(&prng, (uint32_t)time(NULL));
    for (size_t i = 0; i < key_size; ++i)
        key[i] = (byte)prng_rand(&prng, 0, 255);
}
void aes_gen_iv(byte *iv, size_t size) {
    PRNG prng; prng_init(&prng, (uint32_t)time(NULL));
    for (size_t i = 0; i < size; ++i)
        iv[i] = (byte)prng_rand(&prng, 0, 255);
}

/* ===================== MODE IMPLEMENTATIONS ===================== */

/* ------- ECB ------- */
void aes_ecb_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len) {
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
        aes_encrypt_block(ctx, in+i, out+i);
}
void aes_ecb_decrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len) {
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
        aes_decrypt_block(ctx, in+i, out+i);
}

/* ------- CBC ------- */
void aes_cbc_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) {
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte block[16];
        for (int j = 0; j < 16; ++j)
            block[j] = in[i+j] ^ prev[j];
        aes_encrypt_block(ctx, block, out+i);
        memcpy(prev, out+i, 16);
    }
}
void aes_cbc_decrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) {
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte block[16];
        aes_decrypt_block(ctx, in+i, block);
        for (int j = 0; j < 16; ++j)
            out[i+j] = block[j] ^ prev[j];
        memcpy(prev, in+i, 16);
    }
}

/* ------- CFB ------- */
void aes_cfb_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) {
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[16];
        aes_encrypt_block(ctx, prev, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        memcpy(prev, out + i, 16);
    }
}
void aes_cfb_decrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) {
    byte prev[16];
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[16];
        aes_encrypt_block(ctx, prev, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        memcpy(prev, in + i, 16);
    }
}

/* ------- OFB ------- */
void aes_ofb_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte iv[16]) {
    byte feedback[16];
    memcpy(feedback, iv, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[16];
        aes_encrypt_block(ctx, feedback, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        memcpy(feedback, keystream, 16);
    }
}
#define aes_ofb_decrypt aes_ofb_encrypt

/* ------- CTR ------- */
static void increment_counter(byte counter[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i]) break;
    }
}
void aes_ctr_encrypt(aes_ctx *ctx, const byte *in, byte *out, size_t len, byte nonce[16]) {
    byte counter[16];
    memcpy(counter, nonce, 16);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        byte keystream[16];
        aes_encrypt_block(ctx, counter, keystream);
        for (size_t j = 0; j < AES_BLOCK_SIZE && i + j < len; ++j)
            out[i + j] = in[i + j] ^ keystream[j];
        increment_counter(counter);
    }
}
#define aes_ctr_decrypt aes_ctr_encrypt

#endif
