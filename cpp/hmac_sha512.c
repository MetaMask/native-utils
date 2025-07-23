/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 *
 * Copyright (C) 2005-2023 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The original source code is available at:
 * https://github.com/ogay/sha2/tree/master
 */

#include "hmac_sha512.h"
#include <string.h>

/* SHA-512 constants */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* SHA-512 context */
typedef struct {
    uint64_t h[8];           /* hash state */
    uint64_t length;         /* message length */
    uint32_t curlen;         /* length of current message block */
    uint8_t buf[128];        /* message block buffer */
} sha512_ctx;

/* Utility functions */
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SIGMA1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define sigma1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

static void sha512_transform(sha512_ctx *ctx, const uint8_t *buf) {
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    int i;

    /* Copy chunk into first 16 words W[0..15] of the message schedule array */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint64_t)buf[i * 8 + 0] << 56) |
               ((uint64_t)buf[i * 8 + 1] << 48) |
               ((uint64_t)buf[i * 8 + 2] << 40) |
               ((uint64_t)buf[i * 8 + 3] << 32) |
               ((uint64_t)buf[i * 8 + 4] << 24) |
               ((uint64_t)buf[i * 8 + 5] << 16) |
               ((uint64_t)buf[i * 8 + 6] << 8) |
               ((uint64_t)buf[i * 8 + 7] << 0);
    }

    /* Extend the first 16 words into the remaining 64 words W[16..79] */
    for (i = 16; i < 80; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    /* Initialize working variables */
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    /* Main loop */
    for (i = 0; i < 80; i++) {
        t1 = h + SIGMA1(e) + CH(e, f, g) + K[i] + W[i];
        t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add this chunk's hash to result so far */
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

static void sha512_init(sha512_ctx *ctx) {
    ctx->curlen = 0;
    ctx->length = 0;
    ctx->h[0] = 0x6a09e667f3bcc908ULL;
    ctx->h[1] = 0xbb67ae8584caa73bULL;
    ctx->h[2] = 0x3c6ef372fe94f82bULL;
    ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->h[4] = 0x510e527fade682d1ULL;
    ctx->h[5] = 0x9b05688c2b3e6c1fULL;
    ctx->h[6] = 0x1f83d9abfb41bd6bULL;
    ctx->h[7] = 0x5be0cd19137e2179ULL;
}

static void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
    size_t n;

    while (len > 0) {
        if (ctx->curlen == 0 && len >= SHA512_BLOCK_SIZE) {
            sha512_transform(ctx, data);
            ctx->length += SHA512_BLOCK_SIZE * 8;
            data += SHA512_BLOCK_SIZE;
            len -= SHA512_BLOCK_SIZE;
        } else {
            n = SHA512_BLOCK_SIZE - ctx->curlen;
            if (n > len) {
                n = len;
            }
            memcpy(ctx->buf + ctx->curlen, data, n);
            ctx->curlen += n;
            data += n;
            len -= n;
            if (ctx->curlen == SHA512_BLOCK_SIZE) {
                sha512_transform(ctx, ctx->buf);
                ctx->length += SHA512_BLOCK_SIZE * 8;
                ctx->curlen = 0;
            }
        }
    }
}

static void sha512_final(sha512_ctx *ctx, uint8_t *hash) {
    uint64_t length_bits = ctx->length + ctx->curlen * 8;
    uint32_t i;

    /* Pad with 0x80 followed by zeros */
    ctx->buf[ctx->curlen++] = 0x80;

    /* If we don't have enough space for the length, process this block */
    if (ctx->curlen > 112) {
        while (ctx->curlen < 128) {
            ctx->buf[ctx->curlen++] = 0;
        }
        sha512_transform(ctx, ctx->buf);
        ctx->curlen = 0;
    }

    /* Pad with zeros and append length */
    while (ctx->curlen < 112) {
        ctx->buf[ctx->curlen++] = 0;
    }

    /* Append length in bits as big-endian 128-bit number */
    for (i = 0; i < 8; i++) {
        ctx->buf[112 + i] = 0; /* High 64 bits are zero */
    }
    for (i = 0; i < 8; i++) {
        ctx->buf[120 + i] = (length_bits >> (8 * (7 - i))) & 0xff;
    }

    sha512_transform(ctx, ctx->buf);

    /* Output hash */
    for (i = 0; i < 8; i++) {
        hash[i * 8 + 0] = (ctx->h[i] >> 56) & 0xff;
        hash[i * 8 + 1] = (ctx->h[i] >> 48) & 0xff;
        hash[i * 8 + 2] = (ctx->h[i] >> 40) & 0xff;
        hash[i * 8 + 3] = (ctx->h[i] >> 32) & 0xff;
        hash[i * 8 + 4] = (ctx->h[i] >> 24) & 0xff;
        hash[i * 8 + 5] = (ctx->h[i] >> 16) & 0xff;
        hash[i * 8 + 6] = (ctx->h[i] >> 8) & 0xff;
        hash[i * 8 + 7] = (ctx->h[i] >> 0) & 0xff;
    }
}

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[SHA512_DIGEST_SIZE]) {
    sha512_ctx ctx;
    uint8_t k_ipad[SHA512_BLOCK_SIZE];
    uint8_t k_opad[SHA512_BLOCK_SIZE];
    uint8_t tk[SHA512_DIGEST_SIZE];
    uint8_t digest[SHA512_DIGEST_SIZE];
    size_t i;

    /* If key is longer than block size, hash it */
    if (key_len > SHA512_BLOCK_SIZE) {
        sha512_init(&ctx);
        sha512_update(&ctx, key, key_len);
        sha512_final(&ctx, tk);
        key = tk;
        key_len = SHA512_DIGEST_SIZE;
    }

    /* Prepare inner and outer padded keys */
    memset(k_ipad, 0x36, SHA512_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA512_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Perform inner hash: SHA512(k_ipad || data) */
    sha512_init(&ctx);
    sha512_update(&ctx, k_ipad, SHA512_BLOCK_SIZE);
    sha512_update(&ctx, data, data_len);
    sha512_final(&ctx, digest);

    /* Perform outer hash: SHA512(k_opad || inner_hash) */
    sha512_init(&ctx);
    sha512_update(&ctx, k_opad, SHA512_BLOCK_SIZE);
    sha512_update(&ctx, digest, SHA512_DIGEST_SIZE);
    sha512_final(&ctx, output);
} 