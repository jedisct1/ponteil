#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC target("sse2")
#pragma GCC target("aes")
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ponteil.h"

#ifdef __x86_64__
#include <immintrin.h>

typedef __m128i AesBlock;

static inline AesBlock
aesround(const AesBlock in, const AesBlock rk)
{
    return _mm_aesenc_si128(in, rk);
}

static inline AesBlock
zero_block(void)
{
    return _mm_setzero_si128();
}

static inline AesBlock
xor_blocks(const AesBlock x, const AesBlock y)
{
    return _mm_xor_si128(x, y);
}

static inline AesBlock
and_blocks(const AesBlock x, const AesBlock y)
{
    return _mm_and_si128(x, y);
}

static inline AesBlock
from_bytes(const uint8_t bytes[16])
{
    return _mm_loadu_si128((const AesBlock *) (const void *) bytes);
}

static inline void
to_bytes(uint8_t bytes[16], const AesBlock block)
{
    _mm_storeu_si128((AesBlock *) (void *) bytes, block);
}

#elif defined(__aarch64__)
#include <arm_neon.h>

typedef uint8x16_t AesBlock;

static inline AesBlock
aesround(const AesBlock in, const AesBlock rk)
{
    return veorq_u8(vaesmcq_u8(vaeseq_u8(in, vmovq_n_u8(0))), rk);
}

static inline AesBlock
zero_block(void)
{
    return vmovq_n_u8(0);
}

static inline AesBlock
xor_blocks(const AesBlock x, const AesBlock y)
{
    return veorq_u8(x, y);
}

static inline AesBlock
and_blocks(const AesBlock x, const AesBlock y)
{
    return vandq_u8(x, y);
}

static inline AesBlock
from_bytes(const uint8_t bytes[16])
{
    return vld1q_u8(bytes);
}

static inline void
to_bytes(uint8_t bytes[16], const AesBlock block)
{
    vst1q_u8(bytes, block);
}

#else
#error Unsupported architecture
#endif

static inline uint64_t
to_le64(uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(x);
#else
    return x;
#endif
}

#define ROUNDS 12

typedef struct State {
    AesBlock b0;
    AesBlock b1;
    AesBlock b2;
    AesBlock b3;
    AesBlock b4;
    AesBlock b5;
    AesBlock b6;
    AesBlock b7;
} State;

typedef struct Ponteil_ {
    State    s;
    uint64_t ctx_segments;
    uint64_t m_segments;
} Ponteil_;

static void
update(Ponteil_ *ponteil, const AesBlock m0, const AesBlock m1)
{
    const State s0 = ponteil->s;
    ponteil->s     = (State) {
        xor_blocks(aesround(s0.b7, s0.b0), m0),
        aesround(s0.b0, s0.b1),
        aesround(s0.b1, s0.b2),
        aesround(s0.b2, s0.b3),
        xor_blocks(aesround(s0.b3, s0.b4), m1),
        aesround(s0.b4, s0.b5),
        aesround(s0.b5, s0.b6),
        aesround(s0.b6, s0.b7),
    };
}

static inline void
absorb_block(Ponteil_ *ponteil, const uint8_t xi[32])
{
    const AesBlock t0 = from_bytes(xi);
    const AesBlock t1 = from_bytes(xi + 16);
    update(ponteil, t0, t1);
}

Ponteil
ponteil_init(const uint8_t k[32])
{
    const AesBlock c0 =
        from_bytes((const uint8_t[32]) { 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22,
                                         0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 });
    const AesBlock c1 =
        from_bytes((const uint8_t[32]) { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11,
                                         0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd });
    const AesBlock zero = zero_block();
    const AesBlock k0   = from_bytes(k);
    const AesBlock k1   = from_bytes(k + 16);

    Ponteil_ ponteil = { .s = (State) {
                             zero,
                             k1,
                             xor_blocks(k0, c1),
                             xor_blocks(k0, c0),
                             zero,
                             k0,
                             xor_blocks(k1, c0),
                             xor_blocks(k1, c1),
                         } };

    int i;
    for (i = 0; i < ROUNDS; i++) {
        update(&ponteil, c0, c1);
    }
    return *(Ponteil *) (void *) &ponteil;
}

static void
absorb(Ponteil_ *ponteil, const void *x_, size_t x_len)
{
    const uint8_t *x = (const uint8_t *) x_;
    size_t         i;
    for (i = 0; i + 32 <= x_len; i += 32) {
        absorb_block(ponteil, x + i);
    }
    if (x_len % 32 != 0) {
        uint8_t pad[32] = { 0 };
        memcpy(pad, x + i, x_len % 32);
        absorb_block(ponteil, pad);
    }

    uint8_t        len[32] = { 0x00 };
    const uint64_t d       = to_le64(((uint64_t) x_len) * 8);
    memcpy(&len[0], &d, 8);
    absorb_block(ponteil, len);
}

void
ponteil_push_context(Ponteil *ponteil_, const char *ctx, size_t ctx_len)
{
    Ponteil_ *ponteil = (Ponteil_ *) (void *) ponteil_;
    absorb(ponteil, (const void *) ctx, ctx_len);
    ponteil->ctx_segments++;
}

void
ponteil_push(Ponteil *ponteil_, const void *m, size_t m_len)
{
    Ponteil_ *ponteil = (Ponteil_ *) (void *) ponteil_;
    absorb(ponteil, m, m_len);
    ponteil->m_segments++;
}

void
ponteil_finalize(Ponteil *ponteil_, uint8_t h[32])
{
    Ponteil_ *ponteil = (Ponteil_ *) (void *) ponteil_;
    uint8_t   b[16];
    uint64_t  d = to_le64(((uint64_t) ponteil->ctx_segments) * 8);
    memcpy(&b[0], &d, 8);
    d = to_le64(((uint64_t) ponteil->m_segments) * 8);
    memcpy(&b[8], &d, 8);

    const State *  s = &ponteil->s;
    const AesBlock t = xor_blocks(s->b2, from_bytes(b));

    int i;
    for (i = 0; i < ROUNDS; i++) {
        update(ponteil, t, t);
    }
    to_bytes(h, xor_blocks(xor_blocks(s->b1, s->b6), and_blocks(s->b2, s->b3)));
    to_bytes(h + 16, xor_blocks(xor_blocks(s->b2, s->b5), and_blocks(s->b6, s->b7)));
}

void
ponteil_hash(uint8_t h[32], const char *ctx, size_t ctx_len, const void *m_, size_t m_len)
{
    Ponteil        ponteil = ponteil_init((const uint8_t[32]) { 0 });
    const uint8_t *m       = (const uint8_t *) m_;
    if (ctx != NULL) {
        ponteil_push_context(&ponteil, ctx, ctx_len);
    }
    ponteil_push(&ponteil, m, m_len);
    ponteil_finalize(&ponteil, h);
}
