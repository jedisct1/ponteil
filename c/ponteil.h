#ifndef ponteil_H
#define ponteil_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CRYPTO_ALIGN
#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif

#include <stdint.h>
#include <stdlib.h>

#define PONTEIL_BYTES    32
#define PONTEIL_KEYBYTES 32

typedef struct Ponteil {
    CRYPTO_ALIGN(16) unsigned char opaque[1280];
} Ponteil;

Ponteil ponteil_init(const uint8_t *k); /* PONTEIL_KEYBYTES bytes or NULL */

void ponteil_push_context(Ponteil *ponteil_, const char *ctx, size_t ctx_len);

void ponteil_push(Ponteil *ponteil_, const void *m, size_t m_len);

void ponteil_finalize(Ponteil *ponteil_, uint8_t *h, size_t h_len);

void ponteil_mac(uint8_t h[PONTEIL_BYTES], const uint8_t k[PONTEIL_KEYBYTES], const char *ctx,
                 size_t ctx_len, const void *m, size_t m_len);

void ponteil_hash(uint8_t h[PONTEIL_BYTES], const char *ctx, size_t ctx_len, const void *m,
                  size_t m_len);

#ifdef __cplusplus
}
#endif

#endif
