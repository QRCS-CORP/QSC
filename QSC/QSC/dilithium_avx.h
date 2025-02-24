#ifndef QSC_DILITHIUM_AVX_H
#define QSC_DILITHIUM_AVX_H

#include "common.h"
#include "intrinsics.h"
#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

// consts

#define _8XQ          0
#define _8XQINV       8
#define _8XDIV_QINV  16
#define _8XDIV       24
#define _ZETAS_QINV  32
#define _ZETAS      328

/* The C ABI on MacOS exports all symbols with a leading
 * underscore. This means that any symbols we refer to from
 * C files (functions) can't be found, and all symbols we
 * refer to from ASM also can't be found.
 *
 * This define helps us get around this
 */
#if defined(__WIN32__) || defined(__APPLE__)
#define decorate(s) _##s
#define _cdecl(s) decorate(s)
#define cdecl(s) _cdecl(DILITHIUM_NAMESPACE(##s))
#else
#define cdecl(s) DILITHIUM_NAMESPACE(##s)
#endif

#define ALIGNED_UINT8(N)        \
    union {                     \
        uint8_t coeffs[N];      \
        __m256i vec[(N+31)/32]; \
    }

#define ALIGNED_INT32(N)        \
    union {                     \
        int32_t coeffs[N];      \
        __m256i vec[(N+7)/8];   \
    }


#define pqcrystals_dilithium2_PUBLICKEYBYTES 1312
#define pqcrystals_dilithium2_SECRETKEYBYTES 2560
#define pqcrystals_dilithium2_BYTES 2420

#define pqcrystals_dilithium2_avx2_PUBLICKEYBYTES pqcrystals_dilithium2_PUBLICKEYBYTES
#define pqcrystals_dilithium2_avx2_SECRETKEYBYTES pqcrystals_dilithium2_SECRETKEYBYTES
#define pqcrystals_dilithium2_avx2_BYTES pqcrystals_dilithium2_BYTES

int pqcrystals_dilithium2_avx2_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium2_avx2_signature(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk);

int pqcrystals_dilithium2_avx2(uint8_t *sm, size_t *smlen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk);

int pqcrystals_dilithium2_avx2_verify(const uint8_t *sig, size_t siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen,
                                      const uint8_t *pk);

int pqcrystals_dilithium2_avx2_open(uint8_t *m, size_t *mlen,
                                    const uint8_t *sm, size_t smlen,
                                    const uint8_t *ctx, size_t ctxlen,
                                    const uint8_t *pk);


#define pqcrystals_dilithium3_PUBLICKEYBYTES 1952
#define pqcrystals_dilithium3_SECRETKEYBYTES 4032
#define pqcrystals_dilithium3_BYTES 3309

#define pqcrystals_dilithium3_avx2_PUBLICKEYBYTES pqcrystals_dilithium3_PUBLICKEYBYTES
#define pqcrystals_dilithium3_avx2_SECRETKEYBYTES pqcrystals_dilithium3_SECRETKEYBYTES
#define pqcrystals_dilithium3_avx2_BYTES pqcrystals_dilithium3_BYTES

int pqcrystals_dilithium3_avx2_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium3_avx2_signature(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk);

int pqcrystals_dilithium3_avx2(uint8_t *sm, size_t *smlen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk);

int pqcrystals_dilithium3_avx2_verify(const uint8_t *sig, size_t siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen,
                                      const uint8_t *pk);

int pqcrystals_dilithium3_avx2_open(uint8_t *m, size_t *mlen,
                                    const uint8_t *sm, size_t smlen,
                                    const uint8_t *ctx, size_t ctxlen,
                                    const uint8_t *pk);


#define pqcrystals_dilithium5_PUBLICKEYBYTES 2592
#define pqcrystals_dilithium5_SECRETKEYBYTES 4896
#define pqcrystals_dilithium5_BYTES 4627

#define pqcrystals_dilithium5_avx2_PUBLICKEYBYTES pqcrystals_dilithium5_PUBLICKEYBYTES
#define pqcrystals_dilithium5_avx2_SECRETKEYBYTES pqcrystals_dilithium5_SECRETKEYBYTES
#define pqcrystals_dilithium5_avx2_BYTES pqcrystals_dilithium5_BYTES

int pqcrystals_dilithium5_avx2_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium5_avx2_signature(uint8_t *sig, size_t *siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk);

int pqcrystals_dilithium5_avx2(uint8_t *sm, size_t *smlen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk);

int pqcrystals_dilithium5_avx2_verify(const uint8_t *sig, size_t siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *ctx, size_t ctxlen,
                                      const uint8_t *pk);

int pqcrystals_dilithium5_avx2_open(uint8_t *m, size_t *mlen,
                                    const uint8_t *sm, size_t smlen,
                                    const uint8_t *ctx, size_t ctxlen,
                                    const uint8_t *pk);

// fips202.h

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct 
{
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

#define KeccakF_RoundConstants FIPS202_NAMESPACE(KeccakF_RoundConstants)
extern const uint64_t KeccakF_RoundConstants[];

void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);
void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

// fips202x4

typedef struct {
  __m256i s[25];
} keccakx4_state;

void f1600x4(__m256i *s, const uint64_t *rc);
void shake128x4_absorb_once(keccakx4_state *state, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen);
void shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t nblocks, keccakx4_state *state);
void shake256x4_absorb_once(keccakx4_state *state, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen);
void shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t nblocks, keccakx4_state *state);
void shake128x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen);
void shake256x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen);

// poly.h

typedef ALIGNED_INT32(N) poly;

void poly_reduce(poly *a);
void poly_caddq(poly *a);
void poly_add(poly *c, const poly *a, const poly *b);
void poly_sub(poly *c, const poly *a, const poly *b);
void poly_shiftl(poly *a);
void poly_ntt(poly *a);
void poly_invntt_tomont(poly *a);
void poly_nttunpack(poly *a);
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);
void poly_power2round(poly *a1, poly *a0, const poly *a);
void poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int poly_make_hint(uint8_t hint[N], const poly *a0, const poly *a1);
void poly_use_hint(poly *b, const poly *a, const poly *h);
int poly_chknorm(const poly *a, int32_t B);
void poly_uniform_preinit(poly *a, stream128_state *state);
void poly_uniform(poly *a, const uint8_t seed[SEEDBYTES], uint16_t nonce);
void poly_uniform_eta_preinit(poly *a, stream256_state *state);
void poly_uniform_eta(poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce);
void poly_uniform_gamma1_preinit(poly *a, stream256_state *state);
void poly_uniform_gamma1(poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce);
void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]);
void poly_uniform_4x(poly *a0, poly *a1, poly *a2, poly *a3, const uint8_t seed[SEEDBYTES], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3);
void poly_uniform_eta_4x(poly *a0, poly *a1, poly *a2, poly *a3, const uint8_t seed[CRHBYTES], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3);
void poly_uniform_gamma1_4x(poly *a0, poly *a1, poly *a2, poly *a3, const uint8_t seed[CRHBYTES], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3);
void polyeta_pack(uint8_t r[POLYETA_PACKEDBYTES], const poly *a);
void polyeta_unpack(poly *r, const uint8_t a[POLYETA_PACKEDBYTES]);
void polyt1_pack(uint8_t r[POLYT1_PACKEDBYTES], const poly *a);
void polyt1_unpack(poly *r, const uint8_t a[POLYT1_PACKEDBYTES]);
void polyt0_pack(uint8_t r[POLYT0_PACKEDBYTES], const poly *a);
void polyt0_unpack(poly *r, const uint8_t a[POLYT0_PACKEDBYTES]);
void polyz_pack(uint8_t r[POLYZ_PACKEDBYTES], const poly *a);
void polyz_unpack(poly *r, const uint8_t *a);
void polyw1_pack(uint8_t *r, const poly *a);

// polyvec.h

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L];
} polyvecl;

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_reduce(polyvecl *v);
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void polyvecl_ntt(polyvecl *v);
void polyvecl_invntt_tomont(polyvecl *v);
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v);
int polyvecl_chknorm(const polyvecl *v, int32_t B);

/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyveck_reduce(polyveck *v);
void polyveck_caddq(polyveck *v);
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_shiftl(polyveck *v);

void polyveck_ntt(polyveck *v);
void polyveck_invntt_tomont(polyveck *v);
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);
int polyveck_chknorm(const polyveck *v, int32_t B);
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int polyveck_make_hint(uint8_t *hint, const polyveck *v0, const polyveck *v1);
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);
void polyveck_pack_w1(uint8_t r[K*POLYW1_PACKEDBYTES], const polyveck *w1);
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);

void polyvec_matrix_expand_row0(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row1(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row4(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row6(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_row7(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);

// ntt.h

void ntt_avx(__m256i *a, const __m256i *qdata);
void invntt_avx(__m256i *a, const __m256i *qdata);
void nttunpack_avx(__m256i *a);
void pointwise_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);
void pointwise_acc_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);




#endif