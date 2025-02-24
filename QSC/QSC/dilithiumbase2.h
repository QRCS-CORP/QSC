#ifndef QSC_DILITHIUMBASE2_H
#define QSC_DILITHIUMBASE2_H

/* \cond */

#include "common.h"

// config.h

//#define DILITHIUM_MODE 2
//#define DILITHIUM_RANDOMIZED_SIGNING
//#define USE_RDPMC
//#define DBENCH

#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 5
#endif

#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium2_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium2_ref_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium3_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium3_ref_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium5_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium5_ref_##s
#endif

// params.h

#define DILITHIUM_SEEDBYTES 32
#define DILITHIUM_CRHBYTES 64
#define DILITHIUM_TRBYTES 64
#define DILITHIUM_RNDBYTES 32
#define DILITHIUM_N 256
#define DILITHIUM_Q 8380417
#define DILITHIUM_D 13
#define DILITHIUM_ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define DILITHIUM_K 4
#define DILITHIUM_L 4
#define DILITHIUM_ETA 2
#define DILITHIUM_TAU 39
#define DILITHIUM_BETA 78
#define DILITHIUM_GAMMA1 (1 << 17)
#define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1)/88)
#define DILITHIUM_OMEGA 80
#define DILITHIUM_CTILDEBYTES 32

#elif DILITHIUM_MODE == 3
#define DILITHIUM_K 6
#define DILITHIUM_L 5
#define DILITHIUM_ETA 4
#define DILITHIUM_TAU 49
#define DILITHIUM_BETA 196
#define DILITHIUM_GAMMA1 (1 << 19)
#define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1)/32)
#define DILITHIUM_OMEGA 55
#define DILITHIUM_CTILDEBYTES 48

#elif DILITHIUM_MODE == 5
#define DILITHIUM_K 8
#define DILITHIUM_L 7
#define DILITHIUM_ETA 2
#define DILITHIUM_TAU 60
#define DILITHIUM_BETA 120
#define DILITHIUM_GAMMA1 (1 << 19)
#define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1)/32)
#define DILITHIUM_OMEGA 75
#define DILITHIUM_CTILDEBYTES 64

#endif

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + DILITHIUM_K)

#if DILITHIUM_GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif DILITHIUM_GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if DILITHIUM_GAMMA2 == (DILITHIUM_Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif DILITHIUM_GAMMA2 == (DILITHIUM_Q-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if DILITHIUM_ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif DILITHIUM_ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define CRYPTO_PUBLICKEYBYTES (DILITHIUM_SEEDBYTES + DILITHIUM_K*POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES (2*DILITHIUM_SEEDBYTES \
                               + DILITHIUM_TRBYTES \
                               + DILITHIUM_L*POLYETA_PACKEDBYTES \
                               + DILITHIUM_K*POLYETA_PACKEDBYTES \
                               + DILITHIUM_K*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (DILITHIUM_CTILDEBYTES + DILITHIUM_L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

// api.h

#define pqcrystals_dilithium2_PUBLICKEYBYTES 1312
#define pqcrystals_dilithium2_SECRETKEYBYTES 2560
#define pqcrystals_dilithium2_BYTES 2420

#define pqcrystals_dilithium2_ref_PUBLICKEYBYTES pqcrystals_dilithium2_PUBLICKEYBYTES
#define pqcrystals_dilithium2_ref_SECRETKEYBYTES pqcrystals_dilithium2_SECRETKEYBYTES
#define pqcrystals_dilithium2_ref_BYTES pqcrystals_dilithium2_BYTES

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int pqcrystals_dilithium2_ref(uint8_t *sm, size_t *smlen,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium2_ref_open(uint8_t *m, size_t *mlen,
                                   const uint8_t *sm, size_t smlen,
                                   const uint8_t *ctx, size_t ctxlen,
                                   const uint8_t *pk);

#define pqcrystals_dilithium3_PUBLICKEYBYTES 1952
#define pqcrystals_dilithium3_SECRETKEYBYTES 4032
#define pqcrystals_dilithium3_BYTES 3309

#define pqcrystals_dilithium3_ref_PUBLICKEYBYTES pqcrystals_dilithium3_PUBLICKEYBYTES
#define pqcrystals_dilithium3_ref_SECRETKEYBYTES pqcrystals_dilithium3_SECRETKEYBYTES
#define pqcrystals_dilithium3_ref_BYTES pqcrystals_dilithium3_BYTES

int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int pqcrystals_dilithium3_ref(uint8_t *sm, size_t *smlen,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium3_ref_open(uint8_t *m, size_t *mlen,
                                   const uint8_t *sm, size_t smlen,
                                   const uint8_t *ctx, size_t ctxlen,
                                   const uint8_t *pk);

#define pqcrystals_dilithium5_PUBLICKEYBYTES 2592
#define pqcrystals_dilithium5_SECRETKEYBYTES 4896
#define pqcrystals_dilithium5_BYTES 4627

#define pqcrystals_dilithium5_ref_PUBLICKEYBYTES pqcrystals_dilithium5_PUBLICKEYBYTES
#define pqcrystals_dilithium5_ref_SECRETKEYBYTES pqcrystals_dilithium5_SECRETKEYBYTES
#define pqcrystals_dilithium5_ref_BYTES pqcrystals_dilithium5_BYTES

int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk);

int pqcrystals_dilithium5_ref(uint8_t *sm, size_t *smlen,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk);

int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk);

int pqcrystals_dilithium5_ref_open(uint8_t *m, size_t *mlen,
                                   const uint8_t *sm, size_t smlen,
                                   const uint8_t *ctx, size_t ctxlen,
                                   const uint8_t *pk);


// reduce.h

#define MONT -4186625 // 2^32 % DILITHIUM_Q
#define QINV 58728449 // q^(-1) mod 2^32

#define montgomery_reduce DILITHIUM_NAMESPACE(montgomery_reduce)
int32_t montgomery_reduce(int64_t a);

#define reduce32 DILITHIUM_NAMESPACE(reduce32)
int32_t reduce32(int32_t a);

#define caddq DILITHIUM_NAMESPACE(caddq)
int32_t caddq(int32_t a);

#define freeze DILITHIUM_NAMESPACE(freeze)
int32_t freeze(int32_t a);

// rounding.h

#define power2round DILITHIUM_NAMESPACE(power2round)
int32_t power2round(int32_t *a0, int32_t a);

#define decompose DILITHIUM_NAMESPACE(decompose)
int32_t decompose(int32_t *a0, int32_t a);

#define make_hint DILITHIUM_NAMESPACE(make_hint)
unsigned int make_hint(int32_t a0, int32_t a1);

#define use_hint DILITHIUM_NAMESPACE(use_hint)
int32_t use_hint(int32_t a, unsigned int hint);

// fips202.h

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define FIPS202_NAMESPACE(s) pqcrystals_dilithium_fips202_ref_##s

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

#define KeccakF_RoundConstants FIPS202_NAMESPACE(KeccakF_RoundConstants)
extern const uint64_t KeccakF_RoundConstants[];

#define shake128_init FIPS202_NAMESPACE(shake128_init)
void shake128_init(keccak_state *state);
#define shake128_absorb FIPS202_NAMESPACE(shake128_absorb)
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_finalize FIPS202_NAMESPACE(shake128_finalize)
void shake128_finalize(keccak_state *state);
#define shake128_squeeze FIPS202_NAMESPACE(shake128_squeeze)
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake128_absorb_once FIPS202_NAMESPACE(shake128_absorb_once)
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_squeezeblocks FIPS202_NAMESPACE(shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

#define shake256_init FIPS202_NAMESPACE(shake256_init)
void shake256_init(keccak_state *state);
#define shake256_absorb FIPS202_NAMESPACE(shake256_absorb)
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_finalize FIPS202_NAMESPACE(shake256_finalize)
void shake256_finalize(keccak_state *state);
#define shake256_squeeze FIPS202_NAMESPACE(shake256_squeeze)
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake256_absorb_once FIPS202_NAMESPACE(shake256_absorb_once)
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_squeezeblocks FIPS202_NAMESPACE(shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);

#define shake128 FIPS202_NAMESPACE(shake128)
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define shake256 FIPS202_NAMESPACE(shake256)
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(sha3_256)
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(sha3_512)
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

// poly.h

typedef struct {
  int32_t coeffs[DILITHIUM_N];
} poly;

#define poly_reduce DILITHIUM_NAMESPACE(poly_reduce)
void poly_reduce(poly *a);
#define poly_caddq DILITHIUM_NAMESPACE(poly_caddq)
void poly_caddq(poly *a);

#define poly_add DILITHIUM_NAMESPACE(poly_add)
void poly_add(poly *c, const poly *a, const poly *b);
#define poly_sub DILITHIUM_NAMESPACE(poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b);
#define poly_shiftl DILITHIUM_NAMESPACE(poly_shiftl)
void poly_shiftl(poly *a);

#define poly_ntt DILITHIUM_NAMESPACE(poly_ntt)
void poly_ntt(poly *a);
#define poly_invntt_tomont DILITHIUM_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *a);
#define poly_pointwise_montgomery DILITHIUM_NAMESPACE(poly_pointwise_montgomery)
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

#define poly_power2round DILITHIUM_NAMESPACE(poly_power2round)
void poly_power2round(poly *a1, poly *a0, const poly *a);
#define poly_decompose DILITHIUM_NAMESPACE(poly_decompose)
void poly_decompose(poly *a1, poly *a0, const poly *a);
#define poly_make_hint DILITHIUM_NAMESPACE(poly_make_hint)
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);
#define poly_use_hint DILITHIUM_NAMESPACE(poly_use_hint)
void poly_use_hint(poly *b, const poly *a, const poly *h);

#define poly_chknorm DILITHIUM_NAMESPACE(poly_chknorm)
int poly_chknorm(const poly *a, int32_t B);
#define poly_uniform DILITHIUM_NAMESPACE(poly_uniform)
void poly_uniform(poly *a,
                  const uint8_t seed[DILITHIUM_SEEDBYTES],
                  uint16_t nonce);
#define poly_uniform_eta DILITHIUM_NAMESPACE(poly_uniform_eta)
void poly_uniform_eta(poly *a,
                      const uint8_t seed[DILITHIUM_CRHBYTES],
                      uint16_t nonce);
#define poly_uniform_gamma1 DILITHIUM_NAMESPACE(poly_uniform_gamma1)
void poly_uniform_gamma1(poly *a,
                         const uint8_t seed[DILITHIUM_CRHBYTES],
                         uint16_t nonce);
#define poly_challenge DILITHIUM_NAMESPACE(poly_challenge)
void poly_challenge(poly *c, const uint8_t seed[DILITHIUM_CTILDEBYTES]);

#define polyeta_pack DILITHIUM_NAMESPACE(polyeta_pack)
void polyeta_pack(uint8_t *r, const poly *a);
#define polyeta_unpack DILITHIUM_NAMESPACE(polyeta_unpack)
void polyeta_unpack(poly *r, const uint8_t *a);

#define polyt1_pack DILITHIUM_NAMESPACE(polyt1_pack)
void polyt1_pack(uint8_t *r, const poly *a);
#define polyt1_unpack DILITHIUM_NAMESPACE(polyt1_unpack)
void polyt1_unpack(poly *r, const uint8_t *a);

#define polyt0_pack DILITHIUM_NAMESPACE(polyt0_pack)
void polyt0_pack(uint8_t *r, const poly *a);
#define polyt0_unpack DILITHIUM_NAMESPACE(polyt0_unpack)
void polyt0_unpack(poly *r, const uint8_t *a);

#define polyz_pack DILITHIUM_NAMESPACE(polyz_pack)
void polyz_pack(uint8_t *r, const poly *a);
#define polyz_unpack DILITHIUM_NAMESPACE(polyz_unpack)
void polyz_unpack(poly *r, const uint8_t *a);

#define polyw1_pack DILITHIUM_NAMESPACE(polyw1_pack)
void polyw1_pack(uint8_t *r, const poly *a);

// polyvec.h

/* Vectors of polynomials of length DILITHIUM_L */
typedef struct {
  poly vec[DILITHIUM_L];
} polyvecl;

#define polyvecl_uniform_eta DILITHIUM_NAMESPACE(polyvecl_uniform_eta)
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);

#define polyvecl_uniform_gamma1 DILITHIUM_NAMESPACE(polyvecl_uniform_gamma1)
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);

#define polyvecl_reduce DILITHIUM_NAMESPACE(polyvecl_reduce)
void polyvecl_reduce(polyvecl *v);

#define polyvecl_add DILITHIUM_NAMESPACE(polyvecl_add)
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

#define polyvecl_ntt DILITHIUM_NAMESPACE(polyvecl_ntt)
void polyvecl_ntt(polyvecl *v);
#define polyvecl_invntt_tomont DILITHIUM_NAMESPACE(polyvecl_invntt_tomont)
void polyvecl_invntt_tomont(polyvecl *v);
#define polyvecl_pointwise_poly_montgomery DILITHIUM_NAMESPACE(polyvecl_pointwise_poly_montgomery)
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
#define polyvecl_pointwise_acc_montgomery \
        DILITHIUM_NAMESPACE(polyvecl_pointwise_acc_montgomery)
void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);


#define polyvecl_chknorm DILITHIUM_NAMESPACE(polyvecl_chknorm)
int polyvecl_chknorm(const polyvecl *v, int32_t B);



/* Vectors of polynomials of length DILITHIUM_K */
typedef struct {
  poly vec[DILITHIUM_K];
} polyveck;

#define polyveck_uniform_eta DILITHIUM_NAMESPACE(polyveck_uniform_eta)
void polyveck_uniform_eta(polyveck *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);

#define polyveck_reduce DILITHIUM_NAMESPACE(polyveck_reduce)
void polyveck_reduce(polyveck *v);
#define polyveck_caddq DILITHIUM_NAMESPACE(polyveck_caddq)
void polyveck_caddq(polyveck *v);

#define polyveck_add DILITHIUM_NAMESPACE(polyveck_add)
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_sub DILITHIUM_NAMESPACE(polyveck_sub)
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_shiftl DILITHIUM_NAMESPACE(polyveck_shiftl)
void polyveck_shiftl(polyveck *v);

#define polyveck_ntt DILITHIUM_NAMESPACE(polyveck_ntt)
void polyveck_ntt(polyveck *v);
#define polyveck_invntt_tomont DILITHIUM_NAMESPACE(polyveck_invntt_tomont)
void polyveck_invntt_tomont(polyveck *v);
#define polyveck_pointwise_poly_montgomery DILITHIUM_NAMESPACE(polyveck_pointwise_poly_montgomery)
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);

#define polyveck_chknorm DILITHIUM_NAMESPACE(polyveck_chknorm)
int polyveck_chknorm(const polyveck *v, int32_t B);

#define polyveck_power2round DILITHIUM_NAMESPACE(polyveck_power2round)
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_decompose DILITHIUM_NAMESPACE(polyveck_decompose)
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_make_hint DILITHIUM_NAMESPACE(polyveck_make_hint)
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);
#define polyveck_use_hint DILITHIUM_NAMESPACE(polyveck_use_hint)
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

#define polyveck_pack_w1 DILITHIUM_NAMESPACE(polyveck_pack_w1)
void polyveck_pack_w1(uint8_t r[DILITHIUM_K*POLYW1_PACKEDBYTES], const polyveck *w1);

#define polyvec_matrix_expand DILITHIUM_NAMESPACE(polyvec_matrix_expand)
void polyvec_matrix_expand(polyvecl mat[DILITHIUM_K], const uint8_t rho[DILITHIUM_SEEDBYTES]);

#define polyvec_matrix_pointwise_montgomery DILITHIUM_NAMESPACE(polyvec_matrix_pointwise_montgomery)
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DILITHIUM_K], const polyvecl *v);

// ntt.h

#define ntt DILITHIUM_NAMESPACE(ntt)
void ntt(int32_t a[DILITHIUM_N]);

#define invntt_tomont DILITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[DILITHIUM_N]);

// packing.h

#define pack_pk DILITHIUM_NAMESPACE(pack_pk)
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[DILITHIUM_SEEDBYTES], const polyveck *t1);

#define pack_sk DILITHIUM_NAMESPACE(pack_sk)
void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[DILITHIUM_SEEDBYTES],
             const uint8_t tr[DILITHIUM_TRBYTES],
             const uint8_t key[DILITHIUM_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

#define pack_sig DILITHIUM_NAMESPACE(pack_sig)
void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[DILITHIUM_CTILDEBYTES], const polyvecl *z, const polyveck *h);

#define unpack_pk DILITHIUM_NAMESPACE(unpack_pk)
void unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES], polyveck *t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

#define unpack_sk DILITHIUM_NAMESPACE(unpack_sk)
void unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES],
               uint8_t tr[DILITHIUM_TRBYTES],
               uint8_t key[DILITHIUM_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sig DILITHIUM_NAMESPACE(unpack_sig)
int unpack_sig(uint8_t c[DILITHIUM_CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES]);

// randombytes

void randombytes(uint8_t *out, size_t outlen);

// sign.h

#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_sign_signature_internal DILITHIUM_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(uint8_t *sig,
                                   size_t *siglen,
                                   const uint8_t *m,
                                   size_t mlen,
                                   const uint8_t *pre,
                                   size_t prelen,
                                   const uint8_t rnd[DILITHIUM_RNDBYTES],
                                   const uint8_t *sk);

#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *sk);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sk);

#define crypto_sign_verify_internal DILITHIUM_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk);

#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *pk);

// symmetric.h

typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

#define dilithium_shake128_stream_init DILITHIUM_NAMESPACE(dilithium_shake128_stream_init)
void dilithium_shake128_stream_init(keccak_state *state,
                                    const uint8_t seed[DILITHIUM_SEEDBYTES],
                                    uint16_t nonce);

#define dilithium_shake256_stream_init DILITHIUM_NAMESPACE(dilithium_shake256_stream_init)
void dilithium_shake256_stream_init(keccak_state *state,
                                    const uint8_t seed[DILITHIUM_CRHBYTES],
                                    uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

#endif