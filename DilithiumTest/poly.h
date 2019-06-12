#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef struct 
{
	uint32_t coeffs[DILITHIUM_N];
} poly;

/*************************************************
* Name:        poly_reduce
*
* Description: Reduce all coefficients of input polynomial to representative
*              in [0,2*DILITHIUM_Q[.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_reduce(poly* a);

/*************************************************
* Name:        poly_csubq
*
* Description: For all coefficients of input polynomial subtract DILITHIUM_Q if
*              coefficient is bigger than DILITHIUM_Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_csubq(poly* a);

/*************************************************
* Name:        poly_freeze
*
* Description: Reduce all coefficients of the polynomial to standard
*              representatives.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_freeze(poly* a);

/*************************************************
* Name:        poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first summand
*              - const poly *b: pointer to second summand
**************************************************/
void poly_add(poly* c, const poly* a, const poly* b);

/*************************************************
* Name:        poly_sub
*
* Description: Subtract polynomials. Assumes coefficients of second input
*              polynomial to be less than 2*DILITHIUM_Q. No modular reduction is
*              performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void poly_sub(poly* c, const poly* a, const poly* b);

/*************************************************
* Name:        poly_shiftl
*
* Description: Multiply polynomial by 2^DILITHIUM_D without modular reduction. Assumes
*              input coefficients to be less than 2^{32-DILITHIUM_D}.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_shiftl(poly* a);

/*************************************************
* Name:        poly_ntt
*
* Description: Forward NTT. Output coefficients can be up to 16*DILITHIUM_Q larger than
*              input coefficients.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_ntt(poly* a);

/*************************************************
* Name:        poly_invntt_montgomery
*
* Description: Inverse NTT and multiplication with 2^{32}. Input coefficients
*              need to be less than 2*DILITHIUM_Q. Output coefficients are less than 2*DILITHIUM_Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_invntt_montgomery(poly* a);

/*************************************************
* Name:        poly_pointwise_invmontgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              with 2^{-32}. Output coefficients are less than 2*DILITHIUM_Q if input
*              coefficient are less than 22*DILITHIUM_Q.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_pointwise_invmontgomery(poly* c, const poly* a, const poly* b);

/*************************************************
* Name:        poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod DILITHIUM_Q = c1*2^DILITHIUM_D + c0
*              with -2^{DILITHIUM_D-1} < c0 <= 2^{DILITHIUM_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients DILITHIUM_Q + a0
*              - const poly *v: pointer to input polynomial
**************************************************/
void poly_power2round(poly* a1, poly* a0, const poly* a);

/*************************************************
* Name:        poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod DILITHIUM_Q = c1*DILITHIUM_ALPHA + c0
*              with -DILITHIUM_ALPHA/2 < c0 <= DILITHIUM_ALPHA/2 except c1 = (DILITHIUM_Q-1)/DILITHIUM_ALPHA where we
*              set c1 = 0 and -DILITHIUM_ALPHA/2 <= c0 = c mod DILITHIUM_Q - DILITHIUM_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients DILITHIUM_Q + a0
*              - const poly *c: pointer to input polynomial
**************************************************/
void poly_decompose(poly* a1, poly* a0, const poly* a);

/*************************************************
* Name:        poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the low bits of the corresponding coefficient of
*              the input polynomial overflow into the high bits.
*
* Arguments:   - poly *h: pointer to output hint polynomial
*              - const poly *a0: pointer to low part of input polynomial
*              - const poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
uint32_t poly_make_hint(poly* h, const poly* a0, const poly* a1);

/*************************************************
* Name:        poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - poly *a: pointer to output polynomial with corrected high bits
*              - const poly *b: pointer to input polynomial
*              - const poly *h: pointer to input hint polynomial
**************************************************/
void poly_use_hint(poly* a, const poly* b, const poly* h);

/*************************************************
* Name:        poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const poly *a: pointer to polynomial
*              - uint32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B and 1 otherwise.
**************************************************/
int32_t  poly_chknorm(const poly* a, uint32_t B);

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,DILITHIUM_Q-1] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length
*                                            DILITHIUM_SEED_SIZE
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void poly_uniform(poly* a, const uint8_t seed[DILITHIUM_SEED_SIZE], uint16_t nonce);

/*************************************************
* Name:        poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-DILITHIUM_ETA,DILITHIUM_ETA] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length
*                                            DILITHIUM_SEED_SIZE
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void poly_uniform_eta(poly* a, const uint8_t seed[DILITHIUM_SEED_SIZE], uint16_t nonce);

/*************************************************
* Name:        poly_uniform_gamma1m1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(DILITHIUM_GAMMA1 - 1), DILITHIUM_GAMMA1 - 1] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length
*                                            DILITHIUM_CRH_SIZE
*              - uint16_t nonce: 16-bit nonce
**************************************************/
void poly_uniform_gamma1m1(poly* a, const uint8_t seed[DILITHIUM_CRH_SIZE], uint16_t nonce);

/*************************************************
* Name:        polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-DILITHIUM_ETA,DILITHIUM_ETA].
*              Input coefficients are assumed to lie in [DILITHIUM_Q-DILITHIUM_ETA,DILITHIUM_Q+DILITHIUM_ETA].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLETA_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyeta_pack(uint8_t* r, const poly* a);

/*************************************************
* Name:        polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-DILITHIUM_ETA,DILITHIUM_ETA].
*              Output coefficients lie in [DILITHIUM_Q-DILITHIUM_ETA,DILITHIUM_Q+DILITHIUM_ETA].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyeta_unpack(poly* r, const uint8_t* a);

/*************************************************
* Name:        polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 9 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLT1_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyt1_pack(uint8_t* r, const poly* a);

/*************************************************
* Name:        polyt1_unpack
*
* Description: Unpack polynomial t1 with 9-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyt1_unpack(poly* r, const uint8_t* a);

/*************************************************
* Name:        polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{DILITHIUM_D-1}, 2^{DILITHIUM_D-1}].
*              Input coefficients are assumed to lie in ]DILITHIUM_Q-2^{DILITHIUM_D-1}, DILITHIUM_Q+2^{DILITHIUM_D-1}].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLT0_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyt0_pack(uint8_t* r, const poly* a);

/*************************************************
* Name:        polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{DILITHIUM_D-1}, 2^{DILITHIUM_D-1}].
*              Output coefficients lie in ]DILITHIUM_Q-2^{DILITHIUM_D-1},DILITHIUM_Q+2^{DILITHIUM_D-1}].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyt0_unpack(poly* r, const uint8_t* a);

/*************************************************
* Name:        polyz_pack
*
* Description: Bit-pack polynomial z with coefficients
*              in [-(DILITHIUM_GAMMA1 - 1), DILITHIUM_GAMMA1 - 1].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLZ_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyz_pack(uint8_t* r, const poly* a);

/*************************************************
* Name:        polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(DILITHIUM_GAMMA1 - 1), DILITHIUM_GAMMA1 - 1].
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyz_unpack(poly* r, const uint8_t* a);

/*************************************************
* Name:        polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0, 15].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLW1_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyw1_pack(uint8_t* r, const poly* a);

#endif
