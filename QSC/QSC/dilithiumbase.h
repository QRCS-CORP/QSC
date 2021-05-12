/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QSC_DILITHIUMBASE_H
#define QSC_DILITHIUMBASE_H

#include "common.h"

/* params.h */

#if defined(QSC_DILITHIUM_S1N256Q8380417)
#	define QCX_DILITHIUM_MODE 2
#elif defined(QSC_DILITHIUM_S2N256Q8380417)
#	define QCX_DILITHIUM_MODE 3
#elif defined(QSC_DILITHIUM_S3N256Q8380417)
#	define QCX_DILITHIUM_MODE 4
#else
#	error No Dilithium implementation is defined, check common.h!
#endif

#define QSC_DILITHIUM_SEED_SIZE 32
#define QSC_DILITHIUM_CRH_SIZE 48
#define QSC_DILITHIUM_N 256
#define QSC_DILITHIUM_Q 8380417 
#define QSC_DILITHIUM_D 14
#define QSC_DILITHIUM_GAMMA1 ((QSC_DILITHIUM_Q - 1) / 16)
#define QSC_DILITHIUM_GAMMA2 (QSC_DILITHIUM_GAMMA1 / 2)
#define QSC_DILITHIUM_ALPHA (2 * QSC_DILITHIUM_GAMMA2)

#if (QCX_DILITHIUM_MODE == 1)
#	define QSC_DILITHIUM_K 3
#	define QSC_DILITHIUM_L 2
#	define QSC_DILITHIUM_ETA 7
#	define QSC_DILITHIUM_SETABITS 4
#	define QSC_DILITHIUM_BETA 375
#	define QSC_DILITHIUM_OMEGA 64
#elif (QCX_DILITHIUM_MODE == 2)
#	define QSC_DILITHIUM_K 4
#	define QSC_DILITHIUM_L 3
#	define QSC_DILITHIUM_ETA 6
#	define QSC_DILITHIUM_SETABITS 4
#	define QSC_DILITHIUM_BETA 325
#	define QSC_DILITHIUM_OMEGA 80
#elif (QCX_DILITHIUM_MODE == 3)
#	define QSC_DILITHIUM_K 5
#	define QSC_DILITHIUM_L 4
#	define QSC_DILITHIUM_ETA 5
#	define QSC_DILITHIUM_SETABITS 4
#	define QSC_DILITHIUM_BETA 275
#	define QSC_DILITHIUM_OMEGA 96
#elif (QCX_DILITHIUM_MODE == 4)
#	define QSC_DILITHIUM_K 6
#	define QSC_DILITHIUM_L 5
#	define QSC_DILITHIUM_ETA 3
#	define QSC_DILITHIUM_SETABITS 3
#	define QSC_DILITHIUM_BETA 175
#	define QSC_DILITHIUM_OMEGA 120
#else
#	error the dilithium mode is invalid!
#endif

/* qsc_dilithium_ntt.h */

/*************************************************
* Name:        qsc_dilithium_ntt
*
* Description: Forward NTT, in-place. No modular reduction is performed after
*              additions or subtractions. Hence output coefficients can be up
*              to 16*QSC_DILITHIUM_Q larger than the coefficients of the input polynomial.
*              Output vector is in bitreversed order.
*
* Arguments:   - uint32_t p[QSC_DILITHIUM_N]: input/output coefficient array
**************************************************/
void qsc_dilithium_ntt(uint32_t p[QSC_DILITHIUM_N]);

/*************************************************
* Name:        qsc_dilithium_invntt_frominvmont
*
* Description: Inverse NTT and multiplication by Montgomery factor 2^32.
*              In-place. No modular reductions after additions or
*              subtractions. Input coefficient need to be smaller than 2*QSC_DILITHIUM_Q.
*              Output coefficient are smaller than 2*QSC_DILITHIUM_Q.
*
* Arguments:   - uint32_t p[QSC_DILITHIUM_N]: input/output coefficient array
**************************************************/
void qsc_dilithium_invntt_frominvmont(uint32_t p[QSC_DILITHIUM_N]);

/* qsc_dilithium_poly.h */

typedef struct
{
	uint32_t coeffs[QSC_DILITHIUM_N];
} qsc_dilithium_poly;

/*************************************************
* Name:        qsc_dilithium_poly_reduce
*
* Description: Reduce all coefficients of input polynomial to representative
*              in [0,2*QSC_DILITHIUM_Q[.
*
* Arguments:   - qsc_dilithium_poly *a: pointer to input/output polynomial
**************************************************/
void qsc_dilithium_poly_reduce(qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_csubq
*
* Description: For all coefficients of input polynomial subtract QSC_DILITHIUM_Q if
*              coefficient is bigger than QSC_DILITHIUM_Q.
*
* Arguments:   - qsc_dilithium_poly *a: pointer to input/output polynomial
**************************************************/
void qsc_dilithium_poly_csubq(qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_freeze
*
* Description: Reduce all coefficients of the polynomial to standard
*              representatives.
*
* Arguments:   - qsc_dilithium_poly *a: pointer to input/output polynomial
**************************************************/
void qsc_dilithium_poly_freeze(qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - qsc_dilithium_poly *c: pointer to output polynomial
*              - const qsc_dilithium_poly *a: pointer to first summand
*              - const qsc_dilithium_poly *b: pointer to second summand
**************************************************/
void qsc_dilithium_poly_add(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b);

/*************************************************
* Name:        qsc_dilithium_poly_sub
*
* Description: Subtract polynomials. Assumes coefficients of second input
*              polynomial to be less than 2*QSC_DILITHIUM_Q. No modular reduction is
*              performed.
*
* Arguments:   - qsc_dilithium_poly *c: pointer to output polynomial
*              - const qsc_dilithium_poly *a: pointer to first input polynomial
*              - const qsc_dilithium_poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void qsc_dilithium_poly_sub(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b);

/*************************************************
* Name:        qsc_dilithium_poly_shiftl
*
* Description: Multiply polynomial by 2^QSC_DILITHIUM_D without modular reduction. Assumes
*              input coefficients to be less than 2^{32-QSC_DILITHIUM_D}.
*
* Arguments:   - qsc_dilithium_poly *a: pointer to input/output polynomial
**************************************************/
void qsc_dilithium_poly_shiftl(qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_ntt
*
* Description: Forward NTT. Output coefficients can be up to 16*QSC_DILITHIUM_Q larger than
*              input coefficients.
*
* Arguments:   - qsc_dilithium_poly *a: pointer to input/output polynomial
**************************************************/
void qsc_dilithium_poly_ntt(qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_invntt_montgomery
*
* Description: Inverse NTT and multiplication with 2^{32}. Input coefficients
*              need to be less than 2*QSC_DILITHIUM_Q. Output coefficients are less than 2*QSC_DILITHIUM_Q.
*
* Arguments:   - qsc_dilithium_poly *a: pointer to input/output polynomial
**************************************************/
void qsc_dilithium_poly_invntt_montgomery(qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_pointwise_invmontgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              with 2^{-32}. Output coefficients are less than 2*QSC_DILITHIUM_Q if input
*              coefficient are less than 22*QSC_DILITHIUM_Q.
*
* Arguments:   - qsc_dilithium_poly *c: pointer to output polynomial
*              - const qsc_dilithium_poly *a: pointer to first input polynomial
*              - const qsc_dilithium_poly *b: pointer to second input polynomial
**************************************************/
void qsc_dilithium_poly_pointwise_invmontgomery(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b);

/*************************************************
* Name:        qsc_dilithium_poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod QSC_DILITHIUM_Q = c1*2^QSC_DILITHIUM_D + c0
*              with -2^{QSC_DILITHIUM_D-1} < c0 <= 2^{QSC_DILITHIUM_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - qsc_dilithium_poly *a1: pointer to output polynomial with coefficients c1
*              - qsc_dilithium_poly *a0: pointer to output polynomial with coefficients QSC_DILITHIUM_Q + a0
*              - const qsc_dilithium_poly *v: pointer to input polynomial
**************************************************/
void qsc_dilithium_poly_power2round(qsc_dilithium_poly* a1, qsc_dilithium_poly* a0, const qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod QSC_DILITHIUM_Q = c1*QSC_DILITHIUM_ALPHA + c0
*              with -QSC_DILITHIUM_ALPHA/2 < c0 <= QSC_DILITHIUM_ALPHA/2 except c1 = (QSC_DILITHIUM_Q-1)/QSC_DILITHIUM_ALPHA where we
*              set c1 = 0 and -QSC_DILITHIUM_ALPHA/2 <= c0 = c mod QSC_DILITHIUM_Q - QSC_DILITHIUM_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - qsc_dilithium_poly *a1: pointer to output polynomial with coefficients c1
*              - qsc_dilithium_poly *a0: pointer to output polynomial with coefficients QSC_DILITHIUM_Q + a0
*              - const qsc_dilithium_poly *c: pointer to input polynomial
**************************************************/
void qsc_dilithium_poly_decompose(qsc_dilithium_poly* a1, qsc_dilithium_poly* a0, const qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the low bits of the corresponding coefficient of
*              the input polynomial overflow into the high bits.
*
* Arguments:   - qsc_dilithium_poly *h: pointer to output hint polynomial
*              - const qsc_dilithium_poly *a0: pointer to low part of input polynomial
*              - const qsc_dilithium_poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
uint32_t qsc_dilithium_poly_make_hint(qsc_dilithium_poly* h, const qsc_dilithium_poly* a0, const qsc_dilithium_poly* a1);

/*************************************************
* Name:        qsc_dilithium_poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - qsc_dilithium_poly *a: pointer to output polynomial with corrected high bits
*              - const qsc_dilithium_poly *b: pointer to input polynomial
*              - const qsc_dilithium_poly *h: pointer to input hint polynomial
**************************************************/
void qsc_dilithium_poly_use_hint(qsc_dilithium_poly* a, const qsc_dilithium_poly* b, const qsc_dilithium_poly* h);

/*************************************************
* Name:        qsc_dilithium_poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const qsc_dilithium_poly *a: pointer to polynomial
*              - uint32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B and 1 otherwise.
**************************************************/
int32_t  qsc_dilithium_poly_chknorm(const qsc_dilithium_poly* a, uint32_t B);

/*************************************************
* Name:        qsc_dilithium_poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,QSC_DILITHIUM_Q-1] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - qsc_dilithium_poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length
*                                            QSC_DILITHIUM_SEED_SIZE
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void qsc_dilithium_poly_uniform(qsc_dilithium_poly* a, const uint8_t seed[QSC_DILITHIUM_SEED_SIZE], uint16_t nonce);

/*************************************************
* Name:        qsc_dilithium_poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-QSC_DILITHIUM_ETA,QSC_DILITHIUM_ETA] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - qsc_dilithium_poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length
*                                            QSC_DILITHIUM_SEED_SIZE
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void qsc_dilithium_poly_uniform_eta(qsc_dilithium_poly* a, const uint8_t seed[QSC_DILITHIUM_SEED_SIZE], uint16_t nonce);

/*************************************************
* Name:        qsc_dilithium_poly_uniform_gamma1m1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(QSC_DILITHIUM_GAMMA1 - 1), QSC_DILITHIUM_GAMMA1 - 1] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - qsc_dilithium_poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length
*                                            QSC_DILITHIUM_CRH_SIZE
*              - uint16_t nonce: 16-bit nonce
**************************************************/
void qsc_dilithium_poly_uniform_gamma1m1(qsc_dilithium_poly* a, const uint8_t seed[QSC_DILITHIUM_CRH_SIZE], uint16_t nonce);

/*************************************************
* Name:        qsc_dilithium_polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-QSC_DILITHIUM_ETA,QSC_DILITHIUM_ETA].
*              Input coefficients are assumed to lie in [QSC_DILITHIUM_Q-QSC_DILITHIUM_ETA,QSC_DILITHIUM_Q+QSC_DILITHIUM_ETA].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLETA_SIZE_PACKED bytes
*              - const qsc_dilithium_poly *a: pointer to input polynomial
**************************************************/
void qsc_dilithium_polyeta_pack(uint8_t* r, const qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-QSC_DILITHIUM_ETA,QSC_DILITHIUM_ETA].
*              Output coefficients lie in [QSC_DILITHIUM_Q-QSC_DILITHIUM_ETA,QSC_DILITHIUM_Q+QSC_DILITHIUM_ETA].
*
* Arguments:   - qsc_dilithium_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void qsc_dilithium_polyeta_unpack(qsc_dilithium_poly* r, const uint8_t* a);

/*************************************************
* Name:        qsc_dilithium_polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 9 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLT1_SIZE_PACKED bytes
*              - const qsc_dilithium_poly *a: pointer to input polynomial
**************************************************/
void qsc_dilithium_polyt1_pack(uint8_t* r, const qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_polyt1_unpack
*
* Description: Unpack polynomial t1 with 9-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - qsc_dilithium_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void qsc_dilithium_polyt1_unpack(qsc_dilithium_poly* r, const uint8_t* a);

/*************************************************
* Name:        qsc_dilithium_polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{QSC_DILITHIUM_D-1}, 2^{QSC_DILITHIUM_D-1}].
*              Input coefficients are assumed to lie in ]QSC_DILITHIUM_Q-2^{QSC_DILITHIUM_D-1}, QSC_DILITHIUM_Q+2^{QSC_DILITHIUM_D-1}].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLT0_SIZE_PACKED bytes
*              - const qsc_dilithium_poly *a: pointer to input polynomial
**************************************************/
void qsc_dilithium_polyt0_pack(uint8_t* r, const qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{QSC_DILITHIUM_D-1}, 2^{QSC_DILITHIUM_D-1}].
*              Output coefficients lie in ]QSC_DILITHIUM_Q-2^{QSC_DILITHIUM_D-1},QSC_DILITHIUM_Q+2^{QSC_DILITHIUM_D-1}].
*
* Arguments:   - qsc_dilithium_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void qsc_dilithium_polyt0_unpack(qsc_dilithium_poly* r, const uint8_t* a);

/*************************************************
* Name:        qsc_dilithium_polyz_pack
*
* Description: Bit-pack polynomial z with coefficients
*              in [-(QSC_DILITHIUM_GAMMA1 - 1), QSC_DILITHIUM_GAMMA1 - 1].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLZ_SIZE_PACKED bytes
*              - const qsc_dilithium_poly *a: pointer to input polynomial
**************************************************/
void qsc_dilithium_polyz_pack(uint8_t* r, const qsc_dilithium_poly* a);

/*************************************************
* Name:        qsc_dilithium_polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(QSC_DILITHIUM_GAMMA1 - 1), QSC_DILITHIUM_GAMMA1 - 1].
*              Output coefficients are standard representatives.
*
* Arguments:   - qsc_dilithium_poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void qsc_dilithium_polyz_unpack(qsc_dilithium_poly* r, const uint8_t* a);

/*************************************************
* Name:        qsc_dilithium_polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0, 15].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                                  DILITHIUM_POLW1_SIZE_PACKED bytes
*              - const qsc_dilithium_poly *a: pointer to input polynomial
**************************************************/
void qsc_dilithium_polyw1_pack(uint8_t* r, const qsc_dilithium_poly* a);

/* polyvec.h */

/* Vectors of polynomials of length QSC_DILITHIUM_L */
typedef struct
{
	qsc_dilithium_poly vec[QSC_DILITHIUM_L];
} qsc_dilithium_polyvecl;

/* Vectors of polynomials of length QSC_DILITHIUM_K */
typedef struct
{
	qsc_dilithium_poly vec[QSC_DILITHIUM_K];
} qsc_dilithium_polyveck;

/*************************************************
* Name:        qsc_dilithium_polyvecl_freeze
*
* Description: Reduce coefficients of polynomials in vector of length QSC_DILITHIUM_L
*              to standard representatives.
*
* Arguments:   - qsc_dilithium_polyvecl *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyvecl_freeze(qsc_dilithium_polyvecl* v);

/*************************************************
* Name:        qsc_dilithium_polyvecl_add
*
* Description: Add vectors of polynomials of length QSC_DILITHIUM_L.
*              No modular reduction is performed.
*
* Arguments:   - qsc_dilithium_polyvecl *w: pointer to output vector
*              - const qsc_dilithium_polyvecl *u: pointer to first summand
*              - const qsc_dilithium_polyvecl *v: pointer to second summand
**************************************************/
void qsc_dilithium_polyvecl_add(qsc_dilithium_polyvecl* w, const qsc_dilithium_polyvecl* u, const qsc_dilithium_polyvecl* v);

/*************************************************
* Name:        qsc_dilithium_polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length QSC_DILITHIUM_L. Output
*              coefficients can be up to 16*QSC_DILITHIUM_Q larger than input coefficients.
*
* Arguments:   - qsc_dilithium_polyvecl *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyvecl_ntt(qsc_dilithium_polyvecl* v);

/*************************************************
* Name:        qsc_dilithium_polyvecl_pointwise_acc_invmontgomery
*
* Description: Pointwise multiply vectors of polynomials of length QSC_DILITHIUM_L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*              Input coefficients are assumed to be less than 22*QSC_DILITHIUM_Q. Output
*              coeffcient are less than 2*QSC_DILITHIUM_L*QSC_DILITHIUM_Q.
*
* Arguments:   - qsc_dilithium_poly *w: output polynomial
*              - const qsc_dilithium_polyvecl *u: pointer to first input vector
*              - const qsc_dilithium_polyvecl *v: pointer to second input vector
**************************************************/
void qsc_dilithium_polyvecl_pointwise_acc_invmontgomery(qsc_dilithium_poly* w, const qsc_dilithium_polyvecl* u, const qsc_dilithium_polyvecl* v);

/*************************************************
* Name:        qsc_dilithium_polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length QSC_DILITHIUM_L.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const qsc_dilithium_polyvecl *v: pointer to vector
*              - uint32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B and 1
* otherwise.
**************************************************/
int32_t qsc_dilithium_polyvecl_chknorm(const qsc_dilithium_polyvecl* v, uint32_t B);

/*************************************************
* Name:        qsc_dilithium_polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length QSC_DILITHIUM_K
*              to representatives in [0,2*QSC_DILITHIUM_Q[.
*
* Arguments:   - qsc_dilithium_polyveck *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyveck_reduce(qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_csubq
*
* Description: For all coefficients of polynomials in vector of length QSC_DILITHIUM_K
*              subtract QSC_DILITHIUM_Q if coefficient is bigger than QSC_DILITHIUM_Q.
*
* Arguments:   - qsc_dilithium_polyveck *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyveck_csubq(qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_freeze
*
* Description: Reduce coefficients of polynomials in vector of length QSC_DILITHIUM_K
*              to standard representatives.
*
* Arguments:   - qsc_dilithium_polyveck *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyveck_freeze(qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_add
*
* Description: Add vectors of polynomials of length QSC_DILITHIUM_K.
*              No modular reduction is performed.
*
* Arguments:   - qsc_dilithium_polyveck *w: pointer to output vector
*              - const qsc_dilithium_polyveck *u: pointer to first summand
*              - const qsc_dilithium_polyveck *v: pointer to second summand
**************************************************/
void qsc_dilithium_polyveck_add(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_sub
*
* Description: Subtract vectors of polynomials of length QSC_DILITHIUM_K.
*              Assumes coefficients of polynomials in second input vector
*              to be less than 2*QSC_DILITHIUM_Q. No modular reduction is performed.
*
* Arguments:   - qsc_dilithium_polyveck *w: pointer to output vector
*              - const qsc_dilithium_polyveck *u: pointer to first input vector
*              - const qsc_dilithium_polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void qsc_dilithium_polyveck_sub(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length QSC_DILITHIUM_K by 2^QSC_DILITHIUM_D without modular
*              reduction. Assumes input coefficients to be less than 2^{32-QSC_DILITHIUM_D}.
*
* Arguments:   - qsc_dilithium_polyveck *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyveck_shiftl(qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length QSC_DILITHIUM_K. Output
*              coefficients can be up to 16*QSC_DILITHIUM_Q larger than input coefficients.
*
* Arguments:   - qsc_dilithium_polyveck *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyveck_ntt(qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_invntt_montgomery
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length QSC_DILITHIUM_K. Input coefficients need to be less
*              than 2*QSC_DILITHIUM_Q.
*
* Arguments:   - qsc_dilithium_polyveck *v: pointer to input/output vector
**************************************************/
void qsc_dilithium_polyveck_invntt_montgomery(qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length QSC_DILITHIUM_K.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const qsc_dilithium_polyveck *v: pointer to vector
*              - uint32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B and 1
* otherwise.
**************************************************/
int32_t qsc_dilithium_polyveck_chknorm(const qsc_dilithium_polyveck* v, uint32_t B);

/*************************************************
* Name:        qsc_dilithium_polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length QSC_DILITHIUM_K,
*              compute a0, a1 such that a mod QSC_DILITHIUM_Q = a1*2^QSC_DILITHIUM_D + a0
*              with -2^{QSC_DILITHIUM_D-1} < a0 <= 2^{QSC_DILITHIUM_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - qsc_dilithium_polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - qsc_dilithium_polyveck *v0: pointer to output vector of polynomials with
*                              coefficients QSC_DILITHIUM_Q + a0
*              - const qsc_dilithium_polyveck *v: pointer to input vector
**************************************************/
void qsc_dilithium_polyveck_power2round(qsc_dilithium_polyveck* v1, qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length QSC_DILITHIUM_K,
*              compute high and low bits a0, a1 such a mod QSC_DILITHIUM_Q = a1*QSC_DILITHIUM_ALPHA + a0
*              with -QSC_DILITHIUM_ALPHA/2 < a0 <= QSC_DILITHIUM_ALPHA/2 except a1 = (QSC_DILITHIUM_Q-1)/QSC_DILITHIUM_ALPHA where we
*              set a1 = 0 and -QSC_DILITHIUM_ALPHA/2 <= a0 = a mod QSC_DILITHIUM_Q - QSC_DILITHIUM_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - qsc_dilithium_polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - qsc_dilithium_polyveck *v0: pointer to output vector of polynomials with
*                              coefficients QSC_DILITHIUM_Q + a0
*              - const qsc_dilithium_polyveck *v: pointer to input vector
**************************************************/
void qsc_dilithium_polyveck_decompose(qsc_dilithium_polyveck* v1, qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v);

/*************************************************
* Name:        qsc_dilithium_polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - qsc_dilithium_polyveck *h: pointer to output vector
*              - const qsc_dilithium_polyveck *v0: pointer to low part of input vector
*              - const qsc_dilithium_polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
uint32_t qsc_dilithium_polyveck_make_hint(qsc_dilithium_polyveck* h, const qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v1);

/*************************************************
* Name:        qsc_dilithium_polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - qsc_dilithium_polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const qsc_dilithium_polyveck *u: pointer to input vector
*              - const qsc_dilithium_polyveck *h: pointer to input hint vector
**************************************************/
void qsc_dilithium_polyveck_use_hint(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* v, const qsc_dilithium_polyveck* h);

/* packing.h */

/*************************************************
* Name:        qsc_dilithium_pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const qsc_dilithium_polyveck *t1: pointer to vector t1
**************************************************/
void qsc_dilithium_pack_pk(uint8_t* pk, const uint8_t* rho, const qsc_dilithium_polyveck* t1);

/*************************************************
* Name:        qsc_dilithium_unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const qsc_dilithium_polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void qsc_dilithium_unpack_pk(uint8_t* rho, qsc_dilithium_polyveck* t1, const uint8_t* pk);

/*************************************************
* Name:        qsc_dilithium_pack_sk
*
* Description: Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t key[]: byte array containing key
*              - const uint8_t tr[]: byte array containing tr
*              - const qsc_dilithium_polyvecl *s1: pointer to vector s1
*              - const qsc_dilithium_polyveck *s2: pointer to vector s2
*              - const qsc_dilithium_polyveck *t0: pointer to vector t0
**************************************************/
void qsc_dilithium_pack_sk(uint8_t* sk, const uint8_t* rho, const uint8_t* key, const uint8_t* tr, const qsc_dilithium_polyvecl* s1, const qsc_dilithium_polyveck* s2, const qsc_dilithium_polyveck* t0);

/*************************************************
* Name:        qsc_dilithium_unpack_sk
*
* Description: Unpack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t key[]: output byte array for key
*              - const uint8_t tr[]: output byte array for tr
*              - const qsc_dilithium_polyvecl *s1: pointer to output vector s1
*              - const qsc_dilithium_polyveck *s2: pointer to output vector s2
*              - const qsc_dilithium_polyveck *r0: pointer to output vector t0
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void qsc_dilithium_unpack_sk(uint8_t* rho, uint8_t* key, uint8_t* tr, qsc_dilithium_polyvecl* s1, qsc_dilithium_polyveck* s2, qsc_dilithium_polyveck* t0, const uint8_t* sk);

/*************************************************
* Name:        qsc_dilithium_pack_sig
*
* Description: Bit-pack signature sig = (z, h, c).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const qsc_dilithium_polyvecl *z: pointer to vector z
*              - const qsc_dilithium_polyveck *h: pointer to hint vector h
*              - const qsc_dilithium_poly *c: pointer to challenge polynomial
**************************************************/
void qsc_dilithium_pack_sig(uint8_t* sig, const qsc_dilithium_polyvecl* z, const qsc_dilithium_polyveck* h, const qsc_dilithium_poly* c);

/*************************************************
* Name:        qsc_dilithium_unpack_sig
*
* Description: Unpack signature sig = (z, h, c).
*
* Arguments:   - qsc_dilithium_polyvecl *z: pointer to output vector z
*              - qsc_dilithium_polyveck *h: pointer to output hint vector h
*              - qsc_dilithium_poly *c: pointer to output challenge polynomial
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int32_t qsc_dilithium_unpack_sig(qsc_dilithium_polyvecl* z, qsc_dilithium_polyveck* h, qsc_dilithium_poly* c, const uint8_t* sig);

/* reduce.h */

/*************************************************
* Name:        qsc_dilithium_montgomery_reduce
*
* Description: For finite field element a with 0 <= a <= QSC_DILITHIUM_Q*2^32,
*              compute r \equiv a*2^{-32} (mod QSC_DILITHIUM_Q) such that 0 <= r < 2*QSC_DILITHIUM_Q.
*
* Arguments:   - uint64_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t qsc_dilithium_montgomery_reduce(uint64_t a);

/*************************************************
* Name:        qsc_dilithium_reduce32
*
* Description: For finite field element a, compute r \equiv a (mod QSC_DILITHIUM_Q)
*              such that 0 <= r < 2*QSC_DILITHIUM_Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t qsc_dilithium_reduce32(uint32_t a);

/*************************************************
* Name:        qsc_dilithium_csubq
*
* Description: Subtract QSC_DILITHIUM_Q if input coefficient is bigger than QSC_DILITHIUM_Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t qsc_dilithium_csubq(uint32_t a);

/*************************************************
* Name:        qsc_dilithium_freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod QSC_DILITHIUM_Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t qsc_dilithium_freeze(uint32_t a);

/* rounding.h */

/*************************************************
* Name:        qsc_dilithium_power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod QSC_DILITHIUM_Q = a1*2^QSC_DILITHIUM_D + a0 with -2^{QSC_DILITHIUM_D-1} < a0 <= 2^{QSC_DILITHIUM_D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t *a0: pointer to output element QSC_DILITHIUM_Q + a0
*
* Returns a1.
**************************************************/
uint32_t qsc_dilithium_power2round(uint32_t a, uint32_t* a0);

/*************************************************
* Name:        qsc_dilithium_decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod QSC_DILITHIUM_Q = a1*QSC_DILITHIUM_ALPHA + a0 with -QSC_DILITHIUM_ALPHA/2 < a0 <= QSC_DILITHIUM_ALPHA/2 except
*              if a1 = (QSC_DILITHIUM_Q-1)/QSC_DILITHIUM_ALPHA where we set a1 = 0 and
*              -QSC_DILITHIUM_ALPHA/2 <= a0 = a mod QSC_DILITHIUM_Q - QSC_DILITHIUM_Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t *a0: pointer to output element QSC_DILITHIUM_Q + a0
*
* Returns a1.
**************************************************/
uint32_t qsc_dilithium_decompose(uint32_t a, uint32_t* a0);

/*************************************************
* Name:        qsc_dilithium_make_hint
*
* Description: Compute hint bit indicating whether the low bits of the
*              input element overflow into the high bits. Inputs assumed to be
*              standard representatives.
*
* Arguments:   - uint32_t a0: low bits of input element
*              - uint32_t a1: high bits of input element
*
* Returns 1 if high bits of a and b differ and 0 otherwise.
**************************************************/
uint32_t qsc_dilithium_make_hint(const uint32_t a0, const uint32_t a1);

/*************************************************
* Name:        qsc_dilithium_use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t hint: hint bit
*
* Returns corrected high bits.
**************************************************/
uint32_t qsc_dilithium_use_hint(const uint32_t a, const uint32_t hint);

/* sign.h */

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to DILITHIUM_PUBLICKEY_SIZE and SPHINCS_SECRETKEY_SIZE.
*
* \param publickey The public verification key
* \param secretkey The private signature key
*/
void qsc_dilithium_ksm_generate(uint8_t* publickey, uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param message The message to be signed
* \param msglen The message length
* \param privatekey The private signature key
*/
void qsc_dilithium_ksm_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message The message to be signed
* \param msglen The message length
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param publickey The public verification key
* \return Returns true for success
*/
bool qsc_dilithium_ksm_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);


#endif