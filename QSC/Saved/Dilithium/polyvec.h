#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length DILITHIUM_L */
typedef struct 
{
	poly vec[DILITHIUM_L];
} polyvecl;

/* Vectors of polynomials of length DILITHIUM_K */
typedef struct 
{
	poly vec[DILITHIUM_K];
} polyveck;

/*************************************************
* Name:        polyvecl_freeze
*
* Description: Reduce coefficients of polynomials in vector of length DILITHIUM_L
*              to standard representatives.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/
void polyvecl_freeze(polyvecl* v);

/*************************************************
* Name:        polyvecl_add
*
* Description: Add vectors of polynomials of length DILITHIUM_L.
*              No modular reduction is performed.
*
* Arguments:   - polyvecl *w: pointer to output vector
*              - const polyvecl *u: pointer to first summand
*              - const polyvecl *v: pointer to second summand
**************************************************/
void polyvecl_add(polyvecl* w, const polyvecl* u, const polyvecl* v);

/*************************************************
* Name:        polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length DILITHIUM_L. Output
*              coefficients can be up to 16*DILITHIUM_Q larger than input coefficients.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/
void polyvecl_ntt(polyvecl* v);

/*************************************************
* Name:        polyvecl_pointwise_acc_invmontgomery
*
* Description: Pointwise multiply vectors of polynomials of length DILITHIUM_L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*              Input coefficients are assumed to be less than 22*DILITHIUM_Q. Output
*              coeffcient are less than 2*DILITHIUM_L*DILITHIUM_Q.
*
* Arguments:   - poly *w: output polynomial
*              - const polyvecl *u: pointer to first input vector
*              - const polyvecl *v: pointer to second input vector
**************************************************/
void polyvecl_pointwise_acc_invmontgomery(poly* w, const polyvecl* u, const polyvecl* v);

/*************************************************
* Name:        polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length DILITHIUM_L.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const polyvecl *v: pointer to vector
*              - uint32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B and 1
* otherwise.
**************************************************/
int32_t polyvecl_chknorm(const polyvecl* v, uint32_t B);

/*************************************************
* Name:        polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length DILITHIUM_K
*              to representatives in [0,2*DILITHIUM_Q[.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_reduce(polyveck* v);

/*************************************************
* Name:        polyveck_csubq
*
* Description: For all coefficients of polynomials in vector of length DILITHIUM_K
*              subtract DILITHIUM_Q if coefficient is bigger than DILITHIUM_Q.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_csubq(polyveck* v);

/*************************************************
* Name:        polyveck_freeze
*
* Description: Reduce coefficients of polynomials in vector of length DILITHIUM_K
*              to standard representatives.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_freeze(polyveck* v);

/*************************************************
* Name:        polyveck_add
*
* Description: Add vectors of polynomials of length DILITHIUM_K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first summand
*              - const polyveck *v: pointer to second summand
**************************************************/
void polyveck_add(polyveck* w, const polyveck* u, const polyveck* v);

/*************************************************
* Name:        polyveck_sub
*
* Description: Subtract vectors of polynomials of length DILITHIUM_K.
*              Assumes coefficients of polynomials in second input vector
*              to be less than 2*DILITHIUM_Q. No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first input vector
*              - const polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void polyveck_sub(polyveck* w, const polyveck* u, const polyveck* v);

/*************************************************
* Name:        polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length DILITHIUM_K by 2^DILITHIUM_D without modular
*              reduction. Assumes input coefficients to be less than 2^{32-DILITHIUM_D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_shiftl(polyveck* v);

/*************************************************
* Name:        polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length DILITHIUM_K. Output
*              coefficients can be up to 16*DILITHIUM_Q larger than input coefficients.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_ntt(polyveck* v);

/*************************************************
* Name:        polyveck_invntt_montgomery
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length DILITHIUM_K. Input coefficients need to be less
*              than 2*DILITHIUM_Q.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_invntt_montgomery(polyveck* v);

/*************************************************
* Name:        polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length DILITHIUM_K.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const polyveck *v: pointer to vector
*              - uint32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B and 1
* otherwise.
**************************************************/
int32_t polyveck_chknorm(const polyveck* v, uint32_t B);

/*************************************************
* Name:        polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length DILITHIUM_K,
*              compute a0, a1 such that a mod DILITHIUM_Q = a1*2^DILITHIUM_D + a0
*              with -2^{DILITHIUM_D-1} < a0 <= 2^{DILITHIUM_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients DILITHIUM_Q + a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_power2round(polyveck* v1, polyveck* v0, const polyveck* v);

/*************************************************
* Name:        polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length DILITHIUM_K,
*              compute high and low bits a0, a1 such a mod DILITHIUM_Q = a1*DILITHIUM_ALPHA + a0
*              with -DILITHIUM_ALPHA/2 < a0 <= DILITHIUM_ALPHA/2 except a1 = (DILITHIUM_Q-1)/DILITHIUM_ALPHA where we
*              set a1 = 0 and -DILITHIUM_ALPHA/2 <= a0 = a mod DILITHIUM_Q - DILITHIUM_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients DILITHIUM_Q + a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_decompose(polyveck* v1, polyveck* v0, const polyveck* v);

/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyveck *h: pointer to output vector
*              - const polyveck *v0: pointer to low part of input vector
*              - const polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
uint32_t polyveck_make_hint(polyveck* h, const polyveck* v0, const polyveck* v1);

/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const polyveck *u: pointer to input vector
*              - const polyveck *h: pointer to input hint vector
**************************************************/
void polyveck_use_hint(polyveck* w, const polyveck* v, const polyveck* h);

#endif
