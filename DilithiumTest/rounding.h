#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>

/*************************************************
* Name:        power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod DILITHIUM_Q = a1*2^DILITHIUM_D + a0 with -2^{DILITHIUM_D-1} < a0 <= 2^{DILITHIUM_D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t *a0: pointer to output element DILITHIUM_Q + a0
*
* Returns a1.
**************************************************/
uint32_t power2round(uint32_t a, uint32_t* a0);

/*************************************************
* Name:        decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod DILITHIUM_Q = a1*DILITHIUM_ALPHA + a0 with -DILITHIUM_ALPHA/2 < a0 <= DILITHIUM_ALPHA/2 except
*              if a1 = (DILITHIUM_Q-1)/DILITHIUM_ALPHA where we set a1 = 0 and
*              -DILITHIUM_ALPHA/2 <= a0 = a mod DILITHIUM_Q - DILITHIUM_Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t *a0: pointer to output element DILITHIUM_Q + a0
*
* Returns a1.
**************************************************/
uint32_t decompose(uint32_t a, uint32_t* a0);

/*************************************************
* Name:        make_hint
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
uint32_t make_hint(const uint32_t a0, const uint32_t a1);

/*************************************************
* Name:        use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t hint: hint bit
*
* Returns corrected high bits.
**************************************************/
uint32_t use_hint(const uint32_t a, const uint32_t hint);

#endif
