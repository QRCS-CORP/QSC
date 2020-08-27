#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

/*************************************************
* Name:        ntt
*
* Description: Forward NTT, in-place. No modular reduction is performed after
*              additions or subtractions. Hence output coefficients can be up
*              to 16*DILITHIUM_Q larger than the coefficients of the input polynomial.
*              Output vector is in bitreversed order.
*
* Arguments:   - uint32_t p[DILITHIUM_N]: input/output coefficient array
**************************************************/
void ntt(uint32_t p[DILITHIUM_N]);

/*************************************************
* Name:        invntt_frominvmont
*
* Description: Inverse NTT and multiplication by Montgomery factor 2^32.
*              In-place. No modular reductions after additions or
*              subtractions. Input coefficient need to be smaller than 2*DILITHIUM_Q.
*              Output coefficient are smaller than 2*DILITHIUM_Q.
*
* Arguments:   - uint32_t p[DILITHIUM_N]: input/output coefficient array
**************************************************/
void invntt_frominvmont(uint32_t p[DILITHIUM_N]);

#endif
