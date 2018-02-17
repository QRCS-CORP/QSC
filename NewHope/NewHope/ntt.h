/**
* \file ntt.h
* \date February 16, 2018
*
* \brief <b>Number Theoretic Transform api</b> \n
* This is an internal class.
*/

#ifndef NEWHOPE_NTT_H
#define NEWHOPE_NTT_H

#include "params.h"

/** \brief powers of nth root of unity in Montgomery domain with R=2^18 in bit-reversed order */
extern uint16_t omegas_bitrev_montgomery[NEWHOPE_N / 2];
/** \brief inverses of powers of nth root of unity  in Montgomery domain with R=2^18 in bit-reversed order */
extern uint16_t omegas_inv_bitrev_montgomery[NEWHOPE_N / 2];
/** \brief powers of nth root of -1 in Montgomery domain with R=2^18 in bit-reversed order */
extern uint16_t psis_bitrev_montgomery[NEWHOPE_N];
/** \brief inverses of powers of nth  root of -1 divided by n in Montgomery domain with R=2^18 */
extern uint16_t psis_inv_montgomery[NEWHOPE_N];

/**
* \brief Permutes coefficients of a polynomial into bitreversed order
*
* \param poly pointer to in/output polynomial
*/
void bitrev_vector(uint16_t* poly);

/**
* \brief Performs pointwise (coefficient-wise) multiplication of two polynomials
*
* \param poly pointer to in/output polynomial
* \param factors pointer to input polynomial, coefficients are assumed to be in Montgomery representation
*/
void mul_coefficients(uint16_t* poly, const uint16_t* factors);

/**
* \brief Computes number-theoretic transform (NTT) of a polynomial in place; 
* inputs assumed to be in bitreversed order, output in normal order
*
* \param poly pointer to input/output polynomial
* \param omegas pointer to input powers of root of unity omega; assumed to be in Montgomery domain
*/
void ntt(uint16_t* poly, const uint16_t* omegas);

#endif
