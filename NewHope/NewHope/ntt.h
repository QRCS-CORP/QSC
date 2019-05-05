#ifndef NEWHOPE_NTT_H
#define NEWHOPE_NTT_H

#include <cstdbool>
#include <stdint.h>

/*extern uint16_t omegas_inv_bitrev_montgomery[];
extern uint16_t gammas_bitrev_montgomery[];
extern uint16_t gammas_inv_montgomery[];*/

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
