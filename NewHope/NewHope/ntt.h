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
