/**
* \file ntt.h
* \brief <b>Number Theoretic Transform</b> \n
* This is an internal class.
*
* \date January 10, 2018
*/

#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include "reduce.h"
#include <stdint.h>
/* jgu -suppressing repeated include warning, using include guards */
/*lint -e537 */

extern int16_t zetas[128];
extern int16_t zetasinv[128];

/**
* \brief Multiplication of polynomials in Zq[X]/((X^2-zeta))
* used for multiplication of elements in Rq in NTT domain.
*
* \param r pointer to the output polynomial
* \param a pointer to the first factor
* \param b pointer to the second factor
* \param zeta integer defining the reduction polynomial
*/
void basemul(uint16_t r[2], const uint16_t a[2], const uint16_t b[2], int16_t zeta);

/**
* \brief Computes inverse of negacyclic number-theoretic transform (NTT) of
* a polynomial (vector of 256 coefficients) in place;
* inputs assumed to be in bitreversed order, output in normal order.
*
* \param p Pointer to input/output polynomial
*/
void invntt(uint16_t* p);

/**
* \brief Computes negacyclic number-theoretic transform (NTT) of
* a polynomial (vector of 256 coefficients) in place;
* inputs assumed to be in normal order, output in bitreversed order.
*
* \param p Pointer to in/output polynomial
*/
void ntt(uint16_t* p);

#endif
