/**
* \file ntt.h
* \brief <b>Number Theoretic Transform</b> \n
* This is an internal class.
*
* \date January 10, 2018
*/

#ifndef NTT_H
#define NTT_H

#include "common.h"

/**
* \brief Computes negacyclic number-theoretic transform (NTT) of
* a polynomial (vector of 256 coefficients) in place;
* inputs assumed to be in normal order, output in bitreversed order.
*
* \param p Pointer to in/output polynomial
*/
void ntt(uint16_t* p);

/**
* \brief Computes inverse of negacyclic number-theoretic transform (NTT) of
* a polynomial (vector of 256 coefficients) in place;
* inputs assumed to be in bitreversed order, output in normal order.
*
* \param p Pointer to input/output polynomial
*/
void invntt(uint16_t* p);

#endif
