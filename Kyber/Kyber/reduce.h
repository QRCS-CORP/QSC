/**
* \file reduce.h
* \brief <b>Kyber polynomial reduction functions</b> \n
* This is an internal class.
*
* \date January 07, 2018
*/

#ifndef REDUCE_H
#define REDUCE_H

#include "common.h"

/**
* \brief Barrett reduction; given a 16-bit integer a, computes
* 16-bit integer congruent to a mod q in {0,...,11768}.
*
* \param x Input unsigned integer to be reduced
*/
uint16_t barrett_reduce(uint16_t x);

/**
* \brief Full reduction; given a 16-bit integer a, computes unsigned integer a mod q.
*
* \param x Input unsigned integer to be reduced
* \return unsigned integer in {0,...,q-1} congruent to a modulo q
*/
uint16_t freeze(uint16_t x);

/**
* \brief Montgomery reduction; given a 32-bit integer a, computes 16-bit integer 
* congruent to a * R^-1 mod q, where R=2^18 (see value of rlog).
*
* \param x Input unsigned integer to be reduced; has to be in {0,...,2281446912}
* \return unsigned integer in {0,...,2^13-1} congruent to a * R^-1 modulo q
*/
uint16_t montgomery_reduce(uint32_t x);

#endif
