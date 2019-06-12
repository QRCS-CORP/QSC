/**
* \file reduce.h
* \brief <b>Kyber polynomial reduction functions</b> \n
* This is an internal class.
*
* \date May 09, 2019
*/

#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include <stdint.h>
/* jgu -suppressing repeated include warning, using include guards */
/*lint -e537 */

#define MONT 2285 // 2^16 % Q
#define QINV 62209 // q^(-1) mod 2^16

/**
* \brief Barrett reduction; given a 16-bit integer a, computes
* 16-bit integer congruent to a mod q in {0,...,11768}.
*
* \param x Input unsigned integer to be reduced
*/
int16_t barrett_reduce(int16_t a);

/**
* \brief Conditionallly subtract q
*
* \param a input integer
* \return a - q if a >= q, else a
*/
int16_t csubq(int16_t a);

/**
* \brief Montgomery reduction; given a 32-bit integer a, computes 16-bit integer 
* congruent to a * R^-1 mod q, where R=2^18 (see value of rlog).
*
* \param x Input unsigned integer to be reduced; has to be in {0,...,2281446912}
* \return unsigned integer in {0,...,2^13-1} congruent to a * R^-1 modulo q
*/
int16_t montgomery_reduce(int32_t a);

#endif
