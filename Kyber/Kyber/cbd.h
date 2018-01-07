/**
* \file cbd.h
* \brief <b>Centered Binomial Distribution</b> \n
* This is an internal class.
*
* \date January 07, 2018
*/

#ifndef CBD_H
#define CBD_H

#include "poly.h"
/*lint !e537 */

/**
* \brief Given an array of uniformly random bytes, 
* compute a polynomial with coefficients distributed according to
* a centered binomial distribution with parameter KYBER_ETA.
*
* \param r Pointer to output polynomial
* \param buf pointer to input byte array
*/
void cbd(poly* r, const uint8_t* buf);

#endif
