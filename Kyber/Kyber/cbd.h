/**
* \file cbd.h
* \brief <b>Centered Binomial Distribution</b> \n
* This is an internal class.
*
* \date January 10, 2018
*/

#ifndef KYBER_CBD_H
#define KYBER_CBD_H

#include "poly.h"

/**
* \brief Given an array of uniformly random bytes, 
* compute a polynomial with coefficients distributed according to
* a centered binomial distribution with parameter KYBER_ETA.
*
* \param r Pointer to output polynomial
* \param buf Pointer to input byte array
*/
void cbd(poly* r, const uint8_t* buf);

#endif
