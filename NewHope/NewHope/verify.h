/**
* \file verify.h
* \date February 16, 2018
*
* \brief <b>Verification and conditional move api</b> \n
* This is an internal class.
*/

#ifndef NEWHOPE_VERIFY_H
#define NEWHOPE_VERIFY_H

#include "common.h"

/**
* \brief Copy len bytes from x to r if b is 1; don't modify x if b is 0. Requires b to be in {0,1}.
* Assumes two's complement representation of negative integers.
* Runs in constant time.
*
* \param r pointer to output byte array
* \param x pointer to input byte array
* \param length number of bytes to be copied
* \param b condition bit; has to be in {0,1}
*/
void cmov(uint8_t* r, const uint8_t* x, size_t length, uint8_t b);

/**
* \brief Compare two arrays for equality in constant time
*
* \param a pointer to first byte array
* \param b pointer to second byte array
* \param length length of the byte arrays
*/
int32_t verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
