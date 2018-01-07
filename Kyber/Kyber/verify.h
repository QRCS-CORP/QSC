/**
* \file verify.h
* \brief <b>Kyber constant-time functions</b> \n
* This is an internal class.
*
* \date January 07, 2018
*/

#ifndef VERIFY_H
#define VERIFY_H

#include <stdint.h>

/**
* \brief Copy len bytes from x to r if b is 1;
* don't modify x if b is 0.
* Requires b to be in {0,1}; assumes two's complement representation of negative integers.
* Runs in constant time.
*
* \param r Pointer to output byte array
* \param x Pointer to input byte array
* \param length Amount of bytes to be copied
* \param b Condition bit; has to be in {0,1}
*/
void cmov(uint8_t* r, const uint8_t* x, size_t length, uint8_t b);

/**
* \brief Compare two arrays for equality in constant time.
*
* \param a Pointer to first byte array
* \param b Pointer to second byte array
* \param length The length of the byte arrays
* \return b Condition bit; has to be in {0,1}
*/
int32_t verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
