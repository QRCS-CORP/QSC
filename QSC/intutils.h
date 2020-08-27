/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* An implementation of supporting integer based functions
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com */

/*
* \file intutils.h
* \brief <b>Integer utilities; supporting integer related functions</b> \n
* This file contains common integer functions
* August 7, 2019
*/

#ifndef QSC_INTUTILS_H
#define QSC_INTUTILS_H

#include "common.h"

/**
* \brief Compare two byte 8-bit integer for equality
*
* \param a: The first array to compare
* \param b: The second array to compare
* \param length: The number of bytes to compare
* \return Returns true for equal values
*/
bool qsc_intutils_are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Convert an 8-bit integer array to a 16-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 16-bit big endian integer
*/
uint16_t qsc_intutils_be8to16(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit big endian integer
*/
uint32_t qsc_intutils_be8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit big endian integer
*/
uint64_t qsc_intutils_be8to64(const uint8_t* input);

/**
* \brief Convert a 16-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 16-bit integer
*/
void qsc_intutils_be16to8(uint8_t* output, uint16_t value);

/**
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 32-bit integer
*/
void qsc_intutils_be32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 64-bit integer
*/
void qsc_intutils_be64to8(uint8_t* output, uint64_t value);

/**
* \brief Increment an 8-bit integer array as a segmented big-endian integer
*
* \param output: The destination integer 8-bit array
* \param outlen: The length of the output counter array
*/
void qsc_intutils_be8increment(uint8_t* output, size_t outlen);

/**
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 8-bit integers to zeroize
*/
void qsc_intutils_clear8(uint8_t* a, size_t count);

/**
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 8-bit integers to zeroize
*/
void qsc_intutils_clear16(uint16_t* a, size_t count);

/**
* \brief Set an an 32-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: the number of 32-bit integers to zeroize
*/
void qsc_intutils_clear32(uint32_t* a, size_t count);

/**
* \brief Set an an 64-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 64-bit integers to zeroize
*/
void qsc_intutils_clear64(uint64_t* a, size_t count);

/**
* \brief Constant-time conditional move function
* b=1 means move, b=0 means don't move
*
* \param r: The return array
* \param x: The source array
* \param length: The number of bytes to move
* \param b: The condition
*/
void qsc_intutils_cmov(uint8_t* r, const uint8_t* x, size_t length, uint8_t b);

/**
* \brief Increment an 8-bit integer array as a segmented little-endian integer
*
* \param output: The source integer 8-bit array
* \param outlen: The length of the output counter array
*/
void qsc_intutils_le8increment(uint8_t* output, size_t outlen);

/**
* \brief Convert an 8-bit integer array to a 16-bit little-endian integer
*
* \param input: The source integer 8-bit array
* \return Returns the 16-bit little endian integer
*/
uint16_t qsc_intutils_le8to16(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 32-bit little-endian integer
*
* \param input: The source integer 8-bit array
* \return Returns the 32-bit little endian integer
*/
uint32_t qsc_intutils_le8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input: The source integer 8-bit array
* \return Returns the 64-bit little endian integer
*/
uint64_t qsc_intutils_le8to64(const uint8_t* input);

/**
* \brief Convert a 16-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 16-bit integer
*/
void qsc_intutils_le16to8(uint8_t* output, uint16_t value);

/**
* \brief Convert a 32-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 32-bit integer
*/
void qsc_intutils_le32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 64-bit integer
*/
void qsc_intutils_le64to8(uint8_t* output, uint64_t value);

/**
* \brief Return the larger of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the larger integer
*/
size_t qsc_intutils_max(size_t a, size_t b);

/**
* \brief Return the smaller of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the smaller integer
*/
size_t qsc_intutils_min(size_t a, size_t b);

/**
* \brief Rotate an unsigned 32-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
uint32_t qsc_intutils_rotl32(uint32_t value, size_t shift);

/**
* \brief Rotate an unsigned 64-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
uint64_t qsc_intutils_rotl64(uint64_t value, size_t shift);

/**
* \brief Rotate an unsigned 32-bit integer to the right
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
uint32_t qsc_intutils_rotr32(uint32_t value, size_t shift);

/**
* \brief Rotate an unsigned 64-bit integer to the right
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
uint64_t qsc_intutils_rotr64(uint64_t value, size_t shift);

/**
* \brief Constant time comparison of two 8-bit arrays
*
* \param a: The first 8-bit integer array
* \param b: The second 8-bit integer array
* \return Returns zero if the arrays are equivalent
*/
int32_t qsc_intutils_verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
