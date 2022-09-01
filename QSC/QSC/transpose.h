/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

#ifndef QSC_TRANSPOSE_H
#define QSC_TRANSPOSE_H

#include "common.h"
#include "intutils.h"

/**
* \file transpose.h
* \brief String and array transposition functions
*/

/**
* \brief Convert 32-bit integers in big-endian format to 8-bit integers
*
* \param output: Pointer to the output 8-bit integer array
* \param input: [const] Pointer to the input 8-bit character array
* \param length: The number of 8-bit integers to convert
*/
QSC_EXPORT_API void qsc_transpose_bytes_to_native(uint32_t* output, const uint8_t* input, size_t length);

/**
* \brief Convert a hexadecimal string to a decimal 8-bit array
*
* \param output: Pointer to the output 8-bit integer array
* \param input: [const] Pointer to the input 8-bit character array
* \param length: The number of hex characters to convert
*/
QSC_EXPORT_API void qsc_transpose_hex_to_bin(uint8_t* output, const char* input, size_t length);

/**
* \brief Convert 8-bit integers to 32-bit integers in big-endian format
*
* \param output: Pointer to the output 8-bit integer array
* \param input: [const] Pointer to the input 8-bit character array
* \param length: The number of 8-bit integers to convert
*/
QSC_EXPORT_API void qsc_transpose_native_to_bytes(uint8_t* output, const uint32_t* input, size_t length);

 /**
 * \brief Convert a 8-bit character array to zero padded 32-bit scalar integers
 *
 * \param output: Pointer to the output 32-bit integer array
 * \param input: [const] Pointer to the input 8-bit character array
 * \param length: The number of 8-bit integers to convert
 */
QSC_EXPORT_API void qsc_transpose_string_to_scalar(uint32_t* output, const char* input, size_t length);

#endif
