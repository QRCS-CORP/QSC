/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
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
