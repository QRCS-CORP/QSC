/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */


#ifndef QSC_TRANSPOSE_H
#define QSC_TRANSPOSE_H

#include "common.h"
#include "intutils.h"

/**
 * \file transpose.h
 * \brief String and array transposition functions
 *
 * \details
 * This header provides functions to convert between different representations
 * of integer arrays and strings. It includes functions for converting:
 * - 32-bit integers in big-endian format to native 32-bit integers.
 * - Hexadecimal strings to binary arrays.
 * - Native 32-bit integers to byte arrays in big-endian format.
 * - 8-bit character arrays to zero-padded 32-bit scalar integers.
 *
 * \code
 * // Example: Convert a hexadecimal string to a binary array.
 * const char* hex_str = "1a2b3c4d";
 * uint8_t binary[4];
 * qsc_transpose_hex_to_bin(binary, hex_str, 8);
 * \endcode
 *
 * \section transpose_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/">Microsoft Intutils Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/">POSIX Standard Documentation</a>
 *
 * \keywords transpose, conversion, big-endian, hexadecimal, string, integer, utility
 */

/**
* \brief Convert 32-bit integers in big-endian format to 8-bit integers
*
* \param output:	[uint32_t*] Pointer to the output 8-bit integer array
* \param input:		[const uint8_t*] Pointer to the input 8-bit character array
* \param length:	[size_t] The number of 8-bit integers to convert
*/
QSC_EXPORT_API void qsc_transpose_bytes_to_native(uint32_t* output, const uint8_t* input, size_t length);

/**
* \brief Convert a hexadecimal string to a decimal 8-bit array
*
* \param output:	[uint8_t*] Pointer to the output 8-bit integer array
* \param input:		[const char*] Pointer to the input 8-bit character array
* \param length:	[size_t] The number of hex characters to convert
*/
QSC_EXPORT_API void qsc_transpose_hex_to_bin(uint8_t* output, const char* input, size_t length);

/**
* \brief Convert 8-bit integers to 32-bit integers in big-endian format
*
* \param output:	[uint8_t*] Pointer to the output 8-bit integer array
* \param input:		[const uint32_t*] Pointer to the input 8-bit character array
* \param length:	[size_t] The number of 8-bit integers to convert
*/
QSC_EXPORT_API void qsc_transpose_native_to_bytes(uint8_t* output, const uint32_t* input, size_t length);

 /**
 * \brief Convert a 8-bit character array to zero padded 32-bit scalar integers
 *
 * \param output:	[uint32_t*] Pointer to the output 32-bit integer array
 * \param input:	[const char*] Pointer to the input 8-bit character array
 * \param length:	[size_t] The number of 8-bit integers to convert
 */
QSC_EXPORT_API void qsc_transpose_string_to_scalar(uint32_t* output, const char* input, size_t length);

#endif
