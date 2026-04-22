/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_TRANSPOSE_H
#define QSC_TRANSPOSE_H

#include "qsccommon.h"
#include "intutils.h"

QSC_CPLUSPLUS_ENABLED_START

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
* \param output: [uint32_t*] Pointer to the output 8-bit integer array
* \param input: [const uint8_t*] Pointer to the input 8-bit character array
* \param length: [size_t] The number of 8-bit integers to convert
*/
QSC_EXPORT_API void qsc_transpose_bytes_to_native(uint32_t* output, const uint8_t* input, size_t length);

/**
* \brief Convert a hexadecimal string to a decimal 8-bit array
*
* \param output: [uint8_t*] Pointer to the output 8-bit integer array
* \param input: [const char*] Pointer to the input 8-bit character array
* \param length: [size_t] The number of hex characters to convert
*/
QSC_EXPORT_API void qsc_transpose_hex_to_bin(uint8_t* output, const char* input, size_t length);

/**
* \brief Convert 8-bit integers to 32-bit integers in big-endian format
*
* \param output: [uint8_t*] Pointer to the output 8-bit integer array
* \param input: [const uint32_t*] Pointer to the input 8-bit character array
* \param length: [size_t] The number of 8-bit integers to convert
*/
QSC_EXPORT_API void qsc_transpose_native_to_bytes(uint8_t* output, const uint32_t* input, size_t length);

 /**
 * \brief Convert a 8-bit character array to zero padded 32-bit scalar integers
 *
 * \param output: [uint32_t*] Pointer to the output 32-bit integer array
 * \param input: [const char*] Pointer to the input 8-bit character array
 * \param length: [size_t] The number of 8-bit integers to convert
 */
QSC_EXPORT_API void qsc_transpose_string_to_scalar(uint32_t* output, const char* input, size_t length);

QSC_CPLUSPLUS_ENABLED_END

#endif
