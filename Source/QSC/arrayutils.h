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

#ifndef QSC_ARRAYUTILS_H
#define QSC_ARRAYUTILS_H

#include "qsccommon.h"
#include <stdio.h>

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file arrayutils.h
 * \brief Functions for handling character arrays.
 *
 * \details
 * This header provides a collection of utility functions for performing common operations 
 * on character arrays. The functions support tasks such as:
 *  - Searching for tokens or substrings within strings.
 *  - Converting hexadecimal-encoded strings to their corresponding binary values.
 *  - Converting numeric values (8-bit, 16-bit, 32-bit, and 64-bit unsigned integers) to 
 *    hexadecimal string representations.
 *  - Parsing unsigned integers from strings.
 *
 * These operations are critical for data formatting, debugging, and preparing string data 
 * for cryptographic processing.
 *
 * \par Example Usage:
 * \code
 * #include "arrayutils.h"
 * #include <string.h>
 *
 * // Example 1: Finding a token within a string.
 * const char* sample = "The quick brown fox jumps over the lazy dog";
 * size_t pos = qsc_arrayutils_find_string(sample, strlen(sample), "brown");
 * if (pos != QSC_ARRAYUTILS_NPOS)
 * {
 *     // Token "brown" found at position 'pos'.
 * }
 *
 * // Example 2: Converting a 32-bit unsigned integer to a hexadecimal string.
 * uint32_t number = 305419896; // 0x12345678
 * char hex_output[9] = {0U};
 * qsc_arrayutils_uint32_to_hex(hex_output, sizeof(hex_output), number);
 * // hex_output now holds the string "12345678".
 * \endcode
 *
 * \section arrtools_links Reference Links:
 * - <a href="https://en.wikipedia.org/wiki/Hexadecimal">Hexadecimal Number System</a>
 */

/*!
 * \def QSC_ARRAYUTILS_NPOS
 * \brief The constant return value indicating that a search token was not found.
 *
 * This value is returned by qsc_arrayutils_find_string when the token cannot be located.
 */
#define QSC_ARRAYUTILS_NPOS -1LL

/**
 * \brief Find the first instance of a token in a string.
 *
 * Searches for the first occurrence of a given token within a string and returns
 * the zero-based character position. If the token is not found, the function returns
 * QSC_ARRAYUTILS_NPOS.
 *
 * \param str: [const char*] Pointer to the constant character string to be searched.
 * \param slen: [size_t] The length of the string in bytes (excluding the null terminator).
 * \param token: [const char*] Pointer to the constant token string to search for.
 *
 * \return [size_t] The zero-based position of the token if found; otherwise QSC_ARRAYUTILS_NPOS.
 *
 * \sa strstr
 */
QSC_EXPORT_API size_t qsc_arrayutils_find_string(const char* str, size_t slen, const char* token);

/**
 * \brief Convert a hexadecimal encoded string to an 8-bit unsigned integer.
 *
 * Reads up to two hexadecimal characters from the input string and converts them
 * into the corresponding \c uint8_t value.
 *
 * \param str: [const char*] Pointer to the constant hexadecimal string.
 * \param slen: [size_t] The length of the string in bytes (excluding the null terminator).
 *
 * \return [uint8_t] The resulting 8-bit unsigned integer.
 */
QSC_EXPORT_API uint8_t qsc_arrayutils_hex_to_uint8(const char* str, size_t slen);

/**
 * \brief Convert an 8-bit unsigned integer to a hexadecimal string.
 *
 * Converts the given \c uint8_t value into a two-digit hexadecimal representation,
 * writing the result to the provided output buffer.
 *
 * \param output: [char*] Pointer to the output character array.
 * \param otplen: [size_t] The length of the output buffer in bytes.
 * \param value: [uint8_t] The 8-bit unsigned integer to convert.
 */
QSC_EXPORT_API void qsc_arrayutils_uint8_to_hex(char* output, size_t otplen, uint8_t value);

/**
 * \brief Convert a 16-bit unsigned integer to a hexadecimal string.
 *
 * Converts the given \c uint16_t value into a four-digit hexadecimal representation,
 * writing the result to the provided output buffer.
 *
 * \param output: [char*] Pointer to the output character array.
 * \param otplen: [size_t] The length of the output buffer in bytes.
 * \param value: [uint16_t] The 16-bit unsigned integer to convert.
 */
QSC_EXPORT_API void qsc_arrayutils_uint16_to_hex(char* output, size_t otplen, uint16_t value);

/**
 * \brief Convert a 32-bit unsigned integer to a hexadecimal string.
 *
 * Converts the given \c uint32_t value into an eight-digit hexadecimal representation,
 * writing the result to the provided output buffer.
 *
 * \param output: [char*] Pointer to the output character array.
 * \param otplen: [size_t] The length of the output buffer in bytes.
 * \param value: [uint32_t] The 32-bit unsigned integer to convert.
 */
QSC_EXPORT_API void qsc_arrayutils_uint32_to_hex(char* output, size_t otplen, uint32_t value);

/**
 * \brief Convert a 64-bit unsigned integer to a hexadecimal string.
 *
 * Converts the given \c uint64_t value into a sixteen-digit hexadecimal representation,
 * writing the result to the provided output buffer.
 *
 * \param output: [char*] Pointer to the output character array.
 * \param otplen: [size_t] The length of the output buffer in bytes.
 * \param value: [uint64_t] The 64-bit unsigned integer to convert.
 */
QSC_EXPORT_API void qsc_arrayutils_uint64_to_hex(char* output, size_t otplen, uint64_t value);

/**
 * \brief Parse an 8-bit unsigned integer from a string.
 *
 * Reads the input string and converts it to a \c uint8_t value.
 *
 * \param str: [const char*] Pointer to the constant character string containing the number.
 * \param slen:	[size_t] The length of the string in bytes (excluding the null terminator).
 *
 * \return [uint8_t] The parsed 8-bit unsigned integer, or zero if parsing fails.
 */
QSC_EXPORT_API uint8_t qsc_arrayutils_string_to_uint8(const char* str, size_t slen);

/**
 * \brief Parse a 16-bit unsigned integer from a string.
 *
 * Reads the input string and converts it to a \c uint16_t value.
 *
 * \param str: [const char*] Pointer to the constant character string containing the number.
 * \param slen:	[size_t] The length of the string in bytes (excluding the null terminator).
 *
 * \return [uint16_t] The parsed 16-bit unsigned integer, or zero if parsing fails.
 */
QSC_EXPORT_API uint16_t qsc_arrayutils_string_to_uint16(const char* str, size_t slen);

/**
 * \brief Parse a 32-bit unsigned integer from a string.
 *
 * Reads the input string and converts it to a \c uint32_t value.
 *
 * \param str: [const char*] Pointer to the constant character string containing the number.
 * \param slen:	[size_t] The length of the string in bytes (excluding the null terminator).
 *
 * \return [uint32_t] The parsed 32-bit unsigned integer, or zero if parsing fails.
 */
QSC_EXPORT_API uint32_t qsc_arrayutils_string_to_uint32(const char* str, size_t slen);

/**
 * \brief Parse a 64-bit unsigned integer from a string.
 *
 * Reads the input string and converts it to a \c uint64_t value.
 *
 * \param str: [const char*] Pointer to the constant character string containing the number.
 * \param slen:	[size_t] The length of the string in bytes (excluding the null terminator).
 *
 * \return [uint64_t] The parsed 64-bit unsigned integer, or zero if parsing fails.
 */
QSC_EXPORT_API uint64_t qsc_arrayutils_string_to_uint64(const char* str, size_t slen);

#if defined(QSC_DEBUG_MODE)
/**
 * \brief Perform a self-test of the array utilities.
 *
 * Runs a series of tests to validate the correctness of the functions in this module.
 *
 * \return [bool] \c true if all tests pass; otherwise \c false.
 */
QSC_EXPORT_API bool qsc_arrayutils_self_test(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
