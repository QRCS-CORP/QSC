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
 * Contact: contact@qrcscorp.ca
 */


#ifndef QSCTEST_TESTUTILS_H
#define QSCTEST_TESTUTILS_H

#include "cavp_common.h"

/**
 * \brief Compare two arrays of 8-bit integers for equality.
 * \ warning This function is not constant time. 
 * Use the \c qsc_intutils_verify for constant time operations.
 *
 * \param a:		[const uint8_t*] The first array.
 * \param b:		[const uint8_t*] The second array.
 * \param length:	[size_t] The number of bytes to compare.
 * \return			[bool] Returns true if the arrays are equal.
 */
bool cavp_byte_arrays_are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Get a single character from the console
* 
* \return Returns the character detected
*/
char cavp_get_char();

/**
* \brief Pause the console until user input is detected
* \return Returns the character detected
*/
char cavp_get_wait();

/*!
 * \brief Decodes a hexadecimal string into binary data.
 *
 * \param input     [const char*] Pointer to the hex encoded string.
 * \param inplen    [size_t] Length of the input string (should be even).
 * \param output    [uint8_t*] Buffer to receive the decoded binary data.
 * \param otplen    [size_t] Size of the output buffer.
 * \param declen    [size_t*] Pointer to a size_t to receive the number of decoded bytes.
 *
 * \return          [bool] Returns true on success, false if the input is invalid or the output buffer is too small.
 */
void cavp_bin_to_hex(const char* input, size_t inplen, uint8_t* output, size_t otplen, size_t* declen);

/**
* \brief Convert a hexadecimal character string to a binary byte array
*
* \param hexstr: the string to convert
* \param output: the binary output array
* \param length: the number of bytes to convert
*/
void cavp_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Convert a binary array to a hexidecimal string and print to the console
*
* \param input: the binary array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void cavp_print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Print an array of characters to the console
*
* \param input: the character array to print
*/
void cavp_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: the character array to print
*/
void cavp_print_line(const char* input);

/**
* \brief Print an unsigned 64-bit integer
*
* \param digit: the number to print
*/
void cavp_print_ulong(uint64_t digit);

/**
* \brief Print a double integer
*
* \param digit: the number to print
*/
void cavp_print_double(double digit);

/**
* \brief User confirmation that and action can continue(Y/N y/n)
*
* \param message: the message to print
*/
bool cavp_test_confirm(const char* message);

#endif
