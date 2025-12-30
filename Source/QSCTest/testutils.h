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

#ifndef QSCTEST_TESTUTILS_H
#define QSCTEST_TESTUTILS_H

#include "qsctestcommon.h"

/**
* \brief Get a single character from the console
* 
* \return Returns the character detected
*/
char qsctest_get_char();

/**
* \brief Pause the console until user input is detected
* \return Returns the character detected
*/
char qsctest_get_wait();

/**
* \brief Convert a hexadecimal character string to a binary byte array
*
* \param hexstr: the string to convert
* \param output: the binary output array
* \param length: the number of bytes to convert
*/
void qsctest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Convert a binary array to a hexidecimal string and print to the console
*
* \param input: the binary array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void qsctest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Print an array of characters to the console
*
* \param input: the character array to print
*/
void qsctest_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: the character array to print
*/
void qsctest_print_line(const char* input);

/**
* \brief Print an unsigned 64-bit integer
*
* \param digit: the number to print
*/
void qsctest_print_ulong(uint64_t digit);

/**
* \brief Print a double integer
*
* \param digit: the number to print
*/
void qsctest_print_double(double digit);

/**
* \brief User confirmation that and action can continue(Y/N y/n)
*
* \param message: the message to print
*/
bool qsctest_test_confirm(const char* message);

#endif
