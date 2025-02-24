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


#ifndef QSCTEST_ENCODING_TEST_H
#define QSCTEST_ENCODING_TEST_H

#include "common.h"

/*!
 * \file encoding_test.h
 * \brief Main Test Runner for Encoding Schemes.
 *
 * \details
 * This source file implements the main function that runs unit tests for various encoding schemes,
 * including Base64, BER, DER, HEX, and PEM. Each test function encodes some data and then decodes it,
 * verifying that the output matches the original input. The tests ensure that the encoding and decoding
 * functions behave correctly according to their respective standards.
 *
 * The test suite includes:
 * - A Base64 test that encodes a fixed plain text string and verifies that the decoded string is identical.
 * - A BER test that encodes an ASN.1 INTEGER element and then decodes it, checking for equality.
 * - A DER test that performs a similar operation to the BER test but uses DER encoding rules.
 * - A HEX test that converts a byte array to a hexadecimal string and back.
 * - A PEM test that encodes binary data into PEM format with a label and decodes it back.
 *
 * The main function \c qsctest_encoding_run() executes each of these tests in sequence and prints the results.
 */

/*!
 * \brief Tests Base64 encoding and decoding.
 *
 * \details
 * This function encodes a fixed plain text string into Base64 format and then decodes it back.
 * It verifies that the decoded output matches the original input string.
 *
 * \return Returns true if the Base64 encoding and decoding test passes; otherwise, false.
 */
bool qsctest_encoding_base64(void);

/*!
 * \brief Tests BER encoding and decoding.
 *
 * \details
 * This function creates an ASN.1 BER element representing an INTEGER value (0x3039, i.e. 12345),
 * encodes it into BER format, and then decodes it back into an element structure.
 * It checks that the decoded element's properties (tag, length, and value) match the original.
 *
 * \return Returns true if the BER encoding and decoding test passes; otherwise, false.
 */
bool qsctest_encoding_ber(void);

/*!
 * \brief Tests DER encoding and decoding.
 *
 * \details
 * This function constructs an ASN.1 element representing an INTEGER value (0x3039) and encodes it using
 * DER encoding rules (which disallow indefinite length encoding). It then decodes the DER-encoded data and
 * verifies that the decoded element matches the original.
 *
 * \return Returns true if the DER encoding and decoding test passes; otherwise, false.
 */
bool qsctest_encoding_der(void);

/*!
 * \brief Tests HEX encoding and decoding.
 *
 * \details
 * This function converts a byte array { 0xDE, 0xAD, 0xBE, 0xEF } to a hexadecimal string and then decodes
 * the string back into a byte array. The test passes if the decoded data is identical to the original array.
 *
 * \return Returns true if the HEX encoding and decoding test passes; otherwise, false.
 */
bool qsctest_encoding_hex(void);

/*!
 * \brief Tests PEM encoding and decoding.
 *
 * \details
 * This function encodes a binary data array into PEM format using the label "TEST LABEL" and then decodes
 * the PEM-formatted string back into binary data. It verifies that the decoded data matches the original.
 *
 * \return Returns true if the PEM encoding and decoding test passes; otherwise, false.
 */
bool qsctest_encoding_pem(void);

/*!
 * \brief Runs all encoding scheme tests.
 *
 * \details
 * This function sequentially executes the tests for Base64, BER, DER, HEX, and PEM encoding/decoding.
 * It prints a success message if a test passes or a failure message if a test does not.
 */
void qsctest_encoding_run(void);


#endif