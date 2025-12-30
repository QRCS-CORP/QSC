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

#ifndef QSCTEST_ENCODING_TEST_H
#define QSCTEST_ENCODING_TEST_H

#include "qsctestcommon.h"

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