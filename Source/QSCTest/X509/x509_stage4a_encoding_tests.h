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

#ifndef QSCTEST_X509_STAGE4A_ENCODING_TESTS_H
#define QSCTEST_X509_STAGE4A_ENCODING_TESTS_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file x509_stage4a_encoder_tests.h
 * \brief Declares the stage 4A X.509 encoder round-trip test functions.
 *
 * This header exposes the test entry points used to validate the X.509
 * encoder and decoder paths exercised by the stage 4A test suite. The
 * tests are intended to confirm that encoded values can be serialized and
 * decoded without alteration across the target container paths, including
 * BIT STRING fields, Subject Public Key Info (SPKI), PKCS#8 private keys,
 * certificate request signatures, and certificate signatures.
 *
 * Each function returns true only if the targeted round-trip path preserves
 * the expected value and all associated validation checks succeed.
 */

/**
 * \brief Tests BIT STRING encoder and decoder round-trip correctness.
 *
 * This test validates that a BIT STRING value written by the encoder can be
 * decoded without modification to its payload or associated metadata. The
 * function is intended to detect corruption in BIT STRING container handling,
 * including length encoding and unused-bit processing.
 *
 * \return Returns true if the BIT STRING round-trip test succeeds.
 */
bool x509_stage4a_encoder_bit_string_roundtrip(void);

/**
 * \brief Tests SPKI encoder and decoder round-trip correctness.
 *
 * This test validates that a Subject Public Key Info structure can be
 * encoded and decoded without altering the algorithm identifier, public key
 * encoding, or associated structural fields.
 *
 * \return Returns true if the SPKI round-trip test succeeds.
 */
bool x509_stage4a_encoder_spki_roundtrip(void);

/**
 * \brief Tests PKCS#8 encoder and decoder round-trip correctness.
 *
 * This test validates that a PKCS#8 private key container can be encoded and
 * decoded without altering the wrapped private key material, algorithm
 * identifier, or container structure.
 *
 * \return Returns true if the PKCS#8 round-trip test succeeds.
 */
bool x509_stage4a_encoder_pkcs8_roundtrip(void);

/**
 * \brief Tests CSR signature field encoder and decoder round-trip correctness.
 *
 * This test validates that the signature field of a certificate signing
 * request can be encoded and decoded without modification. It is intended to
 * detect corruption in the CSR signature container path, including DER and
 * related wrapper handling.
 *
 * \return Returns true if the CSR signature round-trip test succeeds.
 */
bool x509_stage4a_encoder_csr_signature_roundtrip(void);

/**
 * \brief Tests certificate signature field encoder and decoder round-trip correctness.
 *
 * This test validates that the certificate signature field can be encoded and
 * decoded without altering the signature bytes or associated container
 * representation.
 *
 * \return Returns true if the certificate signature round-trip test succeeds.
 */
bool x509_stage4a_encoder_certificate_signature_roundtrip(void);

/**
 * \brief Runs the complete stage 4A encoder test suite.
 *
 * This function executes the full set of stage 4A encoder round-trip tests,
 * including BIT STRING, SPKI, PKCS#8, CSR signature, and certificate
 * signature validation.
 *
 * \return Returns true if all stage 4A encoder tests succeed.
 */
bool qsctest_x509_stage4a_encoding_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
