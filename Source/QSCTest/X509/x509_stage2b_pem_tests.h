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

#ifndef QSCTEST_X509_STAGE2B_PEM_TESTS_H
#define QSCTEST_X509_STAGE2B_PEM_TESTS_H

#include "qsccommon.h"

/**
 * \file x509_stage2b_pem_tests.h
 * \brief X.509 Stage 2B PEM Test Interface.
 *
 * Declares the stage 2B X.509 PEM processing test entry point. 
 * This stage is used to validate PEM decoding, PEM encoding, bundle handling, 
 * and DER/PEM round-trip operations for supported X.509 object types. 
 * The function returns true only when all PEM-related tests succeed.
 */

/**
 * \brief Tests certificate PEM encoding and decoding round-trip.
 *
 * \details
 * This test verifies that a certificate can be encoded to PEM format and then
 * decoded back to its internal representation without loss of information. It
 * ensures structural equivalence between the original and reconstructed objects,
 * including subject, issuer, validity, public key, and extensions.
 *
 * \return
 * true if the certificate round-trip succeeds and data integrity is preserved; false otherwise.
 */
bool x509_stage2b_certificate_pem_roundtrip(void);

/**
 * \brief Tests CSR PEM encoding and decoding round-trip.
 *
 * \details
 * This test validates that a Certificate Signing Request (CSR) can be converted
 * to PEM format and subsequently decoded back without altering its contents.
 * It ensures that subject data, public key, attributes, and signature remain
 * consistent through the conversion process.
 *
 * \return
 * true if the CSR round-trip succeeds and all fields remain intact; false otherwise.
 */
bool x509_stage2b_csr_pem_roundtrip(void);

/**
 * \brief Tests CRL PEM encoding and decoding round-trip.
 *
 * \details
 * This test ensures that a Certificate Revocation List (CRL) can be encoded to
 * PEM format and decoded back while preserving all revocation entries and
 * structural elements. It validates correct handling of issuer information,
 * signature, and revoked certificate list.
 *
 * \return
 * true if the CRL round-trip succeeds with no data loss; false otherwise.
 */
bool x509_stage2b_crl_pem_roundtrip(void);

/**
 * \brief Tests rejection of invalid or malformed private key PEM input.
 *
 * \details
 * This test provides malformed or incorrect PEM-encoded private key data and
 * verifies that the decoder rejects it. It ensures that invalid ASN.1 structures,
 * corrupted encodings, or unsupported formats are not accepted.
 *
 * \return
 * true if invalid private key PEM data is correctly rejected; false otherwise.
 */
bool x509_stage2b_private_key_pem_negative(void);

/**
 * \brief Tests rejection of invalid or malformed public key PEM input.
 *
 * \details
 * This test supplies invalid PEM-encoded public key data and verifies that the
 * decoding logic properly detects and rejects malformed or unsupported input.
 * It ensures robustness against incorrect ASN.1 encoding and invalid key structures.
 *
 * \return
 * true if invalid public key PEM data is correctly rejected; false otherwise.
 */
bool x509_stage2b_public_key_pem_negative(void);

/**
 * \brief Execute the x.509 stage 2b pem test.
 *
 * Runs the complete test set associated with this stage of the X.509 test
 * framework.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_x509_stage2b_pem_tests(void);

#endif
