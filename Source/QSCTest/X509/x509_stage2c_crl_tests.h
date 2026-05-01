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

#ifndef QSCTEST_X509_STAGE2C_CRL_TESTS_H
#define QSCTEST_X509_STAGE2C_CRL_TESTS_H

#include "qsccommon.h"

/**
 * \file x509_stage2c_crl_tests.h
 * \brief X.509 Stage 2C CRL Test Interface.
 *
 * Declares the stage 2C X.509 certificate revocation list test entry point. 
 * This stage is used to validate CRL encoding, decoding, signature verification, 
 * revocation lookup, and related revocation handling paths. 
 * The function returns true only when all CRL tests succeed.
 */

/**
 * \brief Tests decoding of a CRL in PEM format.
 *
 * \details
 * This test verifies that a PEM-encoded Certificate Revocation List (CRL) can
 * be successfully parsed and decoded into its internal representation. It
 * ensures correct handling of the ASN.1 structure, issuer, signature, and
 * revoked certificate entries.
 *
 * \return
 * true if the CRL is successfully decoded from PEM; false otherwise.
 */
bool x509_stage2c_crl_pem_decode(void);

/**
 * \brief Tests decoding of a CRL in DER format.
 *
 * \details
 * This test validates that a DER-encoded CRL can be parsed and decoded correctly.
 * It ensures proper interpretation of ASN.1 encoding, including issuer fields,
 * signature, and the list of revoked certificates.
 *
 * \return
 * true if the CRL is successfully decoded from DER; false otherwise.
 */
bool x509_stage2c_crl_der_decode(void);

/**
 * \brief Tests CRL PEM encoding and decoding round-trip.
 *
 * \details
 * This test verifies that a CRL can be encoded to PEM format and decoded back
 * without loss of information. It ensures that issuer data, signature, and
 * revoked certificate entries remain consistent through the conversion.
 *
 * \return
 * true if the PEM round-trip succeeds and CRL integrity is preserved; false otherwise.
 */
bool x509_stage2c_crl_pem_roundtrip(void);

/**
 * \brief Tests CRL DER encoding and decoding round-trip.
 *
 * \details
 * This test ensures that a CRL can be encoded to DER format and decoded back
 * while preserving all structural and semantic information. It validates
 * correct ASN.1 serialization and deserialization of the CRL.
 *
 * \return
 * true if the DER round-trip succeeds and data integrity is maintained; false otherwise.
 */
bool x509_stage2c_crl_der_roundtrip(void);

/**
 * \brief Tests lookup of a revoked certificate within a CRL.
 *
 * \details
 * This test verifies that a certificate known to be revoked is correctly
 * identified in the CRL. It ensures accurate matching of serial numbers
 * against the CRL revocation entries.
 *
 * \return
 * true if the revoked certificate is correctly detected; false otherwise.
 */
bool x509_stage2c_crl_revoked_lookup(void);

/**
 * \brief Tests lookup of a non-revoked certificate within a CRL.
 *
 * \details
 * This test ensures that a certificate not present in the CRL is correctly
 * identified as not revoked. It validates that no false positives occur
 * during serial number lookup.
 *
 * \return
 * true if the certificate is correctly identified as not revoked; false otherwise.
 */
bool x509_stage2c_not_revoked_lookup(void);

/**
 * \brief Execute the x.509 stage 2c crl test.
 *
 * Runs the complete test set associated with this stage of the X.509 test
 * framework.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_x509_stage2c_crl_tests(void);

#endif
