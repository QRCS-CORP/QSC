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

#ifndef QSCTEST_X509_STAGE4B_PQC_TESTS_H
#define QSCTEST_X509_STAGE4B_PQC_TESTS_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_stage4_pqc_tests.h
 * \brief Stage 4 X.509 post-quantum integration test declarations.
 *
 * \details
 * This header declares the Stage 4 X.509 test routines used to validate
 * post-quantum public-key and signature integration paths, including ML-DSA
 * SubjectPublicKeyInfo round-trip handling, ML-DSA CSR generation and
 * verification, tamper rejection, certificate-chain verification, ML-KEM CA
 * rejection behavior, ML-KEM SubjectPublicKeyInfo round-trip handling, and
 * PKCS #8 private-key round-trip and certificate matching checks.
 *
 * The entry-point test function executes the Stage 4 PQC test set as an
 * aggregate suite.
 */

/*!
 * \brief Test ML-DSA SubjectPublicKeyInfo round-trip encoding and decoding.
 *
 * \details
 * Verifies that an ML-DSA SubjectPublicKeyInfo object can be constructed,
 * encoded, decoded, and compared without loss of algorithm or public-key
 * information.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_spki_roundtrip(void);

/*!
 * \brief Test ML-DSA CSR round-trip encoding and verification.
 *
 * \details
 * Verifies that an ML-DSA-backed certificate signing request can be generated,
 * encoded, decoded, and signature-verified successfully.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_csr_roundtrip(void);

/*!
 * \brief Test rejection of a tampered ML-DSA CSR.
 *
 * \details
 * Verifies that modifying an ML-DSA certificate signing request causes
 * signature verification failure or equivalent rejection by the CSR validation
 * path.
 *
 * \return Returns true if the tampered CSR is correctly rejected; otherwise returns false.
 */
bool x509_stage4b_mldsa_csr_tamper_reject(void);

/*!
 * \brief Test ML-DSA certificate chain verification.
 *
 * \details
 * Verifies that a certificate chain signed and verified through the ML-DSA
 * integration path is accepted when all chain elements and signatures are
 * valid.
 *
 * \return Returns true if the chain verification test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_chain_verify(void);

/*!
 * \brief Test rejection of ML-KEM keys in CA signing roles.
 *
 * \details
 * Verifies that ML-KEM keys are rejected when used in a certification-authority
 * role or other signing context where an encryption or key-establishment key
 * must not be accepted as a certificate-signing key.
 *
 * \return Returns true if the invalid CA usage is correctly rejected; otherwise returns false.
 */
bool x509_stage4b_mlkem_ca_reject(void);

/*!
 * \brief Test ML-KEM SubjectPublicKeyInfo round-trip encoding and decoding.
 *
 * \details
 * Verifies that an ML-KEM SubjectPublicKeyInfo object can be constructed,
 * encoded, decoded, and compared without loss of algorithm or public-key
 * information.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mlkem_spki_roundtrip(void);

/*!
 * \brief Test RFC 9881 and RFC 9935 post-quantum key-usage profiles.
 *
 * \details
 * Verifies that ML-KEM certificates with a keyUsage extension permit only
 * keyEncipherment and that ML-DSA certificates require at least one permitted
 * signature usage while rejecting encipherment and key-agreement usages.
 *
 * \return Returns true if the PQC key-usage profile tests complete successfully; otherwise returns false.
 */
bool x509_stage4b_pqc_key_usage_profiles(void);

/*!
 * \brief Test ML-DSA PKCS #8 round-trip decoding and certificate-key matching.
 *
 * \details
 * Verifies that an ML-DSA private key can be encoded and decoded through the
 * PKCS #8 path and that the recovered key material matches the corresponding
 * certificate public key.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_pkcs8_roundtrip_and_match(void);

/*!
 * \brief Test RFC 9881 ML-DSA private-key encodings.
 *
 * \details
 * Verifies canonical expanded-key output, seed and combined seed/expanded-key
 * input handling, RFC 5958 public-key tagging, and rejection of inconsistent
 * combined ML-DSA private-key material.
 *
 * \return Returns true if the RFC 9881 private-key tests complete successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_rfc9881_private_key_formats(void);

/*!
 * \brief Test RFC 9935 ML-KEM private-key encodings.
 *
 * \details
 * Verifies canonical expanded-key output, seed and combined seed/expanded-key
 * input handling, RFC 5958 public-key tagging, the FIPS 203 expanded-key hash
 * check, and rejection of inconsistent combined ML-KEM private-key material.
 *
 * \return Returns true if the RFC 9935 private-key tests complete successfully; otherwise returns false.
 */
bool x509_stage4b_mlkem_rfc9935_private_key_formats(void);

/*!
 * \brief Execute the full Stage 4 X.509 post-quantum test suite.
 *
 * \details
 * Runs the complete collection of Stage 4 PQC tests declared in this header
 * and returns a single aggregate success or failure result.
 *
 * \return Returns true if all Stage 4 tests completed successfully; otherwise returns false.
 */
bool qsctest_x509_stage4b_pqc_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
