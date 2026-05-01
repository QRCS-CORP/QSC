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

#ifndef QSCTEST_X509_STAGE1_TESTS_H
#define QSCTEST_X509_STAGE1_TESTS_H

#include "qsccommon.h"

/**
 * \file x509_stage1_tests.h
 * \brief X.509 Stage 1 Test Interface.
 *
 * Declares the stage 1 X.509 test entry point. This stage is used for foundational certificate, chain, 
 * and revocation validation tests that exercise the baseline verification pipeline before later PEM, CSR, CRL generation, 
 * and interoperability stages are run. The function returns true only when every test in the stage completes successfully.
 */

/**
 * \brief Tests DNS name matching against X.509 Subject Alternative Name (SAN) entries.
 *
 * \details
 * This test validates the correctness of DNS name matching logic used during
 * certificate hostname verification. It exercises the internal matcher against
 * certificates containing DNS SAN entries and ensures compliance with expected
 * matching semantics.
 *
 * The test verifies:
 * - Exact hostname matches against SAN DNS entries.
 * - Wildcard matching behavior (e.g. *.example.com).
 * - Rejection of invalid or non-matching hostnames.
 * - Proper precedence of SAN over Common Name (CN), if applicable.
 *
 * \return
 * true if all DNS matching cases succeed; false otherwise.
 */
bool x509_stage1_dns_matcher(void);

/**
 * \brief Tests server certificate chain verification for TLS server usage.
 *
 * \details
 * This test validates the full certificate chain verification process for a
 * TLS server context. It constructs a certificate chain consisting of a leaf
 * certificate and one or more intermediates, and verifies it against a trusted
 * root store.
 *
 * The test ensures:
 * - Correct chain building and issuer linking.
 * - Signature verification across the chain.
 * - Validity period checks.
 * - Proper enforcement of key usage and extended key usage for server
 *   authentication.
 * - Acceptance of a valid server certificate chain anchored to a trusted root.
 *
 * \return
 * true if the chain verifies successfully under server validation rules;
 * false otherwise.
 */
bool x509_stage1_server_chain_verify(void);

/**
 * \brief Tests rejection of certificates with incorrect purpose (client vs server).
 *
 * \details
 * This test ensures that certificate verification correctly enforces the
 * intended usage of a certificate. A certificate that is valid for client
 * authentication is presented in a server validation context, and verification
 * is expected to fail.
 *
 * The test verifies:
 * - Enforcement of Extended Key Usage (EKU) constraints.
 * - Rejection of certificates lacking serverAuth when used for TLS server
 *   validation.
 * - Proper differentiation between clientAuth and serverAuth purposes.
 *
 * \return
 * true if the certificate is correctly rejected for improper usage; false otherwise.
 */
bool x509_stage1_client_purpose_rejection(void);

/**
 * \brief Tests certificate revocation using a Certificate Revocation List (CRL).
 *
 * \details
 * This test validates CRL-based revocation checking within the certificate
 * verification process. A certificate known to be revoked is checked against
 * a corresponding CRL issued by the certificate authority.
 *
 * The test ensures:
 * - Correct parsing and decoding of the CRL structure.
 * - Successful verification of the CRL signature using the issuer certificate.
 * - Accurate matching of revoked serial numbers within the CRL.
 * - Proper reporting of revocation status when a certificate is listed.
 *
 * The test specifically confirms that a revoked certificate produces a
 * revocation status rather than a validation or parsing error.
 *
 * \return
 * true if revocation is correctly detected; false otherwise.
 */
bool x509_stage1_crl_revocation(void);

/**
 * \brief Execute the x.509 stage 1 test.
 *
 * Runs the complete test set associated with this stage of the X.509 test
 * framework.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_x509_stage1_tests(void);

#endif
