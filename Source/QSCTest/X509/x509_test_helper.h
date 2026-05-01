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

#ifndef QSCTEST_X509_TEST_HELPER_H
#define QSCTEST_X509_TEST_HELPER_H

#include "qsccommon.h"
#include "asn1.h"

/**
 * \brief Reads a text file into a dynamically allocated buffer.
 *
 * \details
 * This function loads the contents of a text file from disk into a heap-allocated
 * buffer. It is primarily used by X.509 test routines to load PEM-encoded objects
 * such as certificates, CSRs, CRLs, and keys. The returned buffer is null-terminated
 * for convenience when handling textual PEM data.
 *
 * \param path: [const char*] Path to the file on disk.
 * \param len: [size_t*] Receives the length of the file in bytes (excluding any null terminator).
 *
 * \return
 * Pointer to the allocated buffer containing the file contents, or NULL on failure.
 * The caller is responsible for freeing the returned buffer.
 */
char* qsctest_x509_read_text_file(const char* path, size_t* len);

/**
 * \brief Reads a binary file into a dynamically allocated buffer.
 *
 * \details
 * This function loads the contents of a binary file into a heap-allocated buffer.
 * It is used by test routines for DER-encoded objects or other binary test inputs.
 * The buffer contains the raw file data with no modification.
 *
 * \param path: [const char*] Path to the file on disk.
 * \param len: [size_t*] Receives the length of the file in bytes.
 *
 * \return
 * Pointer to the allocated buffer containing the file contents, or NULL on failure.
 * The caller is responsible for freeing the returned buffer.
 */
uint8_t* qsctest_x509_read_binary_file(const char* path, size_t* len);

/**
 * \brief Retrieves the current system time as an ASN.1 time structure.
 *
 * \details
 * This function populates a qsc_asn1_time structure with the current system time.
 * It is used by X.509 verification tests to evaluate certificate validity periods
 * against the current time. The resulting structure is suitable for use with
 * UTCTime or GeneralizedTime comparisons within the ASN.1/X.509 framework.
 *
 * \param t: [qsc_asn1_time*] Pointer to the time structure to be populated.
 */
void qsctest_x509_current_time(qsc_asn1_time* t);

#endif