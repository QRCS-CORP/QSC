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

#ifndef QSC_X509_TIME_H
#define QSC_X509_TIME_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*
 * x509_time.h
 *
 * X.509 time parsing and validation helpers for the QSC X.509 layer.
 *
 * This module provides decoding of ASN.1 UTCTime and GeneralizedTime
 * values into the normalized qsc_x509_time structure defined in
 * x509_types.h, along with comparison and validation helpers.
 *
 * The implementation follows RFC 5280 requirements for certificate
 * validity evaluation.
 */

/*!
 * \struct qsc_x509_time
 * \brief Represents an ASN.1 UTCTime or GeneralizedTime value normalized into a structured form.
 *
 * \details
 * X.509 certificates encode time values using either UTCTime (YYMMDDHHMMSSZ)
 * or GeneralizedTime (YYYYMMDDHHMMSSZ). During decoding these values are
 * converted into a normalized structure that stores each component separately.
 *
 * The generalized flag indicates whether the source encoding used
 * GeneralizedTime (true) or UTCTime (false).
 */
typedef qsc_asn1_time qsc_x509_time;

/**
 * \brief Decode an ASN.1 time element (UTCTime or GeneralizedTime)
 *
 * \param[out] out: The decoded time structure
 * \param[in] elem: ASN.1 element containing the time
 * \return Returns true on success
 */
bool qsc_x509_time_decode(qsc_x509_time* out, const qsc_encoding_ber_element* elem);

/**
 * \brief Decode an ASN.1 Validity sequence
 *
 * \param[out] validity: The decoded validity structure
 * \param[in] elem: ASN.1 element containing the validity sequence
 * \return Returns the asn1 status
 */
qsc_asn1_status qsc_x509_validity_decode(qsc_x509_validity* validity, const qsc_encoding_ber_element* elem);

/**
 * \brief Compare two X.509 times
 *
 * \param[in] a: First time
 * \param[in] b: Second time
 * \return -1 if a < b, 0 if equal, 1 if a > b
 */
int32_t qsc_x509_time_compare(const qsc_x509_time* a, const qsc_x509_time* b);

/**
 * \brief Check whether a time lies within a validity interval
 *
 * \param[in] validity: Certificate validity interval
 * \param[in] tnow: Time to test
 * \return Returns true if valid
 */
bool qsc_x509_validity_is_valid(const qsc_x509_validity* validity, const qsc_x509_time* tnow);

QSC_CPLUSPLUS_ENABLED_END

#endif
