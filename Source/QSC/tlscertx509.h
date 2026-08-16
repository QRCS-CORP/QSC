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

#ifndef QSC_TLS_CERT_X509_H
#define QSC_TLS_CERT_X509_H

#include "qsccommon.h"
#include "tlscert.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlscert_x509.h
 * \brief X.509-backed implementation of the TLS certificate interface.
 *
 * Provides a compatibility adapter over the canonical QSC X.509 TLS bridge in
 * tlscert.c. Certificate path validation and CertificateVerify verification are
 * therefore implemented in one security-critical backend rather than duplicated
 * in this module.
 *
 * Intermediate certificates carried by the TLS peer are passed through to the
 * canonical path builder. Trust-anchor validation is performed against the
 * qsc_x509_store supplied to qsc_tls_cert_x509_state_initialize. A NULL trust
 * store fails closed; self-signed certificates are accepted only when they are
 * explicitly configured as trust anchors in the supplied store.
 */

/**
 * \brief Holder for the X.509-backed TLS certificate interface.
 *
 * The state stores the trust store used to authenticate the peer certificate
 * chain and the validation policy flags used by the callback. The caller must
 * keep both the state and original DER certificate bytes alive for the duration
 * of the handshake.
 */
typedef struct qsc_tls_cert_x509_state
{
    const qsc_x509_store* truststore;                               /*!< Trust anchors; NULL causes certificate validation to fail closed. */
    bool allowselfsigned;                                           /*!< Legacy compatibility flag; ignored by validation and initialized false. */
    bool enforcehostname;                                           /*!< Fail validation if the leaf doesn't match config.hostname. */
    bool enforcevalidityperiod;                                     /*!< Legacy compatibility flag; the canonical backend always enforces certificate validity periods. */
    qsc_x509_verify_status lastverifystatus;                        /*!< Most recent validation status. */
    qsc_tls_alert_description lastalert;                            /*!< Alert description corresponding to lastverifystatus. */
} qsc_tls_cert_x509_state;

/**
 * \brief Initialize an X.509 interface state with sensible defaults.
 *
 * \param state: [struct*] Destination state, cleared to zero.
 * \param truststore: [const*] Trust anchors; NULL causes certificate validation to fail closed.
 */
QSC_EXPORT_API void qsc_tls_cert_x509_state_initialize(qsc_tls_cert_x509_state* state, const qsc_x509_store* truststore);

/**
 * \brief Bind an X.509-backed state to a TLS certificate interface.
 *
 * \param iface: [struct*] Destination interface with callbacks populated.
 * \param state: [struct*] Caller-owned state; must outlive the interface use.
 */
QSC_EXPORT_API void qsc_tls_cert_x509_bind(qsc_tls_certificate_interface* iface, qsc_tls_cert_x509_state* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
