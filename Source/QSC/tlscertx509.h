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
 * Provides default implementations of qsc_tls_certificate_interface that
 *   - decode each peer certificate from its DER bytes via qsc_x509_certificate_decode_der
 *   - enforce hostname matching against the leaf's Subject Alt Name / CN
 *   - validate the validity period at the current (or caller-supplied) time
 *   - extract the leaf's SubjectPublicKeyInfo for CertificateVerify
 *   - dispatch the extracted public key to qsc_tls_signer_default_verify
 *
 * Intermediate/root trust-store validation is performed when the user provides
 * a qsc_x509_store via qsc_tls_cert_x509_state_initialize_with_store. When the
 * store is NULL, the validator runs in "leaf-only, self-signed acceptable"
 * mode suitable for testing and for pinned-key deployments.
 */

/**
 * \brief Holder for the X.509-backed TLS certificate interface.
 *
 * The state stores a pointer to an optional trust store (NULL for pinned-key
 * or self-signed deployments) plus a scratch buffer used while decoding the
 * peer chain. Decoded certificate objects live on the stack inside the
 * callbacks; the caller must keep the original DER bytes alive for the
 * duration of the handshake.
 */
typedef struct qsc_tls_cert_x509_state
{
    const qsc_x509_store* truststore;                               /*!< Optional trust anchors; NULL => self-signed/pinned OK. */
    bool allowselfsigned;                                           /*!< When truststore is NULL, accept self-signed leaf. */
    bool enforcehostname;                                           /*!< Fail validation if the leaf doesn't match config.hostname. */
    bool enforcevalidityperiod;                                     /*!< Fail validation if notBefore/notAfter excludes now. */
    qsc_x509_verify_status lastverifystatus;                        /*!< Most recent validation status. */
    qsc_tls_alert_description lastalert;                            /*!< Alert description corresponding to lastverifystatus. */
} qsc_tls_cert_x509_state;

/**
 * \brief Initialize an X.509 interface state with sensible defaults.
 *
 * \param state: [struct*] Destination state, cleared to zero.
 * \param truststore: [const*] Optional trust anchors; NULL permits self-signed.
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
