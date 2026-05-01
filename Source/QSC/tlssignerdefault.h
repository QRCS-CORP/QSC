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

#ifndef QSC_TLS_SIGNER_DEFAULT_H
#define QSC_TLS_SIGNER_DEFAULT_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"
#include "tlscert.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlssignerdefault.h
 * \brief Default TLS CertificateVerify signer/verifier backed by QSC signature primitives.
 *
 * \details
 * This module plugs into the qsc_tls_certificate_interface callback set. It maps TLS
 * signature schemes to QSC primitives as follows:
 *
 *   qsc_tls_sig_ed25519                 -> qsc_eddsa_* (64-byte signature)
 *   qsc_tls_sig_ecdsa_secp256r1_sha256  -> qsc_ecdsa_* (DER-wrapped r||s per RFC 8446 4.2.3)
 *   qsc_tls_sig_ecdsa_secp384r1_sha384  -> qsc_ecdsa_* (DER-wrapped r||s per RFC 8446 4.2.3)
 *   qsc_tls_sig_mldsa44/65/87           -> qsc_dilithium_* (parameter set selected at compile time)
 *
 * QSC sign primitives produce the combined signed_message = signature || message form; the
 * TLS detached-signature form is extracted on sign and reassembled on verify with a
 * constant-time message-recovery equality check to reject tampering.
 */

/**
 * \struct qsc_tls_signer_default_context
 * \brief State bound to qsc_tls_certificate_sign_callback when using the default signer.
 *
 * \details
 * The caller populates this struct and passes its address as the \a state parameter of a
 * qsc_tls_certificate_interface. The pointed-to private key must outlive every handshake
 * that uses this signer. Private-key lengths expected:
 *
 *   scheme                               privatekeylen
 *   qsc_tls_sig_ed25519                  64  (QSC_EDDSA_PRIVATEKEY_SIZE)
 *   qsc_tls_sig_ecdsa_secp256r1_sha256   QSC_ECDSA_PRIVATEKEY_SIZE
 *   qsc_tls_sig_ecdsa_secp384r1_sha384   QSC_ECDSA_PRIVATEKEY_SIZE
 *   qsc_tls_sig_mldsa44/65/87            QSC_DILITHIUM_PRIVATEKEY_SIZE
 */
typedef struct qsc_tls_signer_default_context
{
    qsc_tls_signature_scheme scheme;    /*!< The TLS signature scheme this context signs under. */
    const uint8_t* privatekey;          /*!< Caller-owned private-key bytes. */
    size_t privatekeylen;               /*!< Length of privatekey in bytes. */
} qsc_tls_signer_default_context;

/**
 * \brief Produce a TLS CertificateVerify signature.
 *
 * \details
 * Matches the qsc_tls_certificate_sign_callback contract so this function can be installed
 * directly as qsc_tls_local_certificate_config::signcallback.
 *
 * \param scheme: [enum] The TLS signature scheme to use.
 * \param input: [const uint8_t*] The formatted TLS 1.3 CertificateVerify input bytes.
 * \param inputlen: [size_t] Length of input in bytes.
 * \param signature: [uint8_t*] Destination buffer for the signature.
 * \param signaturelen: [size_t*] On input, the available buffer size; on success, the encoded length.
 * \param state: [void*] Must point to a qsc_tls_signer_default_context.
 *
 * \return [bool] Returns true if the signature was produced successfully.
 */
QSC_EXPORT_API bool qsc_tls_signer_default_sign(qsc_tls_signature_scheme scheme,
    const uint8_t* input, size_t inputlen,
    uint8_t* signature, size_t* signaturelen, void* state);

/**
 * \brief Verify a TLS CertificateVerify signature against the supplied public-key view.
 *
 * \details
 * Matches the qsc_tls_certificate_verify_callback contract so this function can be installed
 * directly as qsc_tls_certificate_interface::verifycertificateverify. The \a signer view is
 * expected to expose the raw public-key bytes (not an X.509 DER blob); for SPKI-aware
 * verification wrap this signer through tlscert_x509 which decodes the certificate and
 * extracts the public key before dispatching here.
 *
 * \param scheme: [enum] The negotiated TLS signature scheme.
 * \param input: [const uint8_t*] The formatted TLS 1.3 CertificateVerify input bytes covered by the signature.
 * \param inputlen: [size_t] Length of input in bytes.
 * \param signature: [const uint8_t*] The encoded signature bytes (DER for ECDSA, raw for Ed25519 / ML-DSA).
 * \param signaturelen: [size_t] Length of the signature in bytes.
 * \param signer: [const struct*] View exposing the peer's raw public-key bytes.
 * \param state: [void*] Unused; pass NULL.
 *
 * \return [bool] Returns true if the signature verifies.
 */
QSC_EXPORT_API bool qsc_tls_signer_default_verify(qsc_tls_signature_scheme scheme,
    const uint8_t* input, size_t inputlen,
    const uint8_t* signature, size_t signaturelen,
    const qsc_tls_certificate_view* signer, void* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
