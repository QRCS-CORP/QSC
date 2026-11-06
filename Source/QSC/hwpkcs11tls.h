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

#ifndef QSC_HWPKCS11_TLS_H
#define QSC_HWPKCS11_TLS_H

#include "hwpkcs11.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "x509csr.h"

QSC_CPLUSPLUS_ENABLED_START

/** \file hwpkcs11tls.h
 * \brief Optional PKCS#11 ECDSA signing bridge for QSC TLS 1.3 and X.509.
 * \details Enabled only when both QSC_HARDWARE_ENABLED and QSC_HARDWARE_PKCS11_ENABLED
 * are defined. This bridge never owns, duplicates, or exports a private key.
 * The caller must keep the signer, token key, session, module, and certificate DER
 * buffers alive until every TLS connection using them has finished. Callers must
 * serialize writes to signer.laststatus across concurrent handshakes.
 */

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

/** \struct qsc_hw_pkcs11_tls_signer
 * \brief Caller-owned non-exportable key binding shared with TLS and X.509 callbacks.
 */
typedef struct qsc_hw_pkcs11_tls_signer
{
	qsc_hw_pkcs11_key* key;				/**< Borrowed nonexportable token key; must remain valid for callback lifetime. */
	qsc_tls_signature_scheme scheme;	/**< Exact supported TLS ECDSA scheme; fixes curve and digest. */
	qsc_hw_status laststatus;			/**< Most recent backend result; caller serializes access. */
} qsc_hw_pkcs11_tls_signer;

/** \brief Initialize a signer from an existing protected PKCS#11 ECDSA key.
 * \param signer Caller-owned signer initialized on success; cleared on error.
 * \param key Live protected token private key, borrowed for signer lifetime.
 * \param scheme One of TLS ECDSA P-256/SHA-256, P-384/SHA-384 or P-521/SHA-512.
 * \return Typed status. No key ownership is transferred; no private material is read.
 * \note Not thread-safe with concurrent release, removal or mutation of the same signer.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_tls_signer_initialize(qsc_hw_pkcs11_tls_signer* signer, qsc_hw_pkcs11_key* key, qsc_tls_signature_scheme scheme);

/** \brief Generate TLS CertificateVerify DER ECDSA signature from a token-protected key.
 * \param scheme Negotiated TLS signature scheme; must match signer scheme exactly.
 * \param input Formatted CertificateVerify bytes; hashed once by QSC SHA-2.
 * \param inputlen Input length in bytes; zero or NULL input is refused.
 * \param signature Caller output buffer for DER ECDSA signature; never partial on failure.
 * \param signaturelen In/out output capacity and encoded signature size, in bytes.
 * \param state Caller-owned qsc_hw_pkcs11_tls_signer; borrowed for operation.
 * \return True only on successful hardware operation and DER encoding.
 * \note Synchronous; never silently falls back to software. Caller synchronizes operations.
 */
QSC_EXPORT_API bool qsc_hw_pkcs11_tls_sign_callback(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state);

/** \brief Configure TLS 1.3 client authentication using a non-exportable token key.
 * \param config Existing client configuration; no other field is modified on failure.
 * \param chain Nonempty leaf-first DER certificate chain, borrowed until handshake finishes.
 * \param chainlength Number of chain elements, max QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES.
 * \param signer Live token signer; certificate leaf public key must match token key.
 * \return TLS status; invalid or mismatched identity is rejected.
 * \note No private-key bytes are copied or stored; signer is caller-owned.
 */
QSC_EXPORT_API qsc_tls_status qsc_hw_pkcs11_tls_client_config_set_identity(qsc_tls_client_config* config, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_hw_pkcs11_tls_signer* signer);

/** \brief Configure TLS 1.3 server certificate identity using a protected token key.
 * \param config Existing server configuration, changed only on successful verification.
 * \param chain Nonempty leaf-first DER certificate chain, borrowed through handshake.
 * \param chainlength Number of chain elements.
 * \param signer Live non-exportable token signer, borrowed through all handshakes.
 * \return Typed TLS status; rejects certificate/key mismatch and malformed chain.
 */
QSC_EXPORT_API qsc_tls_status qsc_hw_pkcs11_tls_server_config_set_identity(qsc_tls_server_config* config, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_hw_pkcs11_tls_signer* signer);

/** \brief Add a host-specific TLS 1.3 server identity for SNI selection.
 * \param config Existing server configuration; caller owns selected certificate buffers.
 * \param hostname Bounded, NUL-terminated hostname, as required by QSC server config.
 * \param chain Nonempty leaf-first DER certificate chain, borrowed through handshake.
 * \param chainlength Number of entries in chain.
 * \param signer Live token signer, retained by pointer only.
 * \return TLS status, including error from QSC's existing SNI identity setter.
 */
QSC_EXPORT_API qsc_tls_status qsc_hw_pkcs11_tls_server_config_add_identity(qsc_tls_server_config* config, const char* hostname, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_hw_pkcs11_tls_signer* signer);

/** \brief Sign X.509/PKCS#10 TBS input via the protected PKCS#11 key.
 * \param algorithm X.509 ECDSA/SHA-2 algorithm; must correspond exactly to signer.
 * \param tbs DER TBSCertificate or CertificationRequestInfo bytes, prehash input.
 * \param tbslen Input length, in bytes.
 * \param signature Caller output buffer for DER ECDSA signature; erased on error.
 * \param signaturelen In/out buffer capacity and DER signature length, in bytes.
 * \param context Borrowed qsc_hw_pkcs11_tls_signer, updated with backend status.
 * \return ASN.1 success only if token signing and DER encoding succeed.
 */
QSC_EXPORT_API qsc_asn1_status qsc_hw_pkcs11_x509_sign_callback(qsc_x509_signature_algorithm algorithm, const uint8_t* tbs, size_t tbslen, uint8_t* signature, size_t* signaturelen, void* context);

/** \brief Encode and sign a PKCS#10 CSR using a protected PKCS#11 private key.
 * \param csr Fully configured CSR with token-matching subjectPublicKeyInfo and ECDSA algorithm.
 * \param signer Live protected token signer; signer key must match CSR SPKI.
 * \param output Caller-owned DER output buffer; no private bytes are returned.
 * \param outputlen In/out DER capacity and encoded length, in bytes.
 * \return Typed ASN.1 status; mismatched public key or unsupported scheme fails closed.
 */
QSC_EXPORT_API qsc_asn1_status qsc_hw_pkcs11_x509_csr_sign(const qsc_x509_csr* csr, qsc_hw_pkcs11_tls_signer* signer, uint8_t* output, size_t* outputlen);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
