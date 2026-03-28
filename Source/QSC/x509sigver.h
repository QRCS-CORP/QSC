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

#ifndef QSC_X509_SIGVER_H
#define QSC_X509_SIGVER_H

#include "qsccommon.h"
#include "x509csr.h"
#include "x509crl.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509sigver.h
 * \brief QSC-backed X.509 certificate, CSR, CRL, and raw signed-data signature verification interface.
 *
 * \details
 * This header defines the verification state container and helper functions used to verify signatures over X.509 certificates, 
 * certificate revocation lists, certificate signing requests, and generic signed-data buffers using the QSC
 * cryptographic back-end. The interface binds the X.509 object model to the underlying signature implementations 
 * selected by the decoded signature algorithm and subject public key information.
 *
 * The verification routines use a caller-supplied working buffer encapsulated by qsc_x509_verify_state so that signature 
 * verification can reconstruct or stage the signed message representation without requiring internal dynamic allocation. 
 * This is particularly important for DER-encoded TBS certificate, CRL, and CSR verification flows, and for large post-quantum signature schemes.
 */

/*!
 * \struct qsc_x509_verify_state
 * \brief Working state used by QSC-backed X.509 signature verification helpers.
 *
 * \details
 * This structure stores a caller-supplied scratch buffer used during signature
 * verification. The verification routines use the preserved signed DER region
 * supplied by the decoded object and stage algorithm-specific verification
 * input in this buffer without treating normalized convenience fields as the
 * canonical verification source.
 */
typedef struct qsc_x509_verify_state_t
{
    uint8_t* signaturemessage;     /*!< Caller-supplied scratch buffer used to hold reconstructed or staged signed-message bytes. */
    size_t signaturemessage_size;  /*!< The capacity of the \c signaturemessage buffer in bytes. */
} qsc_x509_verify_state;

/*!
 * \brief Initialize a QSC X.509 verification state object.
 *
 * \details
 * Associates the verification state with a caller-managed scratch buffer and
 * records the available buffer capacity. This function shall be called before
 * using the state object with the QSC-backed verification helpers.
 *
 * \param state: [struct] The verification state object to initialize.
 * \param buffer: The caller-supplied scratch buffer.
 * \param buflen: The capacity of the scratch buffer in bytes.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_qsc_verify_state_initialize(qsc_x509_verify_state* state, uint8_t* buffer, size_t buflen);

/*!
 * \brief Verify a certificate signature using the issuer certificate and QSC back-end.
 *
 * \details
 * Verifies the signature on the supplied certificate using the issuer
 * certificate subject public key information and the signature algorithm
 * declared by the certificate. Verification uses the preserved TBSCertificate
 * DER bytes carried by the decoded certificate object and rejects inconsistent
 * algorithm pairings before invoking the cryptographic back-end.
 *
 * \param certificate: [const][struct] The certificate whose signature is to be verified.
 * \param issuer: [const][struct] The issuer certificate providing the verification public key.
 * \param state: Caller-supplied verification state, typically a \ref qsc_x509_verify_state object.
 *
 * \return Returns true if the certificate signature is valid; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_qsc_signature_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, void* state);

/*!
 * \brief Verify a CRL signature using the issuer certificate and QSC back-end.
 *
 * \details
 * Verifies the signature on the supplied certificate revocation list using the
 * issuer certificate subject public key information and the CRL signature
 * algorithm metadata. Verification uses the preserved TBSCertList DER bytes
 * carried by the decoded CRL object and rejects inconsistent algorithm
 * pairings before invoking the cryptographic back-end.
 *
 * \param crl: [const][struct] The certificate revocation list whose signature is to be verified.
 * \param issuer: [const][struct] The issuer certificate providing the verification public key.
 * \param state: Caller-supplied verification state, typically a \ref qsc_x509_verify_state object.
 *
 * \return Returns true if the CRL signature is valid; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_qsc_crl_signature_verify(const qsc_x509_crl* crl, const qsc_x509_certificate* issuer, void* state);

/*!
 * \brief Verify a CSR signature using the CSR subject key and QSC back-end.
 *
 * \details
 * Verifies the signature on the supplied certificate signing request using the
 * subject public key information carried inside the CSR and the declared CSR
 * signature algorithm. Verification uses the preserved CertificationRequestInfo
 * DER bytes carried by the decoded CSR object and does not reconstruct the
 * signed region from normalized fields.
 *
 * \param csr: [const][struct] The certificate signing request whose signature is to be verified.
 * \param state: Caller-supplied verification state, typically a \ref qsc_x509_verify_state object.
 *
 * \return Returns true if the CSR signature is valid; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_qsc_csr_signature_verify(const qsc_x509_csr* csr, void* state);

/*!
 * \brief Verify a generic signed-data object using explicit signature metadata.
 *
 * \details
 * Verifies a raw signed-data buffer using the supplied signature bytes,
 * signature algorithm selector, and signer subject public key information.
 * This helper provides the algorithm-dispatch core used by the higher-level
 * certificate, CRL, and CSR verification wrappers. The object-specific wrappers
 * enforce signed-region preservation and AlgorithmIdentifier consistency before
 * delegating to this routine.
 *
 * \param data: [const] The signed-data message buffer.
 * \param datalen: The length of the signed-data buffer in bytes.
 * \param signature: [const] The signature bytes to verify.
 * \param signaturelen: The length of the signature in bytes.
 * \param unusedbits: The number of unused bits in the final signature octet when the signature originated from an ASN.1 BIT STRING.
 * \param signaturealgorithm: [enum] The normalized signature algorithm identifier.
 * \param spki: [const][struct] The signer subject public key information used for verification.
 * \param state: Caller-supplied verification state, typically a \ref qsc_x509_verify_state object.
 *
 * \return Returns true if the signature is valid for the supplied data and public key; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_qsc_verify_signed_data(const uint8_t* data, size_t datalen, const uint8_t* signature, size_t signaturelen, 
    uint8_t unusedbits, qsc_x509_signature_algorithm signaturealgorithm, const qsc_x509_subject_public_key_info* spki, void* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
