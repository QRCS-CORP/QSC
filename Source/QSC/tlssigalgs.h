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

#ifndef QSC_TLS_SIGALGS_H
#define QSC_TLS_SIGALGS_H

#include "tlserrors.h"
#include "tlstypes.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlssigalgs.h
 * \brief TLS signature-scheme registry queries and capability inspection.
 *
 * \details
 * This header defines the public query interface used to inspect the TLS
 * signature-scheme registry exposed by the QSC TLS implementation. The
 * interface provides access to per-scheme metadata such as the TLS wire
 * identifier, the associated transcript hash, encoded signature length,
 * support status, CertificateVerify eligibility, and X.509 algorithm mapping.
 *
 * The functions declared here do not perform signing or signature
 * verification. They provide registry and policy information used by the
 * handshake, certificate processing, and validation layers when selecting,
 * negotiating, or validating TLS signature algorithms.
 *
 * The registry is intended to centralize the relationship between TLS
 * signature scheme identifiers and implementation-specific properties,
 * including classical and post-quantum algorithm classes.
 */

 /**
  * \struct qsc_tls_signature_scheme_descriptor
  * \brief Describes a TLS signature scheme supported by the registry.
  *
  * \details
  * This structure contains the static properties associated with a TLS signature scheme. 
  * It is returned by the descriptor query function and may be used by handshake and 
  * certificate-validation code to determine whether a scheme is implemented, 
  * whether it is suitable for CertificateVerify, what transcript hash is associated with it, 
  * and what signature size limits apply.
  */
typedef struct qsc_tls_signature_scheme_descriptor
{
	qsc_tls_signature_scheme scheme;    /*!< TLS wire identifier of the signature scheme. */
	const char* name;                   /*!< Human-readable TLS signature-scheme name. */
	qsc_tls_hash_algorithm hash;        /*!< Transcript hash or pre-hash mode associated with the scheme. */
	size_t signaturesize;               /*!< Maximum encoded signature size in bytes. */
	bool supported;                     /*!< True if the scheme is implemented by the TLS registry. */
	bool certificateverifycapable;      /*!< True if the scheme may be used in the TLS CertificateVerify message. */
	bool ispq;                          /*!< True if the scheme is post-quantum. */
	bool ismldsa;                       /*!< True if the scheme belongs to the ML-DSA family. */
} qsc_tls_signature_scheme_descriptor;

/**
 * \brief Get the registry descriptor for a TLS signature scheme.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return A pointer to the constant descriptor for the selected scheme, or NULL if the scheme is unknown to the registry.
 */
QSC_EXPORT_API const qsc_tls_signature_scheme_descriptor* qsc_tls_signature_scheme_descriptor_get(qsc_tls_signature_scheme scheme);

/**
 * \brief Determine whether a TLS signature scheme is supported by the registry.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return Returns true if the scheme is implemented and available for use.
 */
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_supported(qsc_tls_signature_scheme scheme);

/**
 * \brief Determine whether a TLS signature scheme may be used in CertificateVerify.
 *
 * \details
 * This query reports whether the scheme is valid for use in the TLS CertificateVerify message under the local registry policy. 
 * A scheme may be recognized by the registry but still not be eligible for CertificateVerify.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return Returns true if the scheme is CertificateVerify-capable.
 */
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_certificate_verify_capable(qsc_tls_signature_scheme scheme);

/**
 * \brief Determine whether a TLS signature scheme is post-quantum.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return Returns true if the scheme is classified as post-quantum.
 */
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_pq(qsc_tls_signature_scheme scheme);

/**
 * \brief Determine whether a TLS signature scheme belongs to the ML-DSA family.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return Returns true if the scheme is an ML-DSA variant.
 */
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_mldsa(qsc_tls_signature_scheme scheme);

/**
 * \brief Get the private key size associated with a TLS signature scheme.
 *
 * \details
 * The returned value is the implementation-defined private key size in bytes for the selected scheme. 
 * For schemes that are unknown or unsupported, the function may return zero.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return The private key size in bytes.
 */
QSC_EXPORT_API size_t qsc_tls_signature_scheme_private_key_size(qsc_tls_signature_scheme scheme);

/**
 * \brief Get the public key size associated with a TLS signature scheme.
 *
 * \details
 * The returned value is the implementation-defined public key size in bytes for the selected scheme. 
 * For schemes that are unknown or unsupported, the function may return zero.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return The public key size in bytes.
 */
QSC_EXPORT_API size_t qsc_tls_signature_scheme_public_key_size(qsc_tls_signature_scheme scheme);

/**
 * \brief Get the maximum encoded signature size for a TLS signature scheme.
 *
 * \details
 * This value represents the maximum encoded signature size expected by the TLS implementation for the specified scheme. 
 * It may be used to size working buffers or to validate received signature lengths.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return The maximum signature size in bytes.
 */
QSC_EXPORT_API size_t qsc_tls_signature_scheme_signature_size(qsc_tls_signature_scheme scheme);

/**
 * \brief Validate a received or generated signature length for a TLS signature scheme.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 * \param signaturelen: [size_t] The signature length in bytes to validate.
 *
 * \return Returns true if the length is valid for the selected scheme.
 */
QSC_EXPORT_API bool qsc_tls_signature_scheme_validate_signature_length(qsc_tls_signature_scheme scheme, size_t signaturelen);

/**
 * \brief Get the X.509 signature algorithm corresponding to a TLS signature scheme.
 *
 * \details
 * This function maps a TLS signature-scheme identifier to the corresponding
 * X.509 signature algorithm identifier used by the certificate subsystem.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return The mapped X.509 signature algorithm identifier.
 */
QSC_EXPORT_API qsc_x509_signature_algorithm qsc_tls_signature_scheme_x509_algorithm(qsc_tls_signature_scheme scheme);

/**
 * \brief Determine whether a TLS signature scheme matches an X.509 signature algorithm.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 * \param algorithm: [enum] The X.509 signature algorithm identifier.
 *
 * \return Returns true if the TLS scheme and X.509 algorithm correspond.
 */
QSC_EXPORT_API bool qsc_tls_signature_scheme_matches_x509_algorithm(qsc_tls_signature_scheme scheme, qsc_x509_signature_algorithm algorithm);

/**
 * \brief Get the transcript hash algorithm associated with a TLS signature scheme.
 *
 * \details
 * For signature schemes that bind a specific transcript hash or pre-hash mode, this function returns the corresponding TLS hash identifier. 
 * For schemes with no valid mapping, the return value may indicate an unset or null hash.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return The associated TLS hash algorithm identifier.
 */
QSC_EXPORT_API qsc_tls_hash_algorithm qsc_tls_signature_scheme_hash(qsc_tls_signature_scheme scheme);

/**
 * \brief Get the human-readable name of a TLS signature scheme.
 *
 * \param scheme: [enum] The TLS signature scheme identifier.
 *
 * \return A constant string naming the scheme, or NULL if the scheme is not known.
 */
QSC_EXPORT_API const char* qsc_tls_signature_scheme_name(qsc_tls_signature_scheme scheme);

QSC_CPLUSPLUS_ENABLED_END

#endif
