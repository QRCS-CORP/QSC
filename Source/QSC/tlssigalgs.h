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
  * This structure contains the static properties associated with a TLS
  * signature scheme. It is returned by the descriptor query function and may
  * be used by handshake and certificate-validation code to determine whether a
  * scheme is implemented, whether it is suitable for CertificateVerify, what
  * transcript hash is associated with it, and what signature size limits apply.
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
 * \return A pointer to the constant descriptor for the selected scheme, or NULL
 * if the scheme is unknown to the registry.
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
 * This query reports whether the scheme is valid for use in the TLS
 * CertificateVerify message under the local registry policy. A scheme may be
 * recognized by the registry but still not be eligible for CertificateVerify.
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
 * The returned value is the implementation-defined private key size in bytes
 * for the selected scheme. For schemes that are unknown or unsupported, the
 * function may return zero.
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
 * The returned value is the implementation-defined public key size in bytes
 * for the selected scheme. For schemes that are unknown or unsupported, the
 * function may return zero.
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
 * This value represents the maximum encoded signature size expected by the
 * TLS implementation for the specified scheme. It may be used to size working
 * buffers or to validate received signature lengths.
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
 * For signature schemes that bind a specific transcript hash or pre-hash mode,
 * this function returns the corresponding TLS hash identifier. For schemes
 * with no valid mapping, the return value may indicate an unset or null hash.
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
