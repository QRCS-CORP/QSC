#ifndef QSC_TLS_SIGALGS_H
#define QSC_TLS_SIGALGS_H

#include "tlserrors.h"
#include "tlstypes.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlssigalgs.h
 * \brief TLS signature-scheme capability queries.
 */

typedef struct qsc_tls_signature_scheme_descriptor
{
	qsc_tls_signature_scheme scheme;    /*!< TLS wire identifier of the signature scheme. */
	const char* name;                   /*!< Human-readable TLS signature-scheme name. */
	qsc_tls_hash_algorithm hash;        /*!< Transcript hash or pre-hash mode associated with the scheme. */
	size_t signaturesize;               /*!< Maximum encoded signature size in bytes. */
	bool supported;                     /*!< True when the scheme is implemented by the TLS registry. */
	bool certificateverifycapable;      /*!< True when the scheme may be used in CertificateVerify. */
	bool ispq;                          /*!< True when the scheme is post-quantum. */
	bool ismldsa;                       /*!< True when the scheme belongs to the ML-DSA family. */
} qsc_tls_signature_scheme_descriptor;

QSC_EXPORT_API const qsc_tls_signature_scheme_descriptor* qsc_tls_signature_scheme_descriptor_get(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_supported(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_certificate_verify_capable(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_pq(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API bool qsc_tls_signature_scheme_is_mldsa(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API size_t qsc_tls_signature_scheme_signature_size(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API bool qsc_tls_signature_scheme_validate_signature_length(qsc_tls_signature_scheme scheme, size_t signaturelen);
QSC_EXPORT_API qsc_x509_signature_algorithm qsc_tls_signature_scheme_x509_algorithm(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API bool qsc_tls_signature_scheme_matches_x509_algorithm(qsc_tls_signature_scheme scheme, qsc_x509_signature_algorithm algorithm);
QSC_EXPORT_API qsc_tls_hash_algorithm qsc_tls_signature_scheme_hash(qsc_tls_signature_scheme scheme);
QSC_EXPORT_API const char* qsc_tls_signature_scheme_name(qsc_tls_signature_scheme scheme);

QSC_CPLUSPLUS_ENABLED_END

#endif
