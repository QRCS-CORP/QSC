#ifndef QSC_TLS_CERT_H
#define QSC_TLS_CERT_H

#include "qsccommon.h"
#include "tlstypes.h"
#include "tlserrors.h"
#include "x509types.h"
#include "x509time.h"
#include "x509store.h"
#include "x509verify.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlscert.h
 * \brief TLS certificate bridge types and validation callbacks.
 *
 * \details
 * This header defines the lightweight certificate views, validation context,
 * callback interfaces, and QSC X.509 bridge context used by the TLS
 * implementation when validating peer certificate chains and CertificateVerify
 * signatures.
 */

/**
 * \brief A non-owning view over a single encoded certificate.
 */
typedef struct qsc_tls_certificate_view
{
	const uint8_t* data;	/*!< Pointer to the encoded certificate bytes. */
	size_t datalen;			/*!< The length of the encoded certificate in bytes. */
} qsc_tls_certificate_view;

/**
 * \brief Certificate validation context supplied to chain validators.
 */
typedef struct qsc_tls_certificate_validation_context
{
	const char* hostname;			/*!< The expected peer hostname, or NULL when hostname validation is not required. The TLS handshake layer stores its own bounded copy when configured through the standard setters. */
	bool clientauth;				/*!< Set to true when validating a client certificate for mutual authentication. */
	bool requirepeercertificate;	/*!< Set to true when the peer certificate is mandatory for the current role. */
} qsc_tls_certificate_validation_context;

/**
 * \brief Validate a peer certificate chain.
 *
 * \param chain: [struct*] The certificate chain entries in leaf-first order.
 * \param chainlength: [size_t] The number of certificate entries in the chain.
 * \param context: [struct*] The certificate validation context.
 * \param state: [void*] The caller-supplied callback state.
 *
 * \return [bool] Returns true if the certificate chain is accepted.
 */
typedef bool (*qsc_tls_certificate_chain_validate_callback)(const qsc_tls_certificate_view* chain, size_t chainlength, 
	const qsc_tls_certificate_validation_context* context, void* state);

/**
 * \brief Verify the TLS CertificateVerify signature.
 *
 * \param scheme: [enum] The negotiated TLS signature scheme.
 * \param input: [const uint8_t*] The formatted TLS 1.3 CertificateVerify input bytes covered by the signature.
 * \param inputlen: [size_t] The length of the formatted input buffer in bytes.
 * \param signature: [const uint8_t*] The encoded signature bytes.
 * \param signaturelen: [size_t] The length of the signature in bytes.
 * \param signer: [struct*] The leaf certificate that provides the public key.
 * \param state: [void*] The caller-supplied callback state.
 *
 * \return [bool] Returns true if the signature is valid.
 */
typedef bool (*qsc_tls_certificate_verify_callback)(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, 
	const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state);

/**
 * \brief Produce a TLS 1.3 CertificateVerify signature.
 *
 * \param scheme: [enum] The TLS signature scheme used to sign the input.
 * \param input: [const uint8_t*] The formatted TLS 1.3 CertificateVerify input bytes.
 * \param inputlen: [size_t] The length of the formatted input in bytes.
 * \param signature: [uint8_t*] The destination signature buffer.
 * \param signaturelen: [size_t*] On input, the available signature buffer size; on success, the encoded signature length.
 * \param state: [void*] The caller-supplied callback state.
 *
 * \return [bool] Returns true if the signature was produced successfully.
 */
typedef bool (*qsc_tls_certificate_sign_callback)(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen,
	uint8_t* signature, size_t* signaturelen, void* state);

/**
 * \brief Certificate validation and signature verification callback set.
 */
typedef struct qsc_tls_certificate_interface
{
	qsc_tls_certificate_chain_validate_callback validatechain;		/*!< Callback used to validate the peer certificate chain. */
	qsc_tls_certificate_verify_callback verifycertificateverify;	/*!< Callback used to verify the CertificateVerify signature. */
	void* state;													/*!< Opaque caller state passed to both callbacks. The pointed-to object must outlive every handshake that uses this interface unless the built-in QSC X.509 setter is used, which stores an internal copy of its bridge context. */
} qsc_tls_certificate_interface;

/**
 * \brief Context for the built-in bridge between TLS and the QSC X.509 layer.
 */
typedef struct qsc_tls_qsc_x509_context
{
	const qsc_x509_store* truststore;			/*!< Trust anchors used to validate peer certificate chains. */
	const qsc_x509_certificate* intermediates;	/*!< Optional intermediate certificates available during path building. */
	size_t intermediatecount;					/*!< The number of intermediate certificates supplied. */
	const qsc_x509_time* validationtime;		/*!< Validation time used during certificate verification. */
	uint8_t* verifybuffer;						/*!< Scratch buffer used by X.509 verification helpers. */
	size_t verifybufferlen;						/*!< The length of the scratch verification buffer in bytes. */
	bool rejectunsupportedcriticalextensions;	/*!< Set to true to reject certificates containing unsupported critical extensions. */
	qsc_x509_verify_status lastverifystatus;	/*!< Most recent X.509 verification result reported by the built-in bridge. */
	qsc_tls_alert_description lastalert;		/*!< Most recent TLS alert mapped from the built-in bridge verification result. */
} qsc_tls_qsc_x509_context;

/**
 * \brief Initialize a certificate callback interface.
 *
 * \param iface: [struct] The interface structure to initialize.
 * \param validatechain: [function] The chain validation callback.
 * \param verifycertificateverify: [function] The CertificateVerify callback.
 * \param state: [void*] The caller-supplied callback state.
 */
QSC_EXPORT_API void qsc_tls_certificate_interface_initialize(qsc_tls_certificate_interface* iface, qsc_tls_certificate_chain_validate_callback validatechain, qsc_tls_certificate_verify_callback verifycertificateverify, void* state);

/**
 * \brief Determine whether a certificate callback interface is complete.
 *
 * \param iface: [struct*] The interface to inspect.
 *
 * \return [bool] Returns true if the required callbacks are present.
 */
QSC_EXPORT_API bool qsc_tls_certificate_interface_is_valid(const qsc_tls_certificate_interface* iface);

/**
 * \brief Initialize a QSC X.509 bridge context.
 *
 * \param context: [struct] The context structure to initialize.
 * \param truststore: [struct*] The trust store containing the trust anchors.
 * \param intermediates: [struct*] Optional intermediate certificates.
 * \param intermediatecount: [size_t] The number of intermediate certificates supplied.
 * \param validationtime: [struct*] Validation time used during certificate verification.
 * \param verifybuffer: [uint8_t*] Scratch buffer used during verification.
 * \param verifybufferlen: [size_t] The length of the scratch buffer in bytes.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_qsc_x509_context_initialize(qsc_tls_qsc_x509_context* context, const qsc_x509_store* truststore,
	const qsc_x509_certificate* intermediates, size_t intermediatecount, const qsc_x509_time* validationtime,
	uint8_t* verifybuffer, size_t verifybufferlen);

/**
 * \brief Initialize a certificate callback interface using the QSC X.509 bridge.
 *
 * \param iface: [struct] The interface structure to initialize.
 * \param context: [struct] The X.509 bridge context.
 *
 * \return [qsc_tls_status] Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_interface_initialize_qsc_x509(qsc_tls_certificate_interface* iface, qsc_tls_qsc_x509_context* context);

/**
 * \brief Map a TLS signature scheme to a QSC X.509 signature algorithm identifier.
 *
 * \param scheme: [enum] The TLS signature scheme.
 *
 * \return [qsc_x509_signature_algorithm] Returns the mapped X.509 algorithm identifier.
 */
QSC_EXPORT_API qsc_x509_signature_algorithm qsc_tls_qsc_x509_signature_algorithm_from_tls(qsc_tls_signature_scheme scheme);

/**
 * \brief Validate a peer certificate chain using the QSC X.509 bridge.
 *
 * \param chain: [struct*] The certificate chain entries in leaf-first order.
 * \param chainlength: [size_t] The number of certificate entries.
 * \param context: [struct*] The certificate validation context.
 * \param state: [void*] The caller-supplied bridge context.
 *
 * \return [bool] Returns true if the chain is accepted.
 */
QSC_EXPORT_API bool qsc_tls_qsc_x509_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength,
	const qsc_tls_certificate_validation_context* context, void* state);

/**
 * \brief Verify a TLS CertificateVerify signature using the QSC X.509 bridge.
 *
 * \param scheme: [enum] The TLS signature scheme.
 * \param transcript: [const uint8_t*] The transcript bytes covered by the signature.
 * \param transcriptlen: [size_t] The length of the transcript in bytes.
 * \param signature: [const uint8_t*] The encoded signature bytes.
 * \param signaturelen: [size_t] The length of the signature in bytes.
 * \param signer: [struct*] The signer certificate view.
 * \param state: [void*] The caller-supplied bridge context.
 *
 * \return [bool] Returns true if the signature is valid.
 */
QSC_EXPORT_API bool qsc_tls_qsc_x509_verify_certificate_verify(qsc_tls_signature_scheme scheme, const uint8_t* input,
	size_t inputlen, const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state);


/**
 * \brief Map a QSC X.509 verification result to a TLS alert description.
 *
 * \param status: [enum] The QSC X.509 verification status.
 *
 * \return [enum] Returns the mapped TLS alert description.
 */
QSC_EXPORT_API qsc_tls_alert_description qsc_tls_qsc_x509_alert_from_verify_status(qsc_x509_verify_status status);

/**
 * \brief Query the most recent alert reason from a certificate interface.
 *
 * \details
 * Returns a certificate-specific TLS alert when the interface uses the built-in
 * QSC X.509 bridge. For custom callbacks, this helper falls back to a generic
 * certificate or CertificateVerify alert according to the verification phase.
 *
 * \param iface: [struct*] The certificate interface.
 * \param verifyphase: [bool] Set true when the failure occurred during CertificateVerify processing.
 *
 * \return [enum] Returns the mapped TLS alert description.
 */
QSC_EXPORT_API qsc_tls_alert_description qsc_tls_certificate_interface_get_last_alert(const qsc_tls_certificate_interface* iface, bool verifyphase);

QSC_CPLUSPLUS_ENABLED_END

#endif
