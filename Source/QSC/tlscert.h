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

#ifndef QSC_TLS_CERT_H
#define QSC_TLS_CERT_H

#include "qsccommon.h"
#include "tlstypes.h"
#include "tlserrors.h"
#include "x509types.h"
#include "x509crl.h"
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
 * \brief Size in bytes of the retained peer certificate fingerprint.
 */
#define QSC_TLS_CERTIFICATE_FINGERPRINT_SIZE 32U

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
	void* state;													/*!< Opaque caller state passed to both callbacks. Built-in QSC X.509 interfaces are cloned into connection-owned TLS state during client/server initialization. */
} qsc_tls_certificate_interface;

/**
 * \brief Fixed peer-certificate identity summary retained by the built-in QSC X.509 TLS bridge.
 *
 * \details
 * The summary contains bounded, zero-terminated diagnostic identity fields copied from
 * the decoded leaf certificate during certificate-chain validation. The structure does
 * not retain DER pointers or heap ownership. It is intended for post-handshake status
 * inspection by higher-level TLS socket callers.
 */
typedef struct qsc_tls_peer_certificate_summary
{
	char subject[QSC_X509_NAME_ATTRIBUTE_STRING_MAX];		/*!< The formatted peer certificate subject name, when available. */
	char issuer[QSC_X509_NAME_ATTRIBUTE_STRING_MAX];		/*!< The formatted peer certificate issuer name, when available. */
	char commonname[QSC_X509_NAME_ATTRIBUTE_STRING_MAX];	/*!< The first peer certificate commonName value, when available. */
	char dnsname[QSC_X509_NAME_ATTRIBUTE_STRING_MAX];		/*!< The matched DNS subjectAltName, or the first DNS subjectAltName when no hostname check was requested. */
	qsc_x509_verify_status verifystatus;					/*!< The final certificate verification status. */
	bool populated;											/*!< Indicates that the summary was populated from a decoded peer certificate. */
	bool chainvalid;										/*!< Indicates that path validation succeeded before hostname evaluation. */
	bool hostnamechecked;									/*!< Indicates that hostname validation was requested. */
	bool hostnamevalid;										/*!< Indicates that hostname validation succeeded. */
} qsc_tls_peer_certificate_summary;

/**
 * \struct qsc_tls_client_authorization_info
 * \brief Bounded client-certificate identity information supplied to an mTLS authorization callback.
 *
 * \details
 * The certificate summary is copied from the certificate-validation bridge when
 * the built-in QSC X.509 validator is used. The certificate fingerprint is a
 * SHA3-256 digest of the leaf certificate DER encoding. The structure does not
 * retain caller-owned DER pointers.
 */
typedef struct qsc_tls_client_authorization_info
{
	qsc_tls_peer_certificate_summary summary;				/*!< Bounded peer certificate summary produced by certificate validation. */
	uint8_t certificatefingerprint[QSC_TLS_CERTIFICATE_FINGERPRINT_SIZE];	/*!< SHA3-256 fingerprint of the leaf certificate DER encoding. */
	size_t certificatefingerprintlen;						/*!< Length of the certificate fingerprint in bytes. */
	qsc_x509_verify_status verifystatus;					/*!< X.509 verification status reported by the validation layer. */
	bool chainvalid;										/*!< Indicates that certificate-chain validation succeeded. */
} qsc_tls_client_authorization_info;

/**
 * \brief Authorize a cryptographically valid mTLS client certificate.
 *
 * \param info: [const struct*] Bounded peer-certificate authorization information.
 * \param state: [void*] Caller-supplied authorization state.
 *
 * \return [bool] Returns true when the application authorizes the peer.
 */
typedef bool (*qsc_tls_client_authorization_callback)(const qsc_tls_client_authorization_info* info, void* state);

/**
 * \brief Context for the built-in bridge between TLS and the QSC X.509 layer.
 */
typedef struct qsc_tls_qsc_x509_context
{
	const qsc_x509_store* truststore;						/*!< Trust anchors used to validate peer certificate chains. */
	const qsc_x509_certificate* intermediates;				/*!< Optional intermediate certificates available during path building. */
	size_t intermediatecount;								/*!< The number of intermediate certificates supplied. */
	const qsc_x509_time* validationtime;					/*!< Validation time used during certificate verification. */
	const qsc_x509_crl* crls;							/*!< Optional loaded CRLs available for peer revocation checks. */
	size_t crlcount;									/*!< The number of loaded CRLs supplied to the bridge. */
	qsc_x509_revocation_mode revocationmode;				/*!< Active CRL revocation policy used by TLS certificate validation. */
	uint8_t* verifybuffer;									/*!< Scratch buffer used by X.509 verification helpers. */
	size_t verifybufferlen;									/*!< The length of the scratch verification buffer in bytes. */
	qsc_tls_peer_certificate_summary peersummary;			/*!< Most recent peer certificate identity and verification summary. */
	bool rejectunsupportedcriticalextensions;				/*!< Set to true to reject certificates containing unsupported critical extensions. */
	bool retainresults;									/*!< Set to true when mutable verification results are retained in this connection-owned context. */
	qsc_x509_verify_status lastverifystatus;				/*!< Most recent X.509 verification result reported by the built-in bridge. */
	qsc_tls_alert_description lastalert;					/*!< Most recent TLS alert mapped from the built-in bridge verification result. */
} qsc_tls_qsc_x509_context;

/**
 * \brief Decode a TLS Certificate message
 *
 * \details
 * Parses a TLS 1.3 Certificate handshake message and extracts the certificate
 * request context and certificate chain entries as spans into the input buffer.
 * The current QSC profile does not negotiate CertificateEntry extensions, so a
 * non-empty per-certificate extension vector is rejected as unsupported.
 *
 * \param input: [const uint8_t*] Pointer to encoded message buffer
 * \param inlen: [size_t] Length of input buffer in bytes
 * \param requestcontext: [const uint8_t**] Pointer to decoded request context span
 * \param requestcontextlen: [size_t*] Length of request context
 * \param chain: [struct] Output array of certificate views
 * \param chaincapacity: [size_t] Maximum number of entries in chain array
 * \param chainlength: [size_t*] Number of decoded certificates
 *
 * \return qsc_tls_status: Operation status code
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_decode_message(const uint8_t* input, size_t inlen, const uint8_t** requestcontext, size_t* requestcontextlen,
    qsc_tls_certificate_view* chain, size_t chaincapacity, size_t* chainlength);

/**
 * \brief Encode a TLS Certificate message
 *
 * \details
 * Serializes a TLS 1.3 Certificate handshake message containing a certificate
 * request context and a certificate chain. Each certificate entry is encoded
 * as a vector24 with an empty extensions block.
 *
 * \param requestcontext: [const uint8_t*] Pointer to the certificate request context buffer
 * \param requestcontextlen: [size_t] Length of the request context in bytes (<= 255)
 * \param chain: [const struct] Pointer to an array of certificate views
 * \param chainlength: [size_t] Number of certificates in the chain
 * \param output: [uint8_t*] Output buffer for encoded message
 * \param outlen: [size_t] Size of the output buffer in bytes
 * \param offset: [size_t*] Pointer to current write offset in output buffer
 *
 * \return qsc_tls_status: Operation status code
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_encode_message(const uint8_t* requestcontext, size_t requestcontextlen, const qsc_tls_certificate_view* chain,
    size_t chainlength, uint8_t* output, size_t outlen, size_t* offset);

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
QSC_EXPORT_API qsc_tls_status qsc_tls_x509_context_initialize(qsc_tls_qsc_x509_context* context, const qsc_x509_store* truststore,
	const qsc_x509_certificate* intermediates, size_t intermediatecount, const qsc_x509_time* validationtime,
	uint8_t* verifybuffer, size_t verifybufferlen);

/**
 * \brief Clone a configured QSC X.509 TLS context for one TLS connection.
 *
 * \details
 * Copies borrowed validation configuration from \p source, clears mutable result
 * state, and deliberately does not share the source verification scratch buffer.
 *
 * \param destination: [struct*] Destination connection-owned context.
 * \param source: [const struct*] Configured source/template context.
 *
 * \return [enum] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_x509_context_clone(qsc_tls_qsc_x509_context* destination, const qsc_tls_qsc_x509_context* source);

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
 * \brief Decode a TLS CertificateRequest message
 *
 * \details
 * Parses a TLS 1.3 CertificateRequest handshake message and extracts the
 * request context and extensions block as spans into the input buffer.
 *
 * \param input: [const uint8_t*] Pointer to encoded message buffer
 * \param inlen: [size_t] Length of input buffer
 * \param requestcontext: [const uint8_t**] Pointer to request context span
 * \param requestcontextlen: [size_t*] Length of request context
 * \param extensionsblock: [const uint8_t**] Pointer to extensions block span
 * \param extensionsblocklen: [size_t*] Length of extensions block
 *
 * \return qsc_tls_status: Operation status code
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_request_decode(const uint8_t* input, size_t inlen, const uint8_t** requestcontext, size_t* requestcontextlen,
	const uint8_t** extensionsblock, size_t* extensionsblocklen);

/**
 * \brief Encode a TLS CertificateRequest message
 *
 * \details
 * Serializes a TLS 1.3 CertificateRequest handshake message containing a
 * request context and a pre-encoded extensions block.
 *
 * \param requestcontext: [const uint8_t*] Pointer to request context buffer
 * \param requestcontextlen: [size_t] Length of request context in bytes (<= 255)
 * \param extensionsblock: [const uint8_t*] Pointer to extensions block buffer
 * \param extensionsblocklen: [size_t] Length of extensions block in bytes
 * \param output: [uint8_t*] Output buffer for encoded message
 * \param outlen: [size_t] Size of output buffer
 * \param offset: [size_t*] Pointer to current write offset
 *
 * \return qsc_tls_status: Operation status code
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_request_encode(const uint8_t* requestcontext, size_t requestcontextlen, const uint8_t* extensionsblock,
	size_t extensionsblocklen, uint8_t* output, size_t outlen, size_t* offset);

/**
 * \brief Map a QSC X.509 verification result to a TLS alert description.
 *
 * \param status: [enum] The QSC X.509 verification status.
 *
 * \return [enum] Returns the mapped TLS alert description.
 */
QSC_EXPORT_API qsc_tls_alert_description qsc_tls_x509_alert_from_verify_status(qsc_x509_verify_status status);

/**
 * \brief Map a TLS signature scheme to a QSC X.509 signature algorithm identifier.
 *
 * \param scheme: [enum] The TLS signature scheme.
 *
 * \return [qsc_x509_signature_algorithm] Returns the mapped X.509 algorithm identifier.
 */
QSC_EXPORT_API qsc_x509_signature_algorithm qsc_tls_x509_signature_algorithm_from_tls(qsc_tls_signature_scheme scheme);

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
QSC_EXPORT_API bool qsc_tls_x509_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength,
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
QSC_EXPORT_API bool qsc_tls_x509_verify_certificate_verify(qsc_tls_signature_scheme scheme, const uint8_t* input,
	size_t inputlen, const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
