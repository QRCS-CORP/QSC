#ifndef QSC_TLS_CERTMSG_H
#define QSC_TLS_CERTMSG_H

#include "qsccommon.h"
#include "tlslimits.h"
#include "tlscodec.h"
#include "tlscert.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlscertmsg.h
 * \brief TLS Certificate, CertificateRequest, and CertificateVerify message helpers.
 */

/**
 * \brief TLS handshake message types related to certificate processing.
 */
typedef enum qsc_tls_certificate_handshake_type
{
	qsc_tls_certificate_handshake_type_certificate = 11,			/*!< TLS Certificate handshake message. */
	qsc_tls_certificate_handshake_type_certificate_request = 13,	/*!< TLS CertificateRequest handshake message. */
	qsc_tls_certificate_handshake_type_certificate_verify = 15		/*!< TLS CertificateVerify handshake message. */
} qsc_tls_certificate_handshake_type;

/**
 * \brief Non-owning view of a single certificate-list entry.
 */
typedef struct qsc_tls_certificate_entry_view
{
	const uint8_t* certdata;     /*!< Pointer to the encoded certificate bytes. */
	size_t certdatalen;          /*!< The length of the encoded certificate in bytes. */
	const uint8_t* extensions;   /*!< Pointer to the encoded per-certificate extension bytes. */
	size_t extensionslen;        /*!< The length of the encoded extension block in bytes. */
} qsc_tls_certificate_entry_view;

/**
 * \brief Parsed view of a TLS Certificate handshake message.
 */
typedef struct qsc_tls_certificate_message_view
{
	uint8_t requestcontext[QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE];			/*!< The certificate request context bytes. */
	size_t requestcontextlen;														/*!< The number of valid bytes in the request-context array. */
	qsc_tls_certificate_entry_view entries[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES];	/*!< Parsed certificate entries. */
	size_t entrycount;																/*!< The number of parsed certificate entries. */
} qsc_tls_certificate_message_view;

/**
 * \brief Parsed view of a TLS CertificateRequest handshake message.
 */
typedef struct qsc_tls_certificate_request_message
{
	uint8_t requestcontext[QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE]; /*!< The certificate request context bytes. */
	size_t requestcontextlen;                                             /*!< The number of valid request-context bytes. */
	qsc_tls_signature_scheme sigschemes[QSC_TLS_MAX_SIGNATURE_SCHEMES];   /*!< Acceptable peer signature schemes. */
	size_t sigschemecount;                                                /*!< The number of valid signature schemes. */
} qsc_tls_certificate_request_message;

/**
 * \brief Parsed view of a TLS CertificateVerify handshake message.
 */
typedef struct qsc_tls_certificate_verify_message
{
	qsc_tls_signature_scheme scheme;    /*!< The signature scheme used to generate the signature. */
	const uint8_t* signature;           /*!< Pointer to the encoded signature bytes. */
	size_t signaturelen;                /*!< The length of the encoded signature in bytes. */
} qsc_tls_certificate_verify_message;

/**
 * \brief Build a TLS Certificate handshake-message body.
 *
 * \param requestcontext: [const uint8_t*] Certificate request-context bytes, or NULL when the length is zero.
 * \param requestcontextlen: [size_t] The number of request-context bytes.
 * \param entries: [const struct] Certificate-list entry views, or NULL when the count is zero.
 * \param entrycount: [size_t] The number of certificate-list entries to encode.
 * \param output: [uint8_t*] The destination buffer for the encoded message body.
 * \param outlen: [size_t] The capacity of the destination buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded message-body length in bytes.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_message_build(const uint8_t* requestcontext, size_t requestcontextlen, 
	const qsc_tls_certificate_entry_view* entries, size_t entrycount, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Parse a TLS Certificate handshake-message body.
 *
 * \param input: [const uint8_t*] The encoded message body.
 * \param inlen: [size_t] The encoded message-body length in bytes.
 * \param message: [struct] Receives the parsed non-owning message view.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_message_parse(const uint8_t* input, size_t inlen, qsc_tls_certificate_message_view* message);

/**
 * \brief Build a TLS CertificateRequest handshake-message body.
 *
 * \param requestcontext: [const uint8_t*] Certificate request-context bytes, or NULL when the length is zero.
 * \param requestcontextlen: [size_t] The number of request-context bytes.
 * \param sigschemes: [const enum*] Supported peer signature schemes, or NULL when the count is zero.
 * \param sigschemecount: [size_t] The number of signature schemes to encode.
 * \param output: [uint8_t*] The destination buffer for the encoded message body.
 * \param outlen: [size_t] The capacity of the destination buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded message-body length in bytes.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_request_build(const uint8_t* requestcontext, size_t requestcontextlen, const qsc_tls_signature_scheme* sigschemes, size_t sigschemecount, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Parse a TLS CertificateRequest handshake-message body.
 *
 * \param input: [const uint8_t*] The encoded message body.
 * \param inlen: [size_t] The encoded message-body length in bytes.
 * \param message: [struct] Receives the parsed message view.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_request_parse(const uint8_t* input, size_t inlen, qsc_tls_certificate_request_message* message);

/**
 * \brief Build a TLS CertificateVerify handshake-message body.
 *
 * \param scheme: [enum] The certificate-verify signature scheme.
 * \param signature: [const uint8_t*] The encoded signature bytes, or NULL when the length is zero.
 * \param signaturelen: [size_t] The signature length in bytes.
 * \param output: [uint8_t*] The destination buffer for the encoded message body.
 * \param outlen: [size_t] The capacity of the destination buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded message-body length in bytes.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_verify_build(qsc_tls_signature_scheme scheme, const uint8_t* signature, size_t signaturelen, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Parse a TLS CertificateVerify handshake-message body.
 *
 * \param input: [const uint8_t*] The encoded message body.
 * \param inlen: [size_t] The encoded message-body length in bytes.
 * \param message: [struct] Receives the parsed non-owning message view.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_verify_parse(const uint8_t* input, size_t inlen, qsc_tls_certificate_verify_message* message);

/**
 * \brief Build the RFC 8446 CertificateVerify transcript input.
 *
 * \param isserver: [bool] Set true for the server context string, or false for the client context string.
 * \param transcripthash: [const uint8_t*] The transcript hash bytes, or NULL when the length is zero.
 * \param transcripthashlen: [size_t] The transcript-hash length in bytes.
 * \param output: [uint8_t*] The destination buffer for the constructed input.
 * \param outlen: [size_t] The capacity of the destination buffer in bytes.
 * \param outputlen: [size_t*] Receives the constructed input length in bytes.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_verify_input_build(bool isserver, const uint8_t* transcripthash, size_t transcripthashlen,
	uint8_t* output, size_t outlen, size_t* outputlen);

/**
 * \brief Determine whether a signature scheme is valid for TLS CertificateVerify.
 *
 * \param scheme: [enum] The signature scheme.
 *
 * 
eturn Returns true if the scheme is CertificateVerify-capable.
 */
QSC_EXPORT_API bool qsc_tls_certificate_verify_scheme_allowed(qsc_tls_signature_scheme scheme);

/**
 * \brief Validate a parsed peer certificate chain through the configured certificate interface.
 *
 * \param message: [const struct] The parsed Certificate message view.
 * \param context: [const struct] The certificate-validation context.
 * \param iface: [const struct] The certificate-validation callback interface.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_validate_peer(const qsc_tls_certificate_message_view* message, 
	const qsc_tls_certificate_validation_context* context, const qsc_tls_certificate_interface* iface);

/**
 * \brief Validate a parsed CertificateVerify message through the configured certificate interface.
 *
 * \param message: [const struct] The parsed Certificate message view.
 * \param verify: [const struct] The parsed CertificateVerify message.
 * \param verifyinput: [const uint8_t*] The CertificateVerify input bytes.
 * \param verifyinputlen: [size_t] The CertificateVerify input length in bytes.
 * \param iface: [const struct] The certificate-validation callback interface.
 *
 * \return The TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_certificate_validate_verify(const qsc_tls_certificate_message_view* message, 
	const qsc_tls_certificate_verify_message* verify, const uint8_t* verifyinput, size_t verifyinputlen, const qsc_tls_certificate_interface* iface);

QSC_CPLUSPLUS_ENABLED_END

#endif
