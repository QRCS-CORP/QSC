#ifndef QSC_TLS_SERVER_H
#define QSC_TLS_SERVER_H

#include "qsccommon.h"
#include "tlshandshake.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsserver.h
 * \brief High-level TLS 1.3 server wrapper interface.
 */

/**
 * \struct qsc_tls_server
 * \brief High-level TLS server wrapper.
 */
typedef struct qsc_tls_server
{
	qsc_tls_connection_state state; /*!< Embedded TLS connection state for the server role. */
} qsc_tls_server;

/**
 * \brief Initialize a TLS server wrapper instance.
 *
 * \param server: [struct] The server wrapper instance.
 */
QSC_EXPORT_API void qsc_tls_server_initialize(qsc_tls_server* server);

/**
 * \brief Dispose of a TLS server wrapper instance.
 *
 * \param server: [struct] The server wrapper instance.
 */
QSC_EXPORT_API void qsc_tls_server_dispose(qsc_tls_server* server);

/**
 * \brief Set the local certificate chain and static CertificateVerify signature.
 *
 * \param server: [struct] The server wrapper instance.
 * \param chain: [const struct] The local certificate chain.
 * \param chainlength: [size_t] The number of certificates in the chain.
 * \param verifyscheme: [enum] The CertificateVerify signature scheme.
 * \param verifysignature: [const uint8_t*] The precomputed CertificateVerify signature.
 * \param verifysignaturelen: [size_t] The signature length in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_set_local_certificate(qsc_tls_server* server, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen);

/**
 * \brief Set the local certificate chain and dynamic CertificateVerify callback.
 *
 * \param server: [struct] The server wrapper instance.
 * \param chain: [const struct] The local certificate chain.
 * \param chainlength: [size_t] The number of certificates in the chain.
 * \param verifyscheme: [enum] The CertificateVerify signature scheme.
 * \param signcallback: [function] The CertificateVerify signing callback.
 * \param signstate: [void*] The callback state pointer.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_set_local_certificate_signer(qsc_tls_server* server, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, qsc_tls_certificate_sign_callback signcallback, void* signstate);

/**
 * \brief Clear the configured local certificate state.
 *
 * \param server: [struct] The server wrapper instance.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_clear_local_certificate(qsc_tls_server* server);

/**
 * \brief Set the peer certificate validation interface.
 *
 * \param server: [struct] The server wrapper instance.
 * \param iface: [const struct] The certificate validation interface.
 * \param hostname: [const char*] The expected peer hostname, or NULL.
 * \param requirepeercertificate: [bool] Require the peer to present a certificate.
 */
QSC_EXPORT_API void qsc_tls_server_set_certificate_interface(qsc_tls_server* server, const qsc_tls_certificate_interface* iface, const char* hostname, bool requirepeercertificate);

/**
 * \brief Set the QSC X.509 peer certificate validation interface.
 *
 * \param server: [struct] The server wrapper instance.
 * \param context: [struct] The QSC X.509 validation context.
 * \param hostname: [const char*] The expected peer hostname, or NULL.
 * \param requirepeercertificate: [bool] Require the peer to present a certificate.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_set_qsc_x509_interface(qsc_tls_server* server, qsc_tls_qsc_x509_context* context, const char* hostname, bool requirepeercertificate);

/**
 * \brief Export a resumption ticket from the active server connection state.
 *
 * \param server: [const struct] The server wrapper instance.
 * \param ticketbytes: [const uint8_t*] The encoded ticket bytes.
 * \param ticketlen: [size_t] The encoded ticket length in bytes.
 * \param nonce: [const uint8_t*] The ticket nonce bytes.
 * \param noncelen: [size_t] The nonce length in bytes.
 * \param lifetime: [uint32_t] The ticket lifetime in seconds.
 * \param ageadd: [uint32_t] The ticket age-add value.
 * \param ticket: [struct] The output session ticket.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_export_resumption_ticket(const qsc_tls_server* server, const uint8_t* ticketbytes, size_t ticketlen, const uint8_t* nonce, size_t noncelen, uint32_t lifetime, uint32_t ageadd, qsc_tls_session_ticket* ticket);

/**
 * \brief Process a ClientHello and emit the server response flight.
 *
 * \param server: [struct] The server wrapper instance.
 * \param input: [const uint8_t*] The received ClientHello bytes.
 * \param inlen: [size_t] The input length in bytes.
 * \param output: [uint8_t*] The output buffer for the server flight.
 * \param outlen: [size_t] The output buffer length in bytes.
 * \param msglen: [size_t*] Receives the number of bytes written.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_process_client(qsc_tls_server* server, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Complete the handshake by processing the client Finished flight.
 *
 * \param server: [struct] The server wrapper instance.
 * \param input: [const uint8_t*] The received client flight bytes.
 * \param inlen: [size_t] The input length in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_complete(qsc_tls_server* server, const uint8_t* input, size_t inlen);

/**
 * \brief Encrypt application data for transmission to the peer.
 *
 * \param server: [struct] The server wrapper instance.
 * \param output: [uint8_t*] The output record buffer.
 * \param outlen: [size_t] The output buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param input: [const uint8_t*] The plaintext input buffer.
 * \param inlen: [size_t] The plaintext length in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_encrypt_application_data(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Decrypt received application data.
 *
 * \param server: [struct] The server wrapper instance.
 * \param output: [uint8_t*] The plaintext output buffer.
 * \param outlen: [size_t] The output buffer length in bytes.
 * \param written: [size_t*] Receives the number of plaintext bytes written.
 * \param input: [const uint8_t*] The protected record input buffer.
 * \param inlen: [size_t] The protected record length in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_decrypt_application_data(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Encrypt an alert for transmission to the peer.
 *
 * \param server: [struct] The server wrapper instance.
 * \param output: [uint8_t*] The output record buffer.
 * \param outlen: [size_t] The output buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param alert: [const uint8_t*] The alert payload.
 * \param alertlen: [size_t] The alert length in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_encrypt_alert(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* alert, size_t alertlen);

/**
 * \brief Decrypt a received alert record.
 *
 * \param server: [struct] The server wrapper instance.
 * \param output: [uint8_t*] The plaintext alert output buffer.
 * \param outlen: [size_t] The output buffer length in bytes.
 * \param written: [size_t*] Receives the number of alert bytes written.
 * \param input: [const uint8_t*] The protected alert record input buffer.
 * \param inlen: [size_t] The protected record length in bytes.
 *
 * \return Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_decrypt_alert(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Determine whether the handshake has completed.
 *
 * \param server: [const struct] The server wrapper instance.
 *
 * \return Returns true if the handshake has completed.
 */
QSC_EXPORT_API bool qsc_tls_server_is_handshake_complete(const qsc_tls_server* server);

QSC_CPLUSPLUS_ENABLED_END

#endif
