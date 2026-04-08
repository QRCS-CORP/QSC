#ifndef QSC_TLS_CLIENT_H
#define QSC_TLS_CLIENT_H

#include "qsccommon.h"
#include "tlshandshake.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsclient.h
 * \brief High-level TLS client wrapper.
 */

typedef struct qsc_tls_client
{
	qsc_tls_connection_state state; /*!< Embedded TLS connection state for the client role. */
} qsc_tls_client;

/**
 * \brief Initialize a TLS client wrapper and its embedded connection state.
 *
 * \param client: [struct] The client instance to initialize.
 */
QSC_EXPORT_API void qsc_tls_client_initialize(qsc_tls_client* client);

/**
 * \brief Dispose a TLS client wrapper and clear its embedded connection state.
 *
 * \param client: [struct] The client instance to dispose.
 */
QSC_EXPORT_API void qsc_tls_client_dispose(qsc_tls_client* client);

/**
 * \brief Install a certificate verification interface for the peer certificate path.
 *
 * \param client: [struct] The client instance.
 * \param iface: [struct] The certificate interface callbacks.
 * \param hostname: [const char*] The expected peer host name, or NULL if not used.
 * \param requirepeercertificate: [bool] Require a peer certificate when true.
 */
QSC_EXPORT_API void qsc_tls_client_set_certificate_interface(qsc_tls_client* client, const qsc_tls_certificate_interface* iface, const char* hostname, bool requirepeercertificate);

/**
 * \brief Install the built-in QSC X.509 certificate verification interface.
 *
 * \param client: [struct] The client instance.
 * \param context: [struct] The QSC X.509 validation context.
 * \param hostname: [const char*] The expected peer host name, or NULL if not used.
 * \param requirepeercertificate: [bool] Require a peer certificate when true.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_set_qsc_x509_interface(qsc_tls_client* client, qsc_tls_qsc_x509_context* context, const char* hostname, bool requirepeercertificate);

/**
 * \brief Set a fixed local certificate chain and verify callback signature.
 *
 * \param client: [struct] The client instance.
 * \param chain: [struct] The local certificate chain.
 * \param chainlength: [size_t] The number of certificate views in the chain.
 * \param verifyscheme: [enum] The signature scheme used by the certificate verify message.
 * \param verifysignature: [const uint8_t*] The fixed certificate verify signature bytes.
 * \param verifysignaturelen: [size_t] The fixed certificate verify signature length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_set_local_certificate(qsc_tls_client* client, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen);

/**
 * \brief Set a local certificate chain and signing callback for certificate verify generation.
 *
 * \param client: [struct] The client instance.
 * \param chain: [struct] The local certificate chain.
 * \param chainlength: [size_t] The number of certificate views in the chain.
 * \param verifyscheme: [enum] The signature scheme used by the certificate verify message.
 * \param signcallback: [function] The certificate verify signing callback.
 * \param signstate: [void*] Opaque caller state passed to the signing callback.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_set_local_certificate_signer(qsc_tls_client* client, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, qsc_tls_certificate_sign_callback signcallback, void* signstate);

/**
 * \brief Clear the configured local certificate presentation state.
 *
 * \param client: [struct] The client instance.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_clear_local_certificate(qsc_tls_client* client);

/**
 * \brief Enable session resumption with a previously issued session ticket.
 *
 * \param client: [struct] The client instance.
 * \param ticket: [struct] The session ticket.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_set_resumption_ticket(qsc_tls_client* client, const qsc_tls_session_ticket* ticket);

/**
 * \brief Determine whether session resumption is enabled for the client.
 *
 * \param client: [const struct] The client instance.
 *
 * \return True if resumption is enabled.
 */
QSC_EXPORT_API bool qsc_tls_client_is_resumption_enabled(const qsc_tls_client* client);

/**
 * \brief Start a client handshake by building the outbound ClientHello flight.
 *
 * \param client: [struct] The client instance.
 * \param output: [uint8_t*] The output buffer that receives the encoded record bytes.
 * \param outlen: [size_t] The output buffer length.
 * \param msglen: [size_t*] Receives the number of bytes written.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_connect_start(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Process the initial server handshake flight and emit any required client response.
 *
 * \param client: [struct] The client instance.
 * \param input: [const uint8_t*] The inbound server flight bytes.
 * \param inlen: [size_t] The inbound byte length.
 * \param output: [uint8_t*] The output buffer for any generated client response bytes.
 * \param outlen: [size_t] The output buffer length.
 * \param msglen: [size_t*] Receives the number of bytes written to output.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_process_server(qsc_tls_client* client, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Encrypt application data into a protected TLS application-data record.
 *
 * \param client: [struct] The client instance.
 * \param output: [uint8_t*] The output buffer that receives the encoded record.
 * \param outlen: [size_t] The output buffer length.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param input: [const uint8_t*] The plaintext application data.
 * \param inlen: [size_t] The plaintext length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_encrypt_application_data(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Decrypt a protected TLS application-data record.
 *
 * \param client: [struct] The client instance.
 * \param output: [uint8_t*] The output buffer that receives the plaintext.
 * \param outlen: [size_t] The output buffer length.
 * \param written: [size_t*] Receives the number of plaintext bytes written.
 * \param input: [const uint8_t*] The protected record bytes.
 * \param inlen: [size_t] The protected record length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_decrypt_application_data(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Encrypt an alert payload into a protected TLS alert record.
 *
 * \param client: [struct] The client instance.
 * \param output: [uint8_t*] The output buffer that receives the encoded record.
 * \param outlen: [size_t] The output buffer length.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param alert: [const uint8_t*] The alert payload bytes.
 * \param alertlen: [size_t] The alert payload length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_encrypt_alert(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* alert, size_t alertlen);

/**
 * \brief Decrypt a protected TLS alert record.
 *
 * \param client: [struct] The client instance.
 * \param output: [uint8_t*] The output buffer that receives the alert payload.
 * \param outlen: [size_t] The output buffer length.
 * \param written: [size_t*] Receives the number of alert bytes written.
 * \param input: [const uint8_t*] The protected record bytes.
 * \param inlen: [size_t] The protected record length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_decrypt_alert(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Determine whether the client handshake has completed successfully.
 *
 * \param client: [const struct] The client instance.
 *
 * \return True if the handshake is complete.
 */
QSC_EXPORT_API bool qsc_tls_client_is_handshake_complete(const qsc_tls_client* client);

QSC_CPLUSPLUS_ENABLED_END

#endif
