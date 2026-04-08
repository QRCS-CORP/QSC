#ifndef QSC_TLS_HANDSHAKE_H
#define QSC_TLS_HANDSHAKE_H

#include "qsccommon.h"
#include "memutils.h"
#include "tlsalert.h"
#include "tlscertmsg.h"
#include "tlsdefs.h"
#include "tlsextensions.h"
#include "tlsgroups.h"
#include "tlsio.h"
#include "tlslimits.h"
#include "tlspolicy.h"
#include "tlsrecord.h"
#include "tlsresumption.h"
#include "tlsschedule.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlshandshake.h
 * \brief Core TLS handshake state and state-machine entry points.
 */

typedef enum qsc_tls_handshake_type
{
	qsc_tls_handshake_type_client_hello = 1,				/*!< ClientHello handshake message. */
	qsc_tls_handshake_type_server_hello = 2,				/*!< ServerHello handshake message. */
	qsc_tls_handshake_type_encrypted_extensions = 8,		/*!< EncryptedExtensions handshake message. */
	qsc_tls_handshake_type_certificate = 11,				/*!< Certificate handshake message. */
	qsc_tls_handshake_type_certificate_request = 13,		/*!< CertificateRequest handshake message. */
	qsc_tls_handshake_type_certificate_verify = 15,			/*!< CertificateVerify handshake message. */
	qsc_tls_handshake_type_finished = 20,					/*!< Finished handshake message. */
	qsc_tls_handshake_type_message_hash = 254				/*!< Synthetic message_hash handshake message used by HelloRetryRequest transcripts. */
} qsc_tls_handshake_type;

typedef enum qsc_tls_connection_stage
{
	qsc_tls_connection_stage_none = 0,						/*!< No handshake traffic has been processed. */
	qsc_tls_connection_stage_client_hello_sent = 1,			/*!< The current ClientHello flight has been sent. */
	qsc_tls_connection_stage_hello_retry_request_sent = 2,	/*!< The server has sent a HelloRetryRequest and is awaiting a second ClientHello. */
	qsc_tls_connection_stage_server_flight_sent = 3,		/*!< The server flight has been sent. */
	qsc_tls_connection_stage_client_finished_sent = 4,		/*!< The client Finished message has been sent. */
	qsc_tls_connection_stage_connected = 5,					/*!< The handshake has completed and the connection is active. */
	qsc_tls_connection_stage_failed = 6						/*!< A fatal protocol or state error has occurred and the connection must not be reused. */
} qsc_tls_connection_stage;

typedef struct qsc_tls_handshake_parameters
{
	qsc_tls_cipher_suite ciphersuite; /*!< Negotiated cipher suite. */
	qsc_tls_named_group group;        /*!< Negotiated key exchange group. */
	qsc_tls_hash_algorithm hash;      /*!< Hash algorithm implied by the negotiated cipher suite. */
	size_t keysharelength;            /*!< Length of the negotiated key-share payload in bytes. */
} qsc_tls_handshake_parameters;

typedef struct qsc_tls_connection_state
{
	qsc_tls_policy policy;														/*!< Local policy controlling groups and signature algorithms. */
	qsc_tls_transcript_state transcript;										/*!< Running handshake transcript hash state. */
	qsc_tls_handshake_parameters params;										/*!< Negotiated handshake parameters. */
	qsc_tls_certificate_interface certiface;									/*!< Certificate validation and verification callbacks. */
	qsc_tls_certificate_validation_context certctx;								/*!< Peer certificate validation context. */
	qsc_tls_qsc_x509_context ownedx509context;									/*!< Owned copy of the built-in QSC X.509 bridge context. */
	char hostname[QSC_TLS_MAX_HOSTNAME_SIZE + 1U];								/*!< Owned hostname storage used by the certificate-validation context. */
	size_t hostnamelen;															/*!< Length of the stored hostname in bytes, excluding the terminator. */
	bool hasownedx509context;													/*!< True when certiface.state points at ownedx509context. */
	qsc_tls_local_certificate_config localcert;									/*!< Local certificate chain and CertificateVerify material. */
	qsc_tls_certificate_view peercertleaf;										/*!< View of the peer leaf certificate. */
	uint8_t peercertleafstorage[QSC_TLS_CERTIFICATE_MAX_SIZE];					/*!< Owned storage for the peer leaf certificate bytes. */
	qsc_tls_peer_capabilities peercapabilities;									/*!< Parsed peer-supported groups and signature schemes from ClientHello or CertificateRequest context. */
	qsc_tls_named_group offeredgroups[QSC_TLS_MAX_GROUPS];						/*!< Configured client-offered and server-preferred named groups. */
	size_t offeredgroupcount;													/*!< Number of configured group offers or preferences. */
	qsc_tls_signature_scheme offeredsigschemes[QSC_TLS_MAX_SIGNATURE_SCHEMES];	/*!< Configured offered or accepted signature schemes. */
	size_t offeredsigschemecount;												/*!< Number of configured signature-scheme offers or preferences. */
	qsc_tls_cipher_suite offeredsuites[QSC_TLS_MAX_CIPHER_SUITES];				/*!< Configured client-advertised and locally permitted cipher suites. */
	size_t offeredsuitecount;													/*!< Number of configured cipher-suite offers. */
	char localsni[QSC_TLS_MAX_HOSTNAME_SIZE + 1U];								/*!< Locally configured SNI hostname offered by the client role. */
	size_t localsnisize;														/*!< Length of the locally configured SNI hostname in bytes. */
	bool servernameack;															/*!< True when the peer acknowledged the offered server_name extension. */
	uint8_t legacysessionid[32];												/*!< Cached legacy_session_id bytes from the ClientHello or locally generated by the client. */
	size_t legacysessionidlen;													/*!< Length of the cached legacy_session_id in bytes. */
	uint8_t localalpn[QSC_TLS_MAX_ALPN_SIZE + 1U];								/*!< Locally configured ALPN protocol identifier. */
	size_t localalpnsize;														/*!< Length of the locally configured ALPN protocol identifier in bytes. */
	uint8_t peeralpn[QSC_TLS_MAX_ALPN_SIZE + 1U];								/*!< Negotiated peer ALPN protocol identifier. */
	size_t peeralpnsize;														/*!< Length of the negotiated peer ALPN identifier in bytes. */
	bool clientauthrequested;													/*!< True when the peer has requested client authentication. */
	uint8_t clientauthcontext[QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE];	/*!< Cached CertificateRequest context bytes. */
	size_t clientauthcontextlen;												/*!< Length of the cached CertificateRequest context in bytes. */
	uint8_t localshare[QSC_TLS_KEY_SHARE_MAX_SIZE];								/*!< Local key-share bytes. */
	size_t localsharelen;														/*!< Length of the local key-share in bytes. */
	uint8_t localprivatekey[QSC_TLS_MAX_PRIVATE_KEY_SIZE];						/*!< Local private-key state bytes for the selected group. */
	size_t localprivatekeylen;													/*!< Length of the local private-key state implied by the selected group. */
	uint8_t peershare[QSC_TLS_KEY_SHARE_MAX_SIZE];								/*!< Peer key-share bytes. */
	size_t peersharelen;														/*!< Length of the peer key-share in bytes. */
	size_t negotiatedsharedsecretlen;											/*!< Descriptor-derived length of the negotiated shared secret. */
	size_t verifysignaturebound;												/*!< Maximum CertificateVerify signature length for the selected verification scheme. */
	uint8_t handshakesecret[QSC_TLS_MAX_SHARED_SECRET_SIZE];					/*!< Negotiated handshake secret bytes. */
	size_t handshakesecretlen;													/*!< Length of the handshake secret in bytes. */
	uint8_t mastersecret[QSC_TLS_HASH_MAX_SIZE];								/*!< Derived TLS 1.3 master secret bytes. */
	size_t mastersecretlen;														/*!< Length of the derived master secret in bytes. */
	uint8_t apptraffictranscripthash[QSC_TLS_HASH_MAX_SIZE];					/*!< Transcript hash snapshot at the server Finished transcript point for application traffic derivation. */
	size_t apptraffictranscripthashlen;											/*!< Length of the saved application-traffic transcript hash. */
	qsc_tls_record_state writerecord;											/*!< Active write-side application record protection state. */
	qsc_tls_record_state readrecord;											/*!< Active read-side application record protection state. */
	bool applicationkeysready;													/*!< True when post-handshake application record keys are installed. */
	uint8_t instream[QSC_TLS_STREAM_BUFFER_MAX_SIZE];							/*!< Buffered inbound transport bytes awaiting record parsing. */
	size_t instreamlen;															/*!< Number of valid inbound transport bytes currently buffered. */
	uint8_t handshakequeue[QSC_TLS_STREAM_BUFFER_MAX_SIZE];						/*!< Buffered handshake payload bytes reassembled from one or more records. */
	size_t handshakequeuelen;													/*!< Number of valid reassembled handshake bytes currently buffered. */
	uint8_t firstclienthello[QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE + 4U];			/*!< Cached first ClientHello bytes used to rewrite the transcript when processing HelloRetryRequest. */
	size_t firstclienthellolen;													/*!< Length of the cached first ClientHello in bytes. */
	bool helloretryrequested;													/*!< True once a HelloRetryRequest has been sent or processed for the current handshake. */
	qsc_tls_session_ticket resumptionticket;									/*!< Cached resumption ticket bound to the connection. */
	bool resumptionenabled;														/*!< Indicates whether resumption was enabled for the handshake. */
	bool resumedhandshake;														/*!< Indicates whether the current handshake resumed from a ticket. */
	qsc_tls_connection_stage stage;												/*!< Current handshake stage. */
	qsc_tls_alert_description stagedalert;										/*!< Pending fatal alert staged by the handshake logic regardless of certificate interface mode. */
	bool isclient;																/*!< True for the client role; false for the server role. */
	bool handshakecomplete;														/*!< True when the handshake has completed successfully. */
} qsc_tls_connection_state;

/**
 * \brief Initialize a TLS connection-state container for the client or server role.
 *
 * \param state: [struct] The connection-state object to initialize.
 * \param isclient: [bool] Set true for a client role; false for a server role.
 */
QSC_EXPORT_API void qsc_tls_connection_state_initialize(qsc_tls_connection_state* state, bool isclient);

/**
 * \brief Dispose of all sensitive material and reset a TLS connection-state container.
 *
 * \param state: [struct] The connection-state object to dispose.
 */
QSC_EXPORT_API void qsc_tls_connection_state_dispose(qsc_tls_connection_state* state);

/**
 * \brief Refresh the locally offered cipher-suite list from the active policy.
 *
 * \param state: [struct] The connection-state object to refresh.
 */
QSC_EXPORT_API void qsc_tls_connection_state_refresh_offered_cipher_suites(qsc_tls_connection_state* state);

/**
 * \brief Determine whether the current connection state is configured for handshake processing.
 *
 * \param state: [const struct] The connection-state object to inspect.
 *
 * \return True if the configuration is sufficient to start or continue the handshake.
 */
QSC_EXPORT_API bool qsc_tls_connection_state_configuration_permitted(const qsc_tls_connection_state* state);

/**
 * \brief Determine whether application-data protection is currently permitted.
 *
 * \param state: [const struct] The connection-state object to inspect.
 *
 * \return True if application record keys are installed and usable.
 */
QSC_EXPORT_API bool qsc_tls_connection_state_application_data_permitted(const qsc_tls_connection_state* state);

/**
 * \brief Determine whether the connection has entered the failed state.
 *
 * \param state: [const struct] The connection-state object to inspect.
 *
 * \return True if the connection is failed.
 */
QSC_EXPORT_API bool qsc_tls_connection_state_is_failed(const qsc_tls_connection_state* state);

/**
 * \brief Mark the connection state as failed.
 *
 * \param state: [struct] The connection-state object to update.
 */
QSC_EXPORT_API void qsc_tls_connection_state_fail(qsc_tls_connection_state* state);

/**
 * \brief Build a ClientHello handshake message.
 *
 * \param state: [struct] The connection-state object.
 * \param output: [uint8_t*] The output buffer receiving the encoded handshake message.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded message length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_build_client_hello(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Process a ClientHello and build the server flight or HelloRetryRequest.
 *
 * \param state: [struct] The server connection-state object.
 * \param input: [const uint8_t*] The encoded ClientHello handshake message.
 * \param inlen: [size_t] The length of the encoded ClientHello in bytes.
 * \param output: [uint8_t*] The output buffer receiving the encoded server flight.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded server-flight length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_process_client_hello(qsc_tls_connection_state* state, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Process the server flight and optionally build the client Finished message.
 *
 * \param state: [struct] The client connection-state object.
 * \param input: [const uint8_t*] The encoded server-flight bytes.
 * \param inlen: [size_t] The length of the encoded server-flight bytes.
 * \param output: [uint8_t*] The output buffer receiving any generated handshake message.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param msglen: [size_t*] Receives the generated message length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_process_server_flight(qsc_tls_connection_state* state, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Process a client Finished message on the server side.
 *
 * \param state: [struct] The server connection-state object.
 * \param input: [const uint8_t*] The encoded Finished handshake message.
 * \param inlen: [size_t] The length of the encoded Finished message in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_process_client_finished(qsc_tls_connection_state* state, const uint8_t* input, size_t inlen);

/**
 * \brief Generate a local key share for the selected group.
 *
 * \param group: [enum] The selected named group.
 * \param isclient: [bool] Set true for a client share; false for a server share.
 * \param output: [uint8_t*] The output buffer receiving the encoded key share.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param sharelen: [size_t*] Receives the encoded share length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_generate_local_share(qsc_tls_named_group group, bool isclient, uint8_t* output, size_t outlen, size_t* sharelen);

/**
 * \brief Compute a shared secret from the local and peer key shares.
 *
 * \param group: [enum] The selected named group.
 * \param localshare: [const uint8_t*] The local key-share or private-key material.
 * \param localsharelen: [size_t] The length of the local input in bytes.
 * \param peershare: [const uint8_t*] The peer key-share bytes.
 * \param peersharelen: [size_t] The length of the peer key-share in bytes.
 * \param output: [uint8_t*] The output buffer receiving the shared secret.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param secretlen: [size_t*] Receives the shared-secret length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_compute_shared_secret(qsc_tls_named_group group, const uint8_t* localshare, size_t localsharelen, const uint8_t* peershare, size_t peersharelen, uint8_t* output, size_t outlen, size_t* secretlen);

/**
 * \brief Append a handshake message body to the transcript hash.
 *
 * \param transcript: [struct] The transcript state to update.
 * \param type: [enum] The handshake message type.
 * \param body: [const uint8_t*] The encoded handshake message body.
 * \param bodylen: [size_t] The length of the handshake message body in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_append_message(qsc_tls_transcript_state* transcript, qsc_tls_handshake_type type, const uint8_t* body, size_t bodylen);

/**
 * \brief Build a Finished handshake message.
 *
 * \param state: [const struct] The connection-state object.
 * \param output: [uint8_t*] The output buffer receiving the encoded Finished message.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param msglen: [size_t*] Receives the encoded message length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_build_finished(const qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* msglen);

/**
 * \brief Verify a peer Finished handshake message.
 *
 * \param state: [const struct] The connection-state object.
 * \param input: [const uint8_t*] The encoded Finished handshake message.
 * \param inlen: [size_t] The length of the encoded Finished message in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_verify_finished(const qsc_tls_connection_state* state, const uint8_t* input, size_t inlen);

/**
 * \brief Install handshake traffic record keys.
 *
 * \param state: [struct] The connection-state object to update.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_install_handshake_record_keys(qsc_tls_connection_state* state);

/**
 * \brief Rewrite the transcript for a HelloRetryRequest path.
 *
 * \param state: [struct] The connection-state object to update.
 * \param serverhello: [const uint8_t*] The encoded HelloRetryRequest bytes.
 * \param serverhellolen: [size_t] The length of the encoded HelloRetryRequest in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_rewrite_transcript_for_hrr(qsc_tls_connection_state* state, const uint8_t* serverhello, size_t serverhellolen);

/**
 * \brief Install application traffic record keys.
 *
 * \param state: [struct] The connection-state object to update.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_install_application_record_keys(qsc_tls_connection_state* state);

/**
 * \brief Encrypt application-data plaintext into a protected TLS record.
 *
 * \param state: [struct] The connection-state object.
 * \param output: [uint8_t*] The output buffer receiving the encoded record.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param written: [size_t*] Receives the encoded record length in bytes.
 * \param input: [const uint8_t*] The plaintext input buffer.
 * \param inlen: [size_t] The length of the plaintext input in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_encrypt_application_data(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Decrypt a protected TLS application-data record.
 *
 * \param state: [struct] The connection-state object.
 * \param output: [uint8_t*] The output buffer receiving the plaintext.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param written: [size_t*] Receives the plaintext length in bytes.
 * \param input: [const uint8_t*] The encoded record bytes.
 * \param inlen: [size_t] The length of the encoded record in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_decrypt_application_data(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Encrypt an alert payload into a protected TLS record.
 *
 * \param state: [struct] The connection-state object.
 * \param output: [uint8_t*] The output buffer receiving the encoded record.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param written: [size_t*] Receives the encoded record length in bytes.
 * \param alert: [const uint8_t*] The alert payload.
 * \param alertlen: [size_t] The length of the alert payload in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_encrypt_alert(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* written, const uint8_t* alert, size_t alertlen);

/**
 * \brief Decrypt a protected TLS alert record.
 *
 * \param state: [struct] The connection-state object.
 * \param output: [uint8_t*] The output buffer receiving the alert payload.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 * \param written: [size_t*] Receives the alert payload length in bytes.
 * \param input: [const uint8_t*] The encoded record bytes.
 * \param inlen: [size_t] The length of the encoded record in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_decrypt_alert(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen);

/**
 * \brief Install an external certificate-validation interface.
 *
 * \param state: [struct] The connection-state object to update.
 * \param iface: [const struct] The certificate interface to install.
 * \param hostname: [const char*] The reference hostname used for peer validation.
 * \param requirepeercertificate: [bool] Set true to require a peer certificate.
 */
QSC_EXPORT_API void qsc_tls_handshake_set_certificate_interface(qsc_tls_connection_state* state, const qsc_tls_certificate_interface* iface, const char* hostname, bool requirepeercertificate);

/**
 * \brief Install the built-in QSC X.509 certificate-validation bridge.
 *
 * \param state: [struct] The connection-state object to update.
 * \param context: [const struct] The X.509 bridge context to copy.
 * \param hostname: [const char*] The reference hostname used for peer validation.
 * \param requirepeercertificate: [bool] Set true to require a peer certificate.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_set_qsc_x509_interface(qsc_tls_connection_state* state, const qsc_tls_qsc_x509_context* context, const char* hostname, bool requirepeercertificate);

/**
 * \brief Configure a local certificate chain and static CertificateVerify signature.
 *
 * \param state: [struct] The connection-state object to update.
 * \param chain: [const struct] The local certificate chain entries.
 * \param chainlength: [size_t] The number of certificate chain entries.
 * \param verifyscheme: [enum] The CertificateVerify signature scheme.
 * \param verifysignature: [const uint8_t*] The static CertificateVerify signature bytes.
 * \param verifysignaturelen: [size_t] The length of the static signature in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_set_local_certificate(qsc_tls_connection_state* state, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen);

/**
 * \brief Configure a local certificate chain and dynamic CertificateVerify signer.
 *
 * \param state: [struct] The connection-state object to update.
 * \param chain: [const struct] The local certificate chain entries.
 * \param chainlength: [size_t] The number of certificate chain entries.
 * \param verifyscheme: [enum] The CertificateVerify signature scheme.
 * \param signcallback: [function] The callback producing the CertificateVerify signature.
 * \param signstate: [void*] The caller-supplied signing context.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_set_local_certificate_signer(qsc_tls_connection_state* state, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, qsc_tls_certificate_sign_callback signcallback, void* signstate);

/**
 * \brief Clear the configured local certificate state.
 *
 * \param state: [struct] The connection-state object to update.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_clear_local_certificate(qsc_tls_connection_state* state);

/**
 * \brief Determine whether a local certificate chain is configured.
 *
 * \param state: [const struct] The connection-state object to inspect.
 *
 * \return True if a local certificate chain is configured.
 */
QSC_EXPORT_API bool qsc_tls_handshake_has_local_certificate(const qsc_tls_connection_state* state);

/**
 * \brief Enable ticket-based session resumption.
 *
 * \param state: [struct] The connection-state object to update.
 * \param ticket: [const struct] The session ticket to install.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_enable_resumption(qsc_tls_connection_state* state, const qsc_tls_session_ticket* ticket);

/**
 * \brief Determine whether session resumption is enabled.
 *
 * \param state: [const struct] The connection-state object to inspect.
 *
 * \return True if session resumption is enabled.
 */
QSC_EXPORT_API bool qsc_tls_handshake_is_resumption_enabled(const qsc_tls_connection_state* state);

/**
 * \brief Export a resumption ticket view from raw ticket metadata.
 *
 * \param state: [const struct] The connection-state object.
 * \param ticketbytes: [const uint8_t*] The ticket identity bytes.
 * \param ticketlen: [size_t] The length of the ticket identity in bytes.
 * \param nonce: [const uint8_t*] The ticket nonce bytes.
 * \param noncelen: [size_t] The length of the ticket nonce in bytes.
 * \param lifetime: [uint32_t] The advertised ticket lifetime in seconds.
 * \param ageadd: [uint32_t] The advertised ticket age-add value.
 * \param ticket: [struct] Receives the exported session ticket.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_export_resumption_ticket(const qsc_tls_connection_state* state, const uint8_t* ticketbytes, size_t ticketlen, const uint8_t* nonce, size_t noncelen, uint32_t lifetime, uint32_t ageadd, qsc_tls_session_ticket* ticket);

/**
 * \brief Compute a PSK resumption binder over a partial ClientHello transcript.
 *
 * \param state: [const struct] The connection-state object.
 * \param transcript: [const uint8_t*] The partial ClientHello transcript bytes.
 * \param transcriptlen: [size_t] The length of the partial transcript in bytes.
 * \param output: [uint8_t*] The output buffer receiving the binder.
 * \param outlen: [size_t] The length of the output buffer in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_compute_resumption_binder(const qsc_tls_connection_state* state, const uint8_t* transcript, size_t transcriptlen, uint8_t* output, size_t outlen);

/**
 * \brief Stage a fatal alert for later transmission or inspection.
 *
 * \param state: [struct] The connection-state object to update.
 * \param alert: [enum] The alert description to stage.
 */
QSC_EXPORT_API void qsc_tls_handshake_stage_alert(qsc_tls_connection_state* state, qsc_tls_alert_description alert);

QSC_CPLUSPLUS_ENABLED_END

#endif
