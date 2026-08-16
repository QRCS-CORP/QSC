#ifndef QSC_TLS_SERVER_H
#define QSC_TLS_SERVER_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"
#include "tlsstate.h"
#include "tlslimits.h"
#include "tlscert.h"
#include "tlsgroups.h"
#include "tlskeyschedule.h"
#include "tlstranscript.h"
#include "tlssession.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsserver.h
 * \brief TLS 1.3 server handshake state machine.
 */

/**
 * \enum qsc_tls_server_state_phase
 */
typedef enum qsc_tls_server_state_phase
{
    qsc_tls_server_phase_initial = 0,                  /*!< Not yet started. */
    qsc_tls_server_phase_waiting_client_hello = 1,     /*!< Waiting first ClientHello. */
    qsc_tls_server_phase_waiting_client_hello_2 = 2,   /*!< After HRR. */
    qsc_tls_server_phase_sending_flight1 = 3,          /*!< Producing SH..Finished. */
    qsc_tls_server_phase_waiting_client_certificate = 4, /*!< mTLS Certificate expected. */
    qsc_tls_server_phase_waiting_client_certificate_verify = 5,
    qsc_tls_server_phase_waiting_client_finished = 6,
    qsc_tls_server_phase_established = 7,
    qsc_tls_server_phase_closed = 8,
    qsc_tls_server_phase_failed = 9,
    qsc_tls_server_phase_waiting_end_of_early_data = 10 /*!< Reserved compatibility value; unreachable because QSC does not accept 0-RTT. */
} qsc_tls_server_state_phase;

/**
 * \brief Server-side TLS 1.3 resumption-ticket lookup callback.
 *
 * \details
 * Invoked for each PskIdentity considered for resumption. When the identity is
 * recognized, the callback copies the complete server-side ticket metadata into
 * \p ticketout. QSC validates ticket lifetime, KDF-hash compatibility, ticket age,
 * and the corresponding PSK binder before accepting the identity.
 *
 * \return true when the ticket identity was found and copied to \p ticketout.
 */
typedef bool (*qsc_tls_psk_lookup_callback)(const uint8_t* identity, size_t identitylen, qsc_tls_session_ticket* ticketout, void* state);

/**
 * \struct qsc_tls_server_certificate_identity
 * \brief A server certificate identity selectable by SNI.
 *
 * \details
 * The hostname field is a bounded, null-terminated DNS pattern. It is matched
 * against the ClientHello server_name value by the standard X.509 hostname
 * matching helper. The local certificate is copied by value and contains
 * non-owning certificate views plus copied signing key material.
 */
typedef struct qsc_tls_server_certificate_identity
{
    char hostname[QSC_TLS_MAX_HOSTNAME_SIZE + 1U];       /*!< The DNS name or wildcard pattern for this identity. */
    qsc_tls_local_certificate_config localcert;          /*!< The local certificate configuration selected for the identity. */
    bool configured;                                     /*!< Indicates that the identity slot is populated. */
} qsc_tls_server_certificate_identity;

/**
 * \struct qsc_tls_server_config
 * \brief Immutable server configuration.
 */
typedef struct qsc_tls_server_config
{
    const qsc_tls_cipher_suite* ciphersuitepreference;
    size_t ciphersuitepreferencecount;
    const qsc_tls_named_group* groupspreference;
    size_t groupspreferencecount;
    const qsc_tls_signature_scheme* sigschemepreference;
    size_t sigschemepreferencecount;
    qsc_tls_local_certificate_config localcert;
    qsc_tls_server_certificate_identity identities[QSC_TLS_MAX_SERVER_IDENTITIES]; /*!< Optional SNI-selectable server identities. */
    size_t identitycount;                                /*!< Number of valid SNI-selectable identities. */
    bool requiresni;                                     /*!< Reject ClientHello messages without a recognized SNI name when true. */
    qsc_tls_certificate_interface clientcertinterface;  /*!< For validating optional client certificate. */
    qsc_tls_client_authorization_callback clientauthcallback; /*!< Optional application authorization callback for validated mTLS client certificates. */
    void* clientauthstate;                              /*!< Caller-owned state passed to the client authorization callback. */
    bool requireclientauthorization;                    /*!< Reject validated client certificates when no authorization callback is configured or when the callback rejects the peer. */
    qsc_tls_alpn_protocols alpn;                        /*!< Configured server ALPN protocol list and policy. */
    bool requestclientauth;                             /*!< Send CertificateRequest when true. */
    bool requireclientauth;                             /*!< Reject empty Certificate when true. */
    qsc_tls_psk_lookup_callback psklookup;              /*!< Optional: enable PSK resumption when non-NULL. */
    void* psklookupstate;                               /*!< Caller-owned state forwarded to psklookup. */
    bool acceptearlydata;                               /*!< Reserved 0-RTT switch; QSC rejects true because server anti-replay acceptance is not supported. */
} qsc_tls_server_config;

/**
 * \struct qsc_tls_server_state
 * \brief Server handshake state container.
 */
typedef struct qsc_tls_server_state
{
    qsc_tls_server_config config;
    qsc_tls_qsc_x509_context x509context;                    /*!< Connection-owned mutable QSC X.509 validation context when the built-in bridge is used. */
    qsc_tls_server_state_phase phase;
    qsc_tls_cipher_suite negotiatedsuite;
    qsc_tls_hash_algorithm negotiatedhash;
    qsc_tls_named_group negotiatedgroup;
    qsc_tls_signature_scheme negotiatedsigscheme;
    uint8_t clientrandom[32U];
    uint8_t serverrandom[32U];
    uint8_t serverkeyshare[QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE];
    size_t serverkeysharelen;
    uint8_t sharedsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE];
    size_t sharedsecretlen;
    uint8_t handshakebuffer[QSC_TLS_STREAM_BUFFER_MAX_SIZE];   /*!< Inbound handshake-message reassembly buffer. */
    size_t handshakebufferlen;                                 /*!< Number of valid bytes in the handshake reassembly buffer. */
    qsc_tls_transcript_state transcript;
    qsc_tls_key_schedule_state keyschedule;
    qsc_tls_record_state readrecord;
    qsc_tls_record_state writerecord;
    qsc_tls_peer_capabilities clientcapabilities;
    qsc_tls_alert_description lastalert;
    char servername[QSC_TLS_MAX_HOSTNAME_SIZE + 1U];       /*!< The bounded ClientHello SNI hostname, when supplied. */
    size_t servernamelen;                                  /*!< The length in bytes of the stored SNI hostname. */
    bool servernamereceived;                               /*!< Indicates that a server_name extension was received. */
    bool servernameaccepted;                               /*!< Indicates that SNI matched a configured certificate identity. */
    uint8_t clientalpn[QSC_TLS_MAX_ALPN_PROTOCOLS][QSC_TLS_MAX_ALPN_SIZE];
    size_t clientalpnlens[QSC_TLS_MAX_ALPN_PROTOCOLS];
    size_t clientalpncount;
    uint8_t selectedalpn[QSC_TLS_MAX_ALPN_SIZE];
    size_t selectedalpnlen;
    bool alpnselected;
    bool helloretryrequestsent;
    qsc_tls_named_group hrrgroup;                       /*!< Group selected for HRR, valid when helloretryrequestsent==true. */
    uint8_t hrrcookie[32U];                             /*!< Stateful cookie emitted with HelloRetryRequest. */
    size_t hrrcookielen;                                /*!< Length of the active HelloRetryRequest cookie. */
    qsc_tls_transcript_state hrrtranscript;             /*!< Transcript snapshot after message_hash(ClientHello1) + HRR. */
    uint8_t clientcertificate[QSC_TLS_CERTIFICATE_MAX_SIZE]; /*!< Transient ClientHello1 storage during HRR, then DER client leaf certificate storage for CertificateVerify validation. */
    size_t clientcertificatelen;                              /*!< Length of the transient ClientHello1 or retained client leaf certificate. */
    bool clientcertificatevalidationattempted;               /*!< True after the presented client certificate chain has been submitted to the configured validation interface. */
    bool clientcertificatevalidated;                         /*!< True after the presented client certificate chain has passed validation. */
    bool clientauthenticated;                                /*!< True only after validated client certificate proof and authorization. */
    bool changecipherspecreceived;
    bool closenotifyreceived;                             /*!< True after an authenticated peer close_notify has been received. */
    bool pskaccepted;                                   /*!< True if we accepted a client PSK (resumption handshake). */
    bool pskticketagevalid;                             /*!< True when the selected ticket age matched server elapsed time within policy tolerance. */
    bool clientpskdhemodeoffered;                       /*!< True if the latest ClientHello advertised psk_dhe_ke for future resumption tickets. */
    uint16_t selectedpskidentity;                       /*!< Index of accepted PSK identity in client's offer list. */
    bool earlydataaccepted;                             /*!< Reserved compatibility field; always false because QSC does not accept 0-RTT. */
    bool earlydatadone;                                 /*!< Reserved compatibility field; always false because EndOfEarlyData is not accepted. */
    uint8_t stashedserverfinhash[QSC_TLS_HASH_MAX_SIZE]; /*!< CH..server_Finished transcript hash retained for application-key derivation. */
    size_t stashedserverfinhashlen;
    uint8_t legacy_session_id[32U];
    size_t legacy_session_id_len;
} qsc_tls_server_state;


/**
 * \brief Copy a client-certificate validation interface into a TLS server configuration.
 *
 * \details
 * This setter is the TLS-side attachment point for mutual-TLS peer validation.
 * X.509 helpers prepare the qsc_tls_certificate_interface, but do not mutate TLS
 * server state directly.
 *
 * \param config: [struct*] The server configuration to update.
 * \param iface: [struct*] Optional certificate-validation interface. Required when
 *                client authentication is requested or required.
 * \param requestclientauth: [bool] Send CertificateRequest when true.
 * \param requireclientauth: [bool] Reject an empty client Certificate when true.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_config_set_certificate_interface(qsc_tls_server_config* config,
    const qsc_tls_certificate_interface* iface, bool requestclientauth, bool requireclientauth);

/**
 * \brief Configure the server-side mTLS application authorization callback.
 *
 * \details
 * During the TLS handshake the callback is evaluated only after certificate-chain
 * validation and CertificateVerify possession proof have both succeeded. If required
 * is true, a missing callback or a callback rejection denies the peer. If required is
 * false, validated certificate possession remains the authentication boundary.
 *
 * \param config: [struct*] The server configuration to update.
 * \param callback: [function] Optional application authorization callback.
 * \param state: [void*] Caller-owned state passed to the callback.
 * \param required: [bool] Require callback acceptance when true.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_config_set_client_authorization(qsc_tls_server_config* config,
    qsc_tls_client_authorization_callback callback, void* state, bool required);

/**
 * \brief Validate and authorize a presented mTLS client certificate chain.
 *
 * \details
 * This helper performs the server-side mTLS chain validation step, prepares a
 * bounded authorization information structure, and then evaluates the configured
 * application authorization callback. CertificateVerify possession checking is
 * performed separately by the TLS handshake state machine.
 *
 * \param state: [struct*] The server handshake state.
 * \param chain: [const struct*] Client certificate chain views in leaf-first order.
 * \param chainlength: [size_t] Number of certificate views in the chain.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success when the certificate is valid and authorized.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_authorize_client_certificate(qsc_tls_server_state* state,
    const qsc_tls_certificate_view* chain, size_t chainlength);

/**
 * \brief Copy a local certificate chain and private signing key into a TLS server configuration.
 *
 * \details
 * The certificate views are copied as non-owning DER pointers. The pointed-to DER
 * buffers must remain valid for the lifetime of handshakes initialized from this
 * configuration. The private key bytes are copied into the configuration and are
 * used by the TLS CertificateVerify signing callback at handshake time.
 *
 * \param config: [struct*] The server configuration to update.
 * \param chain: [struct*] Certificate chain views in leaf-first order.
 * \param chainlength: [size_t] Number of valid chain entries.
 * \param verifyscheme: [enum] TLS CertificateVerify signature scheme.
 * \param privatekeydata: [const uint8_t*] Raw private key bytes for the signing scheme.
 * \param privatekeylen: [size_t] Length of the private key.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_config_set_local_certificate(qsc_tls_server_config* config,
    const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme,
    const uint8_t* privatekeydata, size_t privatekeylen);

/**
 * \brief Add an SNI-selectable certificate identity to a TLS server configuration.
 *
 * \param config: [struct*] The server configuration to update.
 * \param hostname: [const char*] The DNS name or wildcard pattern for this identity.
 * \param localcert: [const struct*] The local certificate configuration for the identity.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_config_add_certificate_identity(qsc_tls_server_config* config,
    const char* hostname, const qsc_tls_local_certificate_config* localcert);

/**
 * \brief Configure whether the server requires a recognized SNI hostname.
 *
 * \param config: [struct*] The server configuration to update.
 * \param required: [bool] Set to true to reject absent or unmatched SNI names.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_config_set_sni_required(qsc_tls_server_config* config, bool required);

QSC_EXPORT_API qsc_tls_status qsc_tls_server_initialize(qsc_tls_server_state* state, const qsc_tls_server_config* config);
QSC_EXPORT_API void qsc_tls_server_dispose(qsc_tls_server_state* state);

/**
 * \brief Process an inbound record and optionally produce an outbound flight.
 *
 * \details
 * Processes one complete inbound TLS record and retains incomplete Handshake messages
 * across record boundaries until the complete message is available. Fragmented
 * Handshake messages may not be interleaved with another record content type or span
 * a TLS 1.3 traffic-key transition.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_process_record(qsc_tls_server_state* state, const uint8_t* input, size_t inlen, size_t* consumed,
    uint8_t* output, size_t outlen, size_t* written);

QSC_EXPORT_API bool qsc_tls_server_is_handshake_complete(const qsc_tls_server_state* state);
QSC_EXPORT_API qsc_tls_cipher_suite qsc_tls_server_get_negotiated_cipher_suite(const qsc_tls_server_state* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
