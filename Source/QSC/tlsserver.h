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
    qsc_tls_server_phase_waiting_end_of_early_data = 10 /*!< 0-RTT accepted; waiting EndOfEarlyData before client Finished. */
} qsc_tls_server_state_phase;

/**
 * \brief Server-side PSK lookup callback.
 *
 * \details
 * Invoked for each PskIdentity offered by a client. Must fill psk_out with
 * the expected resumption PSK bytes (previously derived server-side at NST
 * emission time and keyed on the ticket opaque bytes) if recognized.
 *
 * \return true when the PSK for this identity was found and returned.
 */
typedef bool (*qsc_tls_psk_lookup_callback)(const uint8_t* identity, size_t identitylen,
    uint8_t* psk_out, size_t pskcap, size_t* psk_len_out,
    qsc_tls_cipher_suite* suite_out, uint32_t* max_early_data_out, void* state);

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
    qsc_tls_certificate_interface clientcertinterface;  /*!< For validating optional client certificate. */
    bool requestclientauth;                             /*!< Send CertificateRequest when true. */
    bool requireclientauth;                             /*!< Reject empty Certificate when true. */
    qsc_tls_psk_lookup_callback psklookup;              /*!< Optional: enable PSK resumption when non-NULL. */
    void* psklookupstate;                               /*!< Caller-owned state forwarded to psklookup. */
    bool acceptearlydata;                               /*!< When true and client offers early_data, server may accept it. */
} qsc_tls_server_config;

/**
 * \struct qsc_tls_server_state
 * \brief Server handshake state container.
 */
typedef struct qsc_tls_server_state
{
    qsc_tls_server_config config;
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
    qsc_tls_transcript_state transcript;
    qsc_tls_key_schedule_state keyschedule;
    qsc_tls_record_state readrecord;
    qsc_tls_record_state writerecord;
    qsc_tls_peer_capabilities clientcapabilities;
    qsc_tls_alert_description lastalert;
    bool helloretryrequestsent;
    qsc_tls_named_group hrrgroup;                       /*!< Group selected for HRR, valid when helloretryrequestsent==true. */
    bool clientauthenticated;
    bool changecipherspecreceived;
    bool pskaccepted;                                   /*!< True if we accepted a client PSK (resumption handshake). */
    uint16_t selectedpskidentity;                       /*!< Index of accepted PSK identity in client's offer list. */
    bool earlydataaccepted;                             /*!< True if we signaled acceptance of early_data. */
    bool earlydatadone;                                 /*!< True after EndOfEarlyData received; switch read key to handshake. */
    uint8_t stashedserverfinhash[QSC_TLS_HASH_MAX_SIZE]; /*!< CH..server_Finished transcript hash; set on 0-RTT accept for app-key derivation. */
    size_t stashedserverfinhashlen;
    /* TODO: FIELDS ADDED */
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

QSC_EXPORT_API qsc_tls_status qsc_tls_server_initialize(qsc_tls_server_state* state, const qsc_tls_server_config* config);
QSC_EXPORT_API void qsc_tls_server_dispose(qsc_tls_server_state* state);

/**
 * \brief Process an inbound record and optionally produce an outbound flight.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_server_process_record(qsc_tls_server_state* state, const uint8_t* input, size_t inlen, size_t* consumed,
    uint8_t* output, size_t outlen, size_t* written);

QSC_EXPORT_API bool qsc_tls_server_is_handshake_complete(const qsc_tls_server_state* state);
QSC_EXPORT_API qsc_tls_cipher_suite qsc_tls_server_get_negotiated_cipher_suite(const qsc_tls_server_state* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
