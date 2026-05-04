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

#ifndef QSC_TLS_CLIENT_H
#define QSC_TLS_CLIENT_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"
#include "tlslimits.h"
#include "tlsstate.h"
#include "tlscert.h"
#include "tlsgroups.h"
#include "tlskeyschedule.h"
#include "tlsrecord.h"
#include "tlssession.h"
#include "tlstranscript.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsclient.h
 * \brief TLS 1.3 client handshake state machine declarations.
 *
 * \details
 *  tlsclient.c - TLS 1.3 client handshake state machine.
 *
 * This MVP covers the 1-RTT non-PSK, non-HRR path:
 *    send_hello            -> phase_waiting_server_hello
 *    process ServerHello   -> install handshake keys, phase_waiting_encrypted_extensions
 *    process EncryptedExt  -> phase_waiting_certificate
 *    process Certificate   -> phase_waiting_certificate_verify
 *    process CertVerify    -> phase_waiting_finished
 *    process Finished      -> derive app keys, emit client Finished, phase_established
 *
 * HRR and PSK paths are not implemented in this MVP. Unsupported flows
 * return qsc_tls_status_not_supported with the state set to failed.
 * 
 * This header declares the client-side handshake driver used by the TLS engine.
 * The current implementation is centered on the TLS 1.3 1-RTT certificate-authenticated
 * path. It tracks transcript state, negotiated algorithms, key schedule progression,
 * and the read/write record states required to transition from the handshake epoch to
 * application traffic.
 *
 * The client state does not own application transport resources. Callers supply encoded
 * record buffers to the process function and receive any outbound record material through
 * the provided output buffer.
 */

/**
 * \enum qsc_tls_client_phase
 * \brief Enumerates the major phases of the TLS 1.3 client handshake.
 */
typedef enum qsc_tls_client_phase
{
    qsc_tls_client_phase_initial = 0,                          /*!< State has been initialized and no ClientHello has been emitted. */
    qsc_tls_client_phase_waiting_server_hello = 1,            /*!< ClientHello has been sent and the client is awaiting ServerHello. */
    qsc_tls_client_phase_waiting_encrypted_extensions = 2,    /*!< Handshake keys are installed and the client is awaiting EncryptedExtensions. */
    qsc_tls_client_phase_waiting_certificate = 3,             /*!< The client is awaiting the server Certificate message. */
    qsc_tls_client_phase_waiting_certificate_verify = 4,      /*!< The client is awaiting the server CertificateVerify message. */
    qsc_tls_client_phase_waiting_finished = 5,                /*!< The client is awaiting the server Finished message. */
    qsc_tls_client_phase_established = 6,                     /*!< The handshake completed successfully and application traffic keys are active. */
    qsc_tls_client_phase_closed = 7,                          /*!< The connection has been closed locally or by peer notification. */
    qsc_tls_client_phase_failed = 8                           /*!< A fatal error occurred and the handshake or connection failed. */
} qsc_tls_client_phase;

/**
 * \struct qsc_tls_client_config
 * \brief Stores the static client policy used to initialize a TLS client state.
 */
typedef struct qsc_tls_client_config
{
    const qsc_tls_cipher_suite* ciphersuites;                 /*!< Ordered list of cipher suites offered by the client. */
    size_t ciphersuitecount;                                  /*!< Number of valid entries in the ciphersuites array. */
    const qsc_tls_named_group* groups;                        /*!< Ordered list of supported key-exchange groups. */
    size_t groupcount;                                        /*!< Number of valid entries in the groups array. */
    const qsc_tls_signature_scheme* sigschemes;               /*!< Ordered list of supported signature schemes. */
    size_t sigschemecount;                                    /*!< Number of valid entries in the sigschemes array. */
    const char* hostname;                                     /*!< Optional server name indication and certificate name-check target. */
    qsc_tls_certificate_interface certinterface;              /*!< Certificate verification and certificate-store callback interface. */
    const qsc_tls_session_ticket* offeredticket;              /*!< Optional PSK ticket to offer for resumption; NULL = fresh handshake. */
    bool enableearlydata;                                     /*!< When offeredticket != NULL, also offer early_data (0-RTT). */
} qsc_tls_client_config;

/**
 * \struct qsc_tls_client_state
 * \brief Stores the active TLS 1.3 client handshake and record state.
 */
typedef struct qsc_tls_client_state
{
    qsc_tls_client_config config;                             /*!< Snapshot of the client configuration supplied at initialization. */
    qsc_tls_client_phase phase;                               /*!< Current handshake phase. */
    qsc_tls_cipher_suite negotiatedsuite;                     /*!< Negotiated cipher suite selected by the server. */
    qsc_tls_hash_algorithm negotiatedhash;                    /*!< Transcript and HKDF hash derived from the negotiated suite. */
    qsc_tls_named_group negotiatedgroup;                      /*!< Negotiated key-exchange group used for the active handshake. */
    qsc_tls_signature_scheme negotiatedsigscheme;             /*!< Negotiated CertificateVerify signature scheme. */
    uint8_t clientrandom[32U];                                /*!< ClientHello random value. */
    uint8_t serverrandom[32U];                                /*!< ServerHello random value. */
    qsc_tls_transcript_state transcript;                      /*!< Active transcript hash state. */
    qsc_tls_key_schedule_state keyschedule;                   /*!< TLS 1.3 key schedule state for handshake and application epochs. */
    qsc_tls_record_state readrecord;                          /*!< Active inbound record protection state. */
    qsc_tls_record_state writerecord;                         /*!< Active outbound record protection state. */
    qsc_tls_key_exchange_state keyexchange;                   /*!< Local ephemeral key-exchange state for the offered key share. */
    qsc_tls_peer_capabilities peercapabilities;               /*!< Capabilities advertised by the peer and parsed from extensions. */
    qsc_tls_alert_description lastalert;                      /*!< Most recent alert description observed or generated by the client. */
    bool serverauthenticated;                                 /*!< True once the server certificate path and CertificateVerify have been validated. */
    bool changecipherspecreceived;                            /*!< True once the compatibility ChangeCipherSpec record has been observed. */
    bool helloretryrequestconsumed;                           /*!< True once a HelloRetryRequest path has been consumed for this handshake. */
    bool pskoffered;                                          /*!< True if a pre_shared_key extension was offered in ClientHello. */
    bool pskaccepted;                                         /*!< True if the server selected our PSK (ServerHello pre_shared_key). */
    bool earlydataoffered;                                    /*!< True if early_data extension was emitted in ClientHello. */
    bool earlydataaccepted;                                   /*!< True if server confirmed early_data in EncryptedExtensions. */
} qsc_tls_client_state;

/**
 * \brief Initialize a TLS client handshake state.
 *
 * \details
 * Clears the supplied state object, copies the client policy, selects the initial
 * handshake phase, and prepares the client for ClientHello emission. The configuration
 * arrays referenced by \p config must remain valid for the lifetime of the client state.
 *
 * \param state: [struct*] The client state to initialize.
 * \param config: [const struct*] The client configuration and algorithm policy.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */

/**
 * \brief Copy a certificate-validation interface into a TLS client configuration.
 *
 * \details
 * This setter is the TLS-side attachment point for certificate validation. X.509
 * helpers prepare the qsc_tls_certificate_interface, but do not mutate TLS state
 * objects directly. The hostname pointer is borrowed from the caller and must remain
 * valid for the lifetime of configurations initialized from this object.
 *
 * \param config: [struct*] The client configuration to update.
 * \param iface: [struct*] The certificate-validation interface to copy.
 * \param hostname: [const char*] Optional server hostname for SNI and certificate validation.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_config_set_certificate_interface(qsc_tls_client_config* config,
    const qsc_tls_certificate_interface* iface, const char* hostname);

QSC_EXPORT_API qsc_tls_status qsc_tls_client_initialize(qsc_tls_client_state* state, const qsc_tls_client_config* config);

/**
 * \brief Dispose of a TLS client handshake state.
 *
 * \details
 * Clears record keys, transcript state, and any retained handshake material.
 * The structure is left in a fully erased state.
 *
 * \param state: [struct*] The client state to clear.
 */
QSC_EXPORT_API void qsc_tls_client_dispose(qsc_tls_client_state* state);

/**
 * \brief Build the initial ClientHello flight.
 *
 * \details
 * Encodes a ClientHello record according to the configured cipher suites, groups,
 * signature schemes, and hostname. On success the client advances into the phase that
 * awaits ServerHello.
 *
 * \param state: [struct*] The active client handshake state.
 * \param output: [uint8_t*] The destination output buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written to output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_send_hello(qsc_tls_client_state* state, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Process an inbound TLS record and optionally emit a response flight.
 *
 * \details
 * Consumes one or more bytes of inbound TLS record material, advances the client
 * handshake state machine, and emits any required response records into \p output.
 * The function is used by the engine to process ServerHello, encrypted handshake
 * messages, alerts, and post-transition client Finished output.
 *
 * \param state: [struct*] The active client handshake state.
 * \param input: [const uint8_t*] The inbound record bytes.
 * \param inlen: [size_t] The number of inbound bytes available in input.
 * \param consumed: [size_t*] Receives the number of inbound bytes consumed.
 * \param output: [uint8_t*] The destination buffer for any outbound response records.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written to output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_client_process_record(qsc_tls_client_state* state, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Determine whether the client handshake is complete.
 *
 * \param state: [const struct*] The client state to query.
 *
 * \return [bool] Returns true if the client reached the established phase.
 */
QSC_EXPORT_API bool qsc_tls_client_is_handshake_complete(const qsc_tls_client_state* state);

/**
 * \brief Get the cipher suite negotiated by the server.
 *
 * \param state: [const struct*] The client state to query.
 *
 * \return [qsc_tls_cipher_suite] Returns the negotiated cipher suite, or an unspecified value if negotiation has not completed.
 */
QSC_EXPORT_API qsc_tls_cipher_suite qsc_tls_client_get_negotiated_cipher_suite(const qsc_tls_client_state* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
