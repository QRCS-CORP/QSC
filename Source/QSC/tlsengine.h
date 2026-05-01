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

#ifndef QSC_TLS_ENGINE_H
#define QSC_TLS_ENGINE_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"
#include "tlslimits.h"
#include "tlsstate.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlssession.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsengine.h
 * \brief TLS 1.3 record engine, connection wrapper, handshake driver, application
 *        data transport, key update, and session ticket interface.
 *
 * \details
 * This header defines the QSC TLS engine interface. The engine provides a unified
 * client/server connection handle and a bounded record-processing layer for the
 * QSC TLS 1.3 implementation. It drives handshake progression, frames encrypted
 * application records, decrypts inbound records, dispatches post-handshake
 * messages, emits and consumes session tickets, and constructs closure alerts.
 *
 * The engine does not own sockets or transport resources. Callers provide inbound
 * byte buffers and outbound scratch buffers. The engine consumes available TLS
 * records, updates the associated client or server state, and returns any
 * generated handshake, application, alert, KeyUpdate, or NewSessionTicket records
 * through caller-supplied output buffers.
 *
 * The connection object contains either a client state or server state, selected
 * by role at initialization. All keying material and transient buffers are
 * zeroized by qsc_tls_engine_dispose().
 */

 /**
  * \enum qsc_tls_role
  * \brief TLS engine endpoint role.
  *
  * \details
  * This enumeration identifies whether a qsc_tls_connection instance contains
  * client-side or server-side TLS state. The role determines which state object
  * in the connection union is active and which protocol path is used by the
  * engine functions.
  */
    typedef enum qsc_tls_role
{
    qsc_tls_role_client = 0,    /*!< The connection is operating as a TLS client. */
    qsc_tls_role_server = 1     /*!< The connection is operating as a TLS server. */
} qsc_tls_role;

/**
 * \struct qsc_tls_connection
 * \brief Unified TLS engine connection context.
 *
 * \details
 * This structure stores the active TLS endpoint state, the endpoint role, and
 * bounded scratch buffers used for inbound handshake reassembly and application
 * record processing. The union member selected by \c role is initialized by
 * either qsc_tls_engine_initialize_client() or qsc_tls_engine_initialize_server().
 *
 * The caller must treat this structure as engine-owned after initialization and
 * must not modify internal fields directly. The structure shall be disposed with
 * qsc_tls_engine_dispose() when no longer required.
 */
typedef struct qsc_tls_connection
{
    union
    {
        qsc_tls_client_state client;    /*!< Client-side TLS protocol state. */
        qsc_tls_server_state server;    /*!< Server-side TLS protocol state. */
    } state;

    qsc_tls_role role;                                          /*!< Active endpoint role. */
    uint8_t handshakebuffer[QSC_TLS_STREAM_BUFFER_MAX_SIZE];    /*!< Inbound handshake-message reassembly buffer. */
    size_t handshakebufferlen;                                  /*!< Number of valid bytes in the handshake reassembly buffer. */
    uint8_t applicationbuffer[QSC_TLS_MAX_RECORD_SIZE];         /*!< Inbound application-data scratch buffer. */
    size_t applicationbufferlen;                                /*!< Number of valid bytes in the application scratch buffer. */
} qsc_tls_connection;

/**
 * \brief Initialize a TLS engine connection as a client.
 *
 * \details
 * Initializes the supplied connection object for client-side TLS operation using the caller-provided client configuration. 
 * The function clears and prepares the connection state, selects the client role, 
 * and initializes the embedded client protocol context.
 *
 * \param connection: [qsc_tls_connection*] Pointer to the TLS engine connection context to initialize.
 * \param config: [const qsc_tls_client_config*] Pointer to the client configuration used to initialize the client protocol state.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid input or initialization failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_initialize_client(qsc_tls_connection* connection, const qsc_tls_client_config* config);

/**
 * \brief Initialize a TLS engine connection as a server.
 *
 * \details
 * Initializes the supplied connection object for server-side TLS operation using the caller-provided server configuration. 
 * The function clears and prepares the connection state, selects the server role, and initializes the embedded server protocol context.
 *
 * \param connection: [qsc_tls_connection*] Pointer to the TLS engine connection context to initialize.
 * \param config: [const qsc_tls_server_config*] Pointer to the server configuration used to initialize the server protocol state.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid input or initialization failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_initialize_server(qsc_tls_connection* connection, const qsc_tls_server_config* config);

/**
 * \brief Dispose of a TLS engine connection.
 *
 * \details
 * Releases the active TLS engine state and zeroizes transient buffers, traffic secrets, key schedules, cipher states, 
 * and other sensitive material held by the connection context.
 *
 * \param connection: [qsc_tls_connection*] Pointer to the TLS engine connection context to dispose.
 */
QSC_EXPORT_API void qsc_tls_engine_dispose(qsc_tls_connection* connection);

/**
 * \brief Advance the TLS handshake state machine.
 *
 * \details
 * Processes inbound handshake or record-layer bytes and writes any generated outbound TLS flight to the supplied output buffer. 
 * The caller should invoke this function repeatedly as network data becomes available until qsc_tls_engine_is_handshake_complete() returns true.
 *
 * The function reports how many inbound bytes were consumed and how many outbound bytes were produced. The engine does not perform socket I/O.
 *
 * \param connection: [qsc_tls_connection*] Pointer to an initialized TLS engine connection.
 * \param input: [const uint8_t*] Pointer to inbound TLS bytes. This value may be NULL when \c inlen is zero.
 * \param inlen: [size_t] Number of bytes available in \c input.
 * \param consumed: [size_t*] Pointer receiving the number of inbound bytes consumed by the engine.
 * \param output: [uint8_t*] Pointer to the caller-supplied outbound buffer.
 * \param outlen: [size_t] Size, in bytes, of the outbound buffer.
 * \param written: [size_t*] Pointer receiving the number of outbound bytes written to \c output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on malformed input, 
 * insufficient output capacity, invalid state, or cryptographic failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_handshake(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Encrypt and frame application data.
 *
 * \details
 * Encrypts plaintext application data under the active application write traffic keys and writes one or more TLS application-data records to the output buffer.
 * The handshake must be complete before application data is written.
 *
 * \param connection: [qsc_tls_connection*] Pointer to an established TLS engine connection.
 * \param input: [const uint8_t*] Pointer to plaintext application data.
 * \param inlen: [size_t] Number of plaintext bytes to encrypt.
 * \param output: [uint8_t*] Pointer to the caller-supplied output buffer.
 * \param outlen: [size_t] Size, in bytes, of the output buffer.
 * \param written: [size_t*] Pointer receiving the number of encrypted record bytes written to \c output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid state, invalid input, insufficient output capacity, or encryption failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_write_application_data(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Decrypt inbound application records.
 *
 * \details
 * Consumes inbound TLS records, decrypts application-data records under the active read traffic keys, 
 * and writes plaintext application bytes to the output buffer. 
 * The function reports the number of inbound bytes consumed and plaintext bytes written.
 *
 * \param connection: [qsc_tls_connection*] Pointer to an established TLS engine connection.
 * \param input: [const uint8_t*] Pointer to inbound TLS record bytes.
 * \param inlen: [size_t] Number of inbound bytes available in \c input.
 * \param consumed: [size_t*] Pointer receiving the number of inbound bytes consumed.
 * \param output: [uint8_t*] Pointer to the plaintext output buffer.
 * \param outlen: [size_t] Size, in bytes, of the plaintext output buffer.
 * \param written: [size_t*] Pointer receiving the number of plaintext bytes written to \c output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid state, 
 * malformed records, authentication failure, insufficient output capacity, or closure alert processing.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_read_application_data(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed,
    uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Decrypt inbound records and process post-handshake messages.
 *
 * \details
 * Consumes inbound TLS records, decrypts application-data records, and dispatches supported post-handshake handshake messages such as KeyUpdate. 
 * If an inbound KeyUpdate requests a reciprocal update, the generated response record is written to \c responseoutput when a response buffer is supplied.
 *
 * \param connection: [qsc_tls_connection*] Pointer to an established TLS engine connection.
 * \param input: [const uint8_t*] Pointer to inbound TLS record bytes.
 * \param inlen: [size_t] Number of inbound bytes available in \c input.
 * \param consumed: [size_t*] Pointer receiving the number of inbound bytes consumed.
 * \param output: [uint8_t*] Pointer to the plaintext application output buffer.
 * \param outlen: [size_t] Size, in bytes, of the plaintext output buffer.
 * \param written: [size_t*] Pointer receiving the number of plaintext bytes written to \c output.
 * \param responseoutput: [uint8_t*] Optional pointer to a buffer receiving any automatically generated post-handshake response records.
 * \param responseoutlen: [size_t] Size, in bytes, of \c responseoutput when non-NULL.
 * \param responsewritten: [size_t*] Optional pointer receiving the number of bytes written to \c responseoutput.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid state, malformed records, 
 * authentication failure, unsupported post-handshake input, or insufficient buffer capacity.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_read_application_data_ex(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed,
    uint8_t* output, size_t outlen, size_t* written, uint8_t* responseoutput, size_t responseoutlen, size_t* responsewritten);

/**
 * \brief Initiate a TLS 1.3 KeyUpdate operation.
 *
 * \details
 * Builds and encrypts a KeyUpdate post-handshake record using the active application write traffic keys, advances the local write traffic secret, 
 * and writes the resulting record to the caller-supplied output buffer.
 *
 * \param connection: [qsc_tls_connection*] Pointer to an established TLS engine connection.
 * \param requestpeerupdate: [bool] If true, request that the peer also update its sending keys.
 * \param output: [uint8_t*] Pointer to the output buffer receiving the encrypted KeyUpdate record.
 * \param outlen: [size_t] Size, in bytes, of the output buffer.
 * \param written: [size_t*] Pointer receiving the number of bytes written to \c output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid state, insufficient output capacity, or cryptographic failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_request_key_update(qsc_tls_connection* connection, bool requestpeerupdate, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Emit a TLS 1.3 NewSessionTicket record.
 *
 * \details
 * Builds a NewSessionTicket handshake message for a server-role connection in the established state. 
 * The function generates the ticket nonce and ticket identifier, derives the per-ticket resumption secret from the resumption_master_secret, 
 * encrypts the handshake message under the server application write traffic keys, and returns the generated ticket metadata to the caller.
 *
 * \param connection: [qsc_tls_connection*] Pointer to a server-role TLS engine connection in the established state.
 * \param lifetime_seconds: [uint32_t] Ticket lifetime value, in seconds, to advertise to the client.
 * \param output: [uint8_t*] Pointer to the output buffer receiving the encrypted NewSessionTicket record.
 * \param outlen: [size_t] Size, in bytes, of the output buffer.
 * \param written: [size_t*] Pointer receiving the number of bytes written to \c output.
 * \param ticketout: [qsc_tls_session_ticket*] Pointer receiving the generated ticket metadata, including nonce, ticket value, 
 * lifetime, age-add value, cipher suite, and derived resumption secret.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid role, invalid state, 
 * insufficient output capacity, or cryptographic failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_emit_session_ticket(qsc_tls_connection* connection, uint32_t lifetime_seconds, uint8_t* output,
    size_t outlen, size_t* written, qsc_tls_session_ticket* ticketout);

/**
 * \brief Consume a TLS 1.3 NewSessionTicket record.
 *
 * \details
 * Decrypts an inbound post-handshake NewSessionTicket record for a client-role connection, parses the ticket body, 
 * derives the resumption PSK from the client's resumption_master_secret and the ticket nonce, and writes the parsed ticket metadata to \c ticketout. 
 * The caller may retain the populated ticket structure for later 0-RTT or 1-RTT resumption.
 *
 * \param connection: [qsc_tls_connection*] Pointer to a client-role TLS engine connection in the established state.
 * \param input: [const uint8_t*] Pointer to the encrypted NewSessionTicket record.
 * \param inlen: [size_t] Number of inbound bytes available in \c input.
 * \param consumed: [size_t*] Pointer receiving the number of inbound bytes consumed.
 * \param ticketout: [qsc_tls_session_ticket*] Pointer receiving the parsed and derived ticket metadata.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid role, 
 * invalid state, malformed input, authentication failure, or ticket derivation failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_consume_session_ticket(qsc_tls_connection* connection, const uint8_t* input, size_t inlen,
    size_t* consumed, qsc_tls_session_ticket* ticketout);

/**
 * \brief Build an encrypted close_notify alert record.
 *
 * \details
 * Constructs a TLS closure alert for the active connection and writes the encrypted close_notify record to the caller-supplied output buffer. 
 * The caller is responsible for transmitting the generated record and then closing or draining the underlying transport according to its own I/O policy.
 *
 * \param connection: [qsc_tls_connection*] Pointer to an initialized TLS engine connection.
 * \param output: [uint8_t*] Pointer to the output buffer receiving the close_notify record.
 * \param outlen: [size_t] Size, in bytes, of the output buffer.
 * \param written: [size_t*] Pointer receiving the number of bytes written to \c output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, or an error status on invalid state, insufficient output capacity, or encryption failure.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_engine_close(qsc_tls_connection* connection, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Test whether the TLS handshake is complete.
 *
 * \details
 * Returns the handshake-completion status of the active client or server state.
 * When this function returns true, the connection may send and receive protected application data.
 *
 * \param connection: [const qsc_tls_connection*] Pointer to an initialized TLS engine connection.
 *
 * \return [bool] Returns true when the handshake is complete; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_tls_engine_is_handshake_complete(const qsc_tls_connection* connection);

QSC_CPLUSPLUS_ENABLED_END

#endif
