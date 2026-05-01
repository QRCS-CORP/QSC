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

#ifndef QSC_TLS_IO_H
#define QSC_TLS_IO_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlsengine.h"
#include "socket.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsio.h
 * \brief Blocking socket adapter around qsc_tls_connection.
 *
 * \details
 * This header provides a minimal transport adapter that binds a qsc_tls_connection to a
 * qsc_socket and drives the TLS engine using blocking send and receive calls. The adapter
 * does not allocate or own the engine or the socket. It only stores non-owning pointers and
 * marshals bytes between the engine record interface and the socket API.
 */

/**
 * \struct qsc_tls_io_connection
 * \brief Stores the non-owning association between a TLS engine and a socket.
 */
typedef struct qsc_tls_io_connection
{
    qsc_tls_connection* engine;      /*!< The attached TLS engine instance. */
    qsc_socket* socket;              /*!< The attached blocking socket. */
} qsc_tls_io_connection;

/**
 * \brief Attach a TLS engine and socket to an I/O adapter.
 *
 * \param io: [struct*] The I/O adapter to initialize.
 * \param engine: [struct*] The TLS engine to attach.
 * \param socket: [struct*] The blocking socket to attach.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_io_attach(qsc_tls_io_connection* io, qsc_tls_connection* engine, qsc_socket* socket);

/**
 * \brief Drive the TLS handshake to completion over the attached blocking socket.
 *
 * \details
 * Repeatedly calls the TLS engine handshake function, flushing any produced outbound flight
 * to the socket and receiving additional input whenever the engine requires more record bytes.
 * The call returns when the handshake completes or a fatal error occurs.
 *
 * \param io: [struct*] The attached I/O adapter.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_io_handshake(qsc_tls_io_connection* io);

/**
 * \brief Encrypt and send application data over the attached socket.
 *
 * \param io: [struct*] The attached I/O adapter.
 * \param input: [const uint8_t*] The plaintext application data.
 * \param inlen: [size_t] The plaintext length in bytes.
 * \param written: [size_t*] Receives the number of plaintext bytes accepted for transmission.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_io_send(qsc_tls_io_connection* io, const uint8_t* input, size_t inlen, size_t* written);

/**
 * \brief Receive and decrypt application data from the attached socket.
 *
 * \details
 * Receives socket bytes until at least one protected TLS record has been consumed and
 * any decrypted application payload has been written to the caller-supplied buffer.
 *
 * \param io: [struct*] The attached I/O adapter.
 * \param output: [uint8_t*] The destination buffer for decrypted application data.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param read: [size_t*] Receives the number of plaintext bytes written to output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_io_receive(qsc_tls_io_connection* io, uint8_t* output, size_t outlen, size_t* read);

/**
 * \brief Emit and send a close_notify alert for the attached connection.
 *
 * \param io: [struct*] The attached I/O adapter.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_io_shutdown(qsc_tls_io_connection* io);

QSC_CPLUSPLUS_ENABLED_END

#endif
