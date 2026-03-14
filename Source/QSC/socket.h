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

#ifndef QSC_SOCKET_H
#define QSC_SOCKET_H

#include "qsccommon.h"
#include "socketflags.h"

QSC_CPLUSPLUS_ENABLED_START

/**
* \file socket.h
* \brief TCP/IP function constants and structures
*/

/*!
\def QSC_SOCKET_ADDRESS_MAX_SIZE
* The maximum string length of an address
*/
#define QSC_SOCKET_ADDRESS_MAX_SIZE 65ULL

/*!
\def QSC_SOCKET_MAX_CONN
* The maximum number of simultaneous connections
*/
#define QSC_SOCKET_MAX_CONN 0x7FFFFFFFL

/*!
\def QSC_SOCKET_RET_ERROR
* The base socket error flag
*/
#define QSC_SOCKET_RET_ERROR -1LL

/*!
\def QSC_SOCKET_RET_SUCCESS
* The base socket success flag
*/
#define QSC_SOCKET_RET_SUCCESS 0LL

/*!
\def QSC_SOCKET_TERMINATOR_SIZE
* The length of the message string terminator character
*/
#define QSC_SOCKET_TERMINATOR_SIZE 1U

/*!
\def QSC_SOCKET_TIMEOUT_MSEC
* The default number of seconds to wait for a connection
*/
#define QSC_SOCKET_TIMEOUT_MSEC 10000U

#if defined(QSC_SYSTEM_OS_WINDOWS)
/*!
\typedef socklen_t
* The socket length type
*/
typedef int32_t socklen_t;
#endif

/*!
\typedef socket_t
* The socket instance handle
*/
#if defined(QSC_SYSTEM_OS_WINDOWS)
typedef uintptr_t socket_t;
#else
typedef int32_t socket_t;
#endif

/*!
\const QSC_UNINITIALIZED_SOCKET
* An uninitialized socket handle
*/
#if defined(QSC_SYSTEM_OS_WINDOWS)
#   define QSC_UNINITIALIZED_SOCKET ((socket_t)(uintptr_t)~0U)
#else
#   define QSC_UNINITIALIZED_SOCKET ((socket_t)-1)
#endif

/*! \struct qsc_socket
* \brief The socket instance structure
*/
QSC_EXPORT_API typedef struct
{
	socket_t connection;							/*!< A socket connection pointer */
	char address[QSC_SOCKET_ADDRESS_MAX_SIZE];		/*!< The sockets string address */
	uint32_t instance;								/*!< The sockets instance count */
	uint16_t port;									/*!< The sockets port number */
	qsc_socket_address_families address_family;		/*!< The sockets address family type */
	qsc_socket_states connection_status;			/*!< The connection state type */
	qsc_socket_protocols socket_protocol;			/*!< The socket protocol type */
	qsc_socket_transports socket_transport;			/*!< The socket transport type */
} qsc_socket;

QSC_CPLUSPLUS_ENABLED_END

#endif
