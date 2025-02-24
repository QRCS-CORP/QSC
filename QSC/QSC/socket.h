/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_SOCKET_H
#define QSC_SOCKET_H

/**
* \file socket.h
* \brief TCP/IP function constants and structures
*/

#include "common.h"
#include "socketflags.h"

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
#define QSC_SOCKET_TERMINATOR_SIZE 1ULL

/*!
\def QSC_SOCKET_TIMEOUT_MSEC
* The default number of seconds to wait for a connection
*/
#define QSC_SOCKET_TIMEOUT_MSEC 10000ULL

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
	static const socket_t QSC_UNINITIALIZED_SOCKET = (uintptr_t)~0;
#else
	static const int32_t QSC_UNINITIALIZED_SOCKET = -1;
#endif

/*! \struct qsc_socket
* \brief The socket instance structure
*/
QSC_EXPORT_API typedef struct
{
	socket_t connection;							/*!< A socket connection pointer */
	int8_t address[QSC_SOCKET_ADDRESS_MAX_SIZE];	/*!< The sockets string address */
	uint32_t instance;								/*!< The sockets instance count */
	uint16_t port;									/*!< The sockets port number */
	qsc_socket_address_families address_family;		/*!< The sockets address family type */
	qsc_socket_states connection_status;			/*!< The connection state type */
	qsc_socket_protocols socket_protocol;			/*!< The socket protocol type */
	qsc_socket_transports socket_transport;			/*!< The socket transport type */
} qsc_socket;

#endif
