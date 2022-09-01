/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

#ifndef QSC_SOCKET_H
#define QSC_SOCKET_H

/*
* \file socket.h
* \brief TCP/IP function constants and structures
*/

#include "common.h"
#include "socketflags.h"

/*!
\def QSC_SOCKET_ADDRESS_MAX_LENGTH
* The maximum string length of an address
*/
#define QSC_SOCKET_ADDRESS_MAX_LENGTH 65

/*!
\def QSC_SOCKET_MAX_CONN
* The maximum number of simultaneous connections
*/
#define QSC_SOCKET_MAX_CONN 0x7FFFFFFFL

/*!
\def QSC_SOCKET_RET_ERROR
* The base socket error flag
*/
#define QSC_SOCKET_RET_ERROR -1

/*!
\def QSC_SOCKET_RET_SUCCESS
* The base socket success flag
*/
#define QSC_SOCKET_RET_SUCCESS 0

/*!
\def QSC_SOCKET_TERMINATOR_SIZE
* The length of the message string terminator character
*/
#define QSC_SOCKET_TERMINATOR_SIZE 1

/*!
\def QSC_SOCKET_TIMEOUT_MSEC
* The default number of seconds to wait for a connection
*/
#define QSC_SOCKET_TIMEOUT_MSEC 10000

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
QSC_EXPORT_API typedef struct qsc_socket
{
	socket_t connection;							/*!< A socket connection pointer */
	int8_t address[QSC_SOCKET_ADDRESS_MAX_LENGTH];	/*!< The sockets string address */
	uint32_t instance;								/*!< The sockets instance count */
	uint16_t port;									/*!< The sockets port number */
	qsc_socket_address_families address_family;		/*!< The sockets address family type */
	qsc_socket_states connection_status;			/*!< The connection state type */
	qsc_socket_protocols socket_protocol;			/*!< The socket protocol type */
	qsc_socket_transports socket_transport;			/*!< The socket transport type */
} qsc_socket;

#endif
