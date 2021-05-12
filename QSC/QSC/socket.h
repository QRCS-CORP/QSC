/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* A network sockets class.
* Written by John G. Underhill
* Updated on March 30, 2021
* Contact: develop@vtdev.com */

#ifndef QSC_SOCKET_H
#define QSC_SOCKET_H

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
\def QSC_SOCKET_TIMEOUT_MSEC
* The default number of seconds to wait for a connection
*/
#define QSC_SOCKET_TIMEOUT_MSEC 10000

/*!
\typedef socklen_t
* The socket length type
*/
typedef int32_t socklen_t;

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
* An unitialized socket handle
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
	socket_t connection;						/*!< A socket conection pointer */
	int8_t address[QSC_SOCKET_ADDRESS_MAX_LENGTH];	/*!< The sockets string address */
	uint32_t instance;							/*!< The sockets instance count */
	uint16_t port;								/*!< The sockets port number */
	qsc_socket_address_families address_family;	/*!< The sockets address family type */
	qsc_socket_states connection_status;		/*!< The connection state type */
	qsc_socket_protocols socket_protocol;		/*!< The socket protocol type */
	qsc_socket_transports socket_transport;		/*!< The socket transport type */
} qsc_socket;

#endif