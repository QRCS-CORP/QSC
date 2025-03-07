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

#ifndef QSC_SOCKETSERVER_H
#define QSC_SOCKETSERVER_H

#include "common.h"
#include "socketbase.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file socketserver.h
 * \brief The socket server function definitions.
 *
 * \details
 * This header provides the public API for socket server operations. It includes functions
 * to initialize a server socket, listen for incoming connections (both synchronously and asynchronously),
 * accept incoming connections, send and receive data, and manage socket options. The API supports
 * both IPv4 and IPv6 addressing and is designed for use in multi-threaded server applications.
 *
 * \code
 * // Example usage: Initialize a server socket and accept a connection.
 * qsc_socket server, client;
 * qsc_socket_server_initialize(&server);
 *
 * // Listen on the server socket for incoming connections on IPv4 at port 8080.
 * if (qsc_socket_server_listen_ipv4(&server, &client, &ipv4_address, 8080) != QSC_SOCKET_RET_SUCCESS)
 * {
 *     // Handle connection error.
 * }
 *
 * // Alternatively, to accept connections asynchronously:
 * qsc_socket_server_async_accept_state asyncState;
 * asyncState.source = &server;
 * asyncState.callback = qsc_socket_server_accept_callback;
 * asyncState.error = qsc_socket_server_error_callback;
 * 
 * if (qsc_socket_server_listen_async_ipv4(&asyncState, &ipv4_address, 8080) != QSC_SOCKET_RET_SUCCESS)
 * {
 *     // Handle asynchronous connection error.
 * }
 * \endcode
 *
 * \section socketserver_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page">Windows Sockets (Winsock) Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html">POSIX Sockets Documentation</a>
 */

/*!
* \def QSC_SOCKET_SERVER_LISTEN_BACKLOG
* \brief The socket connection backlog, default is 128
*/
#define QSC_SOCKET_SERVER_LISTEN_BACKLOG 128ULL

/*!
* \def QSC_SOCKET_SERVER_MAX_THREADS
* \brief The maximum number of active threads
*/
#define QSC_SOCKET_SERVER_MAX_THREADS 1024ULL

/*** Structures ***/

/*! \struct qsc_socket_server_accept_result
* \brief The async socket result structure.
*/
typedef struct
{
	qsc_socket target;	/*!< The accepted socket */
} qsc_socket_server_accept_result;

/*! \struct qsc_socket_server_async_accept_state
* \brief The async listener-accept state structure.
* The structure contains a pointer to the listener socket,
* and pointers to a callback and error functions.
* The callback function returns a populated qsc_socket_server_accept_result structure.
* The error function returns the listener socket and an qsc_socket_exceptions error code.
*/
typedef struct
{
	qsc_socket* source;													/*!< A pointer to the listener socket */
	void (*callback)(qsc_socket_server_accept_result* result);			/*!< A pointer to a callback function */
	void (*error)(qsc_socket* sock, qsc_socket_exceptions exception);	/*!< A pointer to an error function */
} qsc_socket_server_async_accept_state;

/*** Function Prototypes ***/

/**
* \brief The socket server accept callback prototype
*
* \param ares:		[qsc_socket_server_accept_result*] A pointer to the server accept result structure
*/
QSC_EXPORT_API void qsc_socket_server_accept_callback(qsc_socket_server_accept_result* ares);

/**
* \brief The socket server error callback prototype
*
* \param source:	[const qsc_socket*] A pointer to the initialized socket
* \param error:		[qsc_socket_exceptions] The socket exception
*/
QSC_EXPORT_API void qsc_socket_server_error_callback(const qsc_socket* source, qsc_socket_exceptions error);

/*** Accessors ***/

/**
* \brief Get the sockets address family, IPv4 or IPv6
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
*
* \return			[qsc_socket_address_families] The socket address family
*/
QSC_EXPORT_API qsc_socket_address_families qsc_socket_server_address_family(const qsc_socket* sock);

/**
* \brief Get the socket protocol type
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
*
* \return			[qsc_socket_protocols] The socket protocol type
*/
QSC_EXPORT_API qsc_socket_protocols qsc_socket_server_socket_protocol(const qsc_socket* sock);

/**
* \brief Get the socket transport type
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
*
* \return			[qsc_socket_transports] The socket transport type
*/
QSC_EXPORT_API qsc_socket_transports qsc_socket_server_socket_transport(const qsc_socket* sock);

/**
* \brief Shut down channels and close the socket
*
* \param sock:		[qsc_socket*] A pointer to the socket structure
*/
QSC_EXPORT_API void qsc_socket_server_close_socket(qsc_socket* sock);

/**
* \brief Initialize the server socket
*
* \param sock:		[qsc_socket*] A pointer to the socket structure
*/
QSC_EXPORT_API void qsc_socket_server_initialize(qsc_socket* sock);

/**
* \brief Places the source socket in a blocking listening state, and waits for a connection.
* Returns a single socket, and must be called to listen for each new connection.
*
* \param source:	[qsc_socket*] The listening socket
* \param target:	[qsc_socket*] The accepted remote socket
* \param address:	[const char*] The servers address
* \param port:		[uint16_t] The servers port number
* \param family:	[qsc_socket_address_families] The socket address family
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen(qsc_socket* source, qsc_socket* target, const char* address, uint16_t port, qsc_socket_address_families family);

/**
* \brief Places the source IPv4 socket in a blocking listening state, and waits for a connection.
* Returns a single socket, and must be called to listen for each new connection.
*
* \param source:	[qsc_socket*] The listening socket
* \param target:	[qsc_socket*] The accepted remote socket
* \param address:	[const qsc_ipinfo_ipv4_address*] The servers IPv4 address
* \param port:		[uint16_t] The servers port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_ipv4(qsc_socket* source, qsc_socket* target, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Places the source IPv6 socket in a blocking listening state, and waits for a connection.
* Returns a single socket, and must be called to listen for each new connection.
*
* \param source:	[qsc_socket*] The listening socket
* \param target:	[qsc_socket*] The accepted remote socket
* \param address:	[const qsc_ipinfo_ipv6_address*] The servers IPv6 address
* \param port:		[uint16_t] The servers port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_ipv6(qsc_socket* source, qsc_socket* target, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Places the socket in an asynchronous listening state
*
* \param state:		[qsc_socket_server_async_accept_state*] The asynchronous server state
* \param address:	[const char*] The servers address
* \param port:		[uint16_t] The servers port number
* \param family:	[qsc_socket_address_families] The socket address family
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_async(qsc_socket_server_async_accept_state* state, const char* address, uint16_t port, qsc_socket_address_families family);

/**
* \brief Places the IPv4 socket in an asynchronous listening state
*
* \param state:		[qsc_socket_server_async_accept_state*] The asynchronous server state
* \param address:	[const qsc_ipinfo_ipv4_address*] The servers address
* \param port:		[uint16_t] The servers port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_async_ipv4(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Places the IPv6 socket in an asynchronous listening state
*
* \param state:		[qsc_socket_server_async_accept_state*] The asynchronous server state
* \param address:	[const qsc_ipinfo_ipv6_address*] The servers address
* \param port:		[uint16_t] The servers port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_async_ipv6(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Send an option command to the socket.
* Options that use a boolean are format: 0=false, 1=true.
*
* \param sock:		[const qsc_socket*] The socket instance
* \param level:		[qsc_socket_protocols] The level at which the option is assigned
* \param option:	[qsc_socket_options] The option command to send
* \param optval:	[int32_t] The value of the option command
*/
QSC_EXPORT_API void qsc_socket_server_set_options(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval);

/**
* \brief Shut down the server
*
* \param sock:		[qsc_socket*] The listening socket
*/
QSC_EXPORT_API void qsc_socket_server_shut_down(qsc_socket* sock);

QSC_CPLUSPLUS_ENABLED_END

#endif
