/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef QSC_SOCKETSERVER_H
#define QSC_SOCKETSERVER_H

#include "common.h"
#include "socketbase.h"

/*
* \file socketserver.h
* \brief The socket server function definitions
*/

/*!
* \def QSC_SOCKET_SERVER_LISTEN_BACKLOG
* \brief The socket connection backlog, default is 128
*/
#define QSC_SOCKET_SERVER_LISTEN_BACKLOG 128

/*!
* \def QSC_SOCKET_SERVER_MAX_THREADS
* \brief The maximum number of active threads
*/
#define QSC_SOCKET_SERVER_MAX_THREADS 1024

/*** Structures ***/

/*! \struct qsc_socket_server_accept_result
* \brief The async socket result structure.
*/
typedef struct qsc_socket_server_accept_result
{
	qsc_socket target;		/*!< The accepted socket */
} qsc_socket_server_accept_result;

/*! \struct qsc_socket_server_async_accept_state
* \brief The async listener-accept state structure.
* The structure contains a pointer to the listener socket,
* and pointers to a callback and error functions.
* The callback function returns a populated qsc_socket_server_accept_result structure.
* The error function returns the listener socket and an qsc_socket_exceptions error code.
*/
typedef struct qsc_socket_server_async_accept_state
{
	qsc_socket* source;													/*!< A pointer to the listener socket */
	void (*callback)(qsc_socket_server_accept_result* result);			/*!< A pointer to a callback function */
	void (*error)(qsc_socket* sock, qsc_socket_exceptions exception);	/*!< A pointer to an error function */
} qsc_socket_server_async_accept_state;

/*** Function Prototypes ***/

/**
* \brief The socket server accept callback prototype
*
* \param ares: A pointer to the server accept result structure
*/
QSC_EXPORT_API void qsc_socket_server_accept_callback(qsc_socket_server_accept_result* ares);

/**
* \brief The socket server error callback prototype
*
* \param source: [const] A pointer to the initialized socket
* \param error: The socket exception
*/
QSC_EXPORT_API void qsc_socket_server_error_callback(const qsc_socket* source, qsc_socket_exceptions error);

/*** Accessors ***/

/**
* \brief Get the sockets address family, IPv4 or IPv6
*
* \param sock: [const] A pointer to the initialized socket
*
* \return The socket address family
*/
QSC_EXPORT_API qsc_socket_address_families qsc_socket_server_address_family(const qsc_socket* sock);

/**
* \brief Get the socket protocol type
*
* \param sock: [const] A pointer to the initialized socket
*
* \return The socket protocol type
*/
QSC_EXPORT_API qsc_socket_protocols qsc_socket_server_socket_protocol(const qsc_socket* sock);

/**
* \brief Get the socket transport type
*
* \param sock: [const] A pointer to the initialized socket
*
* \return The socket transport type
*/
QSC_EXPORT_API qsc_socket_transports qsc_socket_server_socket_transport(const qsc_socket* sock);

/**
* \brief Close the socket
*
* \param sock: A pointer to the socket structure
*/
QSC_EXPORT_API void qsc_socket_server_close_socket(qsc_socket* sock);

/**
* \brief Initialize the server socket
*
* \param sock: A pointer to the socket structure
*/
QSC_EXPORT_API void qsc_socket_server_initialize(qsc_socket* sock);

/**
* \brief Places the source socket in a blocking listening state, and waits for a connection.
* Returns a single socket, and must be called to listen for each new connection.
*
* \param source: The listening socket
* \param target: The accepted remote socket
* \param address: [const] The servers address
* \param port: The servers port number
* \param family: The socket address family
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen(qsc_socket* source, qsc_socket* target, const char* address, uint16_t port, qsc_socket_address_families family);

/**
* \brief Places the source IPv4 socket in a blocking listening state, and waits for a connection.
* Returns a single socket, and must be called to listen for each new connection.
*
* \param source: The listening socket
* \param target: The accepted remote socket
* \param address: [const] The servers IPv4 address
* \param port: The servers port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_ipv4(qsc_socket* source, qsc_socket* target, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Places the source IPv6 socket in a blocking listening state, and waits for a connection.
* Returns a single socket, and must be called to listen for each new connection.
*
* \param source: The listening socket
* \param target: The accepted remote socket
* \param address: [const] The servers IPv6 address
* \param port: The servers port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_ipv6(qsc_socket* source, qsc_socket* target, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Places the socket in an asynchronous listening state
*
* \param state: The asynchronous server state
* \param address: [const] The servers address
* \param port: The servers port number
* \param family: The socket address family
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_async(qsc_socket_server_async_accept_state* state, const char* address, uint16_t port, qsc_socket_address_families family);

/**
* \brief Places the IPv4 socket in an asynchronous listening state
*
* \param state: The asynchronous server state
* \param address: [const] The servers address
* \param port: The servers port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_async_ipv4(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Places the IPv6 socket in an asynchronous listening state
*
* \param state: The asynchronous server state
* \param address: The servers address
* \param port: The servers port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_server_listen_async_ipv6(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Send an option command to the socket.
* Options that use a boolean are format: 0=false, 1=true.
*
* \param sock: [const] The socket instance
* \param level: The level at which the option is assigned
* \param option: The option command to send
* \param optval: The value of the option command
*/
QSC_EXPORT_API void qsc_socket_server_set_options(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval);

/**
* \brief Shut down the server
*
* \param sock: The listening socket
*/
QSC_EXPORT_API void qsc_socket_server_shut_down(qsc_socket* sock);

#endif
