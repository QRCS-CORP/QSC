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

#ifndef QSC_SOCKETCLIENT_H
#define QSC_SOCKETCLIENT_H

#include "common.h"
#include "ipinfo.h"
#include "socketbase.h"

/*
* \file socketclient.h
* \brief The socket client function definitions
*/

/*** Accessors ***/

/**
* \brief Get the sockets address family, IPv4 or IPv6
*
* \param sock: [const] A pointer to the initialized socket
*
* \return The socket address family
*/
QSC_EXPORT_API qsc_socket_address_families qsc_socket_client_address_family(const qsc_socket* sock);

/**
* \brief Get the socket protocol type
*
* \param sock: [const] A pointer to the initialized socket
*
* \return The socket protocol type
*/
QSC_EXPORT_API qsc_socket_protocols qsc_socket_client_socket_protocol(const qsc_socket* sock);

/**
* \brief Connect to a remote host using the network host name and service name
*
* \param sock: [const] A pointer to the initialized socket
* \param host: [const] The remote host name
* \param service: The service name
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_host(qsc_socket* sock, const char* host, const char* service);

/**
* \brief Establishes a socket connection to a remote host using IPv4 addressing
*
* \param sock: A pointer to the initialized socket
* \param address: [const] The remote hosts IPv4 address
* \param port: The remote hosts service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Establishes a socket connection to a remote host using IPv6 addressing
*
* \param sock: A pointer to the initialized socket
* \param address: [const] The remote hosts IPv6 address
* \param port: The remote hosts service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Get the socket transport type
*
* \param sock: [const] A pointer to the initialized socket
*
* \return The socket transport type
*/
QSC_EXPORT_API qsc_socket_transports qsc_socket_client_socket_transport(const qsc_socket* sock);

/**
* \brief Initialize the server socket
*
* \param sock: A pointer to the socket structure
*/
QSC_EXPORT_API void qsc_socket_client_initialize(qsc_socket* sock);

/**
* \brief Receive data from a synchronous connected socket or a bound connectionless socket
*
* \param sock: [const] A pointer to the initialized socket
* \param output: The buffer that receives incoming data
* \param outlen: The length of the output buffer
* \param flag: Flag that influences the behavior of the receive function
*
* \return Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_receive(const qsc_socket* sock, char* output, size_t outlen, qsc_socket_receive_flags flag);

/**
* \brief Receive UDP data from a remote host
*
* \param sock: A pointer to the initialized socket
* \param address: The remote host address
* \param port: The remote port
* \param output: The output buffer receiving the data
* \param outlen: The number of bytes in the output buffer
* \param flag: Flag that influence the behavior of the receive function
*
* \return Returns the number of bytes sent by the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_receive_from(qsc_socket* sock, char* address, uint16_t port, char* output, size_t outlen, qsc_socket_receive_flags flag);

/**
* \brief Sends data on a connected socket
*
* \param sock: [const] A pointer to the initialized socket
* \param input: [const] The input buffer containing the data to be transmitted
* \param inplen: The number of bytes to send
* \param flag: Flag that influence the behavior of the send function
*
* \return Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_send(const qsc_socket* sock, const char* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Sends UDP data to a remote host
*
* \param sock: [const] A pointer to the initialized socket
* \param address: [const] The remote host address
* \param port: The remote port
* \param input: [const] The input buffer containing the data to be transmitted
* \param inplen: The number of bytes to send
* \param flag: Flag that influence the behavior of the send function
*
* \return Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_send_to(const qsc_socket* sock, const char* address, uint16_t port, const char* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Shut down the socket
*
* \param sock: A pointer to the initialized socket
*/
QSC_EXPORT_API void qsc_socket_client_shut_down(qsc_socket* sock);

#endif
