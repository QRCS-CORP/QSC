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

#ifndef QSC_SOCKETCLIENT_H
#define QSC_SOCKETCLIENT_H

#include "common.h"
#include "ipinfo.h"
#include "socketbase.h"

/**
 * \file socketclient.h
 * \brief The socket client function definitions.
 *
 * \details
 * This header provides the interface for socket client operations, including connecting to remote hosts
 * via host names or IP addresses (IPv4 and IPv6). It defines functions to retrieve socket attributes such as
 * address family, protocol, and transport type, as well as functions to initialize client sockets, connect,
 * send and receive data, and gracefully shut down socket connections.
 *
 * \code
 * // Example: Creating a client socket, connecting, sending and receiving data
 * qsc_socket client;
 * qsc_socket_client_initialize(&client);
 * 
 * // Connect using a host name and service (e.g., HTTP port 80)
 * if (qsc_socket_client_connect_host(&client, "example.com", "80") != QSC_SOCKET_RET_SUCCESS) {
 *     // Handle connection error...
 * }
 * 
 * // Send data over the connection
 * size_t bytesSent = qsc_socket_client_send(&client, "Hello, world!", 13, 0);
 * 
 * // Receive response from the remote host
 * char buffer[1024];
 * size_t bytesReceived = qsc_socket_client_receive(&client, buffer, sizeof(buffer), 0);
 * 
 * // Shutdown and close the socket
 * qsc_socket_client_shut_down(&client);
 * \endcode
 *
 * \section socketclient_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page">Windows Sockets (Winsock) Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html">POSIX Sockets Documentation</a>
 */

/*** Accessors ***/

/**
* \brief Get the sockets address family, IPv4 or IPv6
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
*
* \return			[qsc_socket_address_families] The socket address family
*/
QSC_EXPORT_API qsc_socket_address_families qsc_socket_client_address_family(const qsc_socket* sock);

/**
* \brief Get the socket protocol type
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
*
* \return			[qsc_socket_protocols] The socket protocol type
*/
QSC_EXPORT_API qsc_socket_protocols qsc_socket_client_socket_protocol(const qsc_socket* sock);

/**
* \brief Connect to a remote host using the network host name and service name
*
* \param sock:		[qsc_socket*] A pointer to the initialized socket
* \param host:		[const char*] The remote host name
* \param service:	[const char*] The service name
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_host(qsc_socket* sock, const char* host, const char* service);

/**
* \brief Establishes a socket connection to a remote host using IPv4 addressing
*
* \param sock:		[qsc_socket*] A pointer to the initialized socket
* \param address:	[const qsc_ipinfo_ipv4_address*] The remote hosts IPv4 address
* \param port:		[uint16_t] The remote hosts service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Establishes a socket connection to a remote host using IPv6 addressing
*
* \param sock:		[qsc_socket*] A pointer to the initialized socket
* \param address:	[const qsc_ipinfo_ipv6_address*] The remote hosts IPv6 address
* \param port:		[uint16_t] The remote hosts service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Get the socket transport type
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
*
* \return			[qsc_socket_transports] The socket transport type
*/
QSC_EXPORT_API qsc_socket_transports qsc_socket_client_socket_transport(const qsc_socket* sock);

/**
* \brief Initialize the server socket
*
* \param sock:		[qsc_socket*] A pointer to the socket structure
*/
QSC_EXPORT_API void qsc_socket_client_initialize(qsc_socket* sock);

/**
* \brief Receive data from a synchronous connected socket or a bound connectionless socket
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
* \param output:	[size_t] The buffer that receives incoming data
* \param otplen:	[size_t] The length of the output buffer
* \param flag:		[qsc_socket_receive_flags] Flag that influences the behavior of the receive function
*
* \return			[size_t] Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_receive(const qsc_socket* sock, char* output, size_t otplen, qsc_socket_receive_flags flag);

/**
* \brief Receive UDP data from a remote host
*
* \param sock:		[qsc_socket*] A pointer to the initialized socket
* \param address:	[char*] The remote host address
* \param port:		[uint16_t] The remote port
* \param output:	[char*] The output buffer receiving the data
* \param otplen:	[size_t] The number of bytes in the output buffer
* \param flag:		[qsc_socket_receive_flags] Flag that influence the behavior of the receive function
*
* \return			[size_t] Returns the number of bytes sent by the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_receive_from(qsc_socket* sock, char* address, uint16_t port, char* output, size_t otplen, qsc_socket_receive_flags flag);

/**
* \brief Sends data on a connected socket
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
* \param input:		[const char*] The input buffer containing the data to be transmitted
* \param inplen:	[size_t] The number of bytes to send
* \param flag:		[qsc_socket_send_flags] Flag that influence the behavior of the send function
*
* \return			[size_t] Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_send(const qsc_socket* sock, const char* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Sends UDP data to a remote host
*
* \param sock:		[const qsc_socket*] A pointer to the initialized socket
* \param address:	[const char*] The remote host address
* \param port:		[uint16_t] The remote port
* \param input:		[const char*] The input buffer containing the data to be transmitted
* \param inplen:	[size_t] The number of bytes to send
* \param flag:		[qsc_socket_send_flags] Flag that influence the behavior of the send function
*
* \return			[size_t] Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_send_to(const qsc_socket* sock, const char* address, uint16_t port, const char* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Shut down channels and close the socket
*
* \param sock:		[qsc_socket*] A pointer to the initialized socket
*/
QSC_EXPORT_API void qsc_socket_client_shut_down(qsc_socket* sock);

#endif
