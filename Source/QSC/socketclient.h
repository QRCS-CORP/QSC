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

#ifndef QSC_SOCKETCLIENT_H
#define QSC_SOCKETCLIENT_H

#include "qsccommon.h"
#include "ipinfo.h"
#include "socketbase.h"

QSC_CPLUSPLUS_ENABLED_START

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
* \param sock: [const qsc_socket*] A pointer to the initialized socket
*
* \return [qsc_socket_address_families] The socket address family
*/
QSC_EXPORT_API qsc_socket_address_families qsc_socket_client_address_family(const qsc_socket* sock);

/**
* \brief Get the socket protocol type
*
* \param sock: [const qsc_socket*] A pointer to the initialized socket
*
* \return [qsc_socket_protocols] The socket protocol type
*/
QSC_EXPORT_API qsc_socket_protocols qsc_socket_client_socket_protocol(const qsc_socket* sock);

/**
* \brief Connect to a remote host using the network host name and service name
*
* \param sock: [qsc_socket*] A pointer to the initialized socket
* \param host: [const char*] The remote host name
* \param service: [const char*] The service name
*
* \return [qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_host(qsc_socket* sock, const char* host, const char* service);

/**
* \brief Establishes a socket connection to a remote host using IPv4 addressing
*
* \param sock: [qsc_socket*] A pointer to the initialized socket
* \param address: [const qsc_ipinfo_ipv4_address*] The remote hosts IPv4 address
* \param port: [uint16_t] The remote hosts service port number
*
* \return [qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Establishes a socket connection to a remote host using IPv6 addressing
*
* \param sock: [qsc_socket*] A pointer to the initialized socket
* \param address: [const qsc_ipinfo_ipv6_address*] The remote hosts IPv6 address
* \param port: [uint16_t] The remote hosts service port number
*
* \return [qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_client_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Get the socket transport type
*
* \param sock: [const qsc_socket*] A pointer to the initialized socket
*
* \return [qsc_socket_transports] The socket transport type
*/
QSC_EXPORT_API qsc_socket_transports qsc_socket_client_socket_transport(const qsc_socket* sock);

/**
* \brief Initialize the server socket
*
* \param sock: [qsc_socket*] A pointer to the socket structure
*/
QSC_EXPORT_API void qsc_socket_client_initialize(qsc_socket* sock);

/**
* \brief Receive data from a synchronous connected socket or a bound connectionless socket
*
* \param sock: [const qsc_socket*] A pointer to the initialized socket
* \param output: [uint8_t*] The buffer that receives incoming data
* \param otplen: [size_t] The length of the output buffer
* \param flag: [qsc_socket_receive_flags] Flag that influences the behavior of the receive function
*
* \return [size_t] Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_receive(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag);

/**
* \brief Receive UDP data from a remote host
*
* \param sock: [qsc_socket*] A pointer to the initialized socket
* \param address: [char*] The remote host address
* \param addlen: [size_t] The length of the address string
* \param port: [uint16_t] The remote port
* \param output: [uint8_t*] The output buffer receiving the data
* \param otplen: [size_t] The number of bytes in the output buffer
* \param flag: [qsc_socket_receive_flags] Flag that influence the behavior of the receive function
*
* \return [size_t] Returns the number of bytes sent by the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_receive_from(qsc_socket* sock, char* address, size_t addlen, uint16_t port, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag);

/**
* \brief Sends data on a connected socket
*
* \param sock: [const qsc_socket*] A pointer to the initialized socket
* \param input: [const uint8_t*] The input buffer containing the data to be transmitted
* \param inplen: [size_t] The number of bytes to send
* \param flag: [qsc_socket_send_flags] Flag that influence the behavior of the send function
*
* \return [size_t] Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_send(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Sends UDP data to a remote host
*
* \param sock: [const qsc_socket*] A pointer to the initialized socket
* \param input: [const uint8_t*] The input buffer containing the data to be transmitted
* \param inplen: [size_t] The number of bytes to send
* \param flag: [qsc_socket_send_flags] Flag that influence the behavior of the send function
*
* \return			[size_t] Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_client_send_to(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Shut down channels and close the socket
*
* \param sock: [qsc_socket*] A pointer to the initialized socket
*/
QSC_EXPORT_API void qsc_socket_client_shut_down(qsc_socket* sock);

QSC_CPLUSPLUS_ENABLED_END

#endif
