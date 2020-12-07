/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 Digital Freedom Defence Inc.
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
* A network sockets base class.
* Written by John G. Underhill
* Updated on November 11, 2020
* Contact: develop@vtdev.com */

#ifndef QSC_SOCKETCLIENT_H
#define QSC_SOCKETCLIENT_H

#include "common.h"
#include "asyncresult.h"
#include "socketbase.h"

/*** Accessors ***/

/// <summary>
/// Get: The sockets address family, IPv4 or IPv6
/// </summary>
QSC_EXPORT_API qsc_socket_address_families qsc_socket_client_address_family()
{

}

/// <summary>
/// Get: The socket protocol type
/// </summary>
QSC_EXPORT_API qsc_socket_protocols qsc_socket_client_socket_protocol()
{

}

/// <summary>
/// Get: The socket transport type
/// </summary>
QSC_EXPORT_API qsc_socket_transports qsc_socket_client_socket_transport() {

}

/*** Public Functions ***/

/// <summary>
/// The Connect function establishes a connection to a remote host
/// </summary>
///
/// <param name="Host">The remote host name</param>
/// <param name="Service">The connection service name</param>
QSC_EXPORT_API bool qsc_socket_client_connect_host(const char host[256], char service[256])
{

}

/// <summary>
/// The Connect function establishes a connection to a remote host using IPv4 addressing
/// </summary>
///
/// <param name="Address">The remote hosts IPv4 address</param>
/// <param name="Port">The remote hosts service port number</param>
QSC_EXPORT_API bool qsc_socket_client_connect_ipv4(const qsc_ipv4_address* address, uint16_t port)
{

}

/// <summary>
/// The Connect function establishes a connection to a remote host using IPv6 addressing
/// </summary>
///
/// <param name="Address">The remote hosts IPv6 address</param>
/// <param name="Port">The remote hosts service port number</param>
QSC_EXPORT_API bool qsc_socket_client_connect_ipv6(const qsc_ipv6_address* address, uint16_t Port)
{

}

/// <summary>
/// Start Non-Blocking connect to a remote host
/// </summary>
/// 
/// <param name="Address">The IP protocol address string</param>
/// <param name="Port">The application port number</param>
/// 
/// <exception cref="CryptoSocketException">Thrown if the Tcp connect operation has failed</exception>
QSC_EXPORT_API void qsc_socket_client_connect_async(const char address[256], uint16_t Port) {

}

/// <summary>
/// The async connect callback
/// </summary>
QSC_EXPORT_API void qsc_socket_client_connect_callback(qsc_async_result* result)
{

}

/// <summary>
/// Receive data from a synchronous connected socket or a bound connectionless socket
/// </summary>
/// 
/// <param name="Output">The buffer that receives incoming data</param>
/// <param name="Flags">Flags that influence the behavior of the receive function</param>
/// 
/// <returns>The number of bytes received from the remote host</returns>
///
/// <remarks>Successful receive operation raises the SocketChanged event with the SocketEvents::Received flag</remarks>
QSC_EXPORT_API size_t qsc_socket_client_receive(char* output, size_t outlen, qsc_socket_receive_flags flags)
{

}

/// <summary>
/// Begin Non-Blocking receiver of incoming messages (called after a connection is made)
/// </summary>
/// 
/// <param name="BufferLength">The byte length of the input buffer</param>
/// <param name="Flags">The bitwise combination of Socket Flags (default is None)</param>
/// 
/// <exception cref="CryptoSocketException">Thrown if the Tcp receive operation has failed</exception>
QSC_EXPORT_API void qsc_socket_client_receive_async(size_t bufflen, qsc_socket_receive_flags flags)
{

}

/// <summary>
/// The ReceiveAsync callback
/// </summary>
/// 
/// <param name="Result">The asynchronous result structure</param>
/// 
/// <exception cref="CryptoSocketException">Thrown on socket error or if the Tcp stream is larger than the maximum allocation size</exception>
QSC_EXPORT_API void qsc_socket_client_receive_callback(qsc_async_result* result)
{

}
 //SocketSendFlags::SendOOB
/// <summary>
/// Sends data on a connected socket
/// </summary>
/// 
/// <param name="Input">The input buffer containing the data to be transmitted</param>
/// <param name="Length">The number of bytes to send</param>
/// <param name="Flags">Flags that influence the behavior of the send function</param>
/// 
/// <returns>The number of bytes sent to the remote host</returns>
///
/// <remarks>Successful send operation raises the SocketChanged event with the SocketEvents::Sent flag</remarks>
QSC_EXPORT_API size_t qsc_socket_client_send(const char* input, size_t length, qsc_socket_send_flags flags)
{

}

/// <summary>
/// Non-blocking transmission of data to the remote host
/// </summary>
/// 
/// <param name="Input">The input buffer containing the data to be transmitted</param>
/// <param name="Length">The number of bytes to send</param>
/// <param name="Flags">Flags that influence the behavior of the send function</param>
/// 
/// <exception cref="CryptoSocketException">Thrown if the Tcp Send operation has failed, or the maximum allocation size is exceeded</exception>
QSC_EXPORT_API void qsc_socket_client_send_async(const char* input, size_t length, qsc_socket_send_flags flags)
{

}

/// <summary>
/// The Send callback
/// </summary>
/// 
/// <param name="Result">The asynchronous result structure</param>
QSC_EXPORT_API void qsc_socket_client_send_callback(qsc_async_result* result)
{

}

/// <summary>
/// Tests the socket to see if it is ready to send data
/// </summary>
///
/// <exception cref="CryptoSocketException">Thrown if the socket returns an error</exception>
/// <remarks>Successful change to shutdown state raises the SocketChanged event with the SocketEvents::ShutDown flag</remarks>
QSC_EXPORT_API void qsc_socket_client_shut_down()
{

}

#endif
