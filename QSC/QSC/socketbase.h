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

#ifndef QSC_SOCKETBASE_H
#define QSC_SOCKETBASE_H

#include "common.h"
#include "intutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "socket.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <WinSock2.h>
#	include <WS2tcpip.h>
#	include <ws2def.h>
#	include <objbase.h>
#	include <inaddr.h>
#	include <iphlpapi.h>
#	pragma comment(lib, "ws2_32.lib")
#elif defined(QSC_SYSTEM_OS_POSIX)
#	include <ifaddrs.h>
#	include <netinet/in.h> 
#	include <arpa/inet.h>
#	include <sys/socket.h>
#	include <sys/types.h>
#	include <unistd.h>
#else
#	error the operating system is unsupported! 
#endif

/*! \enum SocketExceptions
* \brief Symmetric AEAD cipher mode enumeration names
*/
typedef enum qsc_socket_exceptions
{
	socket_success = 0,									/*!< The operation completed succesfully */
	socket_error = -1,									/*!< The operation has failed */
#if defined(QSC_SYSTEM_OS_WINDOWS)
	socket_network_failure = WSAENETDOWN,				/*!< The network subsystem has failed */
	socket_broadcast_address = WSAEACCES,				/*!< The requested address is a broadcast address, but the appropriate flag was not set */
	socket_blocking_cancelled = WSAEINTR,				/*!< A blocking Windows Sockets 1.1 call was canceled through WSACancelBlockingCall */
	socket_blocking_in_progress = WSAEINPROGRESS,		/*!< A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function */
	socket_address_buffer_fault = WSAEFAULT,			/*!< The buf parameter is not completely contained in a valid part of the user address space */
	socket_keep_alive_fail = WSAENETRESET,				/*!< The connection has been broken due to the keep-alive activity detecting a failure while the operation was in progress */
	socket_no_buffer_space = WSAENOBUFS,				/*!< No buffer space is available */
	socket_not_connected = WSAENOTCONN,					/*!< The socket is not connected */
	socket_descriptor_not_socket = WSAENOTSOCK,			/*!< The descriptor is not a socket */
	socket_shut_down = WSAESHUTDOWN,					/*!< The socket has been shut down; it is not possible to send on a socket after shutdown has been invoked with how set to SD_SEND or SD_BOTH */
	socket_would_block = WSAEWOULDBLOCK,				/*!< The socket is marked as nonblocking and the requested operation would block */
	socket_message_oriented = WSAEMSGSIZE,				/*!< The socket is message oriented, and the message is larger than the maximum supported by the underlying transport */
	socket_host_unreachable = WSAEHOSTUNREACH,			/*!< The remote host cannot be reached from this host at this time */
	socket_not_bound = WSAEINVAL,						/*!< The socket has not been bound with bind, or an unknown flag was specified, or MSG_OOB was specified for a socket with SO_OOBINLINE enabled */
	socket_circuit_terminated = WSAECONNABORTED,		/*!< The virtual circuit was terminated due to a time-out or other failure. The application should close the socket as it is no longer usable */
	socket_circuit_reset = WSAECONNRESET,				/*!< The virtual circuit was reset by the remote side executing a hard or abortive close.
	* For UDP sockets, the remote host was unable to deliver a previously sent UDP datagram and responded with a "port Unreachable" ICMP packet.
	* The application should close the socket as it is no longer usable. */
	socket_circuit_timeout = WSAETIMEDOUT,				/*!< The connection has been dropped, because of a network failure or because the system on the other end went down without notice */
	socket_not_initialized = WSANOTINITIALISED,			/*!< A successful WSAStartup call must occur before using this function */
	socket_address_in_use = WSAEADDRINUSE,				/*!< The socket's local address is already in use and the socket was not marked to allow address reuse with SO_REUSEADDR.
	* This error usually occurs during execution of the bind function, but could be delayed until this function if the bind was to a partially wildcard address
	* (involving ADDR_ANY) and if a specific address needs to be committed at the time of this function. */
	socket_already_in_use = WSAEISCONN,					/*!< The socket is already connected */
	socket_no_descriptors = WSAEMFILE,					/*!< No more socket descriptors are available */
	socket_not_listener = WSAEOPNOTSUPP,				/*!< The referenced socket is not of a type that supports the operation */
#else
	socket_not_available = EWOULDBLOCK,					/*!< Operation would block */
	socket_in_progress = EINPROGRESS,					/*!< Operation now in progress */
	socket_is_processing = EALREADY,					/*!< Operation already in progress */
	socket_is_invalid = ENOTSOCK,						/*!< qsc_socket operation on non-socket */
	socket_no_destination = EDESTADDRREQ,				/*!< Destination address required */
	socket_message_too_long = EMSGSIZE,					/*!< Message too long */
	socket_protocol_wrong_type = EPROTOTYPE,			/*!< Protocol wrong type for socket */
	socket_protocol_not_available = ENOPROTOOPT,		/*!< Protocol not available */
	socket_protocol_not_supported = EPROTONOSUPPORT,	/*!< Protocol not supported */
	socket_not_supported = ESOCKTNOSUPPORT,				/*!< qsc_socket type not supported */
	socket_operation_not_supported = EOPNOTSUPP,		/*!< Operation not supported on socket */
	socket_family_not_supported = EPFNOSUPPORT,			/*!< Protocol family not supported */
	socket_address_in_use = EADDRINUSE,					/*!< address already in use */
	socket_invalid_address = EADDRNOTAVAIL,				/*!< Can't assign requested address */
	socket_network_down = ENETDOWN,						/*!< Network is down */
	socket_network_unreachable = ENETUNREACH,			/*!< Network is unreachable */
	socket_dropped_connection = ENETRESET,				/*!< Network dropped connection on reset */
	socket_connected_abort = ECONNABORTED,				/*!< Software caused connection abort */
	socket_connection_reset_by_peer = ECONNRESET,		/*!< connection reset by peer */
	socket_connection_no_buffer = ENOBUFS,				/*!< No buffer space available */
	socket_already_connected = EISCONN					/*!< qsc_socket is already connected */
	socket_not_connected = ENOTCONN,					/*!< qsc_socket is not connected */
	socket_is_shutdown = ESHUTDOWN,						/*!< Can't send after socket shutdown */
	socket_connection_timed_out = ETIMEDOUT,			/*!< connection timed out */
	socket_connection_refused = ECONNREFUSED,			/*!< connection refused */
#endif
} qsc_socket_exceptions;

/**
* \brief Determines if the socket is in blocking mode
* 
* \param source: The source socket instance
*
* \return Returns true if the source is blocking
*/
QSC_EXPORT_API bool qsc_socket_is_blocking(qsc_socket* source);

/**
* \brief Determines if the socket is connected
* 
* \param source: The source socket instance
*
* \return Returns true if the source is connected
*/
QSC_EXPORT_API bool qsc_socket_is_connected(qsc_socket* source);

/*~~~Public Functions~~~/*

/**
* \brief The Accept function permits an incoming connection attempt on the socket
* 
* \param source: The source socket instance
* \param target: The socket that has been placed in the listening state
*
* \return Returns true if the connection has been accepted
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_accept(qsc_socket* source, qsc_socket* target);

/**
* \brief Attach a socket to the local socket
* 
* \param source: The source socket instance
* \param target: The socket to attach
*/
QSC_EXPORT_API void qsc_socket_attach(qsc_socket* source, qsc_socket* target);

/**
* \brief The Bind function associates an address with a socket
* 
* \param source: The source socket instance
* \param address: The address to bind to the socket
* \param port:The service port number
*
* \return Returns true if the binding was successful
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind(qsc_socket* source, const qsc_ipv4_address* address, uint16_t port);

/**
* \brief The Bind function associates an address with a socket
* 
* \param soure: The source socket instance
* \param address: The address to bind to the socket
* \param port: The service port number
*
* \return Returns true if the binding was successful
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind_ipv6(qsc_socket* source, const qsc_ipv6_address* address, uint16_t port);

/**
* \brief The CloseSocket function closes and disposes of the socket
*
* \param source: The source socket instance
*
* \return Returns the error code or zero for success
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_close_socket(qsc_socket* source);

/**
* \brief The Connect function establishes a connection to a remote host using IPv4 addressing
*
* \param source: The source socket instance
* \param address: The remote hosts IPv4 address
* \param port: The remote hosts service port number
*
* \return Returns true if the connection was successful
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect(qsc_socket* source, const qsc_ipv4_address* address, uint16_t port);

/**
* \brief The Connect function establishes a connection to a remote host using IPv6 addressing
*
* \param source: The source socket instance
* \param address: The remote hosts IPv6 address
* \param port: The remote hosts service port number
*
* \return Returns true if the connection was successful
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect_ipv6(qsc_socket* source, const qsc_ipv6_address* address, uint16_t port);

/**
* \brief The Create function creates a socket that is bound to a specific transport provider
* 
* \param source: The source socket instance
*
* \return Returns true if the socket was created successfully
*/
QSC_EXPORT_API bool qsc_socket_create(qsc_socket* source);

/**
* \brief Places the socket in the listening state, waiting for a connection
* 
* \param source: The source socket instance
* \param backLog: The maximum pending connections queue length
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_listen(qsc_socket* source, int32_t backLog); //SOCKET_MAX_CONN

/**
* \brief Receive data from a synchronous connected socket or a bound connectionless socket
* 
* \param source: The source socket instance
* \param output: The output buffer that receives data
* \param length: The length of the output received
* \param flag: Flags that influence the behavior of the receive function
* 
* \return The number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive(qsc_socket* source, uint8_t* output, size_t length, qsc_socket_receive_flags flag);

/**
* \brief Receive a block of data from a synchronous connected socket or a bound connectionless socket, and returns when buffer is full
*
* \param source: The source socket instance
* \param output: The output buffer that receives data
* \param length: The length of the output received
* \param flag: Flags that influence the behavior of the receive function
*
* \return The number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive_all(qsc_socket* source, uint8_t* output, size_t length, qsc_socket_receive_flags flag);

/**
* \brief Sends data on a connected socket
* 
* \param source: The source socket instance
* \param input: The input buffer containing the data to be transmitted
* \param length: The number of bytes to send
* \param flag: Flags that influence the behavior of the send function
* 
* \return The number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send(qsc_socket* source, const uint8_t* input, size_t length, qsc_socket_send_flags flag);

/**
* \brief Sends a block of data larger than a single packet size, on a connected socket and returns when sent
*
* \param source: The source socket instance
* \param input: The input buffer containing the data to be transmitted
* \param length: The number of bytes to send
* \param flag: Flags that influence the behavior of the send function
*
* \return The number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send_all(qsc_socket* source, const uint8_t* input, size_t length, qsc_socket_send_flags flag);

/**
* \brief Tests the socket to see if it is ready to send data
* 
* \param source: The source socket instance
* \param parameters: The shutdown parameters
*
* \return The error number, or zero for success
*/
QSC_EXPORT_API int32_t qsc_socket_shut_down(qsc_socket* source, qsc_socket_shut_down_flags parameters);

/*~~~ Helper Functions ~~~*/

/**
* \brief  the last error generated by the internal socket library
*
* \return Returns the last error state
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_get_last_error();

/**
* \brief Sets the IO mode of the socket
* 
* \param source: The source socket instance
* \param command: The command to pass to the socket
* \param arguments: The command arguments
*
* \return The error number, or zero for success
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_ioctl(qsc_socket* source, int32_t command, uint32_t* arguments);

/**
* \brief Determines the status of a socket waiting for a synchronous connection
* 
* \param source: The source socket instance
* \param timeout: The receive wait timeout
*
* \return Returns the ready state of the receive operation
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_receive_ready(qsc_socket* source, const struct timeval* timeout);

/**
* \brief Tests the socket to see if it is ready to send data
* 
* \param Source: The source socket instance
* \param Timeout: The maximum time to wait for a response from the socket
*
* \return Returns the ready state of the send operation
*/
QSC_EXPORT_API bool qsc_socket_send_ready(qsc_socket* source, const struct timeval* timeout);

/**
* \brief Set the last error generated by the socket library
* 
* \param ErrorCode: The error code
*/
QSC_EXPORT_API void qsc_socket_set_last_error(int32_t ErrorCode);

/**
* \brief Shut down the sockets library
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_shut_down_sockets();

/**
* \brief Send an option command to the socket
* 
* \param source: The source socket instance
* \param protocol: The ip protocol parameter
* \param option: The option command to send
*/	//  = SocketProtocols::TCP,  = SocketOptions::TcpNoDelay
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_option(qsc_socket* source, qsc_socket_protocols protocol, qsc_socket_options option);

/**
* \brief Start the sockets library
*/
QSC_EXPORT_API bool qsc_socket_start_sockets();

#endif