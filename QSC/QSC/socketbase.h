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

#ifndef QSC_SOCKETBASE_H
#define QSC_SOCKETBASE_H

#include "common.h"
#include "intutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "socket.h"

/*
* \file socketbase.h
* \brief Time-stamp function definitions
*/

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <WinSock2.h>
#	include <WS2tcpip.h>
#	include <ws2def.h>
#	include <objbase.h>
#	include <inaddr.h>
#	include <iphlpapi.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC) && defined(QSC_SYSTEM_MAX_PATH)
#	    pragma comment(lib, "iphlpapi.lib")
#	    pragma comment(lib, "ws2_32.lib")
#   endif
#else //elif defined(QSC_SYSTEM_OS_POSIX)

#	include <errno.h>
#	include <netdb.h>
#	include <ifaddrs.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#include <sys/select.h>
#	include <sys/socket.h>
#	include <string.h>
#	include <sys/types.h>
#	include <unistd.h>
#	if defined(QSC_SYSTEM_OS_APPLE)
#
#	else
#		include <netpacket/packet.h>
#	endif
//#else
//#	error "The operating system is not supported!"
#endif

///*!
//\def QSC_SOCKET_DUAL_IPV6_STACK
//* \brief Enables a dual stack ipv4 and ipv6 listener.
//*/
//#if !defined(QSC_SOCKET_DUAL_IPV6_STACK)
//#	define QSC_SOCKET_DUAL_IPV6_STACK
//#endif

/*** Function State ***/

/*!
\def QSC_SOCKET_RECEIVE_BUFFER_SIZE
* \brief The socket receive buffer size
*/
#define QSC_SOCKET_RECEIVE_BUFFER_SIZE 1600

/*! \enum qsc_socket_exceptions
* \brief Socket code enumeration names
*/
typedef enum qsc_socket_exceptions
{
	qsc_socket_exception_success = 0,								/*!< The operation completed successfully */
	qsc_socket_exception_error = -1,								/*!< The operation has failed */
	qsc_socket_invalid_input = -2,									/*!< The input parameters are incorrect */
#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_socket_exception_address_in_use = WSAEADDRINUSE,			/*!< The socket's local address is already in use and the socket was not marked to allow address reuse with SO_REUSEADDR */
	qsc_socket_exception_address_required = WSAEDESTADDRREQ,		/*!< A destination address is required */
	qsc_socket_exception_address_unsupported = WSAEAFNOSUPPORT,		/*!< The address family is not supported */
	qsc_socket_exception_already_in_use = WSAEISCONN,				/*!< The socket is already connected */
	qsc_socket_exception_blocking_cancelled = WSAEINTR,				/*!< A blocking sockets call was canceled */
	qsc_socket_exception_blocking_in_progress = WSAEINPROGRESS,		/*!< A blocking sockets call is in progress, or the service provider is still processing a callback function */
	qsc_socket_exception_broadcast_address = WSAEACCES,				/*!< The requested address is a broadcast address, but the appropriate flag was not set */
	qsc_socket_exception_buffer_fault = WSAEFAULT,					/*!< The buffer parameter is not completely contained in a valid part of the user address space */
	qsc_socket_exception_circuit_reset = WSAECONNRESET,				/*!< The virtual circuit was reset by the remote side executing a hard or abortive close. */
	qsc_socket_exception_circuit_terminated = WSAECONNABORTED,		/*!< The virtual circuit was terminated due to a time-out or other failure. The application should close the socket as it is no longer usable */
	qsc_socket_exception_circuit_timeout = WSAETIMEDOUT,			/*!< The connection has been dropped, because of a network failure or because the system on the other end went down without notice */
	qsc_socket_exception_connection_refused = WSAECONNREFUSED,		/*!< The connection was refused */
	qsc_socket_exception_descriptor_not_socket = WSAENOTSOCK,		/*!< The descriptor is not a socket */
	qsc_socket_exception_disk_quota_exceeded = WSAEDQUOT,			/*!< The disk quota is exceeded */
	qsc_socket_exception_dropped_connection = WSAENETRESET,			/*!< The connection has been broken due to the keep-alive activity detecting a failure while the operation was in progress */
	qsc_socket_exception_family_unsupported = WSAEPFNOSUPPORT,		/*!< The protocol family is not supported */
	qsc_socket_exception_host_is_down = WSAEHOSTDOWN,				/*!< The destination host is down */
	qsc_socket_exception_host_unreachable = WSAEHOSTUNREACH,		/*!< The remote host cannot be reached from this host at this time */
	qsc_socket_exception_in_progress = WSAEALREADY,					/*!< Operation in progress */
	qsc_socket_exception_invalid_address = WSAEADDRNOTAVAIL,		/*!< The address is not available */
	qsc_socket_exception_invalid_parameter = WSA_INVALID_PARAMETER,	/*!< One or more parameters are invalid */
	qsc_socket_exception_invalid_protocol = WSAEPROTOTYPE,			/*!< The protocol type is invalid for the socket */
	qsc_socket_exception_invalid_protocol_option = WSAENOPROTOOPT,	/*!< The protocol option is invalid */
	qsc_socket_exception_invalid_provider = WSAEINVALIDPROVIDER,	/*!< The service provider is invalid */
	qsc_socket_exception_item_is_remote = WSAEREMOTE,				/*!< The item is not available locally */
	qsc_socket_exception_message_too_long = WSAEMSGSIZE,			/*!< The message size is too long */
	qsc_socket_exception_name_too_long = WSAENAMETOOLONG,			/*!< The name is too long */
	qsc_socket_exception_network_failure = WSAENETDOWN,				/*!< The network subsystem has failed */
	qsc_socket_exception_network_unreachable = WSAENETUNREACH,		/*!< The network is unreachable */
	qsc_socket_exception_no_buffer_space = WSAENOBUFS,				/*!< No buffer space is available */
	qsc_socket_exception_no_descriptors = WSAEMFILE,				/*!< No more socket descriptors are available */
	qsc_socket_exception_no_memory = WSA_NOT_ENOUGH_MEMORY,			/*!< The system does not have enough memory available */
	qsc_socket_exception_not_bound = WSAEINVAL,						/*!< The socket has not been bound with bind, or an unknown flag was specified, or MSG_OOB was specified for a socket with SO_OOBINLINE enabled */
	qsc_socket_exception_not_connected = WSAENOTCONN,				/*!< The socket is not connected */
	qsc_socket_exception_not_initialized = WSANOTINITIALISED,		/*!< A successful WSAStartup call must occur before using this function */
	qsc_socket_exception_operation_unsupported = WSAEOPNOTSUPP,		/*!< The socket operation is not supported */
	qsc_socket_exception_protocol_unsupported = WSAEPROTONOSUPPORT,	/*!< The protocol is not supported */
	qsc_socket_exception_shut_down = WSAESHUTDOWN,					/*!< The socket has been shut down; it is not possible to send on a socket after shutdown has been invoked with how set to QSC_SOCKET_SD_SEND or QSC_SOCKET_SD_BOTH */
	qsc_socket_exception_socket_unsupported = WSAESOCKTNOSUPPORT,	/*!< The socket type is not supported */
	qsc_socket_exception_system_not_ready = WSASYSNOTREADY,			/*!< The subsystem is unavailable */
	qsc_socket_exception_too_many_processes = WSAEPROCLIM,			/*!< The host is using too many processes */
	qsc_socket_exception_too_many_users = WSAEUSERS,				/*!< The user quota is exceeded */
	qsc_socket_exception_translation_failed = WSAELOOP,				/*!< Can not translate name */
	qsc_socket_exception_would_block = WSAEWOULDBLOCK,				/*!< The socket is marked as nonblocking and the requested operation would block */
#else
	qsc_socket_exception_address_in_use = EADDRINUSE,				/*!< address already in use */
	qsc_socket_exception_address_required = EDESTADDRREQ,			/*!< Destination address required */
	qsc_socket_exception_address_unsupported = EAFNOSUPPORT,		/*!< The address family is not supported */
	qsc_socket_exception_already_in_use = EISCONN,					/*!< qsc_socket is already connected */
	qsc_socket_exception_blocking_cancelled = EINTR,				/*!< A blocking call was canceled */
	qsc_socket_exception_blocking_in_progress = EINPROGRESS,		/*!< A blocking sockets call is in progress, or the service provider is still processing a callback function */
	qsc_socket_exception_broadcast_address = EACCES,				/*!< The requested address is a broadcast address, but the appropriate flag was not set */
	qsc_socket_exception_buffer_fault = EFAULT,						/*!< The buffer parameter is not completely contained in a valid part of the user address space */
	qsc_socket_exception_circuit_terminated = ECONNABORTED,			/*!< Software caused connection abort */
	qsc_socket_exception_circuit_reset = ECONNRESET,				/*!< connection reset by peer */
	qsc_socket_exception_circuit_timeout = ETIMEDOUT,				/*!< connection timed out */
	qsc_socket_exception_connection_refused = ECONNREFUSED,			/*!< connection refused */
	qsc_socket_exception_descriptor_not_socket = ENOTSOCK,			/*!< qsc_socket operation on non-socket */
	qsc_socket_exception_disk_quota_exceeded = EDQUOT,				/*!< The disk quota is exceeded */
	qsc_socket_exception_dropped_connection = ENETRESET,			/*!< Network dropped connection on reset */
	qsc_socket_exception_family_unsupported = EPFNOSUPPORT,			/*!< Protocol family not supported */
	qsc_socket_exception_host_is_down = EHOSTDOWN,					/*!< The destination host is down */
	qsc_socket_exception_host_unreachable = EHOSTUNREACH,			/*!< The remote host cannot be reached from this host at this time */
	qsc_socket_exception_in_progress = EALREADY,					/*!< Operation already in progress */
	qsc_socket_exception_invalid_address = EADDRNOTAVAIL,			/*!< Can't assign requested address */
	//qsc_socket_exception_invalid_parameter = EOTHER,				/*!< One or more parameters are invalid */
	qsc_socket_exception_invalid_protocol = EPROTOTYPE,				/*!< Protocol wrong type for socket */
	qsc_socket_exception_invalid_protocol_option = ENOPROTOOPT,		/*!< Protocol not available */
	//qsc_socket_exception_invalid_provider = EINVALIDPROVIDER,		/*!< The service provider is invalid */
	qsc_socket_exception_item_is_remote = EREMOTE,					/*!< The item is not available locally */
	qsc_socket_exception_message_too_long = EMSGSIZE,				/*!< The message size is too long */
	qsc_socket_exception_name_too_long = ENAMETOOLONG,				/*!< The name is too long */
	qsc_socket_exception_network_failure = ENETDOWN,				/*!< Network is down */
	qsc_socket_exception_network_unreachable = ENETUNREACH,			/*!< Network is unreachable */
	qsc_socket_exception_no_buffer_space = ENOBUFS,					/*!< No buffer space available */
	qsc_socket_exception_no_descriptors = EMFILE,					/*!< No more socket descriptors are available */
	qsc_socket_exception_not_bound = EINVAL,						/*!< The socket has not been bound with bind, or an unknown flag was specified, or MSG_OOB was specified for a socket with SO_OOBINLINE enabled */
	qsc_socket_exception_not_connected = ENOTCONN,					/*!< qsc_socket is not connected */
	qsc_socket_exception_operation_unsupported = EOPNOTSUPP,		/*!< The socket operation is not supported */
	qsc_socket_exception_protocol_unsupported = EPROTONOSUPPORT,	/*!< Protocol not supported */
	qsc_socket_exception_socket_unsupported = ESOCKTNOSUPPORT,		/*!< qsc_socket type not supported */
	qsc_socket_exception_shut_down = ESHUTDOWN,						/*!< Can't send after socket shutdown */
	qsc_socket_exception_system_not_ready = ETXTBSY,				/*!< The subsystem is unavailable */
	//qsc_socket_exception_too_many_processes = EPROCLIM,			/*!< The host is using too many processes */
	qsc_socket_exception_too_many_users = EUSERS,					/*!< The user quota is exceeded */
	qsc_socket_exception_translation_failed = ELOOP,				/*!< Can not translate name */
	qsc_socket_exception_would_block = EWOULDBLOCK,					/*!< Operation would block */

#endif
} qsc_socket_exceptions;

/*! \brief The socket error strings array.
* \brief Error messages corresponding to the qsc_socket_exceptions enumeration.
*/
static const char QSC_SOCKET_ERROR_STRINGS[48][128] =
{
	"SUCCESS: The operation completed successfully.",
	"ERROR: The operation has failed.",
	"INVALID: The input parameters are incorrect.",
	"EADDRINUSE: The socket's local address is in use and the socket was not marked to allow address reuse with SO_REUSEADDR.",
	"EDESTADDRREQ: A destination address is required.",
	"EAFNOSUPPORT: The address family is not supported.",
	"EISCONN: The socket is already connected.",
	"EINTR: A blocking sockets call was canceled.",
	"EINPROGRESS: A blocking sockets call is in progress, or the service provider is still processing a callback function.",
	"EACCES: The requested address is a broadcast address, but the appropriate flag was not set.",
	"EFAULT: The buffer parameter is not completely contained in a valid part of the user address space.",
	"ECONNRESET: The virtual circuit was reset by the remote side executing a hard or abortive close.",
	"ECONNABORTED: The virtual circuit was terminated due to a time-out or other failure.",
	"ETIMEDOUT: The connection has been dropped, because of a network failure.",
	"ECONNREFUSED: The connection was refused.",
	"ENOTSOCK: The descriptor is not a socket.",
	"EDQUOT: The disk quota is exceeded.",
	"ENETRESET: The connection has been broken due to the keep-alive activity detecting a failure.",
	"EPFNOSUPPORT: The protocol family is not supported.",
	"EHOSTDOWN: The destination host is down.",
	"EHOSTUNREACH: The remote host cannot be reached from this host at this time.",
	"EALREADY: Operation in progress.",
	"EADDRNOTAVAIL: The address is not available.",
	"INVALID_PARAMETER: One or more parameters are invalid.",
	"EPROTOTYPE: The protocol type is invalid for the socket.",
	"ENOPROTOOPT: The protocol option is invalid.",
	"EINVALIDPROVIDER: The service provider is invalid.",
	"EREMOTE: The item is not available locally.",
	"EMSGSIZE: The message size is too long.",
	"ENAMETOOLONG: The name is too long.",
	"ENETDOWN: The network subsystem has failed.",
	"ENETUNREACH: The network is unreachable.",
	"ENOBUFS: No buffer space is available.",
	"EMFILE: No more socket descriptors are available.",
	"_NOT_ENOUGH_MEMORY: The system does not have enough memory available.",
	"EINVAL: The socket has not been bound with bind, or MSG_OOB was specified for a socket with SO_OOBINLINE enabled.",
	"ENOTCONN: The socket is not connected.",
	"NOTINITIALISED: A successful Startup call must occur before using this function.",
	"EOPNOTSUPP: The socket operation is not supported.",
	"EPROTONOSUPPORT: The protocol is not supported.",
	"ESHUTDOWN: The socket has been shut down.",
	"ESOCKTNOSUPPORT: The socket type is not supported.",
	"SYSNOTREADY: The subsystem is unavailable.",
	"EPROCLIM: The host is using too many processes.",
	"EUSERS: The user quota is exceeded.",
	"ELOOP: Can not translate name.",
	"EWOULDBLOCK: The socket is marked as nonblocking and the requested operation would block.",
	"",
};

/*! \struct qsc_socket_receive_async_state
* \brief The socket async receive state structure.
* The structure contains pointers to the originating socket,
* message and error call-backs, and the message buffer.
*/
typedef struct qsc_socket_receive_async_state
{
	void (*callback)(const qsc_socket* sock, const uint8_t* message, size_t* msglen);	/*!< A pointer to a callback function */
	void (*error)(const qsc_socket* sock, qsc_socket_exceptions exception);				/*!< A pointer to an error function */
	qsc_socket* source;																	/*!< A pointer to the originating socket */
	uint8_t buffer[QSC_SOCKET_RECEIVE_BUFFER_SIZE];										/*!< A pointer to the message buffer */
} qsc_socket_receive_async_state;

/*! \struct qsc_socket_receive_poll_state
* \brief The socket polling state structure.
* The structure contains an array of client sockets,
* and a socket counter with sockets that are ready to receive data.
*/
typedef struct qsc_socket_receive_poll_state
{
	qsc_socket** sockarr;																/*!< A pointer to an array of sockets */
	void (*callback)(qsc_socket* sock, size_t id);										/*!< A pointer to a callback function */
	void (*error)(qsc_socket* sock, qsc_socket_exceptions exception);					/*!< A pointer to an error function */
	uint32_t count;																		/*!< The number of active sockets */
} qsc_socket_receive_poll_state;

/*** Function Prototypes ***/

/**
* \brief The socket exception callback prototype
*
* \param source: [const] The socket source
* \param error: The socket exception
*/
QSC_EXPORT_API void qsc_socket_exception_callback(const qsc_socket* source, qsc_socket_exceptions error);

/**
* \brief The socket receive asynchronous callback prototype
*
* \param source: [const] The socket source
* \param message: [const] The socket message buffer
* \param msglen: A pointer to the size of the message
*/
QSC_EXPORT_API void qsc_socket_receive_async_callback(const qsc_socket* source, const uint8_t* message, size_t* msglen);

/**
* \brief The receive polling callback prototype
*
* \param source: [const] The socket source
* \param error: The socket exception
*/
QSC_EXPORT_API void qsc_socket_receive_poll_callback(const qsc_socket* source, size_t error);

/*** Accessors ***/

/**
* \brief Detects if the string contains a valid IPV4 address
* \param address: [const] The IP address string
*
* \return Returns true if the address is a valid IPV4 address
*/
QSC_EXPORT_API bool qsc_socket_ipv4_valid_address(const char* address);

/**
* \brief Detects if the string contains a valid IPV6 address
* \param address: [const] The IP address string
*
* \return Returns true if the address is a valid IPV6 address
*/
QSC_EXPORT_API bool qsc_socket_ipv6_valid_address(const char* address);

/**
* \brief Determines if the socket is in blocking mode
*
* \param sock: [const] The socket instance
*
* \return Returns true if the socket is blocking
*/
QSC_EXPORT_API bool qsc_socket_is_blocking(const qsc_socket* sock);

/**
* \brief Determines if the socket is connected
*
* \param sock: [const] The socket instance
*
* \return Returns true if the socket is connected
*/
QSC_EXPORT_API bool qsc_socket_is_connected(const qsc_socket* sock);

/**
* \brief The Accept function handles an incoming connection attempt on the socket
*
* \param source: [const] The source listening socket instance
* \param target: The socket receiving the new socket
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_accept(const qsc_socket* source, qsc_socket* target);

/**
* \brief Copy a socket to the target socket
*
* \param source: The source socket instance
* \param target: The socket to attach
*/
QSC_EXPORT_API void qsc_socket_attach(qsc_socket* source, qsc_socket* target);

/**
* \brief The Bind function associates an IP address with a socket
*
* \param sock: The socket instance
* \param address: [const] The IP address to bind to the socket
* \param port: The service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind(qsc_socket* sock, const char* address, uint16_t port);

/**
* \brief The Bind function associates an IPv4 address with a socket
*
* \param sock: The socket instance
* \param address: [const] The IPv4 address to bind to the socket
* \param port: The service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief The Bind function associates an IPv6 address with a socket
*
* \param sock: The socket instance
* \param address: [const] The IPv6 address to bind to the socket
* \param port: The service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief The Close socket function closes and disposes of the socket
*
* \param sock: [const] The socket instance
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_close_socket(const qsc_socket* sock);

/**
* \brief The Connect function establishes a connection to a remote host
*
* \param sock: The socket instance
* \param address: [const] The remote hosts IP address
* \param port: The remote hosts service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect(qsc_socket* sock, const char* address, uint16_t port);

/**
* \brief The Connect function establishes a connection to a remote host using IPv4 addressing
*
* \param sock: The socket instance
* \param address: [const] The remote hosts IPv4 address
* \param port: The remote hosts service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief The Connect function establishes a connection to a remote host using IPv6 addressing
*
* \param sock: The socket instance
* \param address: [const] The remote hosts IPv6 address
* \param port: The remote hosts service port number
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief The Create function creates a socket that is bound to a specific transport provider
*
* \param sock: The socket instance
* \param family: The address family
* \param transport: The transport layer
* \param protocol: The socket protocol
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_create(qsc_socket* sock, qsc_socket_address_families family, qsc_socket_transports transport, qsc_socket_protocols protocol);

/**
* \brief Places the socket in the listening state, waiting for a connection
*
* \param sock: [const] The socket instance
* \param backlog: The maximum pending connections queue length
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_listen(const qsc_socket* sock, int32_t backlog);

/**
* \brief Receive data from a synchronous connected socket or a bound connection-less socket
*
* \param sock: [const] The socket instance
* \param output: The output buffer that receives data
* \param outlen: The length of the output received
* \param flag: Flags that influence the behavior of the receive function
*
* \return Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive(const qsc_socket* sock, uint8_t* output, size_t outlen, qsc_socket_receive_flags flag);

/**
* \brief Receive data from a connected socket asynchronously
*
* \param state: A pointer to the async receive data structure
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_receive_async(qsc_socket_receive_async_state* state);

/**
* \brief Receive a block of data from a synchronous connected socket or a bound connection-less socket, and returns when buffer is full
*
* \param sock: [const] The socket instance
* \param output: The output buffer that receives data
* \param outlen: The length of the output received
* \param flag: Flags that influence the behavior of the receive function
*
* \return Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive_all(const qsc_socket* sock, uint8_t* output, size_t outlen, qsc_socket_receive_flags flag);

/**
* \brief Receive data from a synchronous connected socket or a bound connection-less socket
*
* \param sock: The local socket
* \param destination: The destination IP address string
* \param port: The port receiving the data
* \param output: The output buffer
* \param outlen: The length of the output buffer
* \param flag: Flags that influence the behavior of the receive from function
*
* \return Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive_from(qsc_socket* sock, char* destination, uint16_t port, uint8_t* output, size_t outlen, qsc_socket_receive_flags flag);

/**
* \brief Polls an array of sockets.
* Fires a callback if a socket is ready to receive data, or an error if socket is disconnected.
*
* \param state: [const] The server state, containing a pointer to an array of sockets
*
* \return Returns the number of sockets with data
*/
QSC_EXPORT_API uint32_t qsc_socket_receive_poll(const qsc_socket_receive_poll_state* state);

/**
* \brief Sends data on a TCP connected socket
*
* \param sock: [const] The socket instance
* \param input: [const] The input buffer containing the data to be transmitted
* \param inlen: The number of bytes to send
* \param flag: Flags that influence the behavior of the send function
*
* \return Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send(const qsc_socket* sock, const uint8_t* input, size_t inlen, qsc_socket_send_flags flag);

/**
* \brief Sends data on a UDP socket
*
* \param sock: [const] The socket instance
* \param destination: [const] The destination address string
* \param destlen: The lenghth of the destination address string
* \param port: The destination port number
* \param input: [const] The input buffer containing the data to be transmitted
* \param inlen: The number of bytes to send
* \param flag: Flags that influence the behavior of the send function
*
* \return Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send_to(const qsc_socket* sock, const char* destination, size_t destlen, uint16_t port, const uint8_t* input, size_t inlen, qsc_socket_send_flags flag);

/**
* \brief Sends a block of data larger than a single packet size, on a TCP socket and returns when sent
*
* \param sock: [const] The socket instance
* \param input: [const] The input buffer containing the data to be transmitted
* \param inlen: The number of bytes to send
* \param flag: Flags that influence the behavior of the send function
*
* \return Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send_all(const qsc_socket* sock, const uint8_t* input, size_t inlen, qsc_socket_send_flags flag);

/**
* \brief Shuts down a socket
*
* \param sock: The socket instance
* \param parameters: The shutdown parameters
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_shut_down(qsc_socket* sock, qsc_socket_shut_down_flags parameters);

/*~~~ Helper Functions ~~~*/

/**
* \brief Returns the error string associated with the exception code
* \param code: The exception code
*
* \return [const] Returns the error string
*/
QSC_EXPORT_API const char* qsc_socket_error_to_string(qsc_socket_exceptions code);

/**
* \brief  the last error generated by the internal socket library
*
* \return Returns the last exception code
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_get_last_error(void);

/**
* \brief Sets the IO mode of the socket
*
* \param sock: [const] The socket instance
* \param command: The command to pass to the socket
* \param arguments: The command arguments
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_ioctl(const qsc_socket* sock, int32_t command, uint32_t* arguments);

/**
* \brief Tests the socket to see if it is ready to receive data
*
* \param sock: [const] The socket instance
* \param timeout: [const] The receive wait timeout
*
* \return Returns true if the socket is ready to receive data
*/
QSC_EXPORT_API bool qsc_socket_receive_ready(const qsc_socket* sock, const struct timeval* timeout);

/**
* \brief Tests the socket to see if it is ready to send data
*
* \param sock: [const] The socket instance
* \param timeout: [const] The maximum time to wait for a response from the socket
*
* \return Returns true if the socket is ready to send data
*/
QSC_EXPORT_API bool qsc_socket_send_ready(const qsc_socket* sock, const struct timeval* timeout);

/**
* \brief Set the last error generated by the socket library
*
* \param error: The error code
*/
QSC_EXPORT_API void qsc_socket_set_last_error(qsc_socket_exceptions error);

/**
* \brief Shut down the sockets library
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_shut_down_sockets(void);

/**
* \brief Send an option command to the socket.
* Options that use a boolean are format: 0=false, 1=true.
*
* \param sock: [const] The socket instance
* \param level: The level at which the option is assigned
* \param option: The option command to send
* \param optval: The value of the option command
*
* \return Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_set_option(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval);

/**
* \brief Start the sockets library
*
* \return Returns true on success
*/
QSC_EXPORT_API bool qsc_socket_start_sockets(void);

#endif
