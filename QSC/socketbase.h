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

#ifndef QSC_SOCKETBASE_H
#define QSC_SOCKETBASE_H

#include "common.h"
#include "intutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "socket.h"

/**
 * \file socketbase.h
 * \brief Socket function definitions.
 *
 * \details
 * This header provides the fundamental function definitions, enums, and structures for socket-based networking.
 * It abstracts the underlying system-specific implementations for network socket operations,
 * enabling a unified interface for both Windows and POSIX systems. The API supports the creation,
 * configuration, and management of sockets for TCP/IP communication, including both IPv4 and IPv6.
 * Functions provided in this module handle tasks such as opening, closing, binding, and listening
 * on sockets, as well as setting various socket options and error handling.
 *
 * \section socketbase_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page">Windows Sockets (Winsock) Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html">POSIX Sockets Documentation</a>
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
#elif defined(QSC_SYSTEM_OS_POSIX)
#	include <errno.h>
#	include <netdb.h>
#	include <ifaddrs.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <sys/select.h>
#	include <sys/socket.h>
#	include <string.h>
#	include <sys/types.h>
#	include <sys/un.h>
#	include <unistd.h>
#	if defined(QSC_SYSTEM_OS_LINUX)
#		include <netpacket/packet.h>
#	elif defined(QSC_SYSTEM_OS_APPLE)
#		include <net/if_dl.h>
#		include <netinet/in.h>
//#		include <netinet/in6.h>
#		if !defined(AF_PACKET)
#			define AF_PACKET PF_INET
#		endif
#	elif defined(QSC_SYSTEM_OS_UNIX)

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
#define QSC_SOCKET_RECEIVE_BUFFER_SIZE 1600ULL

/*! \enum qsc_socket_exceptions
* \brief Socket code enumeration names
*/
typedef enum
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
typedef struct
{
	void (*callback)(qsc_socket* sock, const uint8_t* message, size_t* msglen);	/*!< A pointer to a callback function */
	void (*error)(const qsc_socket* sock, qsc_socket_exceptions exception);		/*!< A pointer to an error function */
	qsc_socket* source;															/*!< A pointer to the originating socket */
	uint8_t buffer[QSC_SOCKET_RECEIVE_BUFFER_SIZE];								/*!< A pointer to the message buffer */
} qsc_socket_receive_async_state;

/*! \struct qsc_socket_receive_poll_state
* \brief The socket polling state structure.
* The structure contains an array of client sockets,
* and a socket counter with sockets that are ready to receive data.
*/
typedef struct
{
	qsc_socket** sockarr;														/*!< A pointer to an array of sockets */
	void (*callback)(qsc_socket* sock, size_t id);								/*!< A pointer to a callback function */
	void (*error)(qsc_socket* sock, qsc_socket_exceptions exception);			/*!< A pointer to an error function */
	uint32_t count;																/*!< The number of active sockets */
} qsc_socket_receive_poll_state;

/*** Function Prototypes ***/

///**
//* \brief The socket exception callback prototype
//*
//* \param source:	[qsc_socket*] The socket source
//* \param error:		[qsc_socket_exceptions] The socket exception
//*/
//QSC_EXPORT_API void qsc_socket_exception_callback(qsc_socket* source, qsc_socket_exceptions error);

///**
//* \brief The socket receive asynchronous callback prototype
//*
//* \param source:	[qsc_socket*] The socket source
//* \param message:	[const uint8_t*] The socket message buffer
//* \param msglen:	[size_t*] A pointer to the size of the message
//*/
//QSC_EXPORT_API void qsc_socket_receive_async_callback(qsc_socket* source, const uint8_t* message, size_t* msglen);

///**
//* \brief The receive polling callback prototype
//*
//* \param source:	[const qsc_socket*] The socket source
//* \param error:		[size_t] The socket exception
//*/
//QSC_EXPORT_API void qsc_socket_receive_poll_callback(const qsc_socket* source, size_t error);

/*** Accessors ***/

/**
* \brief Detects if the string contains a valid IPV4 address
* \param address:	[const char*] The IP address string
*
* \return			[bool] Returns true if the address is a valid IPV4 address
*/
QSC_EXPORT_API bool qsc_socket_ipv4_valid_address(const char* address);

/**
* \brief Detects if the string contains a valid IPV6 address
* \param address:	[const char*] The IP address string
*
* \return			[bool] Returns true if the address is a valid IPV6 address
*/
QSC_EXPORT_API bool qsc_socket_ipv6_valid_address(const char* address);

/**
* \brief Determines if the socket is in blocking mode
*
* \param sock:		[const qsc_socket*] The socket instance
*
* \return			[bool] Returns true if the socket is blocking
*/
QSC_EXPORT_API bool qsc_socket_is_blocking(const qsc_socket* sock);

/**
* \brief Determines if the socket is connected
*
* \param sock:		[const qsc_socket*] The socket instance
*
* \return			[bool] Returns true if the socket is connected
*/
QSC_EXPORT_API bool qsc_socket_is_connected(const qsc_socket* sock);

/**
* \brief The Accept function handles an incoming connection attempt on the socket
*
* \param source:	[const qsc_socket*] The source listening socket instance
* \param target:	[const qsc_socket*] The socket receiving the new socket
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_accept(const qsc_socket* source, qsc_socket* target);

/**
* \brief Copy a socket to the target socket
*
* \param source:	[qsc_socket*] The source socket instance
* \param target:	[qsc_socket*] The socket to attach
*/
QSC_EXPORT_API void qsc_socket_attach(qsc_socket* source, qsc_socket* target);

/**
* \brief The Bind function associates an IP address with a socket
*
* \param sock:		[qsc_socket*] The socket instance
* \param address:	[const char*] The IP address to bind to the socket
* \param port:		[uint16_t] The service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind(qsc_socket* sock, const char* address, uint16_t port);

/**
* \brief The Bind function associates an IPv4 address with a socket
*
* \param sock:		[qsc_socket*] The socket instance
* \param address:	[const qsc_ipinfo_ipv4_address*] The IPv4 address to bind to the socket
* \param port:		[uint16_t] The service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief The Bind function associates an IPv6 address with a socket
*
* \param sock:		[qsc_socket*] The socket instance
* \param address:	[const qsc_ipinfo_ipv6_address*] The IPv6 address to bind to the socket
* \param port:		[uint16_t] The service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_bind_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Erases the socket struture
*
* \param sock:		[qsc_socket*] The socket instance
*/
QSC_EXPORT_API void qsc_socket_clear_socket(qsc_socket* sock);

/**
* \brief Closes and disposes of the socket
*
* \param sock:		[qsc_socket*] The socket instance
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_close_socket(qsc_socket* sock);

/**
* \brief The Connect function establishes a connection to a remote host
*
* \param sock:		[qsc_socket*] The socket instance
* \param address:	[const char*] The remote hosts IP address
* \param port:		[uint16_t] The remote hosts service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect(qsc_socket* sock, const char* address, uint16_t port);

/**
* \brief The Connect function establishes a connection to a remote host using IPv4 addressing
*
* \param sock:		[qsc_socket*] The socket instance
* \param address:	[const qsc_ipinfo_ipv4_address*] The remote hosts IPv4 address
* \param port:		[uint16_t] The remote hosts service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief The Connect function establishes a connection to a remote host using IPv6 addressing
*
* \param sock:		[qsc_socket*] The socket instance
* \param address:	[const] The remote hosts IPv6 address
* \param port:		[const qsc_ipinfo_ipv6_address*] The remote hosts service port number
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief The Create function creates a socket that is bound to a specific transport provider
*
* \param sock:		[qsc_socket*] The socket instance
* \param family:	[qsc_socket_address_families] The address family
* \param transport:	[qsc_socket_transports] The transport layer
* \param protocol:	[qsc_socket_protocols] The socket protocol
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_create(qsc_socket* sock, qsc_socket_address_families family, qsc_socket_transports transport, qsc_socket_protocols protocol);

/**
* \brief Places the socket in the listening state, waiting for a connection
*
* \param sock:		[const qsc_socket*] The socket instance
* \param backlog:	[int32_t] The maximum pending connections queue length
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_listen(const qsc_socket* sock, int32_t backlog);

/**
* \brief Get the maximum send buffer size for a socket
*
* \param sock:		[const qsc_socket*] The socket instance
*
* \return			[size_t] Returns the maximum length of a send buffer
*/
QSC_EXPORT_API size_t qsc_socket_max_send_buffer_size(const qsc_socket* sock);

/**
* \brief Receive data from a synchronous connected socket or a bound connection-less socket without downloading the entire message
*
* \param sock:		[const qsc_socket*] The socket instance
* \param output:	[uint8_t*] The output buffer that receives data
* \param otplen:	[size_t] The length of the output received
*
* \return			[size_t] Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_peek(const qsc_socket* sock, uint8_t* output, size_t otplen);

/**
* \brief Receive data from a synchronous connected socket or a bound connection-less socket.
* Note: the receive buffer must be at least 1 byte larger than the expected size to accomodate a packet terminator.
* When calling receive with the wait-all flag, the receiver must include the terminator to empty the buffer.
*
* \param sock:		[const qsc_socket*] The socket instance
* \param output:	[uint8_t*] The output buffer that receives data
* \param otplen:	[size_t] The length of the output received
* \param flag:		[qsc_socket_receive_flags] Flags that influence the behavior of the receive function
*
* \return			[size_t] Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag);

/**
* \brief Receive data from a connected socket asynchronously
*
* \param state:		[qsc_socket_receive_async_state*] A pointer to the async receive data structure
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_receive_async(qsc_socket_receive_async_state* state);

/**
* \brief Receive a block of data from a synchronous connected socket or a bound connection-less socket, and returns when buffer is full
*
* \param sock:		[const qsc_socket*] The socket instance
* \param output:	[uint8_t*] The output buffer that receives data
* \param otplen:	[size_t] The length of the output received
* \param flag:		[qsc_socket_receive_flags] Flags that influence the behavior of the receive function
*
* \return			[size_t] Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive_all(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag);

/**
* \brief Receive data from a synchronous connected socket or a bound connection-less socket
*
* \param sock:		[qsc_socket*] The local socket
* \param dest:		[char*] The destination IP address string
* \param port:		[uint16_t] The port receiving the data
* \param output:	[uint8_t*] The output buffer
* \param otplen:	[size_t] The length of the output buffer
* \param flag:		[qsc_socket_receive_flags] Flags that influence the behavior of the receive from function
*
* \return			[size_t] Returns the number of bytes received from the remote host
*/
QSC_EXPORT_API size_t qsc_socket_receive_from(qsc_socket* sock, char* dest, uint16_t port, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag);

/**
* \brief Polls an array of sockets.
* Fires a callback if a socket is ready to receive data, or an error if socket is disconnected.
*
* \param state:		[const qsc_socket_receive_poll_state*] The server state, containing a pointer to an array of sockets
*
* \return			[uint32_t] Returns the number of sockets with data
*/
QSC_EXPORT_API uint32_t qsc_socket_receive_poll(const qsc_socket_receive_poll_state* state);

/**
* \brief Sends data on a TCP connected socket.
* Note: The input buffer must be at least 1 byte longer than the input length.
* The send function terminates the packet with a null character for simplified string termination.
*
* \param sock:		[const qsc_socket*] The socket instance
* \param input:		[const uint8_t*] The input buffer containing the data to be transmitted
* \param inplen:	[size_t] The number of bytes to send
* \param flag:		[qsc_socket_send_flags] Flags that influence the behavior of the send function
*
* \return			[size_t] Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Sends data on a UDP socket
*
* \param sock:		[const qsc_socket*] The socket instance
* \param input:		[const uint8_t*] The input buffer containing the data to be transmitted
* \param inplen:	[size_t] The number of bytes to send
* \param flag:		[qsc_socket_send_flags] Flags that influence the behavior of the send function
*
* \return			[size_t] Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send_to(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Sends a block of data larger than a single packet size, on a TCP socket and returns when sent
*
* \param sock:		[const qsc_socket*] The socket instance
* \param input:		[const uint8_t*] The input buffer containing the data to be transmitted
* \param inplen:	[size_t] The number of bytes to send
* \param flag:		[qsc_socket_send_flags] Flags that influence the behavior of the send function
*
* \return			[size_t] Returns the number of bytes sent to the remote host
*/
QSC_EXPORT_API size_t qsc_socket_send_all(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag);

/**
* \brief Shuts down a socket
*
* \param sock:		[qsc_socket*] The socket instance
* \param params:	[qsc_socket_shut_down_flags] The shutdown parameters
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_shut_down(qsc_socket* sock, qsc_socket_shut_down_flags params);

/*~~~ Helper Functions ~~~*/

/**
* \brief Returns the error string associated with the exception code
* \param code:		[qsc_socket_exceptions] The exception code
*
* \return			[const char*] Returns the error string
*/
QSC_EXPORT_API const char* qsc_socket_error_to_string(qsc_socket_exceptions code);

/**
* \brief The last error generated by the internal socket library
*
* \return			[qsc_socket_exceptions] Returns the last exception code
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_get_last_error(void);

/**
* \brief Sets the IO mode of the socket
*
* \param sock:		[const qsc_socket*] [const] The socket instance
* \param command:	[int32_t] The command to pass to the socket
* \param arguments:	[uint32_t*] The command arguments
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_ioctl(const qsc_socket* sock, int32_t command, uint32_t* arguments);

/**
* \brief Tests the socket to see if it is ready to receive data
*
* \param sock:		[const qsc_socket*] The socket instance
* \param timeout:	[const struct timeval*] The receive wait timeout
*
* \return			[bool] Returns true if the socket is ready to receive data
*/
QSC_EXPORT_API bool qsc_socket_receive_ready(const qsc_socket* sock, const struct timeval* timeout);

/**
* \brief Tests the socket to see if it is ready to send data
*
* \param sock:		[const qsc_socket*] The socket instance
* \param timeout:	[const struct timeval*] The maximum time to wait for a response from the socket
*
* \return			[bool] Returns true if the socket is ready to send data
*/
QSC_EXPORT_API bool qsc_socket_send_ready(const qsc_socket* sock, const struct timeval* timeout);

/**
* \brief Set the last error generated by the socket library
*
* \param error:		[qsc_socket_exceptions] The error code
*/
QSC_EXPORT_API void qsc_socket_set_last_error(qsc_socket_exceptions error);

/**
* \brief Shut down the sockets library
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_shut_down_sockets(void);

/**
* \brief Send an option command to the socket.
* Options that use a boolean are format: 0=false, 1=true.
*
* \param sock:		[const qsc_socket*] The socket instance
* \param level:		[qsc_socket_protocols] The level at which the option is assigned
* \param option:	[qsc_socket_options] The option command to send
* \param optval:	[int32_t] The value of the option command
*
* \return			[qsc_socket_exceptions] Returns an exception code on failure, or success(0)
*/
QSC_EXPORT_API qsc_socket_exceptions qsc_socket_set_option(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval);

/**
* \brief Start the sockets library
*
* \return			[bool] Returns true on success
*/
QSC_EXPORT_API bool qsc_socket_start_sockets(void);

#endif
