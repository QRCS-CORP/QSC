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

#ifndef QSC_SOCKFLAGS_H
#define QSC_SOCKFLAGS_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

/**
* \file socketflags.h
* \brief The socket flags enumerations
*/

/*! \enum qsc_ipv6_address_prefix_types
* \brief IPv6 address prefixes
*/
typedef enum
{
	qsc_ipv6_prefix_none = 0x00U,							/*!< No prefix is set */
	qsc_ipv6_prefix_link_local = 0x01U,						/*!< An link local address type, not globally routable, prefix: fe80 */
	qsc_ipv6_prefix_multicast = 0x02U,						/*!< A qsc_ipv6_prefix_multicast address type, prefix: ff00 */
	qsc_ipv6_prefix_global = 0x03U,							/*!< A globally routable address type, prefix: 2000 */
	qsc_ipv6_prefix_unique_local = 0x04U					/*!< A unique local address type, not globally routable, prefix: fc00-fd00 */
} qsc_ipv6_address_prefix_types;

/*! \enum qsc_socket_address_families
* \brief The socket address family type
*/
typedef enum
{
	qsc_socket_address_family_none = 0x00000000L,		/*!< No address family is specified AF_UNSPEC */
	qsc_socket_address_family_unix = 0x00000001L,		/*!< Unix local to host (pipes, portals) AF_UNIX */
	qsc_socket_address_family_ipv4 = 0x00000002L,		/*!< The Internet Protocol 4 address family AF_INET */
	qsc_socket_address_family_ipv6 = 0x00000017L		/*!< The Internet Protocol 6 address family AF_INET6 */
} qsc_socket_address_families;

/*! \enum qsc_socket_states
* \brief The socket instance current connection state
*/
typedef enum
{
	qsc_socket_state_none = 0x00U,						/*!< The socket instance is not initialized */
	qsc_socket_state_connected = 0x01U,					/*!< The socket instance is connected */
	qsc_socket_state_listening = 0x02U,					/*!< The socket instance is listening */
	qsc_socket_state_connectionless = 0x03U				/*!< The socket is in connection-less mode */
} qsc_socket_states;

/*! \enum qsc_socket_options
* \brief TCP socket options
*/
typedef enum
{
	qsc_socket_option_none = 0x00000000L,				/*!< No flag is used */
	qsc_socket_option_broadcast = 0x00000020L,			/*!< Configures a socket for sending broadcast data SO_BROADCAST */
	qsc_socket_option_ipv6_only = 0x0000001BL,			/*!< Flag used to enable a dual stack configuration IPV6_V6ONLY */
	qsc_socket_option_keepalive = 0x00000008L,			/*!< Enables sending keep-alive packets for a socket connection SO_KEEPALIVE */
	qsc_socket_option_linger = 0x00000080L,				/*!< Lingers on close if unsent data is present SO_LINGER */
	qsc_socket_option_no_route = 0x00000010L,			/*!< Sets whether outgoing data should be sent on interface the socket is bound to and not a routed on some other interface SO_DONTROUTE */
	qsc_socket_option_out_of_band = 0x00000100L,		/*!< Indicates that out-of-bound data should be returned in-line with regular data SO_OOBINLINE */
	qsc_socket_option_reuse_address = 0x00000004L,		/*!< Enables or disables the reuse of a bound address */
	qsc_socket_option_receive_time_out = 0x00001006L,	/*!< The timeout, in milliseconds, for blocking received calls SO_RCVTIMEO */
	qsc_socket_option_send_time_out = 0x00001005L,		/*!< The timeout, in milliseconds, for blocking send calls SO_SNDTIMEO */
	qsc_socket_option_tcp_no_delay = 0x00000001L		/*!< Enables or disables the Nagle algorithm for TCP sockets. This option is disabled (set to FALSE) by default TCP_NODELAY */
} qsc_socket_options;

/*! \enum qsc_socket_protocols
* \brief The socket IP protocol type
*/
typedef enum
{
	qsc_socket_protocol_none = 0x00000000L,				/*!< No protocol type specified */
	qsc_socket_protocol_ipv4 = 0x00000004L,				/*!< Internet Protocol version 4 IPPROTO_IPV4 */
	qsc_socket_protocol_socket = 0x0000FFFFL,			/*!< Enables or disables a socket level option */
	qsc_socket_protocol_tcp = 0x00000006L,				/*!< Transport Control Protocol IPPROTO_TCP */
	qsc_socket_protocol_udp = 0x00000011L,				/*!< Unreliable Delivery Protocol IPPROTO_UDP */
	qsc_socket_protocol_ipv6 = 0x00000029L,				/*!< IPv6 header IPPROTO_IPV6 */
	qsc_socket_protocol_ipv6_routing = 0x0000002BL,		/*!< IPv6 Routing header IPPROTO_ROUTING */
	qsc_socket_protocol_ipv6_fragment = 0x0000002CL,	/*!< IPv6 fragmentation header IPPROTO_FRAGMENT */
	qsc_socket_protocol_icmpv6 = 0x0000003AL,			/*!< ICMPv6 IPPROTO_ICMPV6 */
	qsc_socket_protocol_ipv6_no_header = 0x0000003BL,	/*!< IPv6 no next header IPPROTO_NONE */
	qsc_socket_protocol_dstopts = 0x0000003CL,			/*!< IPv6 Destination options IPPROTO_DSTOPTS */
	qsc_socket_protocol_raw = 0x000000FFL				/*!< Raw Packet IPPROTO_RAW */
} qsc_socket_protocols;

/*! \enum qsc_socket_receive_flags
* \brief The socket receive api flags
*/
typedef enum
{
	qsc_socket_receive_flag_none = 0x00000000L,			/*!< No flag is used */
	qsc_socket_receive_flag_out_of_band = 0x00000001L,	/*!< Process out of band data MSG_OOB */
	qsc_socket_receive_flag_peek = 0x00000002L,			/*!< Peeks at the incoming data MSG_PEEK */ //0x40
#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_socket_receive_flag_wait_all = 0x00000008L		/*!< Request completes only when buffer is full MSG_WAITALL */
#elif defined(QSC_SYSTEM_OS_APPLE)
	qsc_socket_receive_flag_wait_all = 0x00000040L		/*!< Request completes only when buffer is full MSG_WAITALL */
#else
	qsc_socket_receive_flag_wait_all = 0x00000100L		/*!< Request completes only when buffer is full MSG_WAITALL */
#endif
} qsc_socket_receive_flags;

/*! \enum qsc_socket_send_flags
* \brief The socket send api flags
*/
typedef enum
{
	qsc_socket_send_flag_none = 0x00000000L,			/*!< No flag is used */
	qsc_socket_send_flag_send_oob = 0x00000001L,		/*!< Sends OOB data on a stream type socket MSG_OOB */
	qsc_socket_send_flag_peek_message = 0x00000002L,	/*!< Sends a partial message */
	qsc_socket_send_flag_no_routing = 0x00000004L,		/*!< The data packets should not be routed MSG_DONTROUTE */
} qsc_socket_send_flags;

/*! \enum qsc_socket_shut_down_flags
* \brief The socket shutdown api flags
*/
typedef enum
{
	qsc_socket_shut_down_flag_receive = 0x00000000L,	/*!< Shut down the receiving channel QSC_SOCKET_SD_RECEIVE */
	qsc_socket_shut_down_flag_send = 0x00000001L,		/*!< Shut down the sending channel QSC_SOCKET_SD_SEND */
	qsc_socket_shut_down_flag_both = 0x00000002L		/*!< Shut down both channels QSC_SOCKET_SD_BOTH */
} qsc_socket_shut_down_flags;

/*! \enum qsc_socket_transports
* \brief The socket transmission type
*/
typedef enum
{
	qsc_socket_transport_none = 0x00000000L,			/*!< No flag is used */
	qsc_socket_transport_stream = 0x00000001L,			/*!< Streaming connection SOCK_STREAM */
	qsc_socket_transport_datagram = 0x00000002L,		/*!< Datagram connection SOCK_DGRAM */
	qsc_socket_transport_raw = 0x00000003L,				/*!< TCP Raw socket SOCK_RAW */
	qsc_socket_transport_reliable = 0x00000004L,		/*!< Reliable protocol SOCK_RDM */
	qsc_socket_transport_sequenced = 0x00000005L		/*!< Sequenced packets SOCK_SEQPACKET */
} qsc_socket_transports;

QSC_CPLUSPLUS_ENABLED_END

#endif
