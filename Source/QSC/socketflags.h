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

#ifndef QSC_SOCKFLAGS_H
#define QSC_SOCKFLAGS_H

#include "qsccommon.h"

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
	qsc_ipv6_prefix_none = 0x00U,						/*!< No prefix is set */
	qsc_ipv6_prefix_link_local = 0x01U,					/*!< A link local address type, not globally routable, prefix: fe80 */
	qsc_ipv6_prefix_multicast = 0x02U,					/*!< A multicast address type, prefix: ff00 */
	qsc_ipv6_prefix_global = 0x03U,						/*!< A globally routable address type, prefix: 2000 */
	qsc_ipv6_prefix_unique_local = 0x04U				/*!< A unique local address type, not globally routable, prefix: fc00-fd00 */
} qsc_ipv6_address_prefix_types;

/*! \enum qsc_socket_address_families
 * \brief The socket address family type
 */
typedef enum
{
	qsc_socket_address_family_none = 0x00000000L,		/*!< No address family is specified AF_UNSPEC */
	qsc_socket_address_family_unix = 0x00000001L,		/*!< Unix local to host (pipes, portals) AF_UNIX */
	qsc_socket_address_family_ipv4 = 0x00000002L,		/*!< The Internet Protocol 4 address family AF_INET */
#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_socket_address_family_ipv6 = 23,				/*!< The Internet Protocol 6 address family AF_INET6 */
#elif defined(QSC_SYSTEM_OS_LINUX)
	qsc_socket_address_family_ipv6 = 10,				/*!< The Internet Protocol 6 address family AF_INET6 */
#elif defined(QSC_SYSTEM_OS_MAC)
	qsc_socket_address_family_ipv6 = 30,				/*!< The Internet Protocol 6 address family AF_INET6 */
#elif defined(QSC_SYSTEM_OS_FREEBSD)
	qsc_socket_address_family_ipv6 = 28,				/*!< The Internet Protocol 6 address family AF_INET6 */
#else	/* OpenBSD, NetBSD, and other POSIX */
	qsc_socket_address_family_ipv6 = 24,				/*!< The Internet Protocol 6 address family AF_INET6 */
#endif
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
#if defined(QSC_SYSTEM_OS_LINUX)
	qsc_socket_option_broadcast = 6,					/*!< Configures a socket for sending broadcast data SO_BROADCAST */
	qsc_socket_option_ipv6_only = 26,					/*!< Flag used to enable a dual stack configuration IPV6_V6ONLY */
	qsc_socket_option_keepalive = 9,					/*!< Enables sending keep-alive packets for a socket connection SO_KEEPALIVE */
	qsc_socket_option_linger = 13,						/*!< Lingers on close if unsent data is present SO_LINGER */
	qsc_socket_option_no_route = 5,						/*!< Sets whether outgoing data should be sent on the bound interface and not routed SO_DONTROUTE */
	qsc_socket_option_out_of_band = 10,					/*!< Indicates that out-of-band data should be returned in-line with regular data SO_OOBINLINE */
	qsc_socket_option_reuse_address = 2,				/*!< Enables or disables the reuse of a bound address SO_REUSEADDR */
	qsc_socket_option_receive_time_out = 20,			/*!< The timeout, in milliseconds, for blocking receive calls SO_RCVTIMEO */
	qsc_socket_option_send_time_out = 21,				/*!< The timeout, in milliseconds, for blocking send calls SO_SNDTIMEO */
#else	/* Windows, macOS, BSD */
	qsc_socket_option_broadcast = 0x00000020L,			/*!< Configures a socket for sending broadcast data SO_BROADCAST */
	qsc_socket_option_ipv6_only = 0x0000001BL,			/*!< Flag used to enable a dual stack configuration IPV6_V6ONLY */
	qsc_socket_option_keepalive = 0x00000008L,			/*!< Enables sending keep-alive packets for a socket connection SO_KEEPALIVE */
	qsc_socket_option_linger = 0x00000080L,				/*!< Lingers on close if unsent data is present SO_LINGER */
	qsc_socket_option_no_route = 0x00000010L,			/*!< Sets whether outgoing data should be sent on the bound interface and not routed SO_DONTROUTE */
	qsc_socket_option_out_of_band = 0x00000100L,		/*!< Indicates that out-of-band data should be returned in-line with regular data SO_OOBINLINE */
	qsc_socket_option_reuse_address = 0x00000004L,		/*!< Enables or disables the reuse of a bound address SO_REUSEADDR */
	qsc_socket_option_receive_time_out = 0x00001006L,	/*!< The timeout, in milliseconds, for blocking receive calls SO_RCVTIMEO */
	qsc_socket_option_send_time_out = 0x00001005L,		/*!< The timeout, in milliseconds, for blocking send calls SO_SNDTIMEO */
#endif
	qsc_socket_option_tcp_no_delay = 0x00000001L,		/*!< Enables or disables the Nagle algorithm for TCP sockets TCP_NODELAY */
} qsc_socket_options;

/*! \enum qsc_socket_protocols
 * \brief The socket IP protocol type
 */
typedef enum
{
	qsc_socket_protocol_none = 0x00000000L,				/*!< No protocol type specified */
	qsc_socket_protocol_ipv4 = 0x00000004L,				/*!< Internet Protocol version 4 IPPROTO_IPV4 */
#if defined(QSC_SYSTEM_OS_LINUX)
	qsc_socket_protocol_socket = 1,						/*!< Enables or disables a socket level option SOL_SOCKET */
#else	/* Windows, macOS, BSD */
	qsc_socket_protocol_socket = 0x0000FFFFL,			/*!< Enables or disables a socket level option SOL_SOCKET */
#endif
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
	qsc_socket_receive_flag_peek = 0x00000002L,			/*!< Peeks at the incoming data MSG_PEEK */
#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_socket_receive_flag_wait_all = 0x00000008L		/*!< Request completes only when buffer is full MSG_WAITALL */
#elif defined(QSC_SYSTEM_OS_MAC)
	qsc_socket_receive_flag_wait_all = 0x00000040L		/*!< Request completes only when buffer is full MSG_WAITALL */
#else	/* Linux, BSD */
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
	qsc_socket_send_flag_peek_message = 0x00000002L,	/*!< Sends a partial message MSG_PEEK */
	qsc_socket_send_flag_no_routing = 0x00000004L,		/*!< The data packets should not be routed MSG_DONTROUTE */
} qsc_socket_send_flags;

/*! \enum qsc_socket_shut_down_flags
 * \brief The socket shutdown api flags
 */
typedef enum
{
	qsc_socket_shut_down_flag_receive = 0x00000000L,	/*!< Shut down the receiving channel SHUT_RD */
	qsc_socket_shut_down_flag_send = 0x00000001L,		/*!< Shut down the sending channel SHUT_WR */
	qsc_socket_shut_down_flag_both = 0x00000002L		/*!< Shut down both channels SHUT_RDWR */
} qsc_socket_shut_down_flags;

/*! \enum qsc_socket_transports
 * \brief The socket transmission type
 */
typedef enum
{
	qsc_socket_transport_none = 0x00000000L,			/*!< No flag is used */
	qsc_socket_transport_stream = 0x00000001L,			/*!< Streaming connection SOCK_STREAM */
	qsc_socket_transport_datagram = 0x00000002L,		/*!< Datagram connection SOCK_DGRAM */
	qsc_socket_transport_raw = 0x00000003L,				/*!< Raw socket SOCK_RAW */
	qsc_socket_transport_reliable = 0x00000004L,		/*!< Reliable protocol SOCK_RDM */
	qsc_socket_transport_sequenced = 0x00000005L		/*!< Sequenced packets SOCK_SEQPACKET */
} qsc_socket_transports;

QSC_CPLUSPLUS_ENABLED_END

#endif
