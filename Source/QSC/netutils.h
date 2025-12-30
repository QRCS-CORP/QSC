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

#ifndef QSC_NETUTILS_H
#define QSC_NETUTILS_H

#include "qsccommon.h"
#include "ipinfo.h"
#include "socket.h"
#include "socketbase.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file netutils.h
 * \brief Network utilities; common networking support functions.
 *
 * \details
 * This header provides utility functions for common networking tasks, including socket creation,
 * connection management, data transmission, and reception over TCP/IP. The implementation supports
 * both Microsoft Windows and POSIX-compliant systems, ensuring cross-platform compatibility with
 * the underlying networking protocols.
 *
 * \section netutils_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page">Microsoft Networking (Winsock)  </a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/sockets.html">POSIX Networking (BSD Sockets)</a>
 * - <a href="https://tools.ietf.org/html/rfc793">TCP/IP Protocol Specification</a>
 */

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
\def QSC_NETUTILS_ADAPTOR_NAME_SIZE
* The network adaptors info string
*/
#define QSC_NETUTILS_ADAPTOR_NAME_SIZE 0x104U

/*!
\def QSC_NETUTILS_ADAPTOR_DESCRIPTION_SIZE
* The network adaptors description string
*/
#define QSC_NETUTILS_ADAPTOR_DESCRIPTION_SIZE 0x84U

/*!
\def QSC_NETUTILS_ADAPTOR_INFO_ARRAY_SIZE
* The network adaptors info array size
*/
#define QSC_NETUTILS_ADAPTOR_INFO_ARRAY_SIZE 0x08U

/*!
\def QSC_NETUTILS_DOMAIN_NAME_SIZE
* The size of the domain name buffer
*/
#define QSC_NETUTILS_DOMAIN_NAME_SIZE 0x104U

/*!
\def QSC_NETUTILS_HOSTS_NAME_SIZE
* The size of the hosts name buffer
*/
#define QSC_NETUTILS_HOSTS_NAME_SIZE 0x104U

/*!
\def QSC_NETUTILS_IP_STRING_SIZE
* The IP address string size
*/
#define QSC_NETUTILS_IP_STRING_SIZE 0x80U

/*!
\def QSC_NETUTILS_MAC_ADDRESS_SIZE
* The MAC address buffer length
*/
#define QSC_NETUTILS_MAC_ADDRESS_SIZE 0x12U

/*!
\def QSC_NETUTILS_NAME_BUFFER_SIZE
* The size of the protocol name buffer
*/
#define QSC_NETUTILS_NAME_BUFFER_SIZE 0x80U

/*!
\def QSC_NETUTILS_SERVICE_NAME_BUFFER_SIZE
* The size of the service name buffer
*/
#define QSC_NETUTILS_SERVICE_NAME_BUFFER_SIZE 0x80U

/*!
\def QSC_NETUTILS_SUBNET_STRING_SIZE
* The size of the subnet string
*/
#define QSC_NETUTILS_SUBNET_STRING_SIZE 0x10U

/*! \struct qsc_netutils_adaptor_info
* \brief The netutils adaptor info structure
*/
typedef struct
{
	char desc[QSC_NETUTILS_ADAPTOR_DESCRIPTION_SIZE];	/*!< The description string  */
	char dhcp[QSC_NETUTILS_IP_STRING_SIZE];				/*!< The DHCP address  */
	char gateway[QSC_NETUTILS_IP_STRING_SIZE];			/*!< The IP gateway address  */
	char ip[QSC_NETUTILS_IP_STRING_SIZE];				/*!< The interface IP address  */
	char mac[QSC_NETUTILS_MAC_ADDRESS_SIZE];			/*!< The MAC address  */
	char name[QSC_NETUTILS_ADAPTOR_NAME_SIZE];			/*!< The host name  */
	char subnet[QSC_NETUTILS_IP_STRING_SIZE];			/*!< The subnet address  */

} qsc_netutils_adaptor_info;

//~~~IP Address~~~//

/**
* \brief Retrieves the address information on a named addressable interface
*
* \param info:		[qsc_netutils_adaptor_info*] The adaptor info structure
* \param infname:	[const char*]The adaptor interface name, ex 'eth0' or 'wlan0'
*/
QSC_EXPORT_API void qsc_netutils_get_adaptor_info(qsc_netutils_adaptor_info* info, const char* infname);

/**
* \brief Retrieves the mac address of the primary interface
*
* \param mac:		[uint8_t*] The output array receiving the MAC address
*/
QSC_EXPORT_API void qsc_netutils_get_mac_address(uint8_t mac[QSC_NETUTILS_MAC_ADDRESS_SIZE]);

/**
* \brief Parse a string for a number
*
* \param source:	[const char*] The string to convert
*
* \return			[uint32_t] The number found in the string
*/
QSC_EXPORT_API uint32_t qsc_netutils_atoi(const char* source);

/**
* \brief Retrieves the hosts domain name
*
* \param output:	[char*] The source socket instance
*
* \return			[size_t] Returns the peers name string
*/
QSC_EXPORT_API size_t qsc_netutils_get_domain_name(char output[QSC_NETUTILS_DOMAIN_NAME_SIZE]);

/**
* \brief Retrieves the host name of the local machine
*
* \param host:		[char*] The host-name string
* 
* \return			[bool] Returns true if the call succeeded
*/
QSC_EXPORT_API bool qsc_netutils_get_host_name(char host[QSC_NETUTILS_HOSTS_NAME_SIZE]);

/**
* \brief Retrieves fully qualified name from an IPv4 address
*
* \param address:	[const qsc_ipinfo_ipv4_address*] The input IPv4 address string
* \param host:		[char*] The output host name
*/
QSC_EXPORT_API void qsc_netutils_get_name_from_ipv4_address(const qsc_ipinfo_ipv4_address* address, char host[QSC_NETUTILS_HOSTS_NAME_SIZE]);

/**
* \brief Retrieves the local IPv4 address
*
* \param padd:		[qsc_ipinfo_ipv4_address*] The ipv6 address structure
* \return			[bool] Returns true on function success
*/
QSC_EXPORT_API bool qsc_netutils_get_ipv4_address(qsc_ipinfo_ipv4_address* padd);

/**
* \brief Retrieves the local IPv6 address
*
* \param padd:		[qsc_ipinfo_ipv6_address*] The ipv6 address structure
* \return			[bool] Returns true on function success
*/
QSC_EXPORT_API bool qsc_netutils_get_ipv6_address(qsc_ipinfo_ipv6_address* padd);

/**
* \brief Retrieves the IPv4 address information for a remote host
*
* \param pinfo:		[qsc_ipinfo_ipv4_info*] A pointer to the output ipinfo structure
* \param host:		[const char*] The hosts qualified name
* \param service:	[const char*] The service name
*/
QSC_EXPORT_API void qsc_netutils_get_ipv4_info(qsc_ipinfo_ipv4_info* pinfo, const char* host, const char* service);

/**
* \brief Retrieves the IPv6 address information for a remote host
*
* \param pinfo:		[qsc_ipinfo_ipv6_info*] A pointer to the output ipinfo structure
* \param host:		[const char*] The hosts qualified name
* \param service:	[const char*] The service name
*/
QSC_EXPORT_API void qsc_netutils_get_ipv6_info(qsc_ipinfo_ipv6_info* pinfo, const char* host, const char* service);

/**
* \brief Retrieves the host name of the connected peer
*
* \param output:	[char*] The output buffer
* \param sock:		[const char*] The source socket instance
*/
QSC_EXPORT_API void qsc_netutils_get_peer_name(char output[QSC_NETUTILS_HOSTS_NAME_SIZE], const qsc_socket* sock);

/**
* \brief Retrieves the socket name of the connected peer
*
* \param output:	[char*] The output buffer
* \param sock:		[const qsc_socket*] The source socket instance
*/
QSC_EXPORT_API void qsc_netutils_get_socket_name(char output[QSC_NETUTILS_NAME_BUFFER_SIZE], const qsc_socket* sock);

/**
* \brief Get the port number using the connection parameters
*
* \param portname:	[const char*] The port name
* \param protocol:	[const char*] The protocol name
*
* \return The port number, or zero on failure
*/
QSC_EXPORT_API uint16_t qsc_netutils_port_name_to_number(const char* portname, const char* protocol);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print the output of network function calls
*/
QSC_EXPORT_API void qsc_netutils_values_print(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
