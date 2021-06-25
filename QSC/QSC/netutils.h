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
*
*
* Implementation Details:
* An implementation of common networking support functions
* Written by John G. Underhill
* Updated on March 30, 2021
* Contact: support@vtdev.com */

/*
* \file netutils.h
* \brief <b>Network utilities; common networking support functions</b> \n
* December 1, 2020
*/

#ifndef QSC_NETUTILS_H
#define QSC_NETUTILS_H

#include "common.h"
#include "ipinfo.h"
#include "socketbase.h"

/*!
\def NET_MAC_ADAPTOR_INFO
* The network adaptors info string
*/
#define QSC_NET_MAC_ADAPTOR_NAME 260

/*!
\def QSC_NET_MAC_ADAPTOR_DESCRIPTION
* The network adaptors description string
*/
#define QSC_NET_MAC_ADAPTOR_DESCRIPTION 132

/*!
\def QSC_NET_MAC_ADAPTOR_INFO_ARRAY
* The network adaptors info array size
*/
#define QSC_NET_MAC_ADAPTOR_INFO_ARRAY 8

/*!
\def QSC_NET_IP_STRING_SIZE
* The ip address string size
*/
#define QSC_NET_IP_STRING_SIZE 128

/*!
\def QSC_NET_HOSTS_NAME_BUFFER
* The size of the hosts name buffer
*/
#define QSC_NET_HOSTS_NAME_BUFFER 260

/*!
\def QSC_NET_MAC_ADDRESS_LENGTH
* The mac address buffer length
*/
#define QSC_NET_MAC_ADDRESS_LENGTH 8

/*!
\def QSC_NET_PROTOCOL_NAME_BUFFER
* The size of the protocol name buffer
*/
#define QSC_NET_PROTOCOL_NAME_BUFFER 128

/*!
\def QSC_NET_SERVICE_NAME_BUFFER
* The size of the service name buffer
*/
#define QSC_NET_SERVICE_NAME_BUFFER 128

typedef struct qsc_netutils_adaptor_info
{
	char desc[QSC_NET_MAC_ADAPTOR_DESCRIPTION];
	char dhcp[QSC_NET_IP_STRING_SIZE];
	char gateway[QSC_NET_IP_STRING_SIZE];
	char ip[QSC_NET_IP_STRING_SIZE];
	uint8_t mac[QSC_NET_MAC_ADDRESS_LENGTH];
	char name[QSC_NET_MAC_ADAPTOR_NAME];
	char subnet[QSC_NET_IP_STRING_SIZE];

} qsc_netutils_adaptor_info;

//~~~IP Address~~~//

/**
* \brief Retrieves the MAC address of the first addressable interface
*
* \param mac: The MAC address
*/
QSC_EXPORT_API void qsc_netutils_get_adaptor_info(qsc_netutils_adaptor_info* info);

/**
* \brief Retrieves the MAC address of the first addressable interface
*
* \param mac: The MAC address
*/
QSC_EXPORT_API void qsc_netutils_get_adaptor_info_array(qsc_netutils_adaptor_info ctx[QSC_NET_MAC_ADAPTOR_INFO_ARRAY]);

/**
* \brief Retrieves the hosts domain name
*
* \param output: The source socket instance
*
* \return Returns the peers name string
*/
QSC_EXPORT_API size_t qsc_netutils_get_domain_name(char output[QSC_NET_HOSTS_NAME_BUFFER]);

/**
* \brief Retrieves the local IPv4 address
*
* \return The default interface ip address
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_netutils_get_ipv4_address();

/**
* \brief Retrieves the local IPv6 address
*
* \return The default interface ip address
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_netutils_get_ipv6_address();

/**
* \brief Retrieves the local IPv4 address information for a remote host
*
* \param host: The hosts qualified name
* \param service: The service name
*
* \return Returns the default interface ip info
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_info qsc_netutils_get_ipv4_info(const char host[QSC_NET_HOSTS_NAME_BUFFER], const char service[QSC_NET_SERVICE_NAME_BUFFER]);

/**
* \brief Retrieves the local IPv6 address information for a remote host
*
* \param host: The hosts qualified name
* \param service: The service name
*
* \return Returns the default interface ip info
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_info qsc_netutils_get_ipv6_info(const char host[QSC_NET_HOSTS_NAME_BUFFER], const char service[QSC_NET_SERVICE_NAME_BUFFER]);

/**
* \brief Retrieves the MAC address of the first addressable interface
*
* \param mac: The MAC address
*/
QSC_EXPORT_API void qsc_netutils_get_mac_address(uint8_t mac[QSC_NET_MAC_ADDRESS_LENGTH]);

/**
* \brief Retrieves the name of the connected peer
*
* \param sock: The source socket instance
*
* \return Returns the peers name string
*/
QSC_EXPORT_API void qsc_netutils_get_peer_name(char output[QSC_NET_HOSTS_NAME_BUFFER], qsc_socket* sock);

/**
* \brief
*
* \param sock: The source socket instance
*
* \return Retrieves the name of the socket
*/
QSC_EXPORT_API void qsc_netutils_get_socket_name(char output[QSC_NET_PROTOCOL_NAME_BUFFER], qsc_socket* sock);

/**
* \brief Get the port number using the connection parameters
*
* \param name: The service name
* \param protocol: The protocol name
*
* \return The port number, or zero on failure
*/
QSC_EXPORT_API uint16_t qsc_netutils_port_name_to_number(const char portname[QSC_NET_HOSTS_NAME_BUFFER], const char protocol[QSC_NET_PROTOCOL_NAME_BUFFER]);

/**
* \brief Test the netutils fumctions for correct operation
*
*
* \return Returns true fpr success
*/
QSC_EXPORT_API bool qsc_netutils_self_test();

#endif
