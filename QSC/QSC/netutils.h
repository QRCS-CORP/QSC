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
* An implementation of common networking support functions
* Written by John G. Underhill
* Updated on December 1, 2020
* Contact: develop@vtdev.com */

/*
* \file netutils.h
* \brief <b>Network utilities; common networking support functions</b> \n
* This file contains common network functions
* December 1, 2020
*/

#ifndef QSC_NETUTILS_H
#define QSC_NETUTILS_H

#include "common.h"
#include "ipinfo.h"
#include "socketbase.h"

/*!
\def NET_HOSTS_NAME_BUFFER
* The size of the hosts name buffer
*/
#define NET_HOSTS_NAME_BUFFER 255

/*!
\def NET_PROTOCOL_NAME_BUFFER
* The size of the protocol name buffer
*/
#define NET_PROTOCOL_NAME_BUFFER 128

/*!
\def NET_SERVICE_NAME_BUFFER
* The size of the service name buffer
*/
#define NET_SERVICE_NAME_BUFFER 128

//~~~IP Address~~~//

/**
* \brief Retrieves the local IPv4 address
*
* \return The default interface ip address
*/
QSC_EXPORT_API qsc_ipv4_address qsc_netutils_get_ipv4_address();

/**
* \brief Retrieves the local IPv6 address
*
* \return The default interface ip address
*/
QSC_EXPORT_API qsc_ipv6_address qsc_netutils_get_ipv6_address();

/**
* \brief Retrieves the local IPv4 address information for a remote host
*
* \param host: The hosts qualified name
* \param service: The service name
*
* \return Returns the default interface ip info
*/
QSC_EXPORT_API qsc_ipv4_info qsc_netutils_get_ipv4_info(const char host[NET_HOSTS_NAME_BUFFER], const char service[NET_SERVICE_NAME_BUFFER]);

/**
* \brief Retrieves the local IPv6 address information for a remote host
*
* \param host: The hosts qualified name
* \param service: The service name
*
* \return Returns the default interface ip info
*/
QSC_EXPORT_API qsc_ipv6_info qsc_netutils_get_ipv6_info(const char host[NET_HOSTS_NAME_BUFFER], const char service[NET_SERVICE_NAME_BUFFER]);

/**
* \brief Retrieves the name of the connected peer
*
* \param source: The source socket instance
*
* \return Returns the peers name string
*/
QSC_EXPORT_API void qsc_netutils_get_peer_name(char output[NET_HOSTS_NAME_BUFFER], qsc_socket* source);

/**
* \brief
*
* \param source: The source socket instance
*
* \return Retrieves the name of the socket
*/
QSC_EXPORT_API void qsc_netutils_get_socket_name(char output[NET_PROTOCOL_NAME_BUFFER], qsc_socket* source);

/**
* \brief Get the port number using the connection parameters
*
* \param name: The service name
* \param protocol: The protocol name
*
* \return The port number, or zero on failure
*/
QSC_EXPORT_API uint16_t qsc_netutils_port_name_to_number(const char portname[NET_HOSTS_NAME_BUFFER], const char protocol[NET_PROTOCOL_NAME_BUFFER]);

/**
* \brief Test the netutils fumctions for correct operation
*
*
* \return Returns true fpr success
*/
QSC_EXPORT_API bool qsc_netutils_self_test();

#endif
