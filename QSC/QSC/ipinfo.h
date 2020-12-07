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
* Written by John G. Underhill
* Updated on November 11, 2020
* Contact: develop@vtdev.com */

#ifndef QSC_IPINFO_H
#define QSC_IPINFO_H

#include "common.h"
#include "arrayutils.h"
#include "intutils.h"
#include "memutils.h"
#include "socketflags.h"
#include <stdio.h>
#include <string.h>

/*!
\def QSC_IPV4_BYTELEN
* The ipv4 byte array length
*/
#define QSC_IPV4_BYTELEN 4

/*!
\def QSC_IPV4_STRNLEN
* The ipv4 string length
*/
#define QSC_IPV4_STRNLEN 22

/*!
\def QSC_IPV6_BYTELEN
* The ipv6 byte array length
*/
#define QSC_IPV6_BYTELEN 16

/*!
\def QSC_IPV6_STRNLEN
* The ipv6 string length
*/
#define QSC_IPV6_STRNLEN 65

/*! \struct qsc_ipv4_address
* \brief The IPv4 address structure
*/
QSC_EXPORT_API typedef struct qsc_ipv4_address
{
	uint8_t ipv4[QSC_IPV4_BYTELEN];	/*!< The ipv4 address array */
} qsc_ipv4_address;

/*! \struct ipv4_info
* \brief The IPv4 information structure containing the address and port number
*/
QSC_EXPORT_API typedef struct qsc_ipv4_info
{
	qsc_ipv4_address address;			/*!< A pointer to the ipv4 address structure */
	uint16_t port;						/*!< The port number */
	uint8_t mask;						/*!< The network mask */
} qsc_ipv4_info;

/**
* \brief Use the devices primary IPv4 address
*
* \return Returns the IPv4 primary address structure
*/
QSC_EXPORT_API qsc_ipv4_address qsc_ipv4_address_any();

/**
* \brief Clear the address structure
*
* \param address: The ipv4 address structure
*/
QSC_EXPORT_API void qsc_ipv4_address_destroy(qsc_ipv4_address* ctx);

/**
* \brief Instantiate an ipv4 address structure using a serialized 8-bit integer array
*
* \param badd: The byte array containing the serialized address
* \return Returns the initialized ipv4 address structure
*/
QSC_EXPORT_API qsc_ipv4_address qsc_ipv4_address_from_array(uint8_t badd[QSC_IPV4_BYTELEN]);

/**
* \brief Instantiate an ipv4 address structure using a set of 8-bit integers
*
* \param a1: The first address octet
* \param a2: The second address octet
* \param a3: The third address octet
* \param a4: The fourth address octet
* \return Returns the initialized ipv4 address structure
*/
QSC_EXPORT_API qsc_ipv4_address qsc_ipv4_address_from_bytes(uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4);

/**
* \brief Instantiate an address structure using a serialized address string
*
* \param address: The serialized address string
* \return Returns the initialized ipv4 address structure
*/
QSC_EXPORT_API qsc_ipv4_address qsc_ipv4_address_from_string(const char sadd[QSC_IPV4_STRNLEN]);

/**
* \brief Compare two ipv4 address structures for equivalence
*
* \param address: The first ipv4 address structure
* \param address: The second ipv4 address structure
* \return Returns true if address structures are equal
*/
QSC_EXPORT_API bool qsc_ipv4_is_equal(qsc_ipv4_address* a, qsc_ipv4_address* b);

/**
* \brief Get a copy of the IPv4 loopback address
*
* \return Returns a copy of the loopback address
*/
QSC_EXPORT_API qsc_ipv4_address qsc_ipv4_address_loop_back();

/**
* \brief Serialize an address structure to a string
*
* \param output: The serialized address string output array
* \param address: A pointer to the ipv4 address structure
* \return Returns the serialized ipv4 address string
*/
QSC_EXPORT_API void qsc_ipv4_address_to_string(char output[QSC_IPV4_STRNLEN], const qsc_ipv4_address* ctx);

/*! \struct qsc_ipv6_address
* \brief The IPv6 address structure
*/
QSC_EXPORT_API typedef struct qsc_ipv6_address
{
	uint8_t ipv6[QSC_IPV6_BYTELEN];	/*!< The ipv6 address array */
} qsc_ipv6_address;

/*! \struct ipv6_info
* \brief The IPv6 information structure containing the address and port number
*/
QSC_EXPORT_API typedef struct qsc_ipv6_info
{
	qsc_ipv6_address address;			/*!< A pointer to the ipv6 address structure */
	uint16_t port;						/*!< The port number */
	uint8_t mask;						/*!< The network mask */
} qsc_ipv6_info;

/**
* \brief Get the ipv6 address routing prefix type
*
* \param address: A pointer to the ipv6 address structure
* \return Returns the prefix type enumeral
*/
QSC_EXPORT_API qsc_ipv6_address_prefix_types qsc_ipv6_address_address_type(qsc_ipv6_address* ctx);

/**
* \brief Get a copy of the ipv6 loopback address
*
* \return Returns a copy of the loopback address
*/
QSC_EXPORT_API qsc_ipv6_address qsc_ipv6_address_any();

/**
* \brief Clear the ipv6 address structure
*
* \param address: The address structure
*/
QSC_EXPORT_API void qsc_ipv6_address_destroy(qsc_ipv6_address* ctx);

/**
* \brief Instantiate an ipv6 address structure using a serialized 8-bit integer array
*
* \param badd: The byte array containing the serialized address
* \return Returns the initialized ipv6 address structure
*/
QSC_EXPORT_API qsc_ipv6_address qsc_ipv6_address_from_array(uint8_t badd[QSC_IPV6_BYTELEN]);

/**
* \brief Instantiate an ipv6 address structure using a serialized address string
*
* \param address: The serialized address string
* \return Returns the initialized ipv6 address structure
*/
QSC_EXPORT_API qsc_ipv6_address qsc_ipv6_address_from_string(const char sadd[QSC_IPV6_STRNLEN]);

/**
* \brief Compare two ipv6 address structures for equivalence
*
* \param address: The first ipv6 address structure
* \param address: The second ipv6 address structure
* \return Returns true if address structures are equal
*/
QSC_EXPORT_API bool qsc_ipv6_is_equal(qsc_ipv6_address* a, qsc_ipv6_address* b);

/**
* \brief Check if the address is routable
*
* \param address: The address structure
* \return Returns true if the address is routable
*/
QSC_EXPORT_API bool qsc_ipv6_address_is_routable(qsc_ipv6_address* address);

/**
* \brief Get a copy of the ipv6 loopback address
*
* \return Returns a copy of the ipv6 loopback address
*/
QSC_EXPORT_API qsc_ipv6_address qsc_ipv6_address_loop_back();

/**
* \brief Serialize an ipv6 address structure to a string
*
* \param output: The serialized address string output array
* \param address: A pointer to the ipv6 address structure
* \return Returns the serialized ipv6 address string
*/
QSC_EXPORT_API char* qsc_ipv6_address_to_string(char output[QSC_IPV6_STRNLEN], const qsc_ipv6_address* ctx);

/**
* \brief Test the ip address functions
*
* \return Returns true if tests succeed
*/
QSC_EXPORT_API bool qsc_ip_address_self_test();

#endif