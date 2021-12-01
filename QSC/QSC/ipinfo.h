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

#ifndef QSC_IPINFO_H
#define QSC_IPINFO_H

#include <stdio.h>
#include <string.h>
#include "common.h"
#include "arrayutils.h"
#include "intutils.h"
#include "memutils.h"
#include "socketflags.h"

/*
* \file ipinfo.h
* \brief IP information function definitions
*/

/*!
\def QSC_IPINFO_IPV4_BYTELEN
* The ipv4 byte array length
*/
#define QSC_IPINFO_IPV4_BYTELEN 0x04

/*!
\def QSC_IPINFO_IPV4_MINLEN
* The minimum ipv4 string length
*/
#define QSC_IPINFO_IPV4_MINLEN 0x08

/*!
\def QSC_IPINFO_IPV4_STRNLEN
* The ipv4 string length
*/
#define QSC_IPINFO_IPV4_STRNLEN 0x16

/*!
\def QSC_IPINFO_IPV4_MASK_STRNLEN
* The ipv4 subnet mask string length
*/
#define QSC_IPINFO_IPV4_MASK_STRNLEN 0x10

/*!
\def QSC_IPINFO_IPV6_BYTELEN
* The ipv6 byte array length
*/
#define QSC_IPINFO_IPV6_BYTELEN 0x10

/*!
\def QSC_IPINFO_IPV6_STRNLEN
* The ipv6 string length
*/
#define QSC_IPINFO_IPV6_STRNLEN 0x41

/*!
\def QSC_IPINFO_IPV6_MASK_STRNLEN
* The ipv6 subnet mask string length
*/
#define QSC_IPINFO_IPV6_MASK_STRNLEN 0x41

/*! \struct qsc_ipinfo_ipv4_address
* \brief The IPv4 address structure
*/
QSC_EXPORT_API typedef struct qsc_ipinfo_ipv4_address
{
	uint8_t ipv4[QSC_IPINFO_IPV4_BYTELEN];	/*!< The ipv4 address array */
} qsc_ipinfo_ipv4_address;

/*! \struct qsc_ipinfo_ipv4_info
* \brief The IPv4 information structure containing the address and port number
*/
QSC_EXPORT_API typedef struct qsc_ipinfo_ipv4_info
{
	qsc_ipinfo_ipv4_address address;		/*!< A pointer to the ipv4 address structure */
	uint16_t port;							        /*!< The port number */
	uint8_t mask;							        /*!< The network mask */
} qsc_ipinfo_ipv4_info;

/**
* \brief Use the devices primary IPv4 address
*
* \return Returns the IPv4 primary address structure
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_any(void);

/**
* \brief Clear the address structure
*
* \param address: The ipv4 address structure
*/
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_clear(qsc_ipinfo_ipv4_address* address);

/**
* \brief Instantiate an ipv4 address structure using a serialized 8-bit integer array
*
* \param address: [const] The byte array containing the serialized address
* \return Returns the initialized ipv4 address structure
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_array(const uint8_t* address);

/**
* \brief Instantiate an ipv4 address structure using a set of 8-bit integers
*
* \param a1: The first address octet
* \param a2: The second address octet
* \param a3: The third address octet
* \param a4: The fourth address octet
* \return Returns the initialized ipv4 address structure
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_bytes(uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4);

/**
* \brief Instantiate an address structure using a serialized address string
*
* \param input: [const]  serialized address string
* \return Returns the initialized ipv4 address structure
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_string(const char input[QSC_IPINFO_IPV4_STRNLEN]);

/**
* \brief Compare two ipv4 address structures for equivalence
*
* \param a: [const] The first ipv4 address structure
* \param b: [const] The second ipv4 address structure
* \return Returns true if address structures are equal
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_equal(const qsc_ipinfo_ipv4_address* a, const qsc_ipinfo_ipv4_address* b);

/**
* \brief Test the ipv4 address is a valid public address
*
* \param address: [const] The first ipv4 address structure
* \return Returns true if address is valid
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_routable(const qsc_ipinfo_ipv4_address* address);

/**
* \brief Test the ipv4 address for validity
*
* \param address: [const] The first ipv4 address structure
* \return Returns true if address is valid
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_valid(const qsc_ipinfo_ipv4_address* address);

/**
* \brief Test the ipv4 address for zeroed state
*
* \param address: [const] The first ipv4 address structure
* \return Returns true if address is zeroed
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_zeroed(const qsc_ipinfo_ipv4_address* address);

/**
* \brief Get a copy of the IPv4 loopback address
*
* \return Returns a copy of the loopback address
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_loopback(void);

/**
* \brief Get the IPv4 network subnet mask string
*
* \param mask: The output mask string
* \param address: [const] The first ipv4 address structure
* \return Returns the mask length in bits
*/
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_get_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], const qsc_ipinfo_ipv4_address* address);

/**
* \brief Get the IPv4 network subnet CIDR length
*
* \param address: [const] The first ipv4 address structure
* \return Returns the mask length in bits
*/
QSC_EXPORT_API uint8_t qsc_ipinfo_ipv4_address_get_cidr_mask(const qsc_ipinfo_ipv4_address* address);

/**
* \brief Serialize an ipv4 address structure to a byte array
*
* \param output: The address output byte array
* \param address: [const] A pointer to the ipv4 address structure
*/
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_to_array(uint8_t* output, const qsc_ipinfo_ipv4_address* address);

/**
* \brief Serialize an address structure to a string
*
* \param output: The serialized address string output array
* \param address: [const] A pointer to the ipv4 address structure
*/
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const qsc_ipinfo_ipv4_address* address);

/*! \struct qsc_ipinfo_ipv6_address
* \brief The IPv6 address structure
*/
QSC_EXPORT_API typedef struct qsc_ipinfo_ipv6_address
{
	uint8_t ipv6[QSC_IPINFO_IPV6_BYTELEN];	/*!< The ipv6 address array */
} qsc_ipinfo_ipv6_address;

/*! \struct qsc_ipinfo_ipv6_info
* \brief The IPv6 information structure containing the address and port number
*/
QSC_EXPORT_API typedef struct qsc_ipinfo_ipv6_info
{
	qsc_ipinfo_ipv6_address address;		/*!< A pointer to the ipv6 address structure */
	uint16_t port;							/*!< The port number */
	uint8_t mask;							/*!< The network mask */
} qsc_ipinfo_ipv6_info;

/**
* \brief Get the ipv6 address routing prefix type
*
* \param address: [const] A pointer to the ipv6 address structure
* \return Returns the prefix type enumeral
*/
QSC_EXPORT_API qsc_ipv6_address_prefix_types qsc_ipinfo_ipv6_address_type(const qsc_ipinfo_ipv6_address* address);

/**
* \brief Get a copy of the ipv6 loopback address
*
* \return Returns a copy of the loopback address
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_any(void);

/**
* \brief Clear the ipv6 address structure
*
* \param address: The address structure
*/
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_clear(qsc_ipinfo_ipv6_address* address);

/**
* \brief Instantiate an ipv6 address structure using a serialized 8-bit integer array
*
* \param address: [const] The byte array containing the serialized address
* \return Returns the initialized ipv6 address structure
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_array(const uint8_t* address);

/**
* \brief Instantiate an ipv6 address structure using a serialized address string
*
* \param input: [const] The serialized address string
* \return Returns the initialized ipv6 address structure
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_string(const char input[QSC_IPINFO_IPV6_STRNLEN]);

/**
* \brief Compare two ipv6 address structures for equivalence
*
* \param a: [const] The first ipv6 address structure
* \param b: [const] The second ipv6 address structure
* \return Returns true if address structures are equal
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_equal(const qsc_ipinfo_ipv6_address* a, const qsc_ipinfo_ipv6_address* b);

/**
* \brief Test the ipv6 address is a valid public address
*
* \param address: [const] The first ipv6 address structure
* \return Returns true if address is valid
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_routable(const qsc_ipinfo_ipv6_address* address);

/**
* \brief Test the ipv6 address for validity
*
* \param address: [const] The first ipv6 address structure
* \return Returns true if address is valid
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_valid(const qsc_ipinfo_ipv6_address* address);

/**
* \brief Test the ipv6 address for zeroed state
*
* \param address: [const] The first ipv6 address structure
* \return Returns true if address is zeroed
*/
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_zeroed(const qsc_ipinfo_ipv6_address* address);

/**
* \brief Get a copy of the ipv6 loopback address
*
* \return Returns a copy of the ipv6 loopback address
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_loopback(void);

/**
* \brief Get the IPv6 network subnet mask string and the CIDR length
*
* \param mask: The output mask string
* \param address: [const] The first ipv6 address structure
*/
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_get_mask(char mask[QSC_IPINFO_IPV6_MASK_STRNLEN], const qsc_ipinfo_ipv6_address* address);

/**
* \brief Get the IPv6 network subnet CIDR length
*
* \param address: [const] The first ipv6 address structure
* \param address: [const] The output mask string
* \return Returns the mask length in bits
*/
QSC_EXPORT_API uint8_t qsc_ipinfo_ipv6_address_get_cidr_mask(const qsc_ipinfo_ipv6_address* address);

/**
* \brief Serialize an ipv6 address structure to a byte array
*
* \param output: The address output byte array
* \param address: [const] A pointer to the ipv6 address structure
*/
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_to_array(uint8_t* output, const qsc_ipinfo_ipv6_address* address);

/**
* \brief Serialize an ipv6 address structure to a string
*
* \param output: The serialized address string output array
* \param address: [const] A pointer to the ipv6 address structure
* \return Returns the serialized ipv6 address string
*/
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const qsc_ipinfo_ipv6_address* address);

/**
* \brief Convert a subnet mask to a CIDR mask
*
* \param mask: [const] The subnet mask string
* \return Returns the mask length in bits
*/
QSC_EXPORT_API uint8_t qsc_ipinfo_ipv4_mask_to_cidr(const char mask[QSC_IPINFO_IPV4_MASK_STRNLEN]);

/**
* \brief Convert a CIDR mask to a subnet mask
*
* \param mask: The output mask string
* \param cidr: The input CIDR mask
*/
QSC_EXPORT_API void qsc_ipinfo_ipv4_cidr_to_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], uint8_t cidr);

#endif
