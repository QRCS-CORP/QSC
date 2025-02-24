/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef QSC_IPINFO_H
#define QSC_IPINFO_H

#include <stdio.h>
#include <string.h>
#include "common.h"
#include "arrayutils.h"
#include "intutils.h"
#include "memutils.h"
#include "socketflags.h"
#include "stringutils.h"

/*!
 * \file ipinfo.h
 * \brief IP information function definitions.
 *
 * \details
 * This header provides functions for working with IP addresses, including determining the type of an IP address,
 * creating and comparing IPv4 and IPv6 address structures, serializing and deserializing IP addresses,
 * and converting between various representations such as strings, arrays, and CIDR masks.
 *
 * \code
 * // Example usage:
 * ipinfo_t info;
 * if (ipinfo_parse("192.168.1.1", &info)) {
 *     // Process the parsed IP address.
 * }
 * \endcode
 *
 * \section ipinfo_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page">Microsoft Sockets Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html">POSIX Sockets Documentation</a>
 */

/*!
 * \def QSC_IPINFO_IPV4_BYTELEN
 * \brief The IPv4 byte array length.
 */
#define QSC_IPINFO_IPV4_BYTELEN 0x04U

/*!
 * \def QSC_IPINFO_IPV4_MINLEN
 * \brief The minimum IPv4 string length.
 */
#define QSC_IPINFO_IPV4_MINLEN 0x08U

/*!
 * \def QSC_IPINFO_IPV4_STRNLEN
 * \brief The IPv4 string length.
 */
#define QSC_IPINFO_IPV4_STRNLEN 0x16U

/*!
 * \def QSC_IPINFO_IPV4_MASK_STRNLEN
 * \brief The IPv4 subnet mask string length.
 */
#define QSC_IPINFO_IPV4_MASK_STRNLEN 0x10U

/*!
 * \def QSC_IPINFO_IPV6_BYTELEN
 * \brief The IPv6 byte array length.
 */
#define QSC_IPINFO_IPV6_BYTELEN 0x10U

/*!
 * \def QSC_IPINFO_IP_MAX_BYTELEN
 * \brief The maximum IP byte array length.
 */
#define QSC_IPINFO_IP_MAX_BYTELEN (QSC_IPINFO_IPV6_BYTELEN)

/*!
 * \def QSC_IPINFO_IPV6_STRNLEN
 * \brief The IPv6 string length.
 */
#define QSC_IPINFO_IPV6_STRNLEN 0x41U

/*!
 * \def QSC_IPINFO_IPV6_MASK_STRNLEN
 * \brief The IPv6 subnet mask string length.
 */
#define QSC_IPINFO_IPV6_MASK_STRNLEN 0x41U

/*!
 * \def QSC_IPINFO_MAX_SIZE
 * \brief The maximum IP string length.
 */
#define QSC_IPINFO_MAX_SIZE (QSC_IPINFO_IPV6_STRNLEN)

/*!
 * \enum qsc_ipinfo_address_types
 * \brief The IP address family types.
 */
QSC_EXPORT_API typedef enum
{
    qsc_ipinfo_address_type_none = 0x00U,    /*!< The address type is not set. */
    qsc_ipinfo_address_type_ipv4 = 0x01U,    /*!< The address type is IPv4. */
    qsc_ipinfo_address_type_ipv6 = 0x02U,    /*!< The address type is IPv6. */
    qsc_ipinfo_address_type_unknown = 0xFFU  /*!< The address type is unknown. */
} qsc_ipinfo_address_types;

/*!
 * \struct qsc_ipinfo_ipv4_address
 * \brief The IPv4 address structure.
 *
 * Contains an array representing an IPv4 address.
 */
QSC_EXPORT_API typedef struct
{
    uint8_t ipv4[QSC_IPINFO_IPV4_BYTELEN];  /*!< The IPv4 address array. */
} qsc_ipinfo_ipv4_address;

/*!
 * \struct qsc_ipinfo_ipv4_info
 * \brief The IPv4 information structure.
 *
 * Contains an IPv4 address along with a port number and a network mask.
 */
QSC_EXPORT_API typedef struct
{
    qsc_ipinfo_ipv4_address address;    /*!< The IPv4 address structure. */
    uint16_t port;                      /*!< The port number. */
    uint8_t mask;                       /*!< The network mask. */
} qsc_ipinfo_ipv4_info;

/**
 * \brief Determine the IP address type from a string.
 *
 * \param address:  [const char*] A pointer to the address string.
 * \return          [qsc_ipinfo_address_types] Returns the IP address type.
 */
QSC_EXPORT_API qsc_ipinfo_address_types qsc_ipinfo_get_address_type(const char* address);

/**
 * \brief Use the device's primary IPv4 address.
 *
 * \return          [qsc_ipinfo_ipv4_address] Returns the primary IPv4 address structure.
 */
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_any(void);

/**
 * \brief Clear the IPv4 address structure.
 *
 * \param address:  [qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_clear(qsc_ipinfo_ipv4_address* address);

/**
 * \brief Instantiate an IPv4 address structure from a byte array.
 *
 * \param address:  [const uint8_t*] A pointer to the byte array containing the serialized address.
 * \return          [qsc_ipinfo_ipv4_address] Returns the initialized IPv4 address structure.
 */
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_array(const uint8_t* address);

/**
 * \brief Instantiate an IPv4 address structure from individual bytes.
 *
 * \param a1:       [uint8_t] The first address octet.
 * \param a2:       [uint8_t] The second address octet.
 * \param a3:       [uint8_t] The third address octet.
 * \param a4:       [uint8_t] The fourth address octet.
 * \return          [qsc_ipinfo_ipv4_address] Returns the initialized IPv4 address structure.
 */
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_bytes(uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4);

/**
 * \brief Instantiate an IPv4 address structure from a string.
 *
 * \param input:    [const char*] A pointer to the serialized address string.
 * \return          [qsc_ipinfo_ipv4_address] Returns the initialized IPv4 address structure.
 */
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_string(const char input[QSC_IPINFO_IPV4_STRNLEN]);

/**
 * \brief Compare two IPv4 address structures for equality.
 *
 * \param a:        [const qsc_ipinfo_ipv4_address*] A pointer to the first IPv4 address structure.
 * \param b:        [const qsc_ipinfo_ipv4_address*] A pointer to the second IPv4 address structure.
 * \return          [bool] Returns true if the address structures are equal.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_equal(const qsc_ipinfo_ipv4_address* a, const qsc_ipinfo_ipv4_address* b);

/**
 * \brief Test if the IPv4 address is a valid public address.
 *
 * \param address:  [const qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 * \return          [bool] Returns true if the address is valid.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_routable(const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Test if the IPv4 address is valid.
 *
 * \param address:  [const qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 * \return          [bool] Returns true if the address is valid.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_valid(const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Test if the IPv4 address string is valid.
 *
 * \param address:  [const char*] A pointer to the IPv4 address string.
 * \return          [bool] Returns true if the address string is valid.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_string_is_valid(const char* address);

/**
 * \brief Test if the IPv4 address is zeroed.
 *
 * \param address:  [const qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 * \return          [bool] Returns true if the address is zeroed.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv4_address_is_zeroed(const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Get a copy of the IPv4 loopback address.
 *
 * \return          [qsc_ipinfo_ipv4_address] Returns a copy of the IPv4 loopback address.
 */
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_loopback(void);

/**
 * \brief Get the IPv4 network subnet mask string.
 *
 * \param mask:     [char*] The output mask string.
 * \param address:  [const qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_get_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Get the IPv4 network subnet CIDR length.
 *
 * \param address:  [const qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 * \return          [uint8_t] Returns the mask length in bits.
 */
QSC_EXPORT_API uint8_t qsc_ipinfo_ipv4_address_get_cidr_mask(const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Serialize an IPv4 address structure to a byte array.
 *
 * \param output:   [uint8_t*] The address output byte array.
 * \param address:  [const qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_to_array(uint8_t* output, const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Serialize an IPv4 address structure to a string.
 *
 * \param output:   [char*] The serialized address string output array.
 * \param address:  [const qsc_ipinfo_ipv4_address*] A pointer to the IPv4 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv4_address_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Convert an IPv4 address array to a string.
 *
 * \param output:   [char*] The serialized address string output array.
 * \param address:  [const uint8_t*] A pointer to the IPv4 address array.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv4_array_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const uint8_t* address);

/*!
 * \struct qsc_ipinfo_ipv6_address
 * \brief The IPv6 address structure.
 */
QSC_EXPORT_API typedef struct
{
    uint8_t ipv6[QSC_IPINFO_IPV6_BYTELEN];  /*!< The IPv6 address array. */
} qsc_ipinfo_ipv6_address;

/*!
 * \struct qsc_ipinfo_ipv6_info
 * \brief The IPv6 information structure.
 *
 * Contains an IPv6 address along with a port number and a network mask.
 */
QSC_EXPORT_API typedef struct
{
    qsc_ipinfo_ipv6_address address;    /*!< The IPv6 address structure. */
    uint16_t port;                      /*!< The port number. */
    uint8_t mask;                       /*!< The network mask. */
} qsc_ipinfo_ipv6_info;

/**
 * \brief Get the IPv6 address routing prefix type.
 *
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 * \return          [qsc_ipv6_address_prefix_types] Returns the IPv6 prefix type.
 */
QSC_EXPORT_API qsc_ipv6_address_prefix_types qsc_ipinfo_ipv6_address_type(const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Get a copy of the IPv6 loopback address.
 *
 * \return          [qsc_ipinfo_ipv6_address] Returns a copy of the IPv6 loopback address.
 */
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_any(void);

/**
 * \brief Clear the IPv6 address structure.
 *
 * \param address:  [qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_clear(qsc_ipinfo_ipv6_address* address);

/**
 * \brief Instantiate an IPv6 address structure from a byte array.
 *
 * \param address:  [const uint8_t*] A pointer to the byte array containing the serialized address.
 * \return          [qsc_ipinfo_ipv6_address] Returns the initialized IPv6 address structure.
 */
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_array(const uint8_t* address);

/**
 * \brief Instantiate an IPv6 address structure from a string.
 *
 * \param input:    [const char*] A pointer to the serialized address string.
 * \return          [qsc_ipinfo_ipv6_address] Returns the initialized IPv6 address structure.
 */
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_string(const char input[QSC_IPINFO_IPV6_STRNLEN]);

/**
 * \brief Compare two IPv6 address structures for equality.
 *
 * \param a:        [const qsc_ipinfo_ipv6_address*] A pointer to the first IPv6 address structure.
 * \param b:        [const qsc_ipinfo_ipv6_address*] A pointer to the second IPv6 address structure.
 * \return          [bool] Returns true if the address structures are equal.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_equal(const qsc_ipinfo_ipv6_address* a, const qsc_ipinfo_ipv6_address* b);

/**
 * \brief Test if the IPv6 address is a valid public address.
 *
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 * \return          [bool] Returns true if the address is valid.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_routable(const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Test if the IPv6 address is valid.
 *
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 * \return          [bool] Returns true if the address is valid.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_valid(const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Test if the IPv6 address string is valid.
 *
 * \param address:  [const char*] A pointer to the IPv6 address string.
 * \return          [bool] Returns true if the address string is valid.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_string_is_valid(const char* address);

/**
 * \brief Test if the IPv6 address is zeroed.
 *
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 * \return          [bool] Returns true if the address is zeroed.
 */
QSC_EXPORT_API bool qsc_ipinfo_ipv6_address_is_zeroed(const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Get a copy of the IPv6 loopback address.
 *
 * \return          [qsc_ipinfo_ipv6_address] Returns a copy of the IPv6 loopback address.
 */
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_loopback(void);

/**
 * \brief Get the IPv6 network subnet mask string.
 *
 * \param mask:     [char*] The output mask string.
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_get_mask(char mask[QSC_IPINFO_IPV6_MASK_STRNLEN], const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Get the IPv6 network subnet CIDR length.
 *
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 * \return          [uint8_t] Returns the mask length in bits.
 */
QSC_EXPORT_API uint8_t qsc_ipinfo_ipv6_address_get_cidr_mask(const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Serialize an IPv6 address structure to a byte array.
 *
 * \param output:   [uint8_t*] The address output byte array.
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_to_array(uint8_t* output, const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Serialize an IPv6 address structure to a string.
 *
 * \param output:   [char*] The address string output array.
 * \param address:  [const qsc_ipinfo_ipv6_address*] A pointer to the IPv6 address structure.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv6_address_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const qsc_ipinfo_ipv6_address* address);

/**
 * \brief Convert an IPv6 address array to a string.
 *
 * \param output:   [char*] The address string output array.
 * \param address:  [const uint8_t*] A pointer to the IPv6 address array.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv6_array_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const uint8_t* address);

/**
 * \brief Convert a subnet mask string to a CIDR mask.
 *
 * \param mask:     [const char*] The subnet mask string.
 * \return          [uint8_t] Returns the mask length in bits.
 */
QSC_EXPORT_API uint8_t qsc_ipinfo_ipv4_mask_to_cidr(const char mask[QSC_IPINFO_IPV4_MASK_STRNLEN]);

/**
 * \brief Convert a CIDR mask to a subnet mask string.
 *
 * \param mask:     [char*] The output mask string.
 * \param cidr:     [uint8_t] The input CIDR mask.
 */
QSC_EXPORT_API void qsc_ipinfo_ipv4_cidr_to_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], uint8_t cidr);

#endif
