
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSC_ARRAYUTILS_H
#define QSC_ARRAYUTILS_H

#include "common.h"
#include <stdio.h>

/*
* \file arrayutils.h
* \brief Character array functions
*/

/*!
\def QSC_ARRAYTILS_NPOS
* The find string not found return value
*/
#define QSC_ARRAYTILS_NPOS -1

/**
* \brief Find the first instance of a token in a string, and return the char position
*
* \param str: [const] The string to parse
* \param slen: The length of the string, not including null terminator
* \param token: [const] The token to search for in the string
* \return Returns a positive integer if token is found, else zero
*/
QSC_EXPORT_API size_t qsc_arrayutils_find_string(const char* str, size_t slen, const char* token);

/**
* \brief Converts a hexadecimal encoded string to a byte value
*
* \param str: [const] The string to parse
* \param slen: The length of the string, not including null terminator
* \return Returns the byte value
*/
QSC_EXPORT_API uint8_t qsc_arrayutils_hex_to_uint8(const char* str, size_t slen);

/**
* \brief Converts a byte value to hexadecimal and writes to a string
*
* \param output: The output string char array
* \param otplen: The length of the output string
* \param value: The byte value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint8_to_hex(char* output, size_t otplen, uint8_t value);

/**
* \brief Converts an unsigned short value to hexadecimal and writes to a string
*
* \param output: The output string char array
* \param otplen: The length of the output string
* \param value: The unsigned short value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint16_to_hex(char* output, size_t otplen, uint16_t value);

/**
* \brief Converts an unsigned 32-bit integer value to hexadecimal and writes to a string
*
* \param output: The output string char array
* \param otplen: The length of the output string
* \param value: The unsigned 32-bit integer value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint32_to_hex(char* output, size_t otplen, uint32_t value);

/**
* \brief Converts an unsigned 64-bit integer value to hexadecimal and writes to a string
*
* \param output: The output string char array
* \param otplen: The length of the output string
* \param value: The unsigned 64-bit integer value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint64_to_hex(char* output, size_t otplen, uint64_t value);

/**
* \brief Parse an 8-bit unsigned integer from a string
*
* \param str: [const] The string to parse
* \param slen: The length of the string, not including null terminator
* \return Returns an 8-bit integer, zero if not found
*/
QSC_EXPORT_API uint8_t qsc_arrayutils_string_to_uint8(const char* str, size_t slen);

/**
* \brief Parse an 16-bit unsigned integer from a string
*
* \param str: [const] The string to parse
* \param slen: The length of the string, not including null terminator
* \return Returns an 16-bit integer, zero if not found
*/
QSC_EXPORT_API uint16_t qsc_arrayutils_string_to_uint16(const char* str, size_t slen);

/**
* \brief Parse an 32-bit unsigned integer from a string
*
* \param str: [const] The string to parse
* \param slen: The length of the string, not including null terminator
* \return Returns an 32-bit integer, zero if not found
*/
QSC_EXPORT_API uint32_t qsc_arrayutils_string_to_uint32(const char* str, size_t slen);

/**
* \brief Parse an 64-bit unsigned integer from a string
*
* \param str: [const] The string to parse
* \param slen: The length of the string, not including null terminator
* \return Returns an 64-bit integer, zero if not found
*/
QSC_EXPORT_API uint64_t qsc_arrayutils_string_to_uint64(const char* str, size_t slen);

/**
* \brief Array functions self-test
*/
QSC_EXPORT_API bool qsc_arrayutils_self_test(void);

#endif
