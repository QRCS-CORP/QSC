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
* \param outlen: The length of the output string
* \param value: The byte value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint8_to_hex(char* output, size_t outlen, uint8_t value);

/**
* \brief Converts an unsigned short value to hexadecimal and writes to a string
*
* \param output: The output string char array
* \param outlen: The length of the output string
* \param value: The unsigned short value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint16_to_hex(char* output, size_t outlen, uint16_t value);

/**
* \brief Converts an unsigned 32-bit integer value to hexadecimal and writes to a string
*
* \param output: The output string char array
* \param outlen: The length of the output string
* \param value: The unsigned 32-bit integer value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint32_to_hex(char* output, size_t outlen, uint32_t value);

/**
* \brief Converts an unsigned 64-bit integer value to hexadecimal and writes to a string
*
* \param output: The output string char array
* \param outlen: The length of the output string
* \param value: The unsigned 64-bit integer value to convert
*/
QSC_EXPORT_API void qsc_arrayutils_uint64_to_hex(char* output, size_t outlen, uint64_t value);

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
