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

#ifndef QSC_STRINGUTILS_H
#define QSC_STRINGUTILS_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file stringutils.h
 * \brief String utilities; common string support functions.
 *
 * \details
 * This header provides a comprehensive set of functions for handling strings,
 * including operations for formatting (adding and removing line breaks or whitespace),
 * concatenation, substring extraction, comparison, and conversion between data types
 * and their string representations. These utilities are designed to simplify the
 * manipulation and processing of strings within applications.
 *
 * \code
 * // Example: Remove all whitespace from a string.
 * const char* original = "  Hello,   World!  ";
 * char cleaned[50] = { 0 };
 * size_t new_len = qsc_stringutils_whitespace_filter(original, strlen(original), cleaned);
 * printf("Cleaned string: '%s' (length: %zu)\n", cleaned, new_len);
 * \endcode
 *
 * \section stringutils_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/cpp/c-runtime-library/string-functions">Microsoft C Runtime String Functions</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/009695399/functions/index.html">POSIX String Handling Functions</a>
 */

/*!
* \def QSC_STRINGUTILS_TOKEN_NOT_FOUND
* \brief The search token was not found
*/
#define QSC_STRINGUTILS_TOKEN_NOT_FOUND -1LL

/*!
* \def QSC_STRINGUTILS_HEX_EXTENSION_SIZE
* \brief The char size of the hex extension
*/
#define QSC_STRINGUTILS_HEX_EXTENSION_SIZE 2ULL

/*!
* \def QSC_STRINGUTILS_HEX_BYTE_SIZE
* \brief The char size of a hexidecimal byte
*/
#define QSC_STRINGUTILS_HEX_BYTE_SIZE 2ULL

/**
* \brief Counts all white-spaces, line stops, and returns from a string
*
* \param dest:		[const char*] The string dest to check
* \param dstlen:	[size_t] The size of the dest string
* 
* \return			[size_t] Returns the number of line stops, carriage returns and white-spaces in the string
*/
QSC_EXPORT_API size_t qsc_stringutils_formatting_count(const char* dest, size_t dstlen);

/**
* \brief Remove all white-spaces, lines stops, and returns from a string
*
* \param source:	[const char*] The source string to copy from
* \param srclen:	[size_t] The size of the source string
* \param dest:		[char*] The string receiving the filtered characters
* 
* \return			[size_t] Returns the number of characters copied
*/
QSC_EXPORT_API size_t qsc_stringutils_formatting_filter(const char* source, size_t srclen, char* dest);

/**
* \brief Add line breaks to a string at a line length interval
*
* \param dest:		[char*] The string receiving the formatted text
* \param dstlen:	[size_t] The size of the dest array
* \param linelen:	[size_t] The line length where a new line character is placed
* \param source:	[const char*] The source string to copy from
* \param srclen:	[size_t] The length of the source array
* 
* \return			[size_t] Returns the size of the dest string
*/
QSC_EXPORT_API size_t qsc_stringutils_add_line_breaks(char* dest, size_t dstlen, size_t linelen, const char* source, size_t srclen);

/**
* \brief Removes all line breaks from a string
*
* \param dest:		[char*] The string receiving the formatted text
* \param dstlen:	[size_t] The size of the dest array
* \param source:	[const char*] The source string to copy from
* \param srclen:	[size_t] The length of the source array
* 
* \return			[size_t] Returns the size of the dest string
*/
QSC_EXPORT_API size_t qsc_stringutils_remove_line_breaks(char* dest, size_t dstlen, const char* source, size_t srclen);

/**
* \brief Clear a string of data
*
* \param source:	[char*] The string to clear
*/
QSC_EXPORT_API void qsc_stringutils_clear_string(char* source);

/**
* \brief Clear a length of data from a string
*
* \param dest:		[char*] The string dest to clear
* \param length:	[size_t] The number of characters to clear
*/
QSC_EXPORT_API void qsc_stringutils_clear_substring(char* dest, size_t length);

/**
* \brief Compare two strings for equivalence
*
* \param str1:		[const char*] The first string
* \param str2:		[const char*] The second string
* \param length:	[size_t] The number of characters to compare
* 
* \return			[bool] Returns true if the strings are equal
*/
QSC_EXPORT_API bool qsc_stringutils_compare_strings(const char* str1, const char* str2, size_t length);

/**
* \brief Concatenate two strings
*
* \param dest:		[char*] The destination dest
* \param dstlen:	[size_t] The size of the destination dest
* \param source:	[const char*] The source string to copy
* 
* \return			[size_t] Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_concat_strings(char* dest, size_t dstlen, const char* source);

/**
* \brief Concatenate two strings and copy them to a third string
*
* \param dest:		[char*] The destination string to copy to
* \param dstlen:	[size_t] The size of the destination dest
* \param str1:		[const char*] The first string to copy from
* \param str2:		[const char*] The second string to copy from
* 
* \return			[size_t] Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_concat_and_copy(char* dest, size_t dstlen, const char* str1, const char* str2);

/**
* \brief Copy a length of one string to another
*
* \param dest:		[char*] The destination string to copy to
* \param dstlen:	[size_t] The size of the destination dest
* \param source:	[const char*] The string to copy from
* \param srclen:	[size_t] The substring length
* 
* \return			[size_t] Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_copy_substring(char* dest, size_t dstlen, const char* source, size_t srclen);

/**
* \brief Copy a source string to a destination string
*
* \param dest:		[char*] The destination string to copy to
* \param dstlen:	[size_t] The size of the destination dest
* \param source:	[const char*] The string to copy from
* 
* \return			[size_t] Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_copy_string(char* dest, size_t dstlen, const char* source);

/**
* \brief Find a character position within a string
*
* \param source:	[const char*] The string to check for the substring
* \param token:		[char] The character to search for
* 
* \return			[int64_t] Returns the character position within the string, or QSC_STRINGUTILS_TOKEN_NOT_FOUND if the character is not found
*/
QSC_EXPORT_API int64_t qsc_stringutils_find_char(const char* source, const char token);

/**
* \brief Find a substrings position within a string
*
* \param source:	[const char*] The string to check for the substring
* \param token:		[const char*] The substring to search for
* 
* \return			[int64_t] Returns the character position within the string, or QSC_STRINGUTILS_TOKEN_NOT_FOUND if the string is not found
*/
QSC_EXPORT_API int64_t qsc_stringutils_find_string(const char* source, const char* token);

/**
* \brief Convert a byte to a hexidecimal string
*
* \param hex:		[char*] The hex string output
* \param input:		[uint8_t] The byte to be converted
*/
QSC_EXPORT_API void qsc_stringutils_byte_to_hex(char* hex, uint8_t input);

/**
* \brief Convert a hexidecimal string to a byte
*
* \param hex:		[const char*] The hex string
* 
* \return			[uint8_t] Returns the byte value
*/
QSC_EXPORT_API uint8_t qsc_stringutils_hex_to_byte(const char* hex);

/**
* \brief Inserts a substring into a string
*
* \param dest:		[char*] The string receiving the substring
* \param dstlen:	[size_t] The size of the source dest
* \param source:	[const char*] The substring to insert
* \param offset:	[size_t] The insertion starting position within the source string; position is ordinal, 0-n
* 
* \return			[int64_t] Returns the size of the new string, or QSC_STRINGUTILS_TOKEN_NOT_FOUND if the string insert operation failed
*/
QSC_EXPORT_API int64_t qsc_stringutils_insert_string(char* dest, size_t dstlen, const char* source, size_t offset);

/**
* \brief Check if a string contains and characters
*
* \param source:	[const char*] The string to check for characters
* 
* \return			[bool] Returns true if the string is empty
*/
QSC_EXPORT_API bool qsc_stringutils_is_empty(const char* source);

/**
* \brief Check that a string contains only hexadecimal ASCII characters
*
* \param source:	[const char*] The string to check for hexadecimal characters
* \param srclen:	[size_t] The number of characters to check
* 
* \return			[bool] Returns true if the string is hexadecimal
*/
QSC_EXPORT_API bool qsc_stringutils_is_hex(const char* source, size_t srclen);

/**
* \brief Check that a string contains only numeric ASCII characters
*
* \param source:	[const char*] The string to check for numeric characters
* \param srclen:	[size_t] The number of characters to check
* 
* \return			[bool] Returns true if the string is numeric
*/
QSC_EXPORT_API bool qsc_stringutils_is_numeric(const char* source, size_t srclen);

/**
* \brief Join an array of strings to form one string
*
* \warning The string returned must be freed by the caller
*
* \param source:	[char**] The array of substrings
* \param count:		[size_t] The number of substring arrays
* 
* \return			[char*] Returns a concatenated string
*/
QSC_EXPORT_API char* qsc_stringutils_register_string(char** source, size_t count);

/**
* \brief Remove null characters from an array
*
* \param source:	[char*] The string to check for null characters
* \param srclen:	[size_t] The number of characters to check
* 
* \return			[size_t] The size of the cleaned string
*/
QSC_EXPORT_API size_t qsc_stringutils_remove_null_chars(char* source, size_t srclen);

/**
* \brief Find the position of a substring within a string, searching in reverse
*
* \param source:	[const char*] The string to check for the substring
* \param token:		[const char*] The token separator
* \param start:		[size_t] The starting position within the source string
* 
* \return			[int64_t] Returns the substring starting position, or -1 if not found
*/
QSC_EXPORT_API int64_t qsc_stringutils_reverse_find_string(const char* source, const char* token, size_t start);

/**
* \brief Find a substring within a string, searching in reverse
*
* \param source:	[const char*] The string to check for the substring
* \param token:		[const char*] The token separator
* 
* \return			[const char*] Returns the substring, or NULL if not found
*/
QSC_EXPORT_API const char* qsc_stringutils_reverse_sub_string(const char* source, const char* token);

/**
* \brief Compare two strings for equality
*
* \param str1:	[const char*] The string to check for the substring
* \param str2:		[const char*] The substring to search for
* \param length:	[size_t] The string length
* 
* \return			[bool] Returns true if the strings are equal 
*/
bool qsc_stringutils_string_compare(const char* str1, const char* str2, size_t length);

/**
* \brief Test if the string contains a substring
*
* \param source:	[const char*] The string to check for the substring
* \param token:		[const char*] The substring to search for
* 
* \return			[int32_t] Returns zero if the strings are equal 
*/
QSC_EXPORT_API int32_t qsc_stringutils_string_comparison(const char* source, const char* token);

/**
* \brief Test if the string contains a substring
*
* \param source:	[const char*] The string to check for the substring
* \param token:		[const char*] The substring to search for
* 
* \return			[bool] Returns true if the substring is found
*/
QSC_EXPORT_API bool qsc_stringutils_string_contains(const char* source, const char* token);

/**
* \brief Compare two strings for equality
*
* \param str1:		[const char*] The first comparison string
* \param str2:		[const char*] The second first comparison string
*
* \return			[bool] Returns true if the two strings are identical
*/
QSC_EXPORT_API bool qsc_stringutils_strings_equal(const char* str1, const char* str2);

/**
* \brief Split a string into a substring 2-dimensional array
*
* \warning The array of strings returned must be freed by the caller
*
* \param source:	[char*] The string to split
* \param delim:		[const char*] The char delimiter used to split the string
* \param count:		[size_t*] The number of substrings in the new array
* 
* \return			[char**] Returns a 2 dimensional character array of substrings
*/
QSC_EXPORT_API char** qsc_stringutils_split_string(char* source, const char* delim, size_t* count);

/**
* \brief Split a string into two substrings
*
* \param dest1:		[char*] The first destination string
* \param dest2:		[char*] The second destination string
* \param destlen:	[size_t] The destination strings length
* \param source:	[const char*] The source string
* \param token:		[const char*] The search token
*/
QSC_EXPORT_API void qsc_stringutils_split_strings(char* dest1, char* dest2, size_t destlen, const char* source, const char* token);

/**
* \brief Find a substring within a string
*
* \warning The string returned must be freed by the caller
*
* \param source:	[const char*] The string to check for the substring
* \param token:		[const char*] The token separator
* 
* \return			[char*] Returns the substring, or NULL if not found
*/
QSC_EXPORT_API char* qsc_stringutils_sub_string(const char* source, const char* token);

/**
* \brief Convert a string to a 32-bit integer
*
* \param source:	[const char*] The string to convert to an integer
* 
* \return			[int32_t] Returns the converted integer
*/
QSC_EXPORT_API int32_t qsc_stringutils_string_to_int(const char* source);

/**
* \brief Get the character length of a string
*
* \param source:	[const char*] The source string pointer
* 
* \return			[size_t] Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_string_size(const char* source);

/**
* \brief Convert a 32-bit signed integer to a string
*
* \param num:		[int32_t] The integer to convert
* \param dest:		[char*] The destination string
* \param dstlen:	[size_t] The size of the output dest
*/
QSC_EXPORT_API void qsc_stringutils_int_to_string(int32_t num, char* dest, size_t dstlen);

/**
* \brief Convert a 32-bit unsigned integer to a string
*
* \param num:		[uint32_t] The integer to convert
* \param dest:		[char*] The destination string
* \param destlen:	[size_t] The size of the output dest
*/
QSC_EXPORT_API void qsc_stringutils_uint32_to_string(uint32_t num, char* dest, size_t destlen);

/**
* \brief Convert a 64-bit signed integer to a string
*
* \param num:		[int64_t] The integer to convert
* \param dest:		[char*] The destination string
* \param dstlen:	[size_t] The size of the output dest
*/
QSC_EXPORT_API void qsc_stringutils_int64_to_string(int64_t num, char* dest, size_t dstlen);

/**
* \brief Convert a 64-bit unsigned integer to a string
*
* \param num:		[uint64_t] The integer to convert
* \param dest:		[char*] The destination string
* \param dstlen:	[size_t] The size of the output dest
*/
QSC_EXPORT_API void qsc_stringutils_uint64_to_string(uint64_t num, char* dest, size_t dstlen);

/**
* \brief Convert a string to all lower-case characters
*
* \param source:	[char*] The string to convert to lower-case
*/
QSC_EXPORT_API void qsc_stringutils_to_lowercase(char* source);

/**
* \brief Convert a string to all upper-case characters
*
* \param source:	[char*] The string to convert to upper-case
*/
QSC_EXPORT_API void qsc_stringutils_to_uppercase(char* source);

/**
* \brief Trim null and newline characters from a string
*
* \param source:	[char*] The string to trim
*/
QSC_EXPORT_API void qsc_stringutils_trim_newline(char* source);

/**
* \brief Trim a trailing space character from a string
*
* \param source:	[char*] The string to trim
*/
QSC_EXPORT_API void qsc_stringutils_trim_spaces(char* source);

/**
* \brief Count all the white-spaces in a string
*
* \param source:	[const char*] The string dest to check
* \param srclen:	[size_t] The size of the dest string
* 
* \return			[size_t] Returns the number of white-spaces in the string
*/
QSC_EXPORT_API size_t qsc_stringutils_whitespace_count(const char* source, size_t srclen);

/**
* \brief Remove all the white-spaces from a string
*
* \param source:	[const char*] The source string to copy from
* \param srclen:	[size_t] The size of the source string
* \param dest:		[char*] The destination string receiving the filtered characters
* 
* \return			[size_t] Returns the number of characters copied
*/
QSC_EXPORT_API size_t qsc_stringutils_whitespace_filter(const char* source, size_t srclen, char* dest);

QSC_CPLUSPLUS_ENABLED_END

#endif
