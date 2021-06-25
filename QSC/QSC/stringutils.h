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
* An implementation of common string support functions
* Written by John G. Underhill
* Written on January 23, 2021
* Contact: support@vtdev.com 
*/

/*
* \file stringutils.h
* \brief <b>String utilities; common string support functions</b> \n
* January 23, 2021
*/

#ifndef QSC_STRINGUTILS_H
#define QSC_STRINGUTILS_H

#include "common.h"

/**
* \brief Add line breaks to a string at a line length interval
*
* \param buffer: The string receiving the formatted text
* \param buflen: The size of the buffer array
* \param linelen: The line length where a new line character is placed
* \param source: The base string to copy from
* \param sourcelen: The length of the source array
* \return Returns the size of the buffer string
*/
QSC_EXPORT_API size_t qsc_stringutils_add_line_breaks(char* buffer, size_t buflen, size_t linelen, const char* source, size_t sourcelen);

/**
* \brief Removes all line breaks from a string
*
* \param buffer: The string receiving the formatted text
* \param buflen: The size of the buffer array
* \param source: The base string to copy from
* \param sourcelen: The length of the source array
* \return Returns the size of the buffer string
*/
QSC_EXPORT_API size_t qsc_stringutils_remove_line_breaks(char* buffer, size_t buflen, const char* source, size_t sourcelen);

/**
* \brief Clear a string of data
*
* \param source: The string to clear
*/
QSC_EXPORT_API void qsc_stringutils_clear_string(char* source);

/**
* \brief Clear a length of data
*
* \param buffer: The string buffer to clear
* \param count: The number of characters to clear
*/
QSC_EXPORT_API void qsc_stringutils_clear_substring(char* buffer, size_t count);

/**
* \brief Compare two strings for equivalence
*
* \param a: The first string
* \param b: The second string
* \param length: The number of characters to compare
* \return Returns true if the strings are equal
*/
QSC_EXPORT_API bool qsc_stringutils_compare_strings(char* a, const char* b, size_t length);

/**
* \brief Concatonate two strings
*
* \param buffer: The destination buffer
* \param buflen: The size of the destination buffer
* \param substr: The string to copy
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_concat_strings(char* buffer, size_t buflen, const char* substr);

/**
* \brief Concatonate two strings and copy them to a third string
*
* \param buffer: The destination string to copy to
* \param buflen: The size of the destination buffer
* \param substr1: The first string to copy from
* \param substr2: The second string to copy from
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_concat_and_copy(char* buffer, size_t buflen, const char* substr1, const char* substr2);

/**
* \brief Copy a length of one string to another
*
* \param buffer: The destination string to copy to
* \param buflen: The size of the destination buffer
* \param substr: The string to copy from
* \param substr: The string to copy from
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_copy_substring(char* buffer, size_t buflen, const char* substr, size_t sublen);

/**
* \brief Copy one string to another
*
* \param buffer: The destination string to copy to
* \param buflen: The size of the destination buffer
* \param substr: The string to copy from
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_copy_string(char* buffer, size_t buflen, const char* substr);

/**
* \brief Find a substrings position within a string
*
* \param source: The string to check for the substring
* \param token: The substring to search for
* \return Returns the character position withing the string, or -1 if the string is not found
*/
QSC_EXPORT_API int32_t qsc_stringutils_find_string(const char* source, const char* token);

/**
* \brief Inserts a substring into a string
*
* \param buffer: The string receiveing the substring
* \param buflen: The size of the source buffer
* \param substr: The substring to insert
* \param offset: The insertion starting position within the source string; position is ordinal, 0-n
* \return Returns the size of the new string, or -1 if the string insert operation failed
*/
QSC_EXPORT_API int32_t qsc_stringutils_insert_string(char* buffer, size_t buflen, const char* substr, size_t offset);

/**
* \brief Check that a string contains only alpha numeric ascii characters
*
* \param source: The string to check for alpha numeric characters
* \param srclen: The number of characters to check
* \return Returns true if the string is alpha numeric
*/
QSC_EXPORT_API bool qsc_stringutils_is_alpha_numeric(char* source, size_t srclen);

/**
* \brief Check that a string contains only hexadecimal ascii characters
*
* \param source: The string to check for hexadecimal characters
* \param srclen: The number of characters to check
* \return Returns true if the string is hexadecimal
*/
QSC_EXPORT_API bool qsc_stringutils_is_hex(char* source, size_t srclen);

/**
* \brief Check that a string contains only numeric ascii characters
*
* \param source: The string to check for numeric characters
* \param srclen: The number of characters to check
* \return Returns true if the string is numeric
*/
QSC_EXPORT_API bool qsc_stringutils_is_numeric(char* source, size_t srclen);

/**
* \brief Join an array of strings to form one string
*
* \warning The string returned must be deleted by the caller
*
* \param source: The array of substrings
* \param count: The number of substring arrays
* \return Returns a concatonated string
*/
QSC_EXPORT_API char* qsc_stringutils_join_string(char** source, size_t count);

/**
* \brief Find a substring within a string
*
* \param source: The string to check for the substring
* \param token: The token seperator
* \return Returns the substring, or NULL if not found
*/
QSC_EXPORT_API char* qsc_stringutils_reverse_sub_string(const char* source, const char* token);

/**
* \brief Test if the string contains a substring
*
* \param source: The string to check for the substring
* \param token: The substring to search for
* \return Returns true if the substring is found
*/
QSC_EXPORT_API bool qsc_stringutils_string_contains(const char* source, const char* token);

/**
* \brief Split a string into a substring array
*
* \warning The array of strings returned must be freed by the caller
*
* \param source: The string to split
* \param delim: The char delimiter used to split the string
* \param count: The number of substrings in the new array
* \return Returns a 2 dimensional character array of substrings
*/
QSC_EXPORT_API char** qsc_stringutils_split_string(char* source, char* delim, size_t* count);

/**
* \brief Find a substring within a string
*
* \warning The string returned must be deleted by the caller
*
* \param source: The string to check for the substring
* \param token: The token seperator
* \return Returns the substring, or NULL if not found
*/
QSC_EXPORT_API char* qsc_stringutils_sub_string(const char* source, const char* token);

/**
* \brief Convert a string to an integer
*
* \param source: The string to convert to an integer
* \return Returns the converted integer
*/
QSC_EXPORT_API int32_t qsc_stringutils_string_to_int(const char* source);

/**
* \brief Get the char length of a string
*
* \param source: The source string pointer
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_string_size(const char* source);

/**
* \brief Convert an integer to a string
*
* \param num: The integer to convert
* \param output: The output string
* \param outlen: The size of the output buffer
*/
QSC_EXPORT_API void qsc_stringutils_int_to_string(int32_t num, char* output, size_t outlen);

/**
* \brief Convert a string to all lowercase characters
*
* \param source: The string to convert to lowercase
*/
QSC_EXPORT_API void qsc_stringutils_to_lowercase(char* source);

/**
* \brief Convert a string to all uppercase characters
*
* \param source: The string to convert to uppercase
*/
QSC_EXPORT_API void qsc_stringutils_to_uppercase(char* source);

/**
* \brief Trim null and newline characters from a string
*
* \param source: The string to trim
*/
QSC_EXPORT_API void qsc_stringutils_trim_newline(char* source);

#endif
