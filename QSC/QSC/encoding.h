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
* An implementation of supporting integer based functions
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com
*/

/*
* \file encoding.h
* \brief <b>Integer base64 and RAD encoding utilities</b> \n
* This file contains base64 and RAD encoding functions
* March 6, 2021
*/

#ifndef QSC_ENCODING_H
#define QSC_ENCODING_H

#include "common.h"

/**
* \brief Decodes a base64 string to a byte array
*
* \param output: The byte array receiving the decoded output
* \param outlen: The size of the output byte array
* \param input: The base64 encoded input string
* \param inlen: The length of there input string
* \return Returns true if the string was encoded successfully
*/
QSC_EXPORT_API bool qsc_encoding_base64_decode(uint8_t* output, size_t outlen, const char* input, size_t inlen);

/**
* \brief Gets the expected size of an array required by decoding
*
* \param input: The base64 encoded string
* \param length: The length of the encoded string
* \return Returns the required size of the decoded byte array
*/
QSC_EXPORT_API size_t qsc_encoding_base64_decoded_size(const char* input, size_t length);

/**
* \brief Encode a byte array to a base64 string
*
* \param output: The character string receiving the encoded bytes
* \param outlen: The size of the output character array
* \param input: The byte array to encode to base64
* \param inplen: The size of the byte array
*/
QSC_EXPORT_API void qsc_encoding_base64_encode(char* output, size_t outlen, const uint8_t* input, size_t inplen);

/**
* \brief Gets the expected size of an character array required by encoding
*
* \param length:
* \return Returns the required size of the encoded character array
*/
QSC_EXPORT_API size_t qsc_encoding_base64_encoded_size(size_t length);

/**
* \brief Tests if an encoded character is valid
*
* \param c: The character to test
* \return Returns true if the character is valid
*/
QSC_EXPORT_API bool qsc_encoding_base64_is_valid_char(char c);

/**
* \brief Test the encoding and decoding functions
*/
QSC_EXPORT_API void qsc_encoding_self_test();

#endif