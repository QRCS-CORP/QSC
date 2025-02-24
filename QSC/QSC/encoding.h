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
 * Contact: john.underhill\protonmail.com
 */

#ifndef QSC_ENCODING_H
#define QSC_ENCODING_H

#include "common.h"

/*!
 * \file encoding.h
 * \brief Functions and data types for multiple encoding schemes.
 *
 * \details
 * This header provides a collection of functions and data types that support
 * several encoding and decoding schemes used in cryptography and data
 * representation. The supported schemes include:
 *
 * - **Base64 Encoding/Decoding:**  
 *   Functions to encode binary data to a Base64 string and decode Base64-encoded
 *   strings back to binary data. Base64 is defined in RFC 4648 and is widely used
 *   to represent binary data in an ASCII-compatible format.
 *
 * - **Hexadecimal (HEX) Encoding/Decoding:**  
 *   Functions to encode binary data into a hexadecimal string and to decode
 *   hexadecimal strings back to binary data.
 *
 * - **BER (Basic Encoding Rules):**  
 *   Functions to encode and decode ASN.1 elements using BER. This includes
 *   handling the tag, length, and value (TLV) structure, as well as providing
 *   enumerations of the standard Universal ASN.1 tag numbers. BER is a fundamental
 *   encoding rule used in many cryptographic and network protocols.
 *
 * - **PEM (Privacy Enhanced Mail) Encoding/Decoding:**  
 *   Functions to convert binary data into a PEM-formatted text representation
 *   (which typically wraps Base64-encoded data between header and footer lines)
 *   and to decode such PEM strings back to their binary form.
 *
 * \par Example:
 * \code
 * #include "encoding.h"
 *
 * // Example: Base64 Encoding and Decoding
 * uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
 * size_t data_len = sizeof(data);
 * char b64_encoded[128] = { 0 };
 * qsc_encoding_base64_encode(b64_encoded, sizeof(b64_encoded), data, data_len);
 *
 * // Example: Hexadecimal Encoding and Decoding
 * char hex_encoded[128] = { 0 };
 * qsc_encoding_hex_encode(data, data_len, hex_encoded, sizeof(hex_encoded));
 *
 * // Example: BER Encoding and Decoding
 * qsc_encoding_ber_element element;
 * // Populate the 'element' structure as needed...
 * uint8_t ber_buf[256];
 * size_t ber_len = qsc_encoding_ber_encode_element(&element, ber_buf, sizeof(ber_buf));
 *
 * // Example: PEM Encoding and Decoding
 * char pem_output[512] = { 0 };
 * qsc_encoding_pem_encode("CERTIFICATE", pem_output, sizeof(pem_output), data, data_len);
 * \endcode
 *
 * \section encoding_links Reference Links:
 * - Base64: <a href="https://tools.ietf.org/html/rfc4648">RFC 4648</a>
 * - ASN.1/BER: Refer to ISO/IEC 8825 for Basic Encoding Rules (BER) and DER.
 */

/*!
 * \def QSC_ENCODING_BER_CLASS_UNIVERSAL
 * \brief Universal tag class.
 *
 * The universal tag class (0x00) is used for ASN.1 types that are common and standardized,
 * such as INTEGER, BOOLEAN, NULL, OBJECT IDENTIFIER, etc. The two most significant bits
 * in the tag byte for a universal type are '00'.
 */
#define QSC_ENCODING_BER_CLASS_UNIVERSAL 0x00U

/*!
 * \def QSC_ENCODING_BER_CLASS_APPLICATION
 * \brief Application tag class.
 *
 * The application tag class (0x40) is used for types that are defined by specific
 * applications. These types are not necessarily universal; instead, they have meaning
 * only within a particular application context. The two most significant bits are '01'
 * (0x40 in hexadecimal).
 */
#define QSC_ENCODING_BER_CLASS_APPLICATION 0x40U

/*!
 * \def QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC
 * \brief Context-specific tag class.
 *
 * The context-specific tag class (0x80) is used for types whose interpretation depends
 * on their context within a structure. These tags are typically used to differentiate
 * between data elements that occur in the same position in different contexts. The two
 * most significant bits are '10' (0x80 in hexadecimal).
 */
#define QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC 0x80U

/*!
 * \def QSC_ENCODING_BER_CLASS_PRIVATE
 * \brief Private tag class.
 *
 * The private tag class (0xC0) is used for user-defined or vendor-specific types that do
 * not have a standardized universal meaning. These tags are intended for private use.
 * The two most significant bits are '11' (0xC0 in hexadecimal).
 */
#define QSC_ENCODING_BER_CLASS_PRIVATE 0xC0U

/*!
 * \def QSC_BER_ENCODING_INDEFINITE_LENGTH
 * \brief Private tag class.
 *
 * Use this value for indefinite length encoding.
 */
#define QSC_BER_ENCODING_INDEFINITE_LENGTH ((size_t)-1)

/*!
 * \brief Enumeration of the standard Universal ASN.1 tag numbers used in BER.
 *
 * These tag numbers are defined in the ASN.1 specification and are used with
 * BER (Basic Encoding Rules) to identify the type of an element.
 */
typedef enum
{
    BER_ASN1_EOC = 0x00U,                   /*!< End-of-Contents (EOC) marker. */
    BER_ASN1_BOOLEAN = 0x01U,               /*!< BOOLEAN. */
    BER_ASN1_INTEGER = 0x02U,               /*!< INTEGER. */
    BER_ASN1_BIT_STRING = 0x03U,            /*!< BIT STRING. */
    BER_ASN1_OCTET_STRING = 0x04U,          /*!< OCTET STRING. */
    BER_ASN1_NULL = 0x05U,                  /*!< NULL. */
    BER_ASN1_OBJECT_IDENTIFIER = 0x06U,     /*!< OBJECT IDENTIFIER. */
    BER_ASN1_OBJECT_DESCRIPTOR = 0x07U,     /*!< Object Descriptor. */
    BER_ASN1_EXTERNAL = 0x08U,              /*!< EXTERNAL (or Instance-of). */
    BER_ASN1_REAL = 0x09U,                  /*!< REAL (floating-point). */
    BER_ASN1_ENUMERATED = 0x0AU,           /*!< ENUMERATED. */
    BER_ASN1_EMBEDDED_PDV = 0x0BU,         /*!< Embedded PDV. */
    BER_ASN1_UTF8_STRING = 0x0CU,          /*!< UTF8String. */
    BER_ASN1_RELATIVE_OID = 0x0DU,         /*!< Relative Object Identifier. */
    /* Tags 14 and 15 are reserved. */
    BER_ASN1_SEQUENCE = 0x10U,             /*!< SEQUENCE and SEQUENCE OF. */
    BER_ASN1_SET = 0x11U,                  /*!< SET and SET OF. */
    BER_ASN1_NUMERIC_STRING = 0x12U,       /*!< NumericString. */
    BER_ASN1_PRINTABLE_STRING = 0x13U,     /*!< PrintableString. */
    BER_ASN1_T61_STRING = 0x14U,           /*!< TeletexString (T61String). */
    BER_ASN1_VIDEOTEX_STRING = 0x15U,      /*!< VideotexString. */
    BER_ASN1_IA5_STRING = 0x16U,           /*!< IA5String. */
    BER_ASN1_UTCTIME = 0x17U,              /*!< UTCTime. */
    BER_ASN1_GENERALIZEDTIME = 0x18U,      /*!< GeneralizedTime. */
    BER_ASN1_GRAPHIC_STRING = 0x19U,       /*!< GraphicString. */
    BER_ASN1_VISIBLE_STRING = 0x1AU,       /*!< VisibleString (ISO646String). */
    BER_ASN1_GENERAL_STRING = 0x1BU,       /*!< GeneralString. */
    BER_ASN1_UNIVERSAL_STRING = 0x1CU,     /*!< UniversalString. */
    BER_ASN1_CHARACTER_STRING = 0x1DU,     /*!< CharacterString. */
    BER_ASN1_BMP_STRING = 0x1EU            /*!< BMPString. */
} qsc_encoding_ber_asn1_tag_t;

/*!
 * \brief Represents a BER (Basic Encoding Rules) element.
 *
 * This structure is used to represent an ASN.1 element encoded using BER.
 * An element may be either:
 * - Primitive: where the value is encoded directly in the value buffer.
 * - Constructed: where the element contains child BER elements. For constructed
 *   types, either the pre-encoded block is stored in value (definite-length encoding)
 *   or the individual child elements are stored in the children array.
 *
 * The structure holds the tag class, the constructed flag, and the tag number.
 * For primitive elements, value and length are used to represent the element's data.
 * For constructed elements, the children pointer is used (typically during decoding),
 * although in some cases the pre-encoded block is placed in value along with its length.
 */
QSC_EXPORT_API typedef struct qsc_encoding_ber_element
{
    uint8_t tagclass;       /*!< Tag class (e.g., QSC_ENCODING_BER_CLASS_UNIVERSAL, BER_CLASS_APPLICATION, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, or QSC_ENCODING_BER_CLASS_PRIVATE). */
    bool constructed;       /*!< Flag indicating if the element is constructed (true) or primitive (false). */
    uint32_t tagnumber;     /*!< Tag number; may be greater than 30, which requires long-form encoding. */
    bool indefinite;        /*!< true if the element's length was encoded in the indefinite form, false if definite. */
    size_t length;          /*!< For definite-length encoding, the number of bytes in the value or in the pre-encoded block of child elements. */
    uint8_t* value;         /*!< Pointer to the element's raw value bytes. For primitive types, this holds the encoded data. For definite constructed types, it may hold a pre-encoded block. */
    struct qsc_encoding_ber_element** children; /*!< Array of pointers to child qsc_encoding_ber_element structures (used for constructed types when decoding into individual child elements). */
    size_t ccount;          /*!< The number of child elements pointed to by the children array. */
} qsc_encoding_ber_element;

/*!
 * \brief Decodes a Base64 string to a byte array.
 *
 * \param output:	[uint8_t*] The byte array receiving the decoded output.
 * \param otplen:	[size_t] The size of the output byte array.
 * \param input:	[const char*] The Base64 encoded input string.
 * \param inlen:	[size_t] The length of the input string.
 * 
 * \return			[bool] Returns true if the string was decoded successfully.
 */
QSC_EXPORT_API bool qsc_encoding_base64_decode(uint8_t* output, size_t otplen, const char* input, size_t inlen);

/*!
 * \brief Gets the expected size of an array required for Base64 decoding.
 *
 * \param input:	[const char*] The Base64 encoded string.
 * \param length:	[size_t] The length of the encoded string.
 * 
 * \return			[size_t] Returns the required size of the decoded byte array.
 */
QSC_EXPORT_API size_t qsc_encoding_base64_decoded_size(const char* input, size_t length);

/*!
 * \brief Encodes a byte array to a Base64 string.
 *
 * \param output:	[char*] The character string receiving the encoded bytes.
 * \param otplen:	[size_t] The size of the output character array.
 * \param input:	[const uint8_t*] The byte array to encode.
 * \param inplen:	[size_t] The size of the byte array.
 */
QSC_EXPORT_API void qsc_encoding_base64_encode(char* output, size_t otplen, const uint8_t* input, size_t inplen);

/*!
 * \brief Gets the expected size of a character array required for Base64 encoding.
 *
 * \param length:	[size_t] The length of the input byte array.
 * 
 * \return			[size_t] Returns the required size of the encoded character array.
 */
QSC_EXPORT_API size_t qsc_encoding_base64_encoded_size(size_t length);

/*!
 * \brief Tests if an encoded character is a valid Base64 encoding.
 *
 * \param value:	[char] The character to test.
 * 
 * \return			[bool] Returns true if the character is valid.
 */
QSC_EXPORT_API bool qsc_encoding_base64_is_valid_char(char value);

/*!
 * \brief Decodes a BER element from encoded data.
 *
 * This function parses a BER-encoded element from the provided buffer. It decodes the tag,
 * length, and value (or child elements in the case of constructed types) and returns a pointer
 * to a dynamically allocated BER element structure that represents the decoded element.
 *
 * \param buffer    [const uint8_t*] Pointer to the input buffer containing the BER-encoded element.
 * \param buflen    [size_t] The number of bytes available in the input buffer.
 * \param consumed  [size_t*] Pointer to a variable where the number of bytes consumed during decoding will be stored.
 * 
 * \return          [qsc_encoding_ber_element*] Returns a pointer to a dynamically allocated BER element structure representing the decoded element, or NULL if an error occurred during decoding.
 */
QSC_EXPORT_API qsc_encoding_ber_element* qsc_encoding_ber_decode_element(const uint8_t* buffer, size_t buflen, size_t* consumed);

/*!
 * \brief Decodes a BER-encoded length value.
 *
 * This function decodes a length field from BER-encoded data. It supports both the short
 * and long forms of length encoding. If an indefinite length is encountered (indicated by
 * a length byte of 0x80), the output parameter \c indefinite is set to true.
 *
 * \param buffer    [const uint8_t*] Pointer to the input buffer containing the BER-encoded length.
 * \param buflen    [size_t] The number of bytes available in the input buffer.
 * \param length    [size_t*] Pointer to a variable where the decoded length will be stored.
 * \param indef     [bool*] Pointer to a boolean that will be set to true if the length is encoded in the indefinite form.
 * 
 * \return          [size_t] Returns the number of bytes consumed from the buffer on success, or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_ber_decode_length(const uint8_t* buffer, size_t buflen, size_t* length, bool* indef);

/*!
 * \brief Decodes an ASN.1 tag from BER-encoded data.
 *
 * This function reads a BER-encoded tag from the provided buffer and decodes
 * it into its constituent parts: tag class, constructed flag, and tag number.
 * It handles both the short and long forms of tag encoding.
 *
 * \param buffer    [const uint8_t*] Pointer to the input buffer containing the BER-encoded tag.
 * \param buflen    [size_t] The number of bytes available in the input buffer.
 * \param tagclass  [uint8_t*] Pointer to a variable where the decoded tag class will be stored.
 * \param construct [bool*] Pointer to a boolean where the decoded constructed flag will be stored.
 * \param tagnum    [uint32_t*] Pointer to a variable where the decoded tag number will be stored.
 * 
 * \return          [size_t] Returns the number of bytes consumed from the buffer on success, or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_ber_decode_tag(const uint8_t* buffer, size_t buflen, uint8_t* tagclass, bool* construct, uint32_t* tagnum);

/*!
 * \brief Encodes a complete BER element.
 *
 * This function encodes a BER element, including its tag, length, and value,
 * into BER format. For constructed elements, this function handles encoding either a
 * pre-encoded block (definite-length) or a series of child elements (possibly using
 * indefinite-length encoding).
 *
 * \param element   [qsc_encoding_ber_element*] Pointer to the BER element structure to be encoded.
 * \param buffer    [uint8_t*] Pointer to the output buffer where the encoded element will be written.
 * \param buflen    [size_t] The size of the output buffer.
 * 
 * \return          [size_t] Returns the total number of bytes written to the buffer on success, or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_ber_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen);

/*!
 * \brief Encodes a length value into BER format.
 *
 * This function encodes the given length value according to BER rules. For lengths
 * less than 128, a single byte (short form) is used. For longer lengths, the long-form
 * encoding is applied, with the first byte indicating the number of subsequent bytes
 * used to encode the length.
 *
 * \param length    [size_t] The length value to encode.
 * \param buffer    [uint8_t*] Pointer to the output buffer where the encoded length will be written.
 * \param buflen    [size_t] The size of the output buffer.
 * 
 * \return          [size_t] Returns the number of bytes written to the buffer on success, or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_ber_encode_length(size_t length, uint8_t* buffer, size_t buflen);

/*!
 * \brief Encodes an ASN.1 tag into BER format.
 *
 * This function constructs the BER representation of an ASN.1 tag given the
 * tag class, constructed flag, and tag number. For tag numbers less than 31,
 * the short form is used. For larger tag numbers, the long-form encoding is applied,
 * encoding the tag number in base-128.
 *
 * \param tagclass  [uint8_t] The tag class (e.g., BER_CLASS_UNIVERSAL, BER_CLASS_APPLICATION, BER_CLASS_CONTEXT_SPECIFIC, or BER_CLASS_PRIVATE).
 * \param construct [construct] Set to true if the element is constructed; false if primitive.
 * \param tagnum    [uint32_t] The tag number. If tagnumber is 31 or greater, long-form encoding is used.
 * \param buffer    [uint8_t*] Pointer to the output buffer where the encoded tag will be written.
 * \param buflen    [size_t] The size of the output buffer.
 * 
 * \return          [size_t] Returns the number of bytes written to the buffer on success, or 0 on error (e.g. if the output buffer is too small).
 */
QSC_EXPORT_API size_t qsc_encoding_ber_encode_tag(uint8_t tagclass, bool construct, uint32_t tagnum, uint8_t* buffer, size_t buflen);

/*!
 * \brief Free a BER element from the array.
 *
 * \param element   [qsc_encoding_ber_element*] Pointer to the BER element structure to be encoded.
 */
QSC_EXPORT_API void encoding_ber_free_element(qsc_encoding_ber_element* element);

/*!
 * \brief Decodes an ASN.1 element encoded in DER format.
 *
 * This function calls the BER decode routine to decode an element and then checks
 * that the length is encoded in the definite form (as required by DER). If the element
 * uses an indefinite length, the function frees the element and returns NULL.
 *
 * \param buffer    [const uint8_t*] Pointer to the DER-encoded data.
 * \param buflen    [size_t] The number of bytes available in the buffer.
 * \param consumed  [size_t*] Pointer to a variable that receives the number of bytes consumed.
 *
 * \return          [qsc_encoding_ber_element*] Returns a pointer to the decoded element,
 *                  or NULL on error.
 */
QSC_EXPORT_API qsc_encoding_ber_element* qsc_encoding_der_decode_element(const uint8_t* buffer, size_t buflen, size_t* consumed);

/*!
 * \brief Encodes an ASN.1 element using DER (Distinguished Encoding Rules).
 *
 * This function encodes the provided element in DER format. Unlike BER, DER requires
 * definite-length encoding; therefore, if the element is marked as using an indefinite
 * length, the encoding fails.
 *
 * For primitive elements, the value is taken from element->value.
 * For constructed elements, the function recursively encodes all child elements into a
 * temporary buffer, computes the total content length, and then encodes the tag and
 * definite-length followed by the content.
 *
 * \param element  [qsc_encoding_ber_element*] Pointer to the element to be encoded.
 * \param buffer   [uint8_t*] Pointer to the output buffer.
 * \param buflen   [size_t] Size of the output buffer.
 *
 * \return         [size_t] Returns the total number of bytes written on success or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_der_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen);

/*!
 * \brief Decodes a hexadecimal string into binary data.
 *
 * \param input     [const char*] Pointer to the hex encoded string.
 * \param inplen    [size_t] Length of the input string (should be even).
 * \param output    [uint8_t*] Buffer to receive the decoded binary data.
 * \param otplen    [size_t] Size of the output buffer.
 * \param declen    [size_t*] Pointer to a size_t to receive the number of decoded bytes.
 *
 * \return          [bool] Returns true on success, false if the input is invalid or the output buffer is too small.
 */
QSC_EXPORT_API bool qsc_encoding_hex_decode(const char* input, size_t inplen, uint8_t* output, size_t otplen, size_t* declen);

/*!
 * \brief Encodes binary data into a hexadecimal string.
 *
 * \param input     [const uint8_t*] Pointer to the binary input data.
 * \param inplen    [size_t] Number of bytes in the input data.
 * \param output    [char*] Buffer to receive the hex encoded string; must be at least (in_len * 2) + 1 bytes long.
 * \param otplen    [size_t] Length of the output buffer.
 *
 * \return          [bool] Returns true on success, false if the output buffer is too small.
 */
QSC_EXPORT_API bool qsc_encoding_hex_encode(const uint8_t* input, size_t inplen, char* output, size_t otplen);

/*!
 *  \brief Decodes a PEM-formatted string into binary data.
 *
 * \param input:	[const char*] A null-terminated PEM string (including header/footer).
 * \param output:	[uint8_t*] Buffer to receive decoded binary data.
 * \param otplen	[size_t] Length of the output buffer.
 * \param declen	[size_t*] Pointer to receive the number of decoded bytes.
 *
 * \return          [bool] Returns true if successful; false if any error occurs (e.g. output buffer too small).
 */
QSC_EXPORT_API bool qsc_encoding_pem_decode(const char* input, uint8_t* output, size_t otplen, size_t* declen);

/*!
 * \brief Encodes binary data in PEM format.
 *
 * \param label		[const char*] The string label title.
 * \param output	[char*] Buffer to receive the PEM text.
 * \param otplen	[size_t] Length of the output buffer.
 * \param data		[const uint8_t*] Pointer to the binary data to encode.
 * \param datalen	[size_t] Length of the binary data.
 *
 * \return          [bool] Returns true if encoding succeeded; false if the output buffer is too small.
 */
QSC_EXPORT_API bool qsc_encoding_pem_encode(const char* label, char* output, size_t otplen, const uint8_t* data, size_t datalen);

#endif
