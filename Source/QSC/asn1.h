/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_ASN1_H
#define QSC_ASN1_H

#include "qsccommon.h"
#include "encoding.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file asn1.h
 * \brief ASN.1 helper functions and data types built on the QSC BER and DER encoding layer.
 *
 * \details
 * This header provides a compact ASN.1 support layer intended for use by the
 * X.509 certificate parser and validator. The implementation does not replace
 * the generic BER and DER routines in encoding.h. Instead, it adds strict
 * validation and typed decoding helpers for the ASN.1 forms that are required
 * by X.509 and related public key structures.
 *
 * The functions in this module operate on qsc_encoding_ber_element objects
 * produced by qsc_encoding_der_decode_element() or qsc_encoding_ber_decode_element().
 * The primary design goal is to provide a small and explicit bridge between
 * the generic tree representation and the strongly typed objects needed by
 * certificate parsing code.
 *
 * The module includes support for:
 *
 * - Tag and class validation.
 * - Sequence, set, and context-specific element handling.
 * - INTEGER, BOOLEAN, BIT STRING, OCTET STRING, NULL, and OBJECT IDENTIFIER decoding.
 * - Printable string extraction for common distinguished name fields.
 * - UTCTime and GeneralizedTime parsing to a normalized internal time structure.
 * - Helper functions for DER size calculation and child traversal.
 *
 * This layer is intentionally conservative. It is intended for DER-centric
 * certificate parsing, and rejects malformed or ambiguous encodings where a
 * strict X.509 implementation should fail.
 */

/*!
 * \def QSC_ASN1_OID_MAX_SIZE
 * \brief The maximum number of encoded OBJECT IDENTIFIER bytes supported by the helper layer.
 */
#define QSC_ASN1_OID_MAX_SIZE 32U

/*!
 * \def QSC_ASN1_OID_MAX_ARCS
 * \brief The maximum number of arcs stored in the decoded OBJECT IDENTIFIER structure.
 */
#define QSC_ASN1_OID_MAX_ARCS 16U

/*!
 * \def QSC_ASN1_BIT_STRING_MAX_UNUSED_BITS
 * \brief The maximum legal number of unused bits in a BIT STRING final octet.
 */
#define QSC_ASN1_BIT_STRING_MAX_UNUSED_BITS 7U

/*!
 * \brief ASN.1 helper status codes.
 */
typedef enum qsc_asn1_status_t
{
    QSC_ASN1_STATUS_SUCCESS = 0,            /*!< Operation completed successfully. */
    QSC_ASN1_STATUS_FAILURE = -1,           /*!< A generic parsing or validation error occurred. */
    QSC_ASN1_STATUS_INVALID_INPUT = -2,     /*!< An input parameter was invalid. */
    QSC_ASN1_STATUS_INVALID_TAG = -3,       /*!< The element tag class, form, or tag number was not as expected. */
    QSC_ASN1_STATUS_INVALID_LENGTH = -4,    /*!< The element length was malformed or inconsistent. */
    QSC_ASN1_STATUS_INVALID_ENCODING = -5,  /*!< The ASN.1 value encoding was malformed. */
    QSC_ASN1_STATUS_BUFFER_TOO_SMALL = -6,  /*!< The caller-provided output buffer is too small. */
    QSC_ASN1_STATUS_OUT_OF_RANGE = -7,      /*!< The value exceeded the supported numeric or structural range. */
    QSC_ASN1_STATUS_NOT_FOUND = -8,         /*!< The requested child or optional element was not found. */
    QSC_ASN1_STATUS_UNSUPPORTED = -9        /*!< The encoding is recognized but not supported by this helper layer. */
} qsc_asn1_status;

/*!
 * \brief A decoded ASN.1 OBJECT IDENTIFIER.
 *
 * The structure stores both the original DER value octets and the decoded arc
 * sequence. The encoded form is useful for table lookups and direct comparison,
 * while the arc array is useful for debugging and diagnostics.
 */
QSC_EXPORT_API typedef struct qsc_asn1_oid_t
{
    uint8_t data[QSC_ASN1_OID_MAX_SIZE];    /*!< The encoded OID value octets, excluding tag and length. */
    uint32_t arcs[QSC_ASN1_OID_MAX_ARCS];   /*!< The decoded OID arcs. */
    size_t length;                          /*!< The number of valid bytes in the encoded data array. */
    size_t arcscount;                       /*!< The number of valid arcs in the arcs array. */
} qsc_asn1_oid;

/*!
 * \brief A normalized ASN.1 BIT STRING representation.
 */
QSC_EXPORT_API typedef struct qsc_asn1_bit_string_t
{
    const uint8_t* data;                    /*!< Pointer to the BIT STRING payload octets, excluding the unused-bits count byte. */
    size_t length;                          /*!< The number of payload octets. */
    uint8_t unused;                         /*!< The number of unused bits in the final payload octet. */
} qsc_asn1_bit_string;

/*!
 * \brief A normalized ASN.1 time representation.
 */
QSC_EXPORT_API typedef struct qsc_asn1_time_t
{
    uint16_t year;                          /*!< The calendar year. */
    uint8_t month;                          /*!< The calendar month in the range [1, 12]. */
    uint8_t day;                            /*!< The day of the month in the range [1, 31]. */
    uint8_t hour;                           /*!< The hour in the range [0, 23]. */
    uint8_t minute;                         /*!< The minute in the range [0, 59]. */
    uint8_t second;                         /*!< The second in the range [0, 59]. */
    bool generalized;                       /*!< true if decoded from GeneralizedTime, false if decoded from UTCTime. */
} qsc_asn1_time;

/*!
 * \brief Decode a complete DER element and reject trailing octets.
 *
 * \details
 * This helper wraps qsc_encoding_der_decode_element() and requires the input
 * buffer to contain exactly one complete DER element. Inputs with trailing
 * bytes are rejected so callers can fail closed on ambiguous or concatenated
 * encodings.
 *
 * \param der: [const uint8_t*] Pointer to the DER input buffer.
 * \param derlen: [size_t] Length of the DER input buffer in bytes.
 * \param element: [qsc_encoding_ber_element**] Receives the decoded element tree on success.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_der_decode_exact(const uint8_t* der, size_t derlen, qsc_encoding_ber_element** element);

/*!
 * \brief Returns the exact encoded DER slice of a child element within a parent element.
 *
 * \details
 * The parent buffer must contain exactly one DER element. The function walks
 * the encoded child sequence inside the parent content and returns the exact
 * byte range for the requested child element. This is intended for preserving
 * signed substructures such as TBSCertificate, CertificationRequestInfo, and
 * TBSCertList without reconstructing them from normalized fields.
 *
 * \param der: [const uint8_t*] Pointer to the complete parent DER element.
 * \param derlen: [size_t] Length of the parent DER element in bytes.
 * \param index: [size_t] Zero-based child index inside the parent content.
 * \param child: [const uint8_t**] Receives a pointer to the exact child DER encoding.
 * \param childlen: [size_t*] Receives the length of the child DER encoding in bytes.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_der_get_child_region(const uint8_t* der, size_t derlen, size_t index, const uint8_t** child, size_t* childlen);

/*!
 * \brief Compares two decoded ASN.1 OBJECT IDENTIFIER values.
 *
 * This function performs an exact comparison of two OID structures.
 * It is a compatibility wrapper around qsc_asn1_oid_are_equal() used
 * by the X.509 implementation.
 *
 * \param a: [const qsc_asn1_oid*] Pointer to the first OID.
 * \param b: [const qsc_asn1_oid*] Pointer to the second OID.
 *
 * \return [bool] Returns true if both OIDs are identical.
 */
QSC_EXPORT_API bool qsc_asn1_oid_compare(const qsc_asn1_oid* a, const qsc_asn1_oid* b);

/*!
 * \brief Validates that an element is a constructed ASN.1 SEQUENCE.
 *
 * The function verifies that the supplied element has the universal
 * SEQUENCE tag and that the number of child elements lies within the
 * specified inclusive bounds.
 *
 * This helper is used by the X.509 parser to validate DER structures
 * before accessing their child elements.
 *
 * \param element: [const qsc_encoding_ber_element*] Pointer to the ASN.1 element.
 * \param minchildren: [size_t] Minimum allowed number of children.
 * \param maxchildren: [size_t] Maximum allowed number of children.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS if validation succeeds.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_require_sequence(const qsc_encoding_ber_element* element, size_t minchildren, size_t maxchildren);

/*!
 * \brief Retrieves a child element from a constructed ASN.1 element.
 *
 * This function returns the child element at the specified index.
 * It is a compatibility alias for qsc_asn1_child_at().
 *
 * \param element: [const qsc_encoding_ber_element*] Pointer to the parent element.
 * \param index: [size_t] The zero-based child index.
 *
 * \return [const qsc_encoding_ber_element*] Returns a pointer to the child element,
 * or NULL if the index is invalid.
 */
QSC_EXPORT_API const qsc_encoding_ber_element* qsc_asn1_get_child(const qsc_encoding_ber_element* element, size_t index);

/*!
 * \brief Tests whether an ASN.1 element is a BOOLEAN.
 *
 * The function verifies that the supplied element has the universal
 * BOOLEAN tag and is encoded as a primitive value.
 *
 * \param element: [const qsc_encoding_ber_element*] Pointer to the ASN.1 element.
 *
 * \return [bool] Returns true if the element is a BOOLEAN.
 */
QSC_EXPORT_API bool qsc_asn1_is_boolean(const qsc_encoding_ber_element* element);

/*!
 * \brief Tests whether an ASN.1 element is an INTEGER.
 *
 * The function verifies that the supplied element has the universal
 * INTEGER tag and is encoded as a primitive value.
 *
 * \param element: [const qsc_encoding_ber_element*] Pointer to the ASN.1 element.
 *
 * \return [bool] Returns true if the element is an INTEGER.
 */
QSC_EXPORT_API bool qsc_asn1_is_integer(const qsc_encoding_ber_element* element);

/*!
 * \brief Decodes an ASN.1 INTEGER into a 64-bit unsigned value.
 *
 * This function is a compatibility wrapper around qsc_asn1_decode_uint64().
 * The INTEGER must be non-negative and must fit within a 64-bit unsigned
 * integer.
 *
 * \param element: [const qsc_encoding_ber_element*] Pointer to the INTEGER element.
 * \param value: [uint64_t*] Receives the decoded integer value.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS if decoding succeeds.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_integer_u64(const qsc_encoding_ber_element* element, uint64_t* value);

/*!
 * \brief Tests whether an ASN.1 element is a NULL value.
 *
 * The function verifies that the supplied element has the universal
 * NULL tag and is encoded as a primitive value.
 *
 * \param element: [const qsc_encoding_ber_element*] Pointer to the ASN.1 element.
 *
 * \return [bool] Returns true if the element is a NULL.
 */
QSC_EXPORT_API bool qsc_asn1_is_null(const qsc_encoding_ber_element* element);

/*!
 * \brief Tests whether an ASN.1 element is an OBJECT IDENTIFIER.
 *
 * The function verifies that the supplied element has the universal
 * OBJECT IDENTIFIER tag and is encoded as a primitive value.
 *
 * \param element: [const qsc_encoding_ber_element*] Pointer to the ASN.1 element.
 *
 * \return [bool] Returns true if the element is an OBJECT IDENTIFIER.
 */
QSC_EXPORT_API bool qsc_asn1_is_oid(const qsc_encoding_ber_element* element);

/*!
 * \brief Tests whether an ASN.1 element matches an expected tag description.
 *
 * \param element: [const qsc_encoding_ber_element*] The element to test.
 * \param tagclass: [uint8_t] The expected tag class.
 * \param constructed: [bool] The expected constructed flag.
 * \param tagnumber: [uint32_t] The expected tag number.
 *
 * \return [bool] Returns true if the element matches the requested tag description.
 */
QSC_EXPORT_API bool qsc_asn1_element_is_tag(const qsc_encoding_ber_element* element, uint8_t tagclass, bool constructed, uint32_t tagnumber);

/*!
 * \brief Validates that an ASN.1 element matches an expected tag description.
 *
 * \param element: [const qsc_encoding_ber_element*] The element to validate.
 * \param tagclass: [uint8_t] The expected tag class.
 * \param constructed: [bool] The expected constructed flag.
 * \param tagnumber: [uint32_t] The expected tag number.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_require_tag(const qsc_encoding_ber_element* element, uint8_t tagclass, bool constructed, uint32_t tagnumber);

/*!
 * \brief Gets the number of child elements in a constructed ASN.1 element.
 *
 * \param element: [const qsc_encoding_ber_element*] The constructed element.
 *
 * \return [size_t] Returns the number of child elements, or 0 if the input is invalid.
 */
QSC_EXPORT_API size_t qsc_asn1_child_count(const qsc_encoding_ber_element* element);

/*!
 * \brief Gets a child element by index.
 *
 * \param element: [const qsc_encoding_ber_element*] The parent constructed element.
 * \param index: [size_t] The child index.
 *
 * \return [const qsc_encoding_ber_element*] Returns a pointer to the requested child, or NULL on error.
 */
QSC_EXPORT_API const qsc_encoding_ber_element* qsc_asn1_child_at(const qsc_encoding_ber_element* element, size_t index);

/*!
 * \brief Gets an optional context-specific child by tag number.
 *
 * \param element: [const qsc_encoding_ber_element*] The parent constructed element.
 * \param tagnumber: [uint32_t] The requested context-specific tag number.
 *
 * \return [const qsc_encoding_ber_element*] Returns a pointer to the requested child, or NULL if no matching child exists.
 */
QSC_EXPORT_API const qsc_encoding_ber_element* qsc_asn1_find_context_child(const qsc_encoding_ber_element* element, uint32_t tagnumber);

/*!
 * \brief Gets the sole child of an explicitly tagged context-specific element.
 *
 * \param element: [const qsc_encoding_ber_element*] The context-specific wrapper element.
 * \param child: [const qsc_encoding_ber_element**] Receives the wrapped child element.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_get_explicit_child(const qsc_encoding_ber_element* element, const qsc_encoding_ber_element** child);

/*!
 * \brief Decodes a BOOLEAN value.
 *
 * \param element: [const qsc_encoding_ber_element*] The BOOLEAN element.
 * \param value: [bool*] Receives the decoded boolean value.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_boolean(const qsc_encoding_ber_element* element, bool* value);

/*!
 * \brief Decodes a non-negative INTEGER into a 64-bit unsigned integer.
 *
 * \param element: [const qsc_encoding_ber_element*] The INTEGER element.
 * \param value: [uint64_t*] Receives the decoded integer value.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_uint64(const qsc_encoding_ber_element* element, uint64_t* value);

/*!
 * \brief Copies the contents of an OCTET STRING into a caller-provided buffer.
 *
 * \param element: [const qsc_encoding_ber_element*] The OCTET STRING element.
 * \param output: [uint8_t*] The destination byte array.
 * \param otplen: [size_t] The size of the destination byte array.
 * \param outlen: [size_t*] Receives the number of bytes copied.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_octet_string(const qsc_encoding_ber_element* element, uint8_t* output, size_t otplen, size_t* outlen);

/*!
 * \brief Decodes a BIT STRING to a normalized descriptor.
 *
 * \param element: [const qsc_encoding_ber_element*] The BIT STRING element.
 * \param value: [qsc_asn1_bit_string*] Receives the normalized BIT STRING descriptor.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_bit_string(const qsc_encoding_ber_element* element, qsc_asn1_bit_string* value);

/*!
 * \brief Validates that an ASN.1 NULL element is correctly encoded.
 *
 * \param element: [const qsc_encoding_ber_element*] The NULL element.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS if the NULL encoding is valid.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_null(const qsc_encoding_ber_element* element);

/*!
 * \brief Decodes an OBJECT IDENTIFIER value.
 *
 * \param element: [const qsc_encoding_ber_element*] The OBJECT IDENTIFIER element.
 * \param oid: [qsc_asn1_oid*] Receives the decoded object identifier.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_oid(const qsc_encoding_ber_element* element, qsc_asn1_oid* oid);

/*!
 * \brief Compares two decoded OBJECT IDENTIFIER values for equality.
 *
 * \param a: [const qsc_asn1_oid*] The first object identifier.
 * \param b: [const qsc_asn1_oid*] The second object identifier.
 *
 * \return [bool] Returns true if the object identifiers are equal.
 */
QSC_EXPORT_API bool qsc_asn1_oid_are_equal(const qsc_asn1_oid* a, const qsc_asn1_oid* b);

/*!
 * \brief Converts a decoded OBJECT IDENTIFIER to dotted-decimal text.
 *
 * \param oid: [const qsc_asn1_oid*] The decoded object identifier.
 * \param output: [char*] The destination character array.
 * \param otplen: [size_t] The size of the destination character array.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_oid_to_string(const qsc_asn1_oid* oid, char* output, size_t otplen);

/*!
 * \brief Copies the contents of a supported ASN.1 string type into a character buffer.
 *
 * \details
 * This function supports the common string types used by X.509 distinguished names,
 * including PrintableString, UTF8String, IA5String, T61String, VisibleString,
 * BMPString, and UniversalString. For multi-byte encodings such as BMPString and
 * UniversalString, this helper accepts only values in the 7-bit ASCII subset and
 * rejects non-ASCII code points.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 string element.
 * \param output: [char*] The destination character array.
 * \param otplen: [size_t] The size of the destination character array.
 * \param outlen: [size_t*] Receives the length of the copied string, excluding the terminator.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_string(const qsc_encoding_ber_element* element, char* output, size_t otplen, size_t* outlen);

/*!
 * \brief Decodes a UTCTime or GeneralizedTime value to a normalized structure.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 time element.
 * \param value: [qsc_asn1_time*] Receives the normalized time value.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_decode_time(const qsc_encoding_ber_element* element, qsc_asn1_time* value);

/*!
 * \brief Compares two normalized ASN.1 times.
 *
 * \param a: [const qsc_asn1_time*] The first time value.
 * \param b: [const qsc_asn1_time*] The second time value.
 *
 * \return [int32_t] Returns -1 if a is earlier than b, 0 if equal, and 1 if later.
 */
QSC_EXPORT_API int32_t qsc_asn1_time_compare(const qsc_asn1_time* a, const qsc_asn1_time* b);

/*!
 * \brief Computes the encoded DER size of a decoded ASN.1 element.
 *
 * \details
 * This helper calculates the size of the element as it would appear in DER,
 * including the tag, length field, and content octets. For decoded BER trees,
 * this is useful when reconstructing exact spans of explicit wrappers or when
 * checking structure sizes during certificate parsing.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 element.
 * \param length: [size_t*] Receives the computed encoded length.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_asn1_der_size(const qsc_encoding_ber_element* element, size_t* size);

QSC_CPLUSPLUS_ENABLED_END

#endif
