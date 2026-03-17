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

#ifndef QSC_ENCODING_H
#define QSC_ENCODING_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file encoding.h
 * \brief Encoding and decoding functions for Base64, Hex, BER/DER, and PEM.
 *
 * \details
 * This header provides production-quality implementations of four encoding
 * schemes that are heavily used in cryptographic infrastructure.  All
 * implementations are written to their governing specifications so that
 * encoded output is accepted by any conformant decoder, including the
 * certificate-processing pipelines found in X.509 / PKIX.
 *
 * \par Base64 (RFC 4648)
 * \c qsc_encoding_base64_encode and \c qsc_encoding_base64_decode implement
 * the standard Base64 alphabet defined in RFC 4648, Table 1.  The decode
 * function enforces the three RFC 4648 padding rules:
 *   - The total encoded length must be a non-zero multiple of four.
 *   - The '=' padding character may appear only at positions 2 and/or 3 of
 *     the final four-character group.
 *   - If position 2 of the final group contains '=', position 3 must also
 *     contain '=' (two-byte pad form).
 *
 * \par Hexadecimal Encoding
 * \c qsc_encoding_hex_encode produces upper-case hex and writes a null
 * terminator.  \c qsc_encoding_hex_decode accepts both upper- and lower-case
 * digits and rejects input whose character count is odd.  On any decode
 * failure the partially written output buffer is zeroed before the function
 * returns.
 *
 * \par BER/DER (ISO/IEC 8825-1 / X.690)
 * BER (Basic Encoding Rules) and its strict subset DER (Distinguished
 * Encoding Rules) encode ASN.1 values as Tag-Length-Value (TLV) triples.
 * The implementation covers:
 *   - Short-form (1-byte) and long-form (multi-byte) tag encoding.
 *   - Short-form (1-byte) and long-form (multi-byte) definite-length encoding.
 *   - Indefinite-length encoding for constructed BER elements, terminated by
 *     the End-of-Contents (EOC) octet pair 0x00 0x00.
 *   - Recursive encoding and decoding of constructed (composite) elements
 *     using a dynamically grown child pointer array.
 *   - DER encode uses a two-pass approach: a write-free size-computation pass
 *     (\c encoding_der_element_size) followed by a direct in-buffer recursive
 *     write, eliminating any fixed-size temporary allocation and correctly
 *     handling arbitrarily large structures (e.g. post-quantum X.509
 *     certificates).
 *   - DER decode delegates to the BER decoder and then rejects any element
 *     that used the indefinite-length form, as required by X.690 11.1.
 *
 * \par PEM (RFC 7468 / RFC 1421)
 * PEM wraps a Base64 payload between "-----BEGIN \<label\>-----" and
 * "-----END \<label\>-----" boundaries, with the Base64 data split into
 * lines of exactly 64 characters each.  The decode function:
 *   - Validates that the header and footer carry identical type labels.
 *   - Validates that the stripped payload length is a multiple of four.
 *   - Strips intra-line whitespace (spaces, CR, TAB) to tolerate
 *     RFC 2822-style folded encoding.
 *   - Rejects malformed or padded Base64 per the RFC 4648 rules above.
 *
 * \par Memory and resource management
 * Functions that return heap-allocated \c qsc_encoding_ber_element* trees
 * must be freed by the caller with \c qsc_encoding_ber_free_element.
 * All other functions write into caller-supplied buffers.  There are no
 * internal memory leaks; every allocation failure is recovered before the
 * function returns.
 *
 * \par Example: Base64 round-trip
 * \code
 * #include "encoding.h"
 *
 * uint8_t data[]   = { 0xDE, 0xAD, 0xBE, 0xEF };
 * size_t  data_len = sizeof(data);
 *
 * // Encode
 * size_t enc_len  = qsc_encoding_base64_encoded_size(data_len);
 * char   enc[12U] = { 0U };                          // enc_len + 1 for NUL
 * qsc_encoding_base64_encode(enc, sizeof(enc), data, data_len);
 *
 * // Decode
 * uint8_t dec[4U]  = { 0U };
 * size_t  dec_size = qsc_encoding_base64_decoded_size(enc, enc_len);
 * qsc_encoding_base64_decode(dec, sizeof(dec), enc, enc_len);
 * \endcode
 *
 * \par Example: PEM round-trip
 * \code
 * char pem[512U] = { 0U };
 * qsc_encoding_pem_encode("CERTIFICATE", pem, sizeof(pem), data, data_len);
 *
 * uint8_t raw[256U] = { 0U };
 * size_t  rawlen    = 0U;
 * qsc_encoding_pem_decode(pem, raw, sizeof(raw), &rawlen);
 * \endcode
 *
 * \par Example: BER element encode/decode
 * \code
 * // Encode a primitive INTEGER element containing the value 0x01.
 * qsc_encoding_ber_element elem = { 0 };
 * uint8_t val = 0x01U;
 * elem.tagclass   = QSC_ENCODING_BER_CLASS_UNIVERSAL;
 * elem.tagnumber  = BER_ASN1_INTEGER;
 * elem.length     = 1U;
 * elem.value      = &val;
 *
 * uint8_t ber_buf[8U];
 * size_t  ber_len = qsc_encoding_ber_encode_element(&elem, ber_buf, sizeof(ber_buf));
 *
 * // Decode it back.
 * size_t consumed = 0U;
 * qsc_encoding_ber_element* decoded =
 *     qsc_encoding_ber_decode_element(ber_buf, ber_len, &consumed);
 * if (decoded != NULL) { qsc_encoding_ber_free_element(decoded); }
 * \endcode
 *
 * \section encoding_refs Reference Documents
 * - Base64: RFC 4648 - <https://tools.ietf.org/html/rfc4648>
 * - BER/DER: ISO/IEC 8825-1 (X.690)
 * - PEM format: RFC 7468 - <https://tools.ietf.org/html/rfc7468>
 * - ASN.1 modules: ISO/IEC 8824-1 (X.680)
 */

/* ========================================================================== */
/*                        BER Tag-Class Constants                             */
/* ========================================================================== */

/*!
 * \def QSC_ENCODING_BER_CLASS_UNIVERSAL
 * \brief ASN.1 universal tag class (bits 8-7 = 00).
 *
 * Used for types that are common to all ASN.1 applications, such as INTEGER,
 * BOOLEAN, SEQUENCE, SET, BIT STRING, OCTET STRING, OBJECT IDENTIFIER, etc.
 * Defined in X.690 8.1.2.2, Table 1.
 */
#define QSC_ENCODING_BER_CLASS_UNIVERSAL 0x00U

/*!
 * \def QSC_ENCODING_BER_CLASS_APPLICATION
 * \brief ASN.1 application-specific tag class (bits 8-7 = 01).
 *
 * Used for types whose meaning is specific to an application.  The
 * interpretation of the tag number is application-defined.
 * Defined in X.690 8.1.2.2, Table 1.
 */
#define QSC_ENCODING_BER_CLASS_APPLICATION 0x40U

/*!
 * \def QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC
 * \brief ASN.1 context-specific tag class (bits 8-7 = 10).
 *
 * Used to distinguish between data elements that appear at the same position
 * in different contexts within a structured type (e.g. OPTIONAL fields in a
 * SEQUENCE).  Defined in X.690 8.1.2.2, Table 1.
 */
#define QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC 0x80U

/*!
 * \def QSC_ENCODING_BER_CLASS_PRIVATE
 * \brief ASN.1 private tag class (bits 8-7 = 11).
 *
 * Reserved for enterprise or vendor-specific extensions.
 * Defined in X.690 8.1.2.2, Table 1.
 */
#define QSC_ENCODING_BER_CLASS_PRIVATE 0xC0U

/*!
 * \def QSC_BER_ENCODING_INDEFINITE_LENGTH
 * \brief Sentinel value for requesting indefinite-length BER encoding.
 *
 * Pass this value as the \p length argument to
 * \c qsc_encoding_ber_encode_length to produce the single-byte indefinite-
 * length indicator (0x80) defined in X.690 8.1.3.6.  Only valid for
 * constructed BER elements; DER (and primitive BER) always use definite-
 * length form.
 */
#define QSC_BER_ENCODING_INDEFINITE_LENGTH ((size_t)-1)

/* ========================================================================== */
/*                    Universal ASN.1 Tag-Number Enumeration                  */
/* ========================================================================== */

/*!
 * \brief Universal ASN.1 tag numbers as defined in X.680 8.6 and
 *        X.690 Table 1.
 *
 * These values occupy the low five bits of the first tag octet when the
 * tag class is \c QSC_ENCODING_BER_CLASS_UNIVERSAL and the element uses
 * short-form tag encoding (tag number < 31).  Values 14 and 15 are
 * reserved by the standard and are not listed here.
 */
typedef enum
{
    BER_ASN1_EOC               = 0x00U, /*!< End-of-Contents (EOC) marker. */
    BER_ASN1_BOOLEAN           = 0x01U, /*!< BOOLEAN. */
    BER_ASN1_INTEGER           = 0x02U, /*!< INTEGER. */
    BER_ASN1_BIT_STRING        = 0x03U, /*!< BIT STRING. */
    BER_ASN1_OCTET_STRING      = 0x04U, /*!< OCTET STRING. */
    BER_ASN1_NULL              = 0x05U, /*!< NULL. */
    BER_ASN1_OBJECT_IDENTIFIER = 0x06U, /*!< OBJECT IDENTIFIER. */
    BER_ASN1_OBJECT_DESCRIPTOR = 0x07U, /*!< Object Descriptor (GraphicString subtype). */
    BER_ASN1_EXTERNAL          = 0x08U, /*!< EXTERNAL / INSTANCE OF. */
    BER_ASN1_REAL              = 0x09U, /*!< REAL (floating-point). */
    BER_ASN1_ENUMERATED        = 0x0AU, /*!< ENUMERATED. */
    BER_ASN1_EMBEDDED_PDV      = 0x0BU, /*!< EMBEDDED PDV. */
    BER_ASN1_UTF8_STRING       = 0x0CU, /*!< UTF8String. */
    BER_ASN1_RELATIVE_OID      = 0x0DU, /*!< RELATIVE-OID. */
    /* Tags 14 (0x0E) and 15 (0x0F) are reserved by X.680. */
    BER_ASN1_SEQUENCE          = 0x10U, /*!< SEQUENCE / SEQUENCE OF. */
    BER_ASN1_SET               = 0x11U, /*!< SET / SET OF. */
    BER_ASN1_NUMERIC_STRING    = 0x12U, /*!< NumericString. */
    BER_ASN1_PRINTABLE_STRING  = 0x13U, /*!< PrintableString. */
    BER_ASN1_T61_STRING        = 0x14U, /*!< TeletexString (T61String). */
    BER_ASN1_VIDEOTEX_STRING   = 0x15U, /*!< VideotexString. */
    BER_ASN1_IA5_STRING        = 0x16U, /*!< IA5String. */
    BER_ASN1_UTCTIME           = 0x17U, /*!< UTCTime. */
    BER_ASN1_GENERALIZEDTIME   = 0x18U, /*!< GeneralizedTime. */
    BER_ASN1_GRAPHIC_STRING    = 0x19U, /*!< GraphicString. */
    BER_ASN1_VISIBLE_STRING    = 0x1AU, /*!< VisibleString (ISO646String). */
    BER_ASN1_GENERAL_STRING    = 0x1BU, /*!< GeneralString. */
    BER_ASN1_UNIVERSAL_STRING  = 0x1CU, /*!< UniversalString (UTF-32). */
    BER_ASN1_CHARACTER_STRING  = 0x1DU, /*!< CharacterString. */
    BER_ASN1_BMP_STRING        = 0x1EU  /*!< BMPString (UTF-16 subset). */
} qsc_encoding_ber_asn1_tag_t;

/* ========================================================================== */
/*                         BER Element Structure                              */
/* ========================================================================== */

/*!
 * \brief In-memory representation of a single BER/DER ASN.1 TLV element.
 *
 * An element is either:
 *
 * \par Primitive
 * The raw value octets are stored in \c value and \c length reflects their
 * count.  \c children is NULL and \c ccount is 0.
 *
 * \par Constructed (definite-length)
 * For elements created by the encoder with a pre-encoded content block,
 * \c value holds that block and \c length reflects its byte count.
 * For elements produced by the decoder, \c children holds pointers to
 * individually decoded child elements and \c length reflects the total
 * content byte count (not including tag/length overhead of this element).
 *
 * \par Constructed (indefinite-length BER only)
 * \c indefinite is true.  The decoder populates \c children with all
 * elements found before the EOC marker; the encoder iterates \c children
 * and appends the 0x00 0x00 EOC pair.  DER rejects indefinite-length
 * encoding at both encode and decode time.
 *
 * \warning
 * The \c children array is heap-allocated and owned by this element.
 * Always release element trees with \c qsc_encoding_ber_free_element to
 * avoid memory leaks.
 */
QSC_EXPORT_API typedef struct qsc_encoding_ber_element
{
    uint8_t tagclass;       /*!< Tag class: one of QSC_ENCODING_BER_CLASS_UNIVERSAL,
                            *   QSC_ENCODING_BER_CLASS_APPLICATION,
                            *   QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, or
                            *   QSC_ENCODING_BER_CLASS_PRIVATE. */
    bool constructed;       /*!< true if the element is constructed (contains child
                            *   elements); false if primitive. */
    uint32_t tagnumber;     /*!< Tag number.  Values < 31 use short-form tag
                            *   encoding; values >= 31 use long-form (base-128). */
    bool indefinite;        /*!< true if the length was encoded in indefinite form
                            *   (BER only); false for definite form. */
    size_t length;          /*!< For primitive elements: number of bytes in \c value.
                            *   For constructed elements: total content byte count
                            *   (excluding the tag and length header of this node).*/
    uint8_t* value;         /*!< Pointer to the raw value bytes for primitive
                            *   elements, or the pre-encoded content block for
                            *   definite-length constructed elements.  NULL for
                            *   constructed elements decoded from child streams. */
    struct qsc_encoding_ber_element** children; /*!< Heap-allocated array of child
                            *   element pointers; valid only for constructed types
                            *   when decoded into individual child elements. */
    size_t    ccount;       /*!< Number of valid pointers in \c children. */
} qsc_encoding_ber_element;

/* ========================================================================== */
/*                            Base64 Functions                                */
/* ========================================================================== */

/*!
 * \brief Decode a Base64-encoded string to a byte array.
 *
 * Implements RFC 4648, 4.  The function performs three sequential validation
 * passes before writing output:
 *   1. Checks that \p inplen is a non-zero multiple of four.
 *   2. Checks that every character belongs to the Base64 alphabet or is '='.
 *   3. Checks that '=' appears only at the legally permitted positions in the
 *      final four-character group.
 *
 * \param output  [uint8_t*] Buffer that receives the decoded bytes.
 *  Must be at least \c qsc_encoding_base64_decoded_size(\p input, \p inplen) bytes.
 * \param otplen [size_t] Capacity of \p output in bytes.
 * \param input [const char*] Null-terminated or length-bounded Base64 string.
 * \param inplen [size_t] Length of \p input in characters; must be a non-zero multiple of four.
 *
 * \return [bool] true on success; false if any validation check fails or if \p output is too small.
 */
QSC_EXPORT_API bool qsc_encoding_base64_decode(uint8_t* output, size_t otplen, const char* input, size_t inplen);

/*!
 * \brief Compute the byte count required to hold the decoded form of a Base64 string.
 *
 * Accounts for RFC 4648 trailing padding characters ('=').  The result is
 * exact when \p input is a valid, padded Base64 string whose length is a
 * multiple of four.  Returns 0 if \p input is NULL, \p length is zero, or
 * \p length is not a multiple of four.
 *
 * \param input [const char*] Pointer to the Base64-encoded string.
 * \param length [size_t] Length of the encoded string in characters.
 *
 * \return [size_t] Number of decoded bytes, or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_base64_decoded_size(const char* input, size_t length);

/*!
 * \brief Encode a byte array to a Base64 string.
 *
 * Implements RFC 4648, 4, using the standard alphabet (A-Z, a-z, 0-9,
 * '+', '/') with '=' padding to ensure the output length is a multiple of
 * four. A null terminator is written after the encoded data.
 *
 * The caller must supply an \p output buffer of at least \c qsc_encoding_base64_encoded_size(\p inplen) + 1 bytes.
 *
 * \param output [char*] Buffer that receives the Base64 string.
 * \param otplen [size_t] Capacity of \p output in bytes (must be at least \c qsc_encoding_base64_encoded_size(\p inplen) + 1).
 * \param input [const uint8_t*] Binary data to encode.
 * \param inplen [size_t] Number of bytes to encode.
 *
 * \return [bool] true on success; false if the output buffer is too small or if any pointer argument is NULL.
 */
QSC_EXPORT_API bool qsc_encoding_base64_encode(char* output, size_t otplen, const uint8_t* input, size_t inplen);

/*!
 * \brief Compute the character count required to hold the Base64 encoding of \p length input bytes, including trailing '=' padding.
 *
 * The returned value does not include the null terminator; allocate
 * \c qsc_encoding_base64_encoded_size(\p length) + 1 bytes for the output
 * buffer passed to \c qsc_encoding_base64_encode.
 *
 * \param length  [size_t]  Number of raw input bytes.
 *
 * \return [size_t] Number of Base64 characters required (always a multiple of four), or 0 if \p length is zero.
 */
QSC_EXPORT_API size_t qsc_encoding_base64_encoded_size(size_t length);

/*!
 * \brief Test whether a character belongs to the Base64 alphabet.
 *
 * Returns true for A-Z, a-z, 0-9, '+', '/', and the padding character '='. All other characters return false.
 *
 * \param value  [char]  The character to test.
 *
 * \return [bool] true if \p value is a legal Base64 symbol.
 */
QSC_EXPORT_API bool qsc_encoding_base64_is_valid_char(char value);

/* ========================================================================== */
/*                           BER Decode Functions                             */
/* ========================================================================== */

/*!
 * \brief Decode a single BER element from an octet buffer.
 *
 * Parses the tag, length, and value (or child elements for constructed types)
 * from \p buffer according to X.690.  For constructed elements, child elements
 * are decoded recursively and stored in a heap-allocated pointer array.
 * Indefinite-length constructed elements are fully supported; the parser
 * consumes child elements until the EOC marker (0x00 0x00) is reached.
 *
 * On success, \p *consumed is set to the total number of octets read from
 * \p buffer (tag + length + value fields, including the EOC pair for
 * indefinite-length elements).  On failure, \p *consumed is set to 0 and the
 * return value is NULL; any partial allocations are freed internally.
 *
 * The caller must release the returned element tree with
 * \c qsc_encoding_ber_free_element.
 *
 * \param buffer [const uint8_t*] Input buffer containing the BER-encoded element.
 * \param buflen [size_t] Number of bytes available in \p buffer. Must be at least 2.
 * \param consumed [size_t*] Receives the number of bytes consumed on success,  or 0 on failure.
 *
 * \return [qsc_encoding_ber_element*] Pointer to the decoded element tree, or NULL on error.
 */
QSC_EXPORT_API qsc_encoding_ber_element* qsc_encoding_ber_decode_element(const uint8_t* buffer, size_t buflen, size_t* consumed);

/*!
 * \brief Decode a BER length field from an octet buffer.
 *
 * Implements X.690 8.1.3.  All three length forms are supported:
 *   - Short definite form (1 byte, value < 128).
 *   - Long definite form (2-9 bytes; the first byte's low seven bits give
 *     the count of subsequent length octets).
 *   - Indefinite form (single byte 0x80); \p *indef is set to true and
 *     \p *length is set to 0.
 *
 * The reserved value 0xFF (bnum = 127) and any long-form count that would overflow a native \c size_t are rejected.
 *
 * \param buffer [const uint8_t*] Input buffer positioned at the first length octet.
 * \param buflen [size_t] Number of bytes available at \p buffer.
 * \param length [size_t*] Receives the decoded length value on success.
 * \param indef [bool*] Set to true if the indefinite-length form was decoded.
 *
 * \return [size_t] Number of bytes consumed from \p buffer (1 for short and indefinite forms; 1 + bnum for long form), or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_ber_decode_length(const uint8_t* buffer, size_t buflen, size_t* length, bool* indef);

/*!
 * \brief Decode a BER tag field from an octet buffer.
 *
 * Implements X.690 8.1.2.  Both short-form (1-byte, tag number < 31) and
 * long-form (multi-byte base-128, continuation bit in bit 8) tags are
 * handled.  If the buffer is exhausted before the final base-128 octet
 * (bit 8 = 0) is found, the function returns 0 to indicate failure.
 *
 * \param buffer [const uint8_t*] Input buffer positioned at the first tag octet.
 * \param buflen [size_t] Number of bytes available at \p buffer.
 * \param tagclass [uint8_t*] Receives the tag class (QSC_ENCODING_BER_CLASS_UNIVERSAL et al.).
 * \param construct [bool*] Set to true if the Primitive/Constructed bit (bit 6) is set.
 * \param tagnum [uint32_t*] Receives the decoded tag number.
 *
 * \return [size_t] Number of bytes consumed from \p buffer, or 0 on error.
 */
QSC_EXPORT_API size_t qsc_encoding_ber_decode_tag(const uint8_t* buffer, size_t buflen, uint8_t* tagclass, bool* construct, uint32_t* tagnum);

/* ========================================================================== */
/*                           BER Encode Functions                             */
/* ========================================================================== */

/*!
 * \brief Encode a complete BER element (tag + length + value) to an octet buffer.
 *
 * Implements X.690 8.  Behaviour depends on the element type:
 *
 * \par Primitive
 * Writes the tag, a definite-length field, and the raw value bytes from
 * \c element->value.
 *
 * \par Constructed (definite-length)
 * Writes the tag, a definite-length field, then copies the pre-encoded
 * content block from \c element->value.
 *
 * \par Constructed (indefinite-length)
 * Writes the tag, the single-byte indefinite-length indicator (0x80),
 * recursively encodes each child in \c element->children, then appends
 * the EOC pair (0x00 0x00).
 *
 * \param element [qsc_encoding_ber_element*] Element to encode.
 * \param buffer [uint8_t*] Output buffer.
 * \param buflen [size_t] Capacity of \p buffer in bytes.
 *
 * \return [size_t] Total bytes written to \p buffer, or 0 on error (e.g. buffer too small, NULL pointer, or a child encoding failure).
 */
QSC_EXPORT_API size_t qsc_encoding_ber_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen);

/*!
 * \brief Encode a length value to BER form.
 *
 * Implements X.690 8.1.3:
 *   - If \p length equals \c QSC_BER_ENCODING_INDEFINITE_LENGTH, writes the
 *     single-byte indefinite-length indicator 0x80.
 *   - If \p length is in the range [0, 127], writes it as a single byte
 *     (short definite-length form).
 *   - Otherwise encodes \p length in the minimum number of big-endian octets
 *     and prepends a lead byte whose low seven bits give that count.
 *
 * \param length [size_t] Length value to encode, or \c QSC_BER_ENCODING_INDEFINITE_LENGTH.
 * \param buffer [uint8_t*] Output buffer.
 * \param buflen [size_t] Capacity of \p buffer in bytes.
 *
 * \return [size_t] Number of bytes written, or 0 if the buffer is too small or a pointer argument is NULL.
 */
QSC_EXPORT_API size_t qsc_encoding_ber_encode_length(size_t length, uint8_t* buffer, size_t buflen);

/*!
 * \brief Encode an ASN.1 tag to BER form.
 *
 * Implements X.690 8.1.2:
 *   - Composes the first byte from \p tagclass (bits 8-7), \p construct
 *     (bit 6), and the tag-number field (bits 5-1).
 *   - Short form: if \p tagnum < 31, the tag number occupies bits 5-1 of
 *     the first byte and encoding is complete.
 *   - Long form: bits 5-1 of the first byte are set to 11111; subsequent
 *     bytes encode \p tagnum in base-128 big-endian with the continuation
 *     bit (bit 8) set on every byte except the last.
 *
 * \param tagclass [uint8_t] Tag class constant (QSC_ENCODING_BER_CLASS_UNIVERSAL et al.).
 * \param construct [bool] true for constructed (composite) elements.
 * \param tagnum [uint32_t] Tag number; values >= 31 trigger long-form encoding.
 * \param buffer [uint8_t*] Output buffer.
 * \param buflen [size_t] Capacity of \p buffer in bytes.
 *
 * \return [size_t] Number of bytes written, or 0 on error (e.g. buffer too small or NULL pointer).
 */
QSC_EXPORT_API size_t qsc_encoding_ber_encode_tag(uint8_t tagclass, bool construct, uint32_t tagnum, uint8_t* buffer, size_t buflen);

/*!
 * \brief Recursively free a decoded BER element tree.
 *
 * Releases all memory associated with \p element and its descendants:
 * for constructed elements the \c children array and each child element are
 * freed depth-first; for primitive elements the \c value buffer is freed.
 * The element itself is then freed.  Passing NULL is safe and is a no-op.
 *
 * \param element [qsc_encoding_ber_element*] Root of the element tree to free.
 */
QSC_EXPORT_API void qsc_encoding_ber_free_element(qsc_encoding_ber_element* element);

/* ========================================================================== */
/*                           DER Functions                                    */
/* ========================================================================== */

/*!
 * \brief Decode a single DER element from an octet buffer.
 *
 * Delegates to \c qsc_encoding_ber_decode_element and then enforces the DER
 * constraint (X.690 11.1) that indefinite-length encoding is forbidden.  If
 * the decoded element carries an indefinite length, it is freed and NULL is
 * returned with \p *consumed set to 0.
 *
 * The caller must release the returned element with
 * \c qsc_encoding_ber_free_element.
 *
 * \param buffer [const uint8_t*] Input buffer containing the DER-encoded element.
 * \param buflen [size_t] Number of bytes available in \p buffer.
 * \param consumed [size_t*] Receives the number of bytes consumed on success, or 0 on failure.
 *
 * \return [qsc_encoding_ber_element*] Pointer to the decoded element, or NULL on error.
 */
QSC_EXPORT_API qsc_encoding_ber_element* qsc_encoding_der_decode_element(const uint8_t* buffer, size_t buflen, size_t* consumed);

/*!
 * \brief Encode an ASN.1 element tree using DER.
 *
 * Implements X.690 11 (DER).  Indefinite-length encoding is rejected.
 * For constructed elements, the function performs a write-free recursive
 * size-computation pass over the child tree to determine the exact content
 * length before writing any output.  Child elements are then encoded
 * directly into \p buffer without an intermediate temporary allocation,
 * making this function suitable for large structures such as post-quantum
 * X.509 certificates whose content may exceed many kilobytes.
 *
 * \param element [qsc_encoding_ber_element*]  Element tree to encode. Must not contain any indefinite-length nodes.
 * \param buffer [uint8_t*] Output buffer.
 * \param buflen [size_t] Capacity of \p buffer in bytes.
 *
 * \return [size_t] Total bytes written on success, or 0 on error (indefinite-length element present, buffer too small, 
 * NULL pointer, or a child encoding failure).
 */
QSC_EXPORT_API size_t qsc_encoding_der_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen);

/* ========================================================================== */
/*                        Hexadecimal Functions                               */
/* ========================================================================== */

/*!
 * \brief Decode a hexadecimal string to binary data.
 *
 * Accepts both upper- and lower-case hexadecimal digits (0-9, A-F, a-f).
 * The input length must be even.  On any decode error (odd length, out-of-
 * range character, or insufficient output buffer) the function clears any
 * partial output it has written, sets \p *declen to 0, and returns false.
 *
 * \param input [const char*] Hex-encoded input string.
 * \param inplen [size_t] Length of \p input in characters (must be even).
 * \param output [uint8_t*] Buffer that receives the decoded bytes.
 * \param otplen [size_t] Capacity of \p output (must be >= \p inplen / 2).
 * \param declen [size_t*] Receives the number of decoded bytes on success, or 0 on failure.
 *
 * \return [bool] true on success; false on any error.
 */
QSC_EXPORT_API bool qsc_encoding_hex_decode(const char* input, size_t inplen, uint8_t* output, size_t otplen, size_t* declen);

/*!
 * \brief Encode binary data to an upper-case hexadecimal string.
 *
 * Produces exactly \p inplen * 2 upper-case hex characters followed by a
 * null terminator.  The output buffer must be at least \p inplen * 2 + 1 bytes.
 *
 * \param input [const uint8_t*] Binary data to encode.
 * \param inplen [size_t] Number of bytes to encode.
 * \param output [char*] Buffer that receives the hex string.
 * \param otplen [size_t] Capacity of \p output (must be >= \p inplen * 2 + 1).
 *
 * \return [bool] true on success; false if the output buffer is too small or if any pointer argument is NULL.
 */
QSC_EXPORT_API bool qsc_encoding_hex_encode(const uint8_t* input, size_t inplen, char* output, size_t otplen);

/* ========================================================================== */
/*                           PEM Functions                                    */
/* ========================================================================== */

/*!
 * \brief Decode a PEM-formatted string to binary data.
 *
 * Implements RFC 7468 textual-encoding format.  The function:
 *   1. Verifies that the header ("-----BEGIN \<label\>-----") and footer
 *      ("-----END \<label\>-----") carry identical type labels.
 *   2. Verifies that the total Base64 character count (after stripping
 *      whitespace) is a multiple of four.
 *   3. Strips intra-line whitespace (spaces, CR, TAB) from each payload line
 *      to accommodate RFC 2822 folded lines.
 *   4. Decodes the resulting Base64 string with full RFC 4648 padding
 *      validation.
 *
 * On any failure \p *declen is set to 0 and the function returns false.
 *
 * \param input [const char*] Null-terminated PEM string (header + payload + footer).
 * \param output [uint8_t*] Buffer that receives the decoded binary data.
 * \param otplen [size_t] Capacity of \p output in bytes.
 * \param declen [size_t*] Receives the number of decoded bytes on success, or 0 on failure.
 *
 * \return [bool] true on success; false on any validation or capacity error.
 */
QSC_EXPORT_API bool qsc_encoding_pem_decode(const char* input, uint8_t* output, size_t otplen, size_t* declen);

/*!
 * \brief Encode binary data in PEM format.
 *
 * Produces a RFC 7468-conformant PEM encapsulation:
 *   - Header line:  "-----BEGIN \<label\>-----\n"
 *   - Base64 data:  wrapped at exactly 64 characters per line (RFC 7468 2).
 *   - Footer line:  "-----END \<label\>-----\n"
 *   - Null terminator appended to \p output.
 *
 * Returns false (without writing to \p output) if the output buffer is too
 * small to hold the complete PEM encoding or if any pointer argument is NULL.
 *
 * \param label [const char*] Type label string, e.g. "CERTIFICATE".
 * \param output [char*] Buffer that receives the PEM text.
 * \param otplen [size_t] Capacity of \p output in bytes.
 * \param data [const uint8_t*] Binary data to encode.
 * \param datalen [size_t] Number of bytes in \p data.
 *
 * \return [bool] true on success; false if the buffer is too small or if any pointer argument is NULL.
 */
QSC_EXPORT_API bool qsc_encoding_pem_encode(const char* label, char* output, size_t otplen, const uint8_t* data, size_t datalen);

/* ========================================================================== */
/*                          Debug Self-Test Function                          */
/* ========================================================================== */

#if defined(QSC_DEBUG_MODE)
/*!
 * \brief Run the built-in self-tests for the encoding functions.
 *
 * Exercises the PEM encode and decode paths against a set of known-good and
 * known-bad inputs, verifying correct output, correct rejection of malformed
 * PEM, and round-trip fidelity.
 *
 * \return [bool] true if all tests pass; false if any test fails.
 */
QSC_EXPORT_API bool qsc_encoding_tests(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
