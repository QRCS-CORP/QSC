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

#ifndef QSC_TLS_EXTENSIONS_H
#define QSC_TLS_EXTENSIONS_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"
#include "tlslimits.h"
#include "tlsstate.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsextensions.h
 * \brief TLS 1.3 extension encoding, decoding, validation, and selection helpers.
 *
 * \details
 * This header defines the extension-layer utility interface used by the QSC TLS
 * 1.3 implementation. The functions in this interface encode supported TLS
 * extension bodies into caller-owned handshake buffers, decode received extension
 * bodies into bounded output structures, enforce extension placement rules, track
 * duplicate extension appearances, and select mutually supported cipher suites
 * and key-share groups.
 *
 * Encoders write complete extension records, including the extension type and
 * extension-data length field. Decoders generally expect the extension body only,
 * after the extension type and extension-data length have already been parsed by
 * the caller. Span-returning decoders return pointers into the supplied input
 * buffer; those pointers remain valid only while the original input buffer
 * remains valid.
 */

 /**
  * \struct qsc_tls_extension_bitmap
  * \brief Tracks extension types observed while parsing one TLS handshake message.
  *
  * \details
  * This structure is a compact bitmap used to detect duplicate extensions in a
  * single TLS extension block. The TLS 1.3 extension grammar permits each
  * extension type to appear at most once in a given message. The parser may reset
  * this structure before parsing a message and call qsc_tls_extensions_bitmap_set()
  * for each decoded extension type.
  */
    typedef struct qsc_tls_extension_bitmap
{
    uint64_t lowmask;       /*!< Bits for extension types 0 through 63. */
    uint64_t highmask;      /*!< Bits for extension types 64 through 127. */
    uint64_t psk_ke_mask;   /*!< Bits for extension types 128 through 191. */
    uint64_t tailmask;      /*!< Bits for extension types 192 through 255 and folded higher values. */
} qsc_tls_extension_bitmap;

/**
 * \struct qsc_tls_psk_identity_view
 * \brief Non-owning view of a TLS pre-shared-key identity.
 *
 * \details
 * This structure represents a PSK identity entry as used by the TLS 1.3
 * pre_shared_key extension. The identity pointer is non-owning and may either
 * refer to caller-owned ticket bytes during encoding or to bytes inside an
 * encoded extension buffer during decoding.
 */
typedef struct qsc_tls_psk_identity_view
{
    const uint8_t* identity;       /*!< Pointer to the PSK identity or ticket byte string. */
    size_t identitylen;            /*!< Length, in bytes, of the PSK identity. */
    uint32_t obfuscatedticketage;  /*!< Obfuscated ticket age value encoded with the identity. */
} qsc_tls_psk_identity_view;

/**
 * \brief Reset a TLS extension appearance bitmap.
 *
 * \details
 * Clears all extension tracking masks in the supplied bitmap. The bitmap is used
 * while parsing a single handshake message to detect duplicate extensions.
 *
 * \param bitmap: [qsc_tls_extension_bitmap*] Pointer to the extension bitmap to initialize.
 */
QSC_EXPORT_API void qsc_tls_extensions_bitmap_initialize(qsc_tls_extension_bitmap* bitmap);

/**
 * \brief Mark an extension type as present in an appearance bitmap.
 *
 * \details
 * Sets the bit associated with an extension type and reports whether the
 * extension was newly recorded. This function is used to enforce the TLS 1.3
 * rule that an extension shall not appear more than once in the same extension
 * block.
 *
 * \param bitmap: [qsc_tls_extension_bitmap*] Pointer to the extension appearance bitmap.
 * \param extensiontype: [uint16_t] The numeric TLS extension type to mark.
 *
 * \return [bool] Returns true if the extension was newly added; otherwise
 *         returns false if the extension was already present or the bitmap is NULL.
 */
QSC_EXPORT_API bool qsc_tls_extensions_bitmap_set(qsc_tls_extension_bitmap* bitmap, uint16_t extensiontype);

/**
 * \brief Test whether an extension is permitted in a handshake message.
 *
 * \details
 * Applies TLS 1.3 extension placement rules for the extension types supported by
 * this implementation. The function returns true only when the specified
 * extension type is valid for the supplied handshake message type.
 *
 * \param message: [qsc_tls_handshake_type] The TLS handshake message type being parsed or constructed.
 * \param extensiontype: [qsc_tls_extension_type] The TLS extension type to test.
 *
 * \return [bool] Returns true if the extension is permitted in the specified message; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_tls_extensions_is_permitted(qsc_tls_handshake_type message, qsc_tls_extension_type extensiontype);

/**
 * \brief Encode the ClientHello supported_versions extension.
 *
 * \details
 * Writes a TLS supported_versions extension in ClientHello format. The encoded extension advertises TLS 1.3 as the supported protocol version.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success,.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_supported_versions_client(uint8_t* output, size_t outlen, size_t* offset);

/**
 * \brief Encode the ServerHello supported_versions extension.
 *
 * \details
 * Writes a TLS supported_versions extension in ServerHello format. The encoded extension contains the selected TLS 1.3 protocol version.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_supported_versions_server(uint8_t* output, size_t outlen, size_t* offset);

/**
 * \brief Encode the supported_groups extension.
 *
 * \details
 * Writes a supported_groups extension containing the supplied ordered list of named groups.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param groups: [const qsc_tls_named_group*] Pointer to the named-group list.
 * \param groupcount: [size_t] Number of entries in the named-group list.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_supported_groups(uint8_t* output, size_t outlen, size_t* offset, 
    const qsc_tls_named_group* groups, size_t groupcount);

/**
 * \brief Encode the signature_algorithms extension.
 *
 * \details
 * Writes a signature_algorithms extension containing the supplied ordered list of supported signature schemes.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param schemes: [const qsc_tls_signature_scheme*] Pointer to the signature scheme list.
 * \param schemecount: [size_t] Number of entries in the signature scheme list.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_signature_algorithms(uint8_t* output, size_t outlen, size_t* offset, 
    const qsc_tls_signature_scheme* schemes, size_t schemecount);

/**
 * \brief Encode the signature_algorithms_cert extension.
 *
 * \details
 * Writes a signature_algorithms_cert extension containing the supplied ordered list of supported certificate signature schemes.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param schemes: [const qsc_tls_signature_scheme*] Pointer to the certificate signature scheme list.
 * \param schemecount: [size_t] Number of entries in the certificate signature scheme list.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_signature_algorithms_cert(uint8_t* output, size_t outlen, size_t* offset, 
    const qsc_tls_signature_scheme* schemes, size_t schemecount);

/**
 * \brief Encode the ClientHello key_share extension.
 *
 * \details
 * Writes a ClientHello key_share extension containing one KeyShareEntry. The entry contains the named group identifier and the public key-exchange share.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param group: [qsc_tls_named_group] The named group associated with the public share.
 * \param publicshare: [const uint8_t*] Pointer to the public key-exchange share.
 * \param publicsharelen: [size_t] Length, in bytes, of the public share.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_key_share_client(uint8_t* output, size_t outlen, size_t* offset, 
    qsc_tls_named_group group, const uint8_t* publicshare, size_t publicsharelen);

/**
 * \brief Encode the ServerHello key_share extension.
 *
 * \details
 * Writes a ServerHello key_share extension containing the selected named group and the server public key-exchange share.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param group: [qsc_tls_named_group] The selected named group.
 * \param publicshare: [const uint8_t*] Pointer to the server public share.
 * \param publicsharelen: [size_t] Length, in bytes, of the public share.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_key_share_server(uint8_t* output, size_t outlen, size_t* offset, 
    qsc_tls_named_group group, const uint8_t* publicshare, size_t publicsharelen);

/**
 * \brief Encode the HelloRetryRequest key_share extension.
 *
 * \details
 * Writes a key_share extension in HelloRetryRequest form. The encoded body contains only the requested named group identifier.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param group: [qsc_tls_named_group] The named group requested by the server.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_key_share_hello_retry(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_named_group group);

/**
 * \brief Encode the server_name extension.
 *
 * \details
 * Writes a server_name extension containing a single host_name entry. The hostname is copied without a terminating NULL byte.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param hostname: [const char*] Pointer to the NULL-terminated hostname string.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_server_name(uint8_t* output, size_t outlen, size_t* offset, const char* hostname);

/**
 * \brief Encode the psk_key_exchange_modes extension.
 *
 * \details
 * Writes a psk_key_exchange_modes extension containing the supplied list of PSK key exchange mode identifiers.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param modes: [const uint8_t*] Pointer to the PSK key exchange mode list.
 * \param modecount: [size_t] Number of mode identifiers in the list.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_psk_key_exchange_modes(uint8_t* output, size_t outlen, size_t* offset, 
    const uint8_t* modes, size_t modecount);

/**
 * \brief Encode an empty early_data extension.
 *
 * \details
 * Writes an early_data extension with a zero-length body. This form is used in ClientHello and EncryptedExtensions contexts.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_early_data_empty(uint8_t* output, size_t outlen, size_t* offset);

/**
 * \brief Encode an early_data maximum-size extension.
 *
 * \details
 * Writes an early_data extension containing the max_early_data_size value used in a NewSessionTicket context.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param maxearlydatasize: [uint32_t] Maximum permitted early-data size, in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_early_data_max(uint8_t* output, size_t outlen, size_t* offset, uint32_t maxearlydatasize);

/**
 * \brief Decode an early_data maximum-size extension body.
 *
 * \details
 * Parses a NewSessionTicket early_data extension body and returns the max_early_data_size value.
 *
 * \param input: [const uint8_t*] Pointer to the encoded early_data extension body.
 * \param inplen: [size_t] Length, in bytes, of the encoded extension body.
 * \param maxearlydatasize: [uint32_t*] Pointer receiving the decoded maximum early-data size.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_early_data_max(const uint8_t* input, size_t inplen, uint32_t* maxearlydatasize);

/**
 * \brief Encode a ClientHello pre_shared_key extension.
 *
 * \details
 * Writes a ClientHello pre_shared_key extension body containing OfferedPsks. 
 * The identities vector is encoded first, followed by a binders vector. 
 * Binder entries are emitted as zero-filled placeholders of the requested length. 
 * The caller must compute and backpatch the real binder values after hashing the truncated ClientHello transcript.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param identities: [const qsc_tls_psk_identity_view*] Pointer to the PSK identity view array.
 * \param identitycount: [size_t] Number of PSK identities to encode.
 * \param binderlen: [size_t] Length, in bytes, of each binder placeholder.
 * \param binderoffset: [size_t*] Pointer receiving the absolute output offset of the first binder byte.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_offer(uint8_t* output, size_t outlen, size_t* offset, 
    const qsc_tls_psk_identity_view* identities, size_t identitycount, size_t binderlen, size_t* binderoffset);

/**
 * \brief Encode a ServerHello pre_shared_key extension.
 *
 * \details
 * Writes a ServerHello pre_shared_key extension containing the selected PSK identity index.
 *
 * \param output: [uint8_t*] Pointer to the destination extension buffer.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param offset: [size_t*] Pointer to the current write offset; updated on success.
 * \param selidentity: [uint16_t] The selected PSK identity index.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_server(uint8_t* output, size_t outlen, size_t* offset, uint16_t selidentity);

/**
 * \brief Decode a ClientHello pre_shared_key extension body.
 *
 * \details
 * Parses an OfferedPsks body into PSK identity views and binder spans. 
 * The views point directly into the supplied input buffer and remain valid only while that buffer remains valid. 
 * The function also returns the offset of the binders-list length prefix so the caller can recompute binders over the correctly truncated ClientHello transcript.
 *
 * \param input: [const uint8_t*] Pointer to the encoded pre_shared_key extension body.
 * \param inplen: [size_t] Length, in bytes, of the encoded extension body.
 * \param identities: [qsc_tls_psk_identity_view*] Pointer to the output identity view array.
 * \param binders: [const uint8_t**] Pointer to the output binder span array.
 * \param binderlens: [size_t*] Pointer to the output binder-length array.
 * \param capacity: [size_t] Maximum number of identities and binders that can be written to the output arrays.
 * \param count: [size_t*] Pointer receiving the number of identities and binders parsed.
 * \param binderblockoffset: [size_t*] Pointer receiving the offset of the binders-list length prefix within input.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_offer(const uint8_t* input, size_t inplen, qsc_tls_psk_identity_view* identities, 
    const uint8_t** binders, size_t* binderlens, size_t capacity, size_t* count, size_t* binderblockoffset);

/**
 * \brief Decode a ServerHello pre_shared_key extension body.
 *
 * \details
 * Parses a ServerHello pre_shared_key extension body and returns the selected PSK identity index.
 *
 * \param input: [const uint8_t*] Pointer to the encoded pre_shared_key extension body.
 * \param inplen: [size_t] Length, in bytes, of the encoded extension body.
 * \param selidentity: [uint16_t*] Pointer receiving the selected PSK identity index.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_server(const uint8_t* input, size_t inplen, uint16_t* selidentity);

/**
 * \brief Decode a ClientHello supported_versions extension body.
 *
 * \details
 * Parses the ClientHello supported_versions vector and reports whether TLS 1.3 is present in the advertised version list.
 *
 * \param input: [const uint8_t*] Pointer to the encoded supported_versions body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param acceptstls13: [bool*] Pointer receiving true if TLS 1.3 is advertised.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_supported_versions_client(const uint8_t* input, size_t inplen, bool* acceptstls13);

/**
 * \brief Decode a ServerHello supported_versions extension body.
 *
 * \details
 * Parses the selected protocol version from a ServerHello supported_versions extension body.
 *
 * \param input: [const uint8_t*] Pointer to the encoded supported_versions body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param selectedversion: [uint16_t*] Pointer receiving the selected protocol version.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_supported_versions_server(const uint8_t* input, size_t inplen, uint16_t* selectedversion);

/**
 * \brief Decode a supported_groups extension body.
 *
 * \details
 * Parses the named-group vector from a supported_groups extension body and writes the decoded groups to the caller-provided output array.
 *
 * \param input: [const uint8_t*] Pointer to the encoded supported_groups body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param groups: [qsc_tls_named_group*] Pointer to the output named-group array.
 * \param groupcapacity: [size_t] Maximum number of group entries that may be written to groups.
 * \param groupcount: [size_t*] Pointer receiving the number of decoded groups.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_supported_groups(const uint8_t* input, size_t inplen, qsc_tls_named_group* groups, 
    size_t groupcapacity, size_t* groupcount);

/**
 * \brief Decode a signature_algorithms extension body.
 *
 * \details
 * Parses a signature-scheme vector and writes the decoded schemes to the caller-provided output array. 
 * This decoder is suitable for both signature_algorithms and signature_algorithms_cert bodies when the wire format is identical.
 *
 * \param input: [const uint8_t*] Pointer to the encoded signature-scheme vector body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param schemes: [qsc_tls_signature_scheme*] Pointer to the output scheme array.
 * \param schemecapacity: [size_t] Maximum number of scheme entries that may be written to schemes.
 * \param schemecount: [size_t*] Pointer receiving the number of decoded schemes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_signature_algorithms(const uint8_t* input, size_t inplen, qsc_tls_signature_scheme* schemes, 
    size_t schemecapacity, size_t* schemecount);

/**
 * \brief Decode a ClientHello key_share extension body.
 *
 * \details
 * Parses a ClientHello key_share vector into non-owning group and public-share spans. The share pointers refer directly to the supplied input buffer.
 *
 * \param input: [const uint8_t*] Pointer to the encoded key_share extension body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param groups: [qsc_tls_named_group*] Pointer to the output named-group array.
 * \param shares: [const uint8_t**] Pointer to the output public-share pointer array.
 * \param sharelens: [size_t*] Pointer to the output public-share length array.
 * \param capacity: [size_t] Maximum number of key-share entries that may be written to the output arrays.
 * \param count: [size_t*] Pointer receiving the number of decoded key-share entries.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_key_share_client_hello(const uint8_t* input, size_t inplen, qsc_tls_named_group* groups, 
    const uint8_t** shares, size_t* sharelens, size_t capacity, size_t* count);

/**
 * \brief Decode a ServerHello key_share extension body.
 *
 * \details
 * Parses the selected named group and server public-share span from a ServerHello key_share extension body. 
 * The returned share pointer refers directly to the supplied input buffer.
 *
 * \param input: [const uint8_t*] Pointer to the encoded key_share extension body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param selectedgroup: [qsc_tls_named_group*] Pointer receiving the selected named group.
 * \param share: [const uint8_t**] Pointer receiving the public-share span.
 * \param sharelen: [size_t*] Pointer receiving the public-share length, in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_key_share_server_hello(const uint8_t* input, size_t inplen, qsc_tls_named_group* selectedgroup, 
    const uint8_t** share, size_t* sharelen);

/**
 * \brief Decode a HelloRetryRequest key_share extension body.
 *
 * \details
 * Parses the requested named group from a HelloRetryRequest key_share extension body.
 *
 * \param input: [const uint8_t*] Pointer to the encoded key_share extension body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param requestedgroup: [qsc_tls_named_group*] Pointer receiving the requested named group.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_key_share_hello_retry(const uint8_t* input, size_t inplen, qsc_tls_named_group* requestedgroup);

/**
 * \brief Decode a server_name extension body.
 *
 * \details
 * Parses a server_name extension containing a host_name entry. The returned hostname pointer refers directly to the supplied input buffer and is not NULL-terminated.
 *
 * \param input: [const uint8_t*] Pointer to the encoded server_name extension body.
 * \param inplen: [size_t] Length, in bytes, of the encoded body.
 * \param hostname: [const char**] Pointer receiving the hostname span.
 * \param hostnamelen: [size_t*] Pointer receiving the hostname length, in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_decode_server_name(const uint8_t* input, size_t inplen, const char** hostname, size_t* hostnamelen);

/**
 * \brief Select a mutually supported cipher suite.
 *
 * \details
 * Selects the first server-preferred cipher suite that appears in the serialized client cipher-suite vector. 
 * The client vector is expected to contain the inner cipher-suite list bytes, encoded as two-byte suite identifiers.
 *
 * \param clientsuites: [const uint8_t*] Pointer to the serialized client cipher-suite list.
 * \param clientsuiteslen: [size_t] Length, in bytes, of the client cipher-suite list.
 * \param serverpreference: [const qsc_tls_cipher_suite*] Pointer to the ordered server cipher-suite preference list.
 * \param serverpreferencecount: [size_t] Number of entries in the server preference list.
 * \param selected: [qsc_tls_cipher_suite*] Pointer receiving the selected cipher suite.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_select_cipher_suite(const uint8_t* clientsuites, size_t clientsuiteslen, const qsc_tls_cipher_suite* serverpreference, 
    size_t serverpreferencecount, qsc_tls_cipher_suite* selected);

/**
 * \brief Select a mutually supported key-share group.
 *
 * \details
 * Selects the first server-preferred named group that appears in the client group list.
 *
 * \param groups: [const qsc_tls_named_group*] Pointer to the client named-group list.
 * \param groupcount: [size_t] Number of entries in the client named-group list.
 * \param serverpreference: [const qsc_tls_named_group*] Pointer to the ordered server named-group preference list.
 * \param serverpreferencecount: [size_t] Number of entries in the server preference list.
 * \param selected: [qsc_tls_named_group*] Pointer receiving the selected named group.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_extensions_select_key_share(const qsc_tls_named_group* groups, size_t groupcount, const qsc_tls_named_group* serverpreference, 
    size_t serverpreferencecount, qsc_tls_named_group* selected);

QSC_CPLUSPLUS_ENABLED_END

#endif
