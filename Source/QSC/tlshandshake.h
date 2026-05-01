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

#ifndef QSC_TLS_HANDSHAKE_H
#define QSC_TLS_HANDSHAKE_H

#include "qsccommon.h"
#include "tlscert.h"
#include "tlserrors.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlshandshake.h
 * \brief TLS 1.3 handshake framing and compact handshake-body codec helpers.
 *
 * \details
 * This header contains helpers for writing and parsing the TLS 1.3 4-byte handshake
 * header and for encoding or decoding a small set of compact handshake message bodies
 * used by the current client and server state machines. It does not duplicate the full
 * extension or certificate logic; those concerns remain in their dedicated modules.
 */

/**
 * \brief Write a TLS handshake header.
 *
 * \details
 * Writes the 1-byte handshake type followed by the 24-bit body length field.
 * The function emits only the header and does not append the message body.
 *
 * \param output: [uint8_t*] The destination output buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param offset: [size_t*] On input, the starting write offset; on success, advanced by four bytes.
 * \param type: [enum] The handshake message type.
 * \param bodylen: [size_t] The handshake body length in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_write_header(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_handshake_type type, size_t bodylen);

/**
 * \brief Read a TLS handshake header.
 *
 * \param input: [const uint8_t*] The input buffer containing the handshake header.
 * \param inlen: [size_t] The number of bytes available in input.
 * \param offset: [size_t*] On input, the starting read offset; on success, advanced by four bytes.
 * \param type: [enum*] Receives the decoded handshake type.
 * \param bodylen: [size_t*] Receives the decoded handshake body length in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_read_header(const uint8_t* input, size_t inlen, size_t* offset, qsc_tls_handshake_type* type, size_t* bodylen);

/**
 * \brief Encode the compatibility ChangeCipherSpec record used by TLS 1.3 middlebox mode.
 *
 * \details
 * Emits a plaintext TLS record carrying a one-byte ChangeCipherSpec fragment with value 0x01.
 * This helper produces the full TLSPlaintext record rather than a handshake message body.
 *
 * \param output: [uint8_t*] The destination output buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_send_change_cipher_spec_compat(uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Encode the body of a Finished handshake message.
 *
 * \param output: [uint8_t*] The destination output buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param offset: [size_t*] On input, the starting write offset; on success, advanced past the encoded body.
 * \param verifydata: [const uint8_t*] The computed Finished verify_data bytes.
 * \param verifydatalen: [size_t] The verify_data length in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_encode_finished(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* verifydata, size_t verifydatalen);

/**
 * \brief Decode the body of a Finished handshake message.
 *
 * \details
 * The returned verify-data span aliases the input buffer.
 *
 * \param input: [const uint8_t*] The Finished message body.
 * \param inlen: [size_t] The body length in bytes.
 * \param verifydata: [const uint8_t**] Receives a pointer to the verify_data span.
 * \param verifydatalen: [size_t*] Receives the verify_data length in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_decode_finished(const uint8_t* input, size_t inlen, const uint8_t** verifydata, size_t* verifydatalen);

/**
 * \brief Encode the body of a CertificateVerify handshake message.
 *
 * \param output: [uint8_t*] The destination output buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param offset: [size_t*] On input, the starting write offset; on success, advanced past the encoded body.
 * \param scheme: [enum] The signature scheme identifier.
 * \param signature: [const uint8_t*] The encoded signature bytes.
 * \param signaturelen: [size_t] The signature length in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_encode_certificate_verify(uint8_t* output, size_t outlen,
    size_t* offset, qsc_tls_signature_scheme scheme, const uint8_t* signature, size_t signaturelen);

/**
 * \brief Decode the body of a CertificateVerify handshake message.
 *
 * \details
 * The returned signature span aliases the input buffer.
 *
 * \param input: [const uint8_t*] The CertificateVerify message body.
 * \param inlen: [size_t] The body length in bytes.
 * \param scheme: [enum*] Receives the signature scheme identifier.
 * \param signature: [const uint8_t**] Receives a pointer to the encoded signature span.
 * \param signaturelen: [size_t*] Receives the signature length in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_decode_certificate_verify(const uint8_t* input, size_t inlen, qsc_tls_signature_scheme* scheme, const uint8_t** signature, size_t* signaturelen);

/**
 * \brief Encode the body of an EncryptedExtensions handshake message.
 *
 * \details
 * Writes the supplied extensions block as the TLS vector carried by the message body.
 * The caller is responsible for constructing the extension block contents.
 *
 * \param output: [uint8_t*] The destination output buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param offset: [size_t*] On input, the starting write offset; on success, advanced past the encoded body.
 * \param extensions: [const uint8_t*] The raw encoded extension block.
 * \param extensionslen: [size_t] The extension block length in bytes.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_encode_encrypted_extensions(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* extensions, size_t extensionslen);

/**
 * \brief Encode the body of a KeyUpdate handshake message.
 *
 * \param output: [uint8_t*] The destination output buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param offset: [size_t*] On input, the starting write offset; on success, advanced past the encoded body.
 * \param requestupdate: [bool] True to request that the peer also update its sending traffic keys.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_encode_key_update(uint8_t* output, size_t outlen, size_t* offset, bool requestupdate);

/**
 * \brief Decode the body of a KeyUpdate handshake message.
 *
 * \param input: [const uint8_t*] The KeyUpdate message body.
 * \param inlen: [size_t] The body length in bytes.
 * \param requestupdate: [bool*] Receives true when the peer requests a reciprocal key update.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_handshake_decode_key_update(const uint8_t* input, size_t inlen, bool* requestupdate);

QSC_CPLUSPLUS_ENABLED_END

#endif
