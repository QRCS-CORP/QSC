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

#ifndef QSC_TLS_CODEC_H
#define QSC_TLS_CODEC_H

#include "qsccommon.h"
#include "tlserrors.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * File tlscodec.h
 * \brief Primitive TLS wire-format readers and writers.
 */

/**
 * \brief Write an unsigned 8-bit value to a TLS buffer.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param value: [uint8_t] The value to encode.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_u8(uint8_t* output, size_t outlen, size_t* offset, uint8_t value);

/**
 * \brief Write an unsigned 16-bit value to a TLS buffer.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param value: [uint16_t] The value to encode.
 * 
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_u16(uint8_t* output, size_t outlen, size_t* offset, uint16_t value);

/**
 * \brief Write an unsigned 24-bit value to a TLS buffer.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param value: [uint32_t] The value to encode. The upper byte must be zero.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_u24(uint8_t* output, size_t outlen, size_t* offset, uint32_t value);

/**
 * \brief Write an unsigned 32-bit value to a TLS buffer.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param value: [uint32_t] The value to encode.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_u32(uint8_t* output, size_t outlen, size_t* offset, uint32_t value);

/**
 * \brief Write raw bytes to a TLS buffer.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_bytes(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen);

/**
 * \brief Write an 8-bit length-prefixed TLS vector.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * 
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_vector8(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen);

/**
 * \brief Write a 16-bit length-prefixed TLS vector.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_vector16(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen);

/**
 * \brief Write a 24-bit length-prefixed TLS vector.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_vector24(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen);

/**
 * \brief Read an unsigned 8-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint8_t*] The decoded value.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u8(const uint8_t* input, size_t inplen, size_t* offset, uint8_t* value);

/**
 * rief Read an unsigned 16-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint16_t*] The decoded value.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u16(const uint8_t* input, size_t inplen, size_t* offset, uint16_t* value);

/**
 * \brief Read an unsigned 24-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint32_t*] The decoded value.
 * 
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u24(const uint8_t* input, size_t inplen, size_t* offset, uint32_t* value);

/**
 * \brief Read an unsigned 32-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint32_t*] The decoded value.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u32(const uint8_t* input, size_t inplen, size_t* offset, uint32_t* value);

/**
 * \brief Read raw bytes from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_bytes(const uint8_t* input, size_t inplen, size_t* offset, uint8_t* output, size_t outlen);

/**
 * \brief Read an 8-bit length-prefixed TLS vector as a span.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param span: [const uint8_t**] The returned span pointer.
 * \param spanlen: [size_t*] The returned span length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_vector8_span(const uint8_t* input, size_t inplen, size_t* offset, const uint8_t** span, size_t* spanlen);

/**
 * \brief Read a 16-bit length-prefixed TLS vector as a span.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param span: [const uint8_t**] The returned span pointer.
 * \param spanlen: [size_t*] The returned span length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_vector16_span(const uint8_t* input, size_t inplen, size_t* offset, const uint8_t** span, size_t* spanlen);

/**
 * \brief Read a 24-bit length-prefixed TLS vector as a span.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param span: [const uint8_t**] The returned span pointer.
 * \param spanlen: [size_t*] The returned span length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_vector24_span(const uint8_t* input, size_t inplen, size_t* offset, const uint8_t** span, size_t* spanlen);

/**
 * \brief Read an unsigned 64-bit value from a TLS buffer in network byte order.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inplen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint64_t*] The decoded value.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u64(const uint8_t* input, size_t inplen, size_t* offset, uint64_t* value);

/**
 * \brief Reserve space for a length-prefixed vector header and return its position.
 *
 * \details
 * Used for encoding nested TLS structures where the length is unknown until the body
 * has been written. Advance the write offset past the reserved header, write the body
 * using other codec helpers, then call qsc_tls_codec_vector_end_u8 / _u16 / _u24 with
 * the returned header position to backpatch the final length.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param headerposition: [size_t*] Receives the reserved header byte position.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_vector_begin_u8(uint8_t* output, size_t outlen, size_t* offset, size_t* headerposition);

/**
 * \brief Reserve a 16-bit length-prefixed vector header.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_vector_begin_u16(uint8_t* output, size_t outlen, size_t* offset, size_t* headerposition);

/**
 * \brief Reserve a 24-bit length-prefixed vector header.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_vector_begin_u24(uint8_t* output, size_t outlen, size_t* offset, size_t* headerposition);

/**
 * \brief Backpatch the 8-bit length of a reserved vector.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The current write offset; used to compute the body length.
 * \param headerposition: [size_t] The header position returned from qsc_tls_codec_vector_begin_u8.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_vector_end_u8(uint8_t* output, size_t outlen, const size_t* offset, size_t headerposition);

/**
 * \brief Backpatch the 16-bit length of a reserved vector.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_vector_end_u16(uint8_t* output, size_t outlen, const size_t* offset, size_t headerposition);

/**
 * \brief Backpatch the 24-bit length of a reserved vector.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_vector_end_u24(uint8_t* output, size_t outlen, const size_t* offset, size_t headerposition);

QSC_CPLUSPLUS_ENABLED_END

#endif
