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
 * \param inlen: [size_t] The source buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_bytes(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen);

/**
 * \brief Write an 8-bit length-prefixed TLS vector.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * 
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_vector8(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen);

/**
 * \brief Write a 16-bit length-prefixed TLS vector.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_vector16(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen);

/**
 * \brief Write a 24-bit length-prefixed TLS vector.
 *
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 * \param offset: [size_t*] The input and output write offset.
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_write_vector24(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen);

/**
 * \brief Read an unsigned 8-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint8_t*] The decoded value.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u8(const uint8_t* input, size_t inlen, size_t* offset, uint8_t* value);

/**
 * rief Read an unsigned 16-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint16_t*] The decoded value.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u16(const uint8_t* input, size_t inlen, size_t* offset, uint16_t* value);

/**
 * \brief Read an unsigned 24-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint32_t*] The decoded value.
 * 
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u24(const uint8_t* input, size_t inlen, size_t* offset, uint32_t* value);

/**
 * \brief Read an unsigned 32-bit value from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param value: [uint32_t*] The decoded value.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_u32(const uint8_t* input, size_t inlen, size_t* offset, uint32_t* value);

/**
 * \brief Read raw bytes from a TLS buffer.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param output: [uint8_t*] The destination buffer.
 * \param outlen: [size_t] The destination buffer length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_bytes(const uint8_t* input, size_t inlen, size_t* offset, uint8_t* output, size_t outlen);

/**
 * \brief Read an 8-bit length-prefixed TLS vector as a span.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param span: [const uint8_t**] The returned span pointer.
 * \param spanlen: [size_t*] The returned span length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_vector8_span(const uint8_t* input, size_t inlen, size_t* offset, const uint8_t** span, size_t* spanlen);

/**
 * \brief Read a 16-bit length-prefixed TLS vector as a span.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param span: [const uint8_t**] The returned span pointer.
 * \param spanlen: [size_t*] The returned span length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_vector16_span(const uint8_t* input, size_t inlen, size_t* offset, const uint8_t** span, size_t* spanlen);

/**
 * \brief Read a 24-bit length-prefixed TLS vector as a span.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length.
 * \param offset: [size_t*] The input and output read offset.
 * \param span: [const uint8_t**] The returned span pointer.
 * \param spanlen: [size_t*] The returned span length.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_codec_read_vector24_span(const uint8_t* input, size_t inlen, size_t* offset, const uint8_t** span, size_t* spanlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
