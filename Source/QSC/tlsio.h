#ifndef QSC_TLS_IO_H
#define QSC_TLS_IO_H

#include "qsccommon.h"
#include "tlserrors.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsio.h
 * \brief In-memory TLS byte-buffer helper functions.
 */

/**
 * \struct qsc_tls_iobuf
 * \brief Describes a byte buffer with a tracked read or write position.
 */
typedef struct qsc_tls_iobuf
{
	uint8_t* data;     /*!< Pointer to the backing buffer. */
	size_t length;     /*!< Total backing buffer length in bytes. */
	size_t position;   /*!< Current read or write offset in bytes. */
} qsc_tls_iobuf;

/**
 * \brief Initialize an I/O buffer descriptor.
 *
 * \param buffer: [struct] The buffer descriptor to initialize.
 * \param data: [uint8_t*] The backing buffer pointer.
 * \param length: [size_t] The total backing buffer length in bytes.
 */
QSC_EXPORT_API void qsc_tls_iobuf_initialize(qsc_tls_iobuf* buffer, uint8_t* data, size_t length);

/**
 * \brief Reset an I/O buffer position to the start of the backing buffer.
 *
 * \param buffer: [struct] The buffer descriptor to reset.
 */
QSC_EXPORT_API void qsc_tls_iobuf_reset(qsc_tls_iobuf* buffer);

/**
 * \brief Set the current I/O buffer position.
 *
 * \param buffer: [struct] The buffer descriptor to update.
 * \param position: [size_t] The new position in bytes.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_iobuf_set_position(qsc_tls_iobuf* buffer, size_t position);

/**
 * \brief Advance the current I/O buffer position.
 *
 * \param buffer: [struct] The buffer descriptor to update.
 * \param length: [size_t] The number of bytes to advance.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_iobuf_advance(qsc_tls_iobuf* buffer, size_t length);

/**
 * \brief Get the number of bytes remaining from the current position.
 *
 * \param buffer: [const struct] The buffer descriptor to query.
 *
 * \return The number of bytes remaining.
 */
QSC_EXPORT_API size_t qsc_tls_iobuf_remaining(const qsc_tls_iobuf* buffer);

/**
 * \brief Write bytes into the backing buffer at the current position.
 *
 * \param buffer: [struct] The buffer descriptor to update.
 * \param input: [const uint8_t*] The source bytes to write.
 * \param inlen: [size_t] The number of source bytes to write.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_iobuf_write(qsc_tls_iobuf* buffer, const uint8_t* input, size_t inlen);

/**
 * \brief Read bytes from the backing buffer at the current position.
 *
 * \param buffer: [struct] The buffer descriptor to update.
 * \param output: [uint8_t*] The destination buffer receiving the bytes.
 * \param outlen: [size_t] The number of bytes to read.
 *
 * \return The operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_iobuf_read(qsc_tls_iobuf* buffer, uint8_t* output, size_t outlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
