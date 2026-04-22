#ifndef QSC_TLS_ALERT_H
#define QSC_TLS_ALERT_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsalert.h
 * \brief TLS alert message encoding and decoding functions.
 *
 * \details
 * This header declares helpers that convert between the compact two-byte TLS
 * alert wire format and the internal alert description enumeration used by the
 * TLS implementation.
 */

/**
 * \brief Decode a TLS alert record payload.
 *
 * \details
 * Parses the standard two-byte TLS alert payload and extracts the alert
 * description field.
 *
 * \param input [const uint8_t*] The encoded alert payload.
 * \param inlen [size_t] The length of the encoded input in bytes.
 * \param description [enum*] Receives the decoded TLS alert description.
 *
 * \return [qsc_tls_status] Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_alert_decode(const uint8_t* input, size_t inlen, qsc_tls_alert_description* description);

/**
 * \brief Encode a TLS alert record payload.
 *
 * \details
 * Writes the standard two-byte TLS alert payload to the destination buffer.
 * The severity level is implementation-defined by the encoder and the supplied
 * description is written as the alert description field.
 *
 * \param output [uint8_t*] The destination buffer receiving the encoded alert payload.
 * \param outlen [size_t] The length of the destination buffer in bytes.
 * \param description [enum] The TLS alert description to encode.
 *
 * \return [qsc_tls_status] Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_alert_encode(uint8_t* output, size_t outlen, qsc_tls_alert_description description);

/**
 * Brief Encode a plaintext TLS alert record.
 *
 * \details
 * Builds the two-byte alert payload and wraps it in a TLSPlaintext record of
 * content type alert. This is used for alert transmission before encrypted
 * traffic keys are available.
 *
 * \param output [uint8_t*] The destination buffer receiving the encoded record.
 * \param outlen [size_t] The length of the destination buffer in bytes.
 * \param written [size_t*] Receives the number of bytes written.
 * \param description [enum] The TLS alert description to encode.
 *
 * 
 * \return [qsc_tls_status] Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_alert_encode_record(uint8_t* output, size_t outlen, size_t* written, qsc_tls_alert_description description);

/**
 * Brief Map an internal TLS status value to an RFC alert description.
 *
 * \details
 * Converts internal parser, state-machine, and authentication failures to the
 * closest TLS alert description used on the wire. This helper is used when the
 * wrapper layer needs to emit a protocol alert in response to a local failure.
 *
 * \param status [enum] The internal TLS status value.
 *
 * 
 * \return [enum] Returns the mapped TLS alert description.
 */
QSC_EXPORT_API qsc_tls_alert_description qsc_tls_alert_from_status(qsc_tls_status status);

/**
 * \brief Check if alert is close_notify
 *
 * \param description: [enum] Alert description
 *
 * \return: true if close_notify
 */
QSC_EXPORT_API bool qsc_tls_alert_is_close_notify(qsc_tls_alert_description description);

/**
 * \brief Check if alert level is fatal
 *
 * \param level: [uint8_t] Alert level
 *
 * \return: true if fatal
 */
QSC_EXPORT_API bool qsc_tls_alert_is_fatal_level(uint8_t level);

/**
 * \brief Validate alert description
 *
 * \param description: [enum] Alert description
 *
 * \return: true if valid
 */
QSC_EXPORT_API bool qsc_tls_alert_is_valid(qsc_tls_alert_description description);

/**
 * \brief Convert alert description to string (debug only)
 *
 * \param description: [qsc_tls_alert_description] Alert description enumerator
 *
 * \return: const string name
 */
QSC_EXPORT_API const char* qsc_tls_alert_to_string(qsc_tls_alert_description description);

QSC_CPLUSPLUS_ENABLED_END

#endif
