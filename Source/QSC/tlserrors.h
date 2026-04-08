#ifndef QSC_TLS_ERRORS_H
#define QSC_TLS_ERRORS_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlserrors.h
 * \brief TLS status code definitions and diagnostic string conversion.
 */

typedef enum qsc_tls_status
{
	qsc_tls_status_success = 0,						/*!< The operation completed successfully. */
	qsc_tls_status_failure = -1,					/*!< A generic TLS processing failure occurred. */
	qsc_tls_status_invalid_input = -2,				/*!< One or more input parameters were null, invalid, or semantically inconsistent. */
	qsc_tls_status_buffer_too_small = -3,			/*!< The supplied output buffer could not hold the encoded or decoded result. */
	qsc_tls_status_invalid_state = -4,				/*!< The object state did not permit the requested TLS operation. */
	qsc_tls_status_invalid_length = -5,				/*!< A parsed, derived, or supplied length field was outside the valid range. */
	qsc_tls_status_not_supported = -6,				/*!< The requested TLS feature, group, suite, or algorithm is not supported. */
	qsc_tls_status_authentication_failure = -7,		/*!< Authentication failed, or a signature, MAC, or certificate validation step failed. */
	qsc_tls_status_invalid_message = -8				/*!< The TLS message was malformed, truncated, or semantically invalid. */
} qsc_tls_status;

/**
 * \brief Convert a TLS status code to a descriptive diagnostic string.
 *
 * \param status: [enum] The TLS status code.
 *
 * \return: A constant descriptive string for the status code.
 */
QSC_EXPORT_API const char* qsc_tls_error_to_string(qsc_tls_status status);

QSC_CPLUSPLUS_ENABLED_END

#endif
