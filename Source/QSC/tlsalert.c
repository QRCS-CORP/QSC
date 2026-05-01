#include "tlsalert.h"
#include "tlsdefs.h"
#include "tlsrecord.h"
#include "memutils.h"

static bool tls_alert_level_is_valid(uint8_t level)
{
	return ((level == 1U) || (level == 2U));
}

qsc_tls_status qsc_tls_alert_decode(const uint8_t* input, size_t inlen, qsc_tls_alert_description* description)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(description != NULL);

	qsc_tls_status status;
	qsc_tls_alert_description desc;

	status = qsc_tls_status_success;
	desc = qsc_tls_alert_close_notify;

	if (input == NULL || description == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (inlen < QSC_TLS_ALERT_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (tls_alert_level_is_valid(input[0]) == false)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		desc = (qsc_tls_alert_description)input[1];

		if (qsc_tls_alert_is_valid(desc) == false)
		{
			status = qsc_tls_status_invalid_message;
		}
		else
		{
			*description = desc;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_alert_encode(uint8_t* output, size_t outlen, qsc_tls_alert_description description)
{
	QSC_ASSERT(output != NULL);
	
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < QSC_TLS_ALERT_SIZE)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else if (qsc_tls_alert_is_valid(description) == false)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		output[0U] = 2U;
		output[1U] = (uint8_t)description;
	}

	return status;
}

qsc_tls_status qsc_tls_alert_encode_record(uint8_t* output, size_t outlen, size_t* written, qsc_tls_alert_description description)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);

	uint8_t alert[QSC_TLS_ALERT_SIZE] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_failure;

	if (output != NULL && written != NULL)
	{
		status = qsc_tls_alert_encode(alert, sizeof(alert), description);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_record_encode_plaintext(output, outlen, written, qsc_tls_record_content_alert, alert, sizeof(alert));
		}

		qsc_memutils_clear(alert, sizeof(alert));
	}

	return status;
}

qsc_tls_alert_description qsc_tls_alert_from_status(qsc_tls_status status)
{
	qsc_tls_alert_description description;

	description = qsc_tls_alert_internal_error;

	switch (status)
	{
		case qsc_tls_status_success:
		{
			description = qsc_tls_alert_close_notify;
			break;
		}
		case qsc_tls_status_invalid_input:
		case qsc_tls_status_invalid_length:
		case qsc_tls_status_invalid_message:
		{
			description = qsc_tls_alert_decode_error;
			break;
		}
		case qsc_tls_status_invalid_state:
		{
			description = qsc_tls_alert_unexpected_message;
			break;
		}
		case qsc_tls_status_not_supported:
		{
			description = qsc_tls_alert_handshake_failure;
			break;
		}
		case qsc_tls_status_authentication_failure:
		{
			description = qsc_tls_alert_decrypt_error;
			break;
		}
		case qsc_tls_status_buffer_too_small:
		case qsc_tls_status_failure:
		default:
		{
			description = qsc_tls_alert_internal_error;
			break;
		}
	}

	return description;
}

bool qsc_tls_alert_is_close_notify(qsc_tls_alert_description description)
{
	return (description == qsc_tls_alert_close_notify);
}

bool qsc_tls_alert_is_fatal_level(uint8_t level)
{
	return (level == 2U);
}

bool qsc_tls_alert_is_valid(qsc_tls_alert_description description)
{
	bool res;

	res = true;

	switch (description)
	{
		case qsc_tls_alert_close_notify:
		case qsc_tls_alert_unexpected_message:
		case qsc_tls_alert_bad_record_mac:
		case qsc_tls_alert_record_overflow:
		case qsc_tls_alert_handshake_failure:
		case qsc_tls_alert_bad_certificate:
		case qsc_tls_alert_unsupported_certificate:
		case qsc_tls_alert_certificate_revoked:
		case qsc_tls_alert_certificate_expired:
		case qsc_tls_alert_certificate_unknown:
		case qsc_tls_alert_illegal_parameter:
		case qsc_tls_alert_unknown_ca:
		case qsc_tls_alert_access_denied:
		case qsc_tls_alert_decode_error:
		case qsc_tls_alert_decrypt_error:
		case qsc_tls_alert_protocol_version:
		case qsc_tls_alert_insufficient_security:
		case qsc_tls_alert_internal_error:
		case qsc_tls_alert_inappropriate_fallback:
		case qsc_tls_alert_user_canceled:
		case qsc_tls_alert_missing_extension:
		case qsc_tls_alert_unsupported_extension:
		case qsc_tls_alert_unrecognized_name:
		case qsc_tls_alert_bad_certificate_status_response:
		case qsc_tls_alert_unknown_psk_identity:
		case qsc_tls_alert_certificate_required:
		case qsc_tls_alert_no_application_protocol:
			break;
		default:
			res = false;
			break;
	}

	return res;
}

const char* qsc_tls_alert_to_string(qsc_tls_alert_description description)
{
	const char* res;

	switch (description)
	{
		case qsc_tls_alert_close_notify:
		{
			res = "close_notify";
			break;
		}
		case qsc_tls_alert_unexpected_message:
		{
			res = "unexpected_message";
			break;
		}
		case qsc_tls_alert_bad_record_mac:
		{
			res = "bad_record_mac";
			break;
		}
		case qsc_tls_alert_record_overflow:
		{
			res = "record_overflow";
			break;
		}
		case qsc_tls_alert_handshake_failure:
		{
			res = "handshake_failure";
			break;
		}
		case qsc_tls_alert_bad_certificate:
		{
			res = "bad_certificate";
			break;
		}
		case qsc_tls_alert_unsupported_certificate:
		{
			res = "unsupported_certificate";
			break;
		}
		case qsc_tls_alert_certificate_revoked:
		{
			res = "certificate_revoked";
			break;
		}
		case qsc_tls_alert_certificate_expired:
		{
			res = "certificate_expired";
			break;
		}
		case qsc_tls_alert_certificate_unknown:
		{
			res = "certificate_unknown";
			break;
		}
		case qsc_tls_alert_illegal_parameter:
		{
			res = "illegal_parameter";
			break;
		}
		case qsc_tls_alert_unknown_ca:
		{
			res = "unknown_ca";
			break;
		}
		case qsc_tls_alert_access_denied:
		{
			res = "access_denied";
			break;
		}
		case qsc_tls_alert_decode_error:
		{
			res = "decode_error";
			break;
		}
		case qsc_tls_alert_decrypt_error:
		{
			res = "decrypt_error";
			break;
		}
		case qsc_tls_alert_protocol_version:
		{
			res = "protocol_version";
			break;
		}
		case qsc_tls_alert_internal_error:
		{
			res = "internal_error";
			break;
		}
		case qsc_tls_alert_missing_extension:
		{
			res = "missing_extension";
			break;
		}
		case qsc_tls_alert_unsupported_extension:
		{
			res = "unsupported_extension";
			break;
		}
		case qsc_tls_alert_unrecognized_name:
		{
			res = "unrecognized_name";
			break;
		}
		case qsc_tls_alert_unknown_psk_identity:
		{
			res = "unknown_psk_identity";
			break;
		}
		case qsc_tls_alert_certificate_required:
		{
			res = "certificate_required";
			break;
		}
		case qsc_tls_alert_no_application_protocol:
		{
			res = "no_application_protocol";
			break;
		}
		default:
		{
			res = "unknown_alert";
			break;
		}
	}

	return res;
}
