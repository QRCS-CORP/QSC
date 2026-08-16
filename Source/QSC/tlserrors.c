#include "tlserrors.h"

#define QSC_TLS_ERROR_STRING_DEPTH 11U
#define QSC_TLS_ERROR_STRING_WIDTH 128U

static const char QSC_TLS_ERROR_STRINGS[QSC_TLS_ERROR_STRING_DEPTH][QSC_TLS_ERROR_STRING_WIDTH] =
{
	"The operation completed successfully.",
	"A generic TLS processing failure occurred.",
	"One or more input parameters were null, invalid, or semantically inconsistent.",
	"The supplied output buffer was too small for the requested TLS operation.",
	"The current object state does not permit the requested TLS operation.",
	"A parsed, derived, or supplied length field was outside the valid range.",
	"The requested TLS feature, group, suite, or algorithm is not supported.",
	"Authentication failed, or a signature, MAC, or certificate validation step failed.",
	"The TLS message was malformed, truncated, or semantically invalid.",
	"A TLS record exceeded the RFC 9846 record-layer size limit.",
	"The configured cumulative TLS operation deadline expired."
};

const char* qsc_tls_error_to_string(qsc_tls_status status)
{
	const char* ret;
	size_t idx;

	ret = "The TLS status code is unknown.";

	if (((int32_t)status <= 0) && ((int32_t)status >= -10))
	{
		idx = (size_t)(0 - (int32_t)status);
		ret = QSC_TLS_ERROR_STRINGS[idx];
	}

	return ret;
}
