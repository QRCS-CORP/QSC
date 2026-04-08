#include "tls_stage4_schedule_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "sha2.h"
#include "tlscodec.h"
#include "tlsdefs.h"
#include "tlserrors.h"
#include "tlsschedule.h"
#include "tlstranscript.h"
#include "tlstypes.h"
#include <string.h>

static qsc_tls_status tls_stage4_build_label(uint8_t* output, size_t outlen, size_t* msglen, size_t reclen, const char* label, const uint8_t* context, size_t contextlen)
{
	qsc_tls_status status;
	size_t offset;
	size_t labellen;

	status = qsc_tls_status_success;
	offset = 0U;
	labellen = 0U;

	if (output == NULL || msglen == NULL || label == NULL || (context == NULL && contextlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		labellen = strlen(label);

		if (labellen > QSC_TLS_LABEL_MAX_SIZE || contextlen > QSC_TLS_CONTEXT_MAX_SIZE)
		{
			status = qsc_tls_status_invalid_length;
		}
		else if ((QSC_TLS_HKDF_LABEL_PREFIX_SIZE + labellen) > 255U || contextlen > 255U || reclen > 65535U)
		{
			status = qsc_tls_status_invalid_length;
		}
		else
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)reclen);

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)(QSC_TLS_HKDF_LABEL_PREFIX_SIZE + labellen));
			}
			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_bytes(output, outlen, &offset, (const uint8_t*)QSC_TLS_HKDF_LABEL_PREFIX, QSC_TLS_HKDF_LABEL_PREFIX_SIZE);
			}
			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_bytes(output, outlen, &offset, (const uint8_t*)label, labellen);
			}
			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)contextlen);
			}
			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_bytes(output, outlen, &offset, context, contextlen);
			}
		}

		*msglen = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

static bool tls_stage4_extract_matches(qsc_tls_hash_algorithm hash)
{
	static const uint8_t key[] =
	{
		0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU,
		0x10U, 0x32U, 0x54U, 0x76U, 0x98U, 0xBAU, 0xDCU, 0xFEU,
		0x55U, 0x44U, 0x33U, 0x22U, 0x11U, 0x00U, 0x99U, 0x88U
	};

	static const uint8_t salt[] =
	{
		0xA0U, 0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U, 0xA7U,
		0xB0U, 0xB1U, 0xB2U, 0xB3U, 0xB4U, 0xB5U, 0xB6U, 0xB7U
	};

	uint8_t expect[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t output[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	qsc_tls_status status;
	size_t hlen;
	bool res;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);
	res = false;

	if (hlen != 0U)
	{
		switch (hash)
		{
		case qsc_tls_hash_sha256:
			qsc_hkdf256_extract(expect, hlen, key, sizeof(key), salt, sizeof(salt));
			break;
		case qsc_tls_hash_sha384:
		case qsc_tls_hash_sha512:
			qsc_hkdf512_extract(expect, hlen, key, sizeof(key), salt, sizeof(salt));
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}
	else
	{
		status = qsc_tls_status_not_supported;
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_schedule_extract(hash, output, hlen, key, sizeof(key), salt, sizeof(salt));
	}

	if (status == qsc_tls_status_success)
	{
		res = (qsc_memutils_are_equal(expect, output, hlen) == true);
	}

	return res;
}

static bool tls_stage4_expand_label_matches(qsc_tls_hash_algorithm hash, const char* label,
	const uint8_t* context, size_t contextlen, size_t outlen)
{
	static const uint8_t secret[] =
	{
		0xC0U, 0xC1U, 0xC2U, 0xC3U, 0xC4U, 0xC5U, 0xC6U, 0xC7U,
		0xD0U, 0xD1U, 0xD2U, 0xD3U, 0xD4U, 0xD5U, 0xD6U, 0xD7U,
		0xE0U, 0xE1U, 0xE2U, 0xE3U, 0xE4U, 0xE5U, 0xE6U, 0xE7U,
		0xF0U, 0xF1U, 0xF2U, 0xF3U, 0xF4U, 0xF5U, 0xF6U, 0xF7U
	};

	uint8_t expect[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t output[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t info[QSC_TLS_HKDF_LABEL_MAX_WIRE_SIZE] = { 0U };
	size_t infolen;
	qsc_tls_status status;
	bool res;

	infolen = 0U;
	status = tls_stage4_build_label(info, sizeof(info), &infolen, outlen, label, context, contextlen);
	res = false;

	if (status == qsc_tls_status_success)
	{
		switch (hash)
		{
		case qsc_tls_hash_sha256:
			qsc_hkdf256_expand(expect, outlen, secret, sizeof(secret), info, infolen);
			break;
		case qsc_tls_hash_sha384:
		case qsc_tls_hash_sha512:
			qsc_hkdf512_expand(expect, outlen, secret, sizeof(secret), info, infolen);
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_schedule_expand_label(hash, output, outlen, secret, sizeof(secret), label, context, contextlen);
	}

	if (status == qsc_tls_status_success)
	{
		res = (qsc_memutils_are_equal(expect, output, outlen) == true);
	}

	return res;
}

bool tls_stage4_schedule_extract(void)
{
	bool res;

	res = true;

	if (tls_stage4_extract_matches(qsc_tls_hash_sha256) == false)
	{
		res = false;
	}

	if (res == true)
	{
		res = (tls_stage4_extract_matches(qsc_tls_hash_sha384) == true);
	}

	if (res == true)
	{
		res = (tls_stage4_extract_matches(qsc_tls_hash_sha512) == true);
	}

	return res;
}

bool tls_stage4_schedule_expand_label(void)
{
	static const uint8_t contexta[] =
	{
		0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
		0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x10U
	};

	bool res;

	res = true;

	if (tls_stage4_expand_label_matches(qsc_tls_hash_sha256, QSC_TLS_DERIVED_LABEL,
		contexta, sizeof(contexta), QSC_SHA2_256_HASH_SIZE) == false)
	{
		res = false;
	}

	if (res == true)
	{
		res = (tls_stage4_expand_label_matches(qsc_tls_hash_sha384, QSC_TLS_EXT_BINDER_LABEL,
			contexta, sizeof(contexta), QSC_SHA2_384_HASH_SIZE) == true);
	}

	if (res == true)
	{
		res = (tls_stage4_expand_label_matches(qsc_tls_hash_sha512, QSC_TLS_RESUMPTION_LABEL,
			NULL, 0U, QSC_SHA2_512_HASH_SIZE) == true);
	}

	return res;
}

bool tls_stage4_schedule_derive_finished(void)
{
	static const uint8_t transcriptmsg[] =
	{
		0x01U, 0x00U, 0x00U, 0x20U, 0x03U, 0x03U, 0xAAU, 0xBBU,
		0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U, 0x11U, 0x22U, 0x33U,
		0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xA0U, 0xA1U,
		0xA2U, 0xA3U, 0xA4U, 0xA5U, 0x13U, 0x01U, 0x01U, 0x00U,
		0x00U, 0x00U, 0x00U, 0x00U
	};

	static const uint8_t secret[] =
	{
		0x5AU, 0x5BU, 0x5CU, 0x5DU, 0x5EU, 0x5FU, 0x60U, 0x61U,
		0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U,
		0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U,
		0x72U, 0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U, 0x79U,
		0x7AU, 0x7BU, 0x7CU, 0x7DU, 0x7EU, 0x7FU, 0x80U, 0x81U,
		0x82U, 0x83U, 0x84U, 0x85U, 0x86U, 0x87U, 0x88U, 0x89U,
		0x8AU, 0x8BU, 0x8CU, 0x8DU, 0x8EU, 0x8FU, 0x90U, 0x91U,
		0x92U, 0x93U, 0x94U, 0x95U, 0x96U, 0x97U, 0x98U, 0x99U
	};

	qsc_tls_transcript_state transcript = { 0 };
	uint8_t digest[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t expect[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t output[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	size_t digestlen;
	qsc_tls_status status;
	bool res;

	digestlen = 0U;
	res = false;

	status = qsc_tls_transcript_initialize(&transcript, qsc_tls_hash_sha256);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_append(&transcript, transcriptmsg, sizeof(transcriptmsg));
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_snapshot(&transcript, digest, sizeof(digest), &digestlen);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_schedule_expand_label(qsc_tls_hash_sha256, expect, digestlen, secret,
			sizeof(secret), QSC_TLS_DERIVED_LABEL, digest, digestlen);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_schedule_derive_secret(qsc_tls_hash_sha256, output, digestlen, secret,
			sizeof(secret), QSC_TLS_DERIVED_LABEL, &transcript);
	}

	if (status == qsc_tls_status_success)
	{
		res = (qsc_memutils_are_equal(expect, output, digestlen) == true);
	}

	if (res == true)
	{
		status = qsc_tls_schedule_expand_label(qsc_tls_hash_sha256, expect, digestlen, secret,
			sizeof(secret), QSC_TLS_FINISHED_LABEL, NULL, 0U);
	}

	if (status == qsc_tls_status_success && res == true)
	{
		status = qsc_tls_schedule_finished_key(qsc_tls_hash_sha256, output, digestlen, secret, sizeof(secret));
	}

	if (status == qsc_tls_status_success && res == true)
	{
		res = (qsc_memutils_are_equal(expect, output, digestlen) == true);
	}

	qsc_tls_transcript_dispose(&transcript);

	return res;
}

bool tls_stage4_schedule_negative_paths(void)
{
	static const uint8_t key[] = { 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U };
	static const uint8_t salt[] = { 0xA1U, 0xA2U, 0xA3U, 0xA4U };
	static const uint8_t context[] = { 0x10U, 0x20U, 0x30U };
	qsc_tls_transcript_state transcript = { 0U };
	uint8_t output[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t expect[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	char longlabel[QSC_TLS_LABEL_MAX_SIZE + 2U] = { 0U };
	qsc_tls_status status;
	bool res;
	size_t i;

	res = true;

	for (i = 0U; i < QSC_TLS_LABEL_MAX_SIZE + 1U; ++i)
	{
		longlabel[i] = 'a';
	}

	status = qsc_tls_schedule_extract(qsc_tls_hash_sha256, NULL, QSC_SHA2_256_HASH_SIZE, key, sizeof(key), salt, sizeof(salt));

	if (status != qsc_tls_status_invalid_input)
	{
		res = false;
	}

	status = qsc_tls_schedule_extract(qsc_tls_hash_sha256, output, QSC_SHA2_256_HASH_SIZE - 1U, key, sizeof(key), salt, sizeof(salt));

	if (res == true)
	{
		res = (status == qsc_tls_status_buffer_too_small);
	}

	status = qsc_tls_schedule_extract((qsc_tls_hash_algorithm)0x7FFF, output, sizeof(output), key, sizeof(key), salt, sizeof(salt));

	if (res == true)
	{
		res = (status == qsc_tls_status_not_supported);
	}

	status = qsc_tls_schedule_expand_label(qsc_tls_hash_sha256, output, QSC_SHA2_256_HASH_SIZE, NULL, sizeof(key), QSC_TLS_DERIVED_LABEL, context, sizeof(context));
	
	if (res == true)
	{
		res = (status == qsc_tls_status_invalid_input);
	}

	status = qsc_tls_schedule_expand_label(qsc_tls_hash_sha256, output, QSC_SHA2_256_HASH_SIZE, key, sizeof(key), longlabel, context, sizeof(context));
	
	if (res == true)
	{
		res = (status == qsc_tls_status_invalid_length);
	}

	status = qsc_tls_schedule_empty_hash(qsc_tls_hash_sha384, output, QSC_SHA2_384_HASH_SIZE);

	if (res == true)
	{
		{ 
			uint8_t z = 0U;
			qsc_sha384_compute(expect, &z, 0U); 
		}

		res = (status == qsc_tls_status_success && qsc_memutils_are_equal(output, expect, QSC_SHA2_384_HASH_SIZE) == true);
	}

	status = qsc_tls_schedule_empty_hash(qsc_tls_hash_sha512, output, QSC_SHA2_512_HASH_SIZE - 1U);

	if (res == true)
	{
		res = (status == qsc_tls_status_buffer_too_small);
	}

	status = qsc_tls_schedule_derive_secret(qsc_tls_hash_sha256, output, QSC_SHA2_256_HASH_SIZE, key, sizeof(key), QSC_TLS_DERIVED_LABEL, &transcript);
	
	if (res == true)
	{
		res = (status == qsc_tls_status_invalid_state);
	}

	status = qsc_tls_schedule_finished_key(qsc_tls_hash_sha256, output, QSC_SHA2_256_HASH_SIZE - 1U, key, sizeof(key));

	if (res == true)
	{
		res = (status == qsc_tls_status_buffer_too_small);
	}

	return res;
}

bool qsctest_tls_stage4_tests(void)
{
	bool res;

	res = true;

	if (tls_stage4_schedule_extract() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 4 schedule extract test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 4 schedule extract test.");
		res = false;
	}

	if (tls_stage4_schedule_expand_label() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 4 schedule expand-label test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 4 schedule expand-label test.");
		res = false;
	}

	if (tls_stage4_schedule_derive_finished() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 4 schedule derive-secret and finished-key test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 4 schedule derive-secret and finished-key test.");
		res = false;
	}

	if (tls_stage4_schedule_negative_paths() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 4 schedule negative-path and empty-hash test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 4 schedule negative-path and empty-hash test.");
		res = false;
	}

	return res;
}
