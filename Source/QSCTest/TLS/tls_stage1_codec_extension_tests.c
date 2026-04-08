#include "tls_stage1_codec_extension_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlscodec.h"
#include "tlserrors.h"
#include "tlsextensions.h"
#include "tlstypes.h"
#include "tlslimits.h"

static bool qsctest_tls_stage1_codec_integer_roundtrip(void)
{
	uint8_t buf[16U] = { 0U };
	size_t offw;
	size_t offr;
	uint8_t v8;
	uint16_t v16;
	uint32_t v24;
	uint32_t v32;
	qsc_tls_status status;
	bool res;

	qsc_memutils_clear(buf, sizeof(buf));
	offw = 0U;
	offr = 0U;
	v8 = 0U;
	v16 = 0U;
	v24 = 0U;
	v32 = 0U;
	status = qsc_tls_status_success;
	res = true;

	status = qsc_tls_codec_write_u8(buf, sizeof(buf), &offw, 0xA5U);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u16(buf, sizeof(buf), &offw, 0x1234U);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u24(buf, sizeof(buf), &offw, 0x00ABCDEFUL);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u32(buf, sizeof(buf), &offw, 0x89ABCDEFUL);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u8(buf, offw, &offr, &v8);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u16(buf, offw, &offr, &v16);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u24(buf, offw, &offr, &v24);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u32(buf, offw, &offr, &v32);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (offw == 10U && offr == offw && v8 == 0xA5U && v16 == 0x1234U && v24 == 0x00ABCDEFUL && v32 == 0x89ABCDEFUL);
	}

	return res;
}

static bool qsctest_tls_stage1_codec_vector_and_bounds(void)
{
	uint8_t buf[32U] = { 0U };
	uint8_t out[8U] = { 0U };
	const uint8_t data8[3U] = { 0x01U, 0x02U, 0x03U };
	const uint8_t data16[5U] = { 0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U };
	const uint8_t* span;
	size_t offw;
	size_t offr;
	size_t spanlen;
	qsc_tls_status status;
	bool res;

	span = NULL;
	offw = 0U;
	offr = 0U;
	spanlen = 0U;
	status = qsc_tls_status_success;
	res = true;

	status = qsc_tls_codec_write_vector8(buf, sizeof(buf), &offw, data8, sizeof(data8));

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_vector16(buf, sizeof(buf), &offw, data16, sizeof(data16));
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_vector8_span(buf, offw, &offr, &span, &spanlen);
	}

	if (status == qsc_tls_status_success)
	{
		res = (spanlen == sizeof(data8) && qsc_memutils_are_equal(span, data8, sizeof(data8)) == true);
	}

	if (res == true)
	{
		status = qsc_tls_codec_read_vector16_span(buf, offw, &offr, &span, &spanlen);

		if (status == qsc_tls_status_success && res == true)
		{
			res = (spanlen == sizeof(data16) && qsc_memutils_are_equal(span, data16, sizeof(data16)) == true && offr == offw);
		}

		if (res == true)
		{
			offw = 0U;
			status = qsc_tls_codec_write_vector8(buf, 3U, &offw, data8, sizeof(data8));
			res = (status == qsc_tls_status_buffer_too_small);
		}

		if (res == true)
		{
			offr = 0U;
			status = qsc_tls_codec_read_bytes(NULL, 0U, &offr, out, sizeof(out));
			res = (status == qsc_tls_status_invalid_input);
		}
	}

	return res;
}

static bool qsctest_tls_stage1_supported_groups_roundtrip(void)
{
	qsc_tls_named_group groups[3U] = { 0U };
	qsc_tls_named_group decoded[3U] = { 0U };
	uint8_t ext[64U] = { 0U };
	size_t extlen;
	size_t count;
	qsc_tls_status status;
	bool res;

	groups[0U] = qsc_tls_group_x25519;
	groups[1U] = qsc_tls_group_secp256r1;
	groups[2U] = qsc_tls_group_secp384r1;

	extlen = 0U;
	count = 0U;
	status = qsc_tls_status_success;
	res = true;

	status = qsc_tls_extensions_encode_supported_groups(ext, sizeof(ext), &extlen, groups, 3U);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_extensions_decode_supported_groups(ext, extlen, decoded, 3U, &count);
	}

	if (status != qsc_tls_status_success)
	{
		if (res == true)
		{
			res = (count == 3U && decoded[0] == groups[0] && decoded[1] == groups[1] && decoded[2] == groups[2]);
		}

		if (res == true)
		{
			ext[5U] ^= 0x01U;
			status = qsc_tls_extensions_decode_supported_groups(ext, extlen, decoded, 3U, &count);
			res = (status != qsc_tls_status_success);
		}
	}

	return res;
}

static bool qsctest_tls_stage1_signature_algorithms_roundtrip(void)
{
	qsc_tls_signature_scheme sigs[4U] = { 0U };
	qsc_tls_signature_scheme decoded[4U] = { 0U };
	uint8_t ext[64U] = { 0U };
	size_t extlen;
	size_t count;
	qsc_tls_status status;
	bool res;

	sigs[0U] = qsc_tls_sig_ecdsa_secp256r1_sha256;
	sigs[1U] = qsc_tls_sig_ecdsa_secp384r1_sha384;
	sigs[2U] = qsc_tls_sig_ed25519;
	sigs[3U] = qsc_tls_sig_mldsa65;

	extlen = 0U;
	count = 0U;
	status = qsc_tls_status_success;
	res = true;

	status = qsc_tls_extensions_encode_signature_algorithms(ext, sizeof(ext), &extlen, sigs, 4U);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_extensions_decode_signature_algorithms(ext, extlen, decoded, 4U, &count);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (count == 4U && decoded[0] == sigs[0] && decoded[1] == sigs[1] && decoded[2] == sigs[2] && decoded[3] == sigs[3]);
	}

	if (res == true)
	{
		status = qsc_tls_extensions_decode_signature_algorithms(ext, extlen, decoded, 2U, &count);
		res = (status == qsc_tls_status_buffer_too_small);
	}

	return res;
}

static bool qsctest_tls_stage1_key_share_roundtrip_and_malformed(void)
{
	uint8_t ext[128U] = { 0U };
	uint8_t share[32U] = { 0U };
	const uint8_t* decodedshare;
	size_t extlen;
	size_t decodedlen;
	qsc_tls_named_group group;
	qsc_tls_status status;
	bool res;
	size_t i;

	decodedshare = NULL;
	extlen = 0U;
	decodedlen = 0U;
	group = qsc_tls_group_none;
	status = qsc_tls_status_success;
	res = true;

	for (i = 0U; i < sizeof(share); ++i)
	{
		share[i] = (uint8_t)(0xC0U + (uint8_t)i);
	}

	status = qsc_tls_extensions_encode_key_share_single(ext, sizeof(ext), &extlen, qsc_tls_group_x25519, share, sizeof(share));

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_extensions_decode_key_share_single(ext, extlen, &group, &decodedshare, &decodedlen);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (group == qsc_tls_group_x25519 && decodedlen == sizeof(share) && qsc_memutils_are_equal(decodedshare, share, sizeof(share)) == true);
	}

	if (res == true)
	{
		ext[3U] ^= 0x01U;
		status = qsc_tls_extensions_decode_key_share_single(ext, extlen, &group, &decodedshare, &decodedlen);
		res = (status != qsc_tls_status_success);
	}

	return res;
}

bool qsctest_tls_stage1_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage1_codec_integer_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 codec integer round-trip tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 codec integer round-trip tests.");
		res = false;
	}

	if (qsctest_tls_stage1_codec_vector_and_bounds() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 vector and bounds tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 vector and bounds tests.");
		res = false;
	}

	if (qsctest_tls_stage1_supported_groups_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 supported_groups extension tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 supported_groups extension tests.");
		res = false;
	}

	if (qsctest_tls_stage1_signature_algorithms_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 signature_algorithms extension tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 signature_algorithms extension tests.");
		res = false;
	}

	if (qsctest_tls_stage1_key_share_roundtrip_and_malformed() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 key_share extension tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 key_share extension tests.");
		res = false;
	}

	return res;
}
