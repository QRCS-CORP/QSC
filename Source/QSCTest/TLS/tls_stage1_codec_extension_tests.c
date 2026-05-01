#include "tls_stage1_codec_extension_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlscodec.h"
#include "tlserrors.h"

static bool qsctest_tls_stage1_codec_roundtrip_primitives(void)
{
	uint8_t buf[32U] = { 0U };
	uint64_t u64v;
	size_t off;
	uint32_t u24v;
	uint32_t u32v;
	uint16_t u16v;
	uint8_t u8v;
	qsc_tls_status status;
	bool res;

	off = 0U;
	u8v = 0U;
	u16v = 0U;
	u24v = 0U;
	u32v = 0U;
	u64v = 0U;
	status = qsc_tls_status_success;
	res = true;

	qsc_memutils_clear(buf, sizeof(buf));

	status = qsc_tls_codec_write_u8(buf, sizeof(buf), &off, 0xABU);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u16(buf, sizeof(buf), &off, 0xCAFEU);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u24(buf, sizeof(buf), &off, 0x123456UL);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u32(buf, sizeof(buf), &off, 0xDEADBEEFUL);
	}

	/* the current codec exposes qsc_tls_codec_read_u64 but not qsc_tls_codec_write_u64. */
	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u32(buf, sizeof(buf), &off, 0x01020304UL);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u32(buf, sizeof(buf), &off, 0x05060708UL);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (off == 18U);
	}

	if (res == true)
	{
		off = 0U;
		status = qsc_tls_codec_read_u8(buf, sizeof(buf), &off, &u8v);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u16(buf, sizeof(buf), &off, &u16v);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u24(buf, sizeof(buf), &off, &u24v);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u32(buf, sizeof(buf), &off, &u32v);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_read_u64(buf, sizeof(buf), &off, &u64v);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (u8v == 0xABU &&
			u16v == 0xCAFEU &&
			u24v == 0x123456UL &&
			u32v == 0xDEADBEEFUL &&
			u64v == 0x0102030405060708ULL &&
			off == 18U);
	}

	return res;
}

static bool qsctest_tls_stage1_codec_vector_begin_end(void)
{
	uint8_t buf[64U] = { 0U };
	const uint8_t* span;
	size_t off;
	size_t hdr;
	size_t i;
	size_t spanlen;
	qsc_tls_status status;
	bool res;

	span = NULL;
	off = 0U;
	hdr = 0U;
	spanlen = 0U;
	status = qsc_tls_status_success;
	res = true;

	status = qsc_tls_codec_vector_begin_u8(buf, sizeof(buf), &off, &hdr);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u8(buf, sizeof(buf), &off, 0x11U);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u8(buf, sizeof(buf), &off, 0x22U);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u8(buf, sizeof(buf), &off, 0x33U);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_vector_end_u8(buf, sizeof(buf), &off, hdr);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (hdr == 0U && buf[0U] == 3U && off == 4U);
	}

	if (res == true)
	{
		status = qsc_tls_codec_vector_begin_u16(buf, sizeof(buf), &off, &hdr);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u16(buf, sizeof(buf), &off, 0xAAAAU);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_write_u16(buf, sizeof(buf), &off, 0xBBBBU);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_vector_end_u16(buf, sizeof(buf), &off, hdr);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (hdr == 4U && buf[4U] == 0U && buf[5U] == 4U);
	}

	if (res == true)
	{
		status = qsc_tls_codec_vector_begin_u24(buf, sizeof(buf), &off, &hdr);
	}

	for (i = 0U; i < 5U && status == qsc_tls_status_success; ++i)
	{
		status = qsc_tls_codec_write_u8(buf, sizeof(buf), &off, (uint8_t)i);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_codec_vector_end_u24(buf, sizeof(buf), &off, hdr);
	}

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		res = (buf[hdr] == 0U && buf[hdr + 1U] == 0U && buf[hdr + 2U] == 5U);
	}

	if (res == true)
	{
		off = 0U;
		status = qsc_tls_codec_read_vector8_span(buf, sizeof(buf), &off, &span, &spanlen);
	}

	if (status == qsc_tls_status_success)
	{
		res = (spanlen == 3U && span[0U] == 0x11U && span[1U] == 0x22U && span[2U] == 0x33U);
	}

	if (res == true)
	{
		status = qsc_tls_codec_read_vector16_span(buf, sizeof(buf), &off, &span, &spanlen);
	}

	if (status == qsc_tls_status_success && res == true)
	{
		res = (spanlen == 4U && span[0U] == 0xAAU && span[1U] == 0xAAU && span[2U] == 0xBBU && span[3U] == 0xBBU);
	}

	if (res == true)
	{
		status = qsc_tls_codec_read_vector24_span(buf, sizeof(buf), &off, &span, &spanlen);
	}

	if (status == qsc_tls_status_success && res == true)
	{
		res = (spanlen == 5U && span[4U] == 4U);
	}

	return res;
}

static bool qsctest_tls_stage1_codec_bounds_and_invalid_input(void)
{
	uint8_t buf[2U] = { 0U };
	uint8_t out[8U] = { 0U };
	size_t off;
	size_t hdr;
	qsc_tls_status status;
	bool res;

	off = 0U;
	hdr = 0U;
	status = qsc_tls_status_success;
	res = true;

	status = qsc_tls_codec_write_u32(buf, sizeof(buf), &off, 0U);
	res = (status == qsc_tls_status_buffer_too_small);

	if (res == true)
	{
		off = 0U;
		status = qsc_tls_codec_vector_begin_u16(buf, sizeof(buf), &off, &hdr);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		status = qsc_tls_codec_write_u16(buf, sizeof(buf), &off, 0U);
		res = (status == qsc_tls_status_buffer_too_small);
	}

	if (res == true)
	{
		off = 0U;
		status = qsc_tls_codec_write_u24(buf, sizeof(buf), &off, 0x01000000UL);
		res = (status == qsc_tls_status_invalid_length);
	}

	if (res == true)
	{
		off = 0U;
		status = qsc_tls_codec_read_u64(NULL, 8U, &off, NULL);
		res = (status == qsc_tls_status_invalid_input);
	}

	if (res == true)
	{
		off = 0U;
		status = qsc_tls_codec_read_bytes(NULL, 0U, &off, out, sizeof(out));
		res = (status == qsc_tls_status_invalid_input);
	}

	return res;
}

bool qsctest_tls_stage1_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage1_codec_roundtrip_primitives() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 codec primitive round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 codec primitive round-trip test.");
		res = false;
	}

	if (qsctest_tls_stage1_codec_vector_begin_end() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 codec vector helper test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 codec vector helper test.");
		res = false;
	}

	if (qsctest_tls_stage1_codec_bounds_and_invalid_input() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 1 codec bounds and invalid-input test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 1 codec bounds and invalid-input test.");
		res = false;
	}

	return res;
}
