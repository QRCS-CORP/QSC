#include "tls_stage2_certificate_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlscert.h"
#include "tlsextensions.h"

static bool qsctest_tls_stage2_certificate_roundtrip(void)
{
	qsc_tls_certificate_view chain[2U] = { 0 };
	qsc_tls_certificate_view decoded[4U] = { 0 };
	uint8_t cert1[100U] = { 0U };
	uint8_t cert2[150U] = { 0U };
	uint8_t buf[512U] = { 0U };
	const uint8_t* rctx;
	size_t decoded_count;
	size_t i;
	size_t off;
	size_t rctxlen;
	qsc_tls_status status;
	bool res;

	rctx = NULL;
	decoded_count = 0U;
	off = 0U;
	rctxlen = 0U;
	status = qsc_tls_status_success;
	res = true;

	for (i = 0U; i < sizeof(cert1); ++i)
	{
		cert1[i] = (uint8_t)(i ^ 0x11U);
	}

	for (i = 0U; i < sizeof(cert2); ++i)
	{
		cert2[i] = (uint8_t)(i ^ 0x22U);
	}

	chain[0U].data = cert1;
	chain[0U].datalen = sizeof(cert1);
	chain[1U].data = cert2;
	chain[1U].datalen = sizeof(cert2);

	status = qsc_tls_certificate_encode_message(NULL, 0U, chain, 2U, buf, sizeof(buf), &off);

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		/* 1-byte context length + 3-byte list length + two entries with
		 * 3-byte cert length and 2-byte extension length fields. */
		res = (off == 264U);
	}

	if (res == true)
	{
		status = qsc_tls_certificate_decode_message(buf, off, &rctx, &rctxlen, decoded, 4U, &decoded_count);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (rctxlen == 0U && decoded_count == 2U);
	}

	if (res == true)
	{
		res = (decoded[0U].datalen == sizeof(cert1) &&
			qsc_memutils_are_equal(decoded[0U].data, cert1, sizeof(cert1)) == true);
	}

	if (res == true)
	{
		res = (decoded[1U].datalen == sizeof(cert2) &&
			qsc_memutils_are_equal(decoded[1U].data, cert2, sizeof(cert2)) == true);
	}

	if (res == true)
	{
		const uint8_t ctx[4U] = { 0x0AU, 0x0BU, 0x0CU, 0x0DU };

		off = 0U;
		decoded_count = 0U;
		rctx = NULL;
		rctxlen = 0U;
		status = qsc_tls_certificate_encode_message(ctx, sizeof(ctx), chain, 1U, buf, sizeof(buf), &off);
		res = (status == qsc_tls_status_success);

		if (res == true)
		{
			status = qsc_tls_certificate_decode_message(buf, off, &rctx, &rctxlen, decoded, 4U, &decoded_count);
			res = (status == qsc_tls_status_success);
		}

		if (res == true)
		{
			res = (rctxlen == sizeof(ctx) &&
				qsc_memutils_are_equal(rctx, ctx, sizeof(ctx)) == true &&
				decoded_count == 1U &&
				decoded[0U].datalen == sizeof(cert1) &&
				qsc_memutils_are_equal(decoded[0U].data, cert1, sizeof(cert1)) == true);
		}
	}

	return res;
}

static bool qsctest_tls_stage2_certificate_malformed(void)
{
	uint8_t buf[8U] = { 0x00U, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U };
	qsc_tls_certificate_view views[2U] = { 0 };
	const uint8_t* rctx;
	size_t count;
	size_t rctxlen;
	qsc_tls_status status;
	bool res;

	rctx = NULL;
	count = 0U;
	rctxlen = 0U;
	status = qsc_tls_certificate_decode_message(buf, sizeof(buf), &rctx, &rctxlen, views, 2U, &count);
	res = (status == qsc_tls_status_invalid_length);

	return res;
}

static bool qsctest_tls_stage2_certificate_request_roundtrip(void)
{
	uint8_t extblk[64U] = { 0U };
	uint8_t buf[128U] = { 0U };
	const qsc_tls_signature_scheme schemes[2U] = { qsc_tls_sig_ed25519, qsc_tls_sig_mldsa65 };
	const uint8_t ctx[3U] = { 0x01U, 0x02U, 0x03U };
	const uint8_t* extspan;
	const uint8_t* rctx;
	size_t extlen;
	size_t extoff;
	size_t off;
	size_t rctxlen;
	qsc_tls_status status;
	bool res;

	extspan = NULL;
	rctx = NULL;
	extlen = 0U;
	extoff = 0U;
	off = 0U;
	rctxlen = 0U;
	res = true;

	status = qsc_tls_extensions_encode_signature_algorithms(extblk, sizeof(extblk), &extoff, schemes, 2U);

	if (status != qsc_tls_status_success)
	{
		res = false;
	}

	if (res == true)
	{
		status = qsc_tls_certificate_request_encode(ctx, sizeof(ctx), extblk, extoff, buf, sizeof(buf), &off);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		status = qsc_tls_certificate_request_decode(buf, off, &rctx, &rctxlen, &extspan, &extlen);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (rctxlen == sizeof(ctx) &&
			qsc_memutils_are_equal(rctx, ctx, sizeof(ctx)) == true &&
			extlen == extoff &&
			qsc_memutils_are_equal(extspan, extblk, extoff) == true);
	}

	return res;
}

bool qsctest_tls_stage2_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage2_certificate_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 certificate round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 certificate round-trip test.");
		res = false;
	}

	if (qsctest_tls_stage2_certificate_malformed() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 malformed certificate test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 malformed certificate test.");
		res = false;
	}

	if (qsctest_tls_stage2_certificate_request_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 certificate request round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 certificate request round-trip test.");
		res = false;
	}

	return res;
}
