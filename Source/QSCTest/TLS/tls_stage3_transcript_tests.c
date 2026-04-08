#include "tls_stage3_transcript_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "sha2.h"
#include "tlserrors.h"
#include "tlstranscript.h"
#include "tlstypes.h"

static bool tls_stage3_snapshot_matches_sha256(const uint8_t* msg, size_t msglen)
{
	qsc_tls_transcript_state state = { 0 };
	uint8_t expect[QSC_SHA2_256_HASH_SIZE] = { 0U };
	uint8_t output[QSC_SHA2_256_HASH_SIZE] = { 0U };
	size_t outlen;
	qsc_tls_status status;
	bool res;

	outlen = 0U;
	res = false;

	qsc_sha256_compute(expect, msg, msglen);
	status = qsc_tls_transcript_initialize(&state, qsc_tls_hash_sha256);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_append(&state, msg, msglen);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_snapshot(&state, output, sizeof(output), &outlen);
	}

	if (status == qsc_tls_status_success)
	{
		res = (outlen == sizeof(expect) && qsc_memutils_are_equal(expect, output, sizeof(expect)) == true);
	}

	qsc_tls_transcript_dispose(&state);

	return res;
}

static bool tls_stage3_snapshot_matches_sha384(const uint8_t* msg, size_t msglen)
{
	qsc_tls_transcript_state state = { 0 };
	uint8_t expect[QSC_SHA2_384_HASH_SIZE] = { 0U };
	uint8_t output[QSC_SHA2_384_HASH_SIZE] = { 0U };
	size_t outlen;
	qsc_tls_status status;
	bool res;

	outlen = 0U;
	res = false;

	qsc_sha384_compute(expect, msg, msglen);
	status = qsc_tls_transcript_initialize(&state, qsc_tls_hash_sha384);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_append(&state, msg, msglen);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_snapshot(&state, output, sizeof(output), &outlen);
	}

	if (status == qsc_tls_status_success)
	{
		res = (outlen == sizeof(expect) && qsc_memutils_are_equal(expect, output, sizeof(expect)) == true);
	}

	qsc_tls_transcript_dispose(&state);

	return res;
}

static bool tls_stage3_snapshot_matches_sha512(const uint8_t* msg, size_t msglen)
{
	qsc_tls_transcript_state state = { 0 };
	uint8_t expect[QSC_SHA2_512_HASH_SIZE] = { 0U };
	uint8_t output[QSC_SHA2_512_HASH_SIZE] = { 0U };
	size_t outlen;
	qsc_tls_status status;
	bool res;

	outlen = 0U;
	res = false;

	qsc_sha512_compute(expect, msg, msglen);
	status = qsc_tls_transcript_initialize(&state, qsc_tls_hash_sha512);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_append(&state, msg, msglen);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_snapshot(&state, output, sizeof(output), &outlen);
	}

	if (status == qsc_tls_status_success)
	{
		res = (outlen == sizeof(expect) && qsc_memutils_are_equal(expect, output, sizeof(expect)) == true);
	}

	qsc_tls_transcript_dispose(&state);

	return res;
}

bool tls_stage3_transcript_initialize(void)
{
	qsc_tls_transcript_state state = { 0 };
	qsc_tls_status status;
	bool res;

	res = true;

	if (qsc_tls_transcript_hash_size(qsc_tls_hash_sha256) != QSC_SHA2_256_HASH_SIZE ||
		qsc_tls_transcript_hash_size(qsc_tls_hash_sha384) != QSC_SHA2_384_HASH_SIZE ||
		qsc_tls_transcript_hash_size(qsc_tls_hash_sha512) != QSC_SHA2_512_HASH_SIZE ||
		qsc_tls_transcript_hash_size((qsc_tls_hash_algorithm)0x7FFF) != 0U)
	{
		res = false;
	}

	status = qsc_tls_transcript_initialize(&state, qsc_tls_hash_sha256);

	if (res == true)
	{
		res = (status == qsc_tls_status_success && state.initialized == true && state.hash == qsc_tls_hash_sha256);
	}

	status = qsc_tls_transcript_reset(&state);

	if (res == true)
	{
		res = (status == qsc_tls_status_success && state.initialized == true && state.hash == qsc_tls_hash_sha256);
	}

	qsc_tls_transcript_dispose(&state);

	if (res == true)
	{
		res = (state.initialized == false && state.hash == qsc_tls_hash_none);
	}

	status = qsc_tls_transcript_initialize(&state, (qsc_tls_hash_algorithm)0x7FFF);

	if (res == true)
	{
		res = (status == qsc_tls_status_not_supported && state.initialized == false);
	}

	return res;
}

bool tls_stage3_transcript_snapshot(void)
{
	static const uint8_t msg[] =
	{
		0x01U, 0x00U, 0x00U, 0x2CU, 0x03U, 0x03U, 0xA1U, 0xA2U,
		0xA3U, 0xA4U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U,
		0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU,
		0xFFU, 0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U,
		0x80U, 0x90U, 0xA0U, 0xB0U, 0xC0U, 0xD0U, 0xE0U, 0xF0U,
		0x00U, 0x13U, 0x01U, 0x00U, 0x00U, 0x00U
	};
	bool res;

	res = true;

	if (tls_stage3_snapshot_matches_sha256(msg, sizeof(msg)) == false)
	{
		res = false;
	}

	if (res == true)
	{
		res = (tls_stage3_snapshot_matches_sha384(msg, sizeof(msg)) == true);
	}

	if (res == true)
	{
		res = (tls_stage3_snapshot_matches_sha512(msg, sizeof(msg)) == true);
	}

	return res;
}

bool tls_stage3_transcript_clone_reset(void)
{
	static const uint8_t parta[] = { 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U };
	static const uint8_t partb[] = { 0x10U, 0x20U, 0x30U, 0x40U, 0x50U };
	qsc_tls_transcript_state left = { 0 };
	qsc_tls_transcript_state right = { 0 };
	uint8_t leftdigest[QSC_SHA2_256_HASH_SIZE] = { 0U };
	uint8_t rightdigest[QSC_SHA2_256_HASH_SIZE] = { 0U };
	size_t leftlen;
	size_t rightlen;
	qsc_tls_status status;
	bool res;

	leftlen = 0U;
	rightlen = 0U;
	res = false;

	status = qsc_tls_transcript_initialize(&left, qsc_tls_hash_sha256);

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_append(&left, parta, sizeof(parta));
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_clone(&right, &left);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_append(&left, partb, sizeof(partb));
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_snapshot(&left, leftdigest, sizeof(leftdigest), &leftlen);
	}

	if (status == qsc_tls_status_success)
	{
		status = qsc_tls_transcript_snapshot(&right, rightdigest, sizeof(rightdigest), &rightlen);
	}

	if (status == qsc_tls_status_success)
	{
		res = (leftlen == sizeof(leftdigest) && rightlen == sizeof(rightdigest) &&
			qsc_memutils_are_equal(leftdigest, rightdigest, sizeof(leftdigest)) == false);
	}

	if (res == true)
	{
		status = qsc_tls_transcript_reset(&left);
	}

	if (status == qsc_tls_status_success && res == true)
	{
		status = qsc_tls_transcript_append(&left, parta, sizeof(parta));
	}

	if (status == qsc_tls_status_success && res == true)
	{
		status = qsc_tls_transcript_snapshot(&left, leftdigest, sizeof(leftdigest), &leftlen);
	}

	if (status == qsc_tls_status_success && res == true)
	{
		res = (qsc_memutils_are_equal(leftdigest, rightdigest, sizeof(leftdigest)) == true);
	}

	qsc_tls_transcript_dispose(&left);
	qsc_tls_transcript_dispose(&right);

	return res;
}

bool tls_stage3_transcript_negative_paths(void)
{
	qsc_tls_transcript_state state = { 0 };
	uint8_t digest[QSC_SHA2_512_HASH_SIZE] = { 0U };
	size_t digestlen;
	qsc_tls_status status;
	bool res;

	qsc_memutils_clear(&state, sizeof(qsc_tls_transcript_state));
	qsc_memutils_clear(digest, sizeof(digest));
	digestlen = 0U;
	res = true;

	status = qsc_tls_transcript_initialize(NULL, qsc_tls_hash_sha256);

	if (status != qsc_tls_status_invalid_input)
	{
		res = false;
	}

	status = qsc_tls_transcript_append(NULL, digest, 1U);

	if (res == true)
	{
		res = (status == qsc_tls_status_invalid_input);
	}

	status = qsc_tls_transcript_append(&state, digest, 1U);

	if (res == true)
	{
		res = (status == qsc_tls_status_invalid_state);
	}

	status = qsc_tls_transcript_snapshot(&state, digest, sizeof(digest), &digestlen);

	if (res == true)
	{
		res = (status == qsc_tls_status_invalid_state && digestlen == 0U);
	}

	status = qsc_tls_transcript_initialize(&state, qsc_tls_hash_sha512);

	if (res == true)
	{
		res = (status == qsc_tls_status_success);
	}

	status = qsc_tls_transcript_append(&state, NULL, 1U);

	if (res == true)
	{
		res = (status == qsc_tls_status_invalid_input);
	}

	status = qsc_tls_transcript_append(&state, NULL, 0U);

	if (res == true)
	{
		res = (status == qsc_tls_status_success);
	}

	status = qsc_tls_transcript_snapshot(&state, digest, QSC_SHA2_384_HASH_SIZE, &digestlen);

	if (res == true)
	{
		res = (status == qsc_tls_status_buffer_too_small && digestlen == 0U);
	}

	qsc_tls_transcript_dispose(&state);

	return res;
}

bool qsctest_tls_stage3_tests(void)
{
	bool res;

	res = true;

	if (tls_stage3_transcript_initialize() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 3 transcript initialize test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 3 transcript initialize test.");
		res = false;
	}

	if (tls_stage3_transcript_snapshot() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 3 snapshot test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 3 snapshot test.");
		res = false;
	}

	if (tls_stage3_transcript_clone_reset() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 3 transcript clone and reset test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 3 transcript clone and reset test.");
		res = false;
	}

	if (tls_stage3_transcript_negative_paths() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 3 transcript negative-path test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 3 transcript negative-path test.");
		res = false;
	}

	return res;
}
