#include "tls_stage10_0rtt_tests.h"
#include "../testutils.h"
#include "tlskeyschedule.h"
#include "tlsextensions.h"
#include "memutils.h"

static uint8_t qsctest_tls_stage10_hex_nibble(const char c)
{
	uint8_t v;

	v = 0U;

	if (c >= '0' && c <= '9')
	{
		v = (uint8_t)(c - '0');
	}
	else if (c >= 'a' && c <= 'f')
	{
		v = (uint8_t)(10U + (uint8_t)(c - 'a'));
	}
	else if (c >= 'A' && c <= 'F')
	{
		v = (uint8_t)(10U + (uint8_t)(c - 'A'));
	}

	return v;
}

static void qsctest_tls_stage10_from_hex(uint8_t* output, const char* hex, const size_t outlen)
{
	for (size_t i = 0U; i < outlen; ++i)
	{
		output[i] = (uint8_t)((qsctest_tls_stage10_hex_nibble(hex[i * 2U]) << 4) |
			qsctest_tls_stage10_hex_nibble(hex[(i * 2U) + 1U]));
	}
}

bool qsctest_tls_stage10_0rtt_rfc8448_vectors(void)
{
	static const char* psk_hex = "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3";
	static const char* early_hex = "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c";
	static const char* binder_key_hex = "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256";
	static const char* ch_trunc_hash_hex = "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14";
	static const char* psk_binder_hex = "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d";
	static const char* ch_full_hash_hex = "08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913";
	static const char* cets_hex = "3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62";
	qsc_tls_key_schedule_state ks = { 0 };
	uint8_t binder[32U] = { 0U };
	uint8_t ch_full_hash[32U] = { 0U };
	uint8_t ch_trunc_hash[32U] = { 0U };
	uint8_t expected_binder[32U] = { 0U };
	uint8_t expected_binder_key[32U] = { 0U };
	uint8_t expected_cets[32U] = { 0U };
	uint8_t expected_early[32U] = { 0U };
	uint8_t psk[32U] = { 0U };
	size_t binderlen;
	qsc_tls_status status;
	bool res;

	qsctest_tls_stage10_from_hex(psk, psk_hex, sizeof(psk));
	qsctest_tls_stage10_from_hex(expected_early, early_hex, sizeof(expected_early));
	qsctest_tls_stage10_from_hex(expected_binder_key, binder_key_hex, sizeof(expected_binder_key));
	qsctest_tls_stage10_from_hex(ch_trunc_hash, ch_trunc_hash_hex, sizeof(ch_trunc_hash));
	qsctest_tls_stage10_from_hex(expected_binder, psk_binder_hex, sizeof(expected_binder));
	qsctest_tls_stage10_from_hex(ch_full_hash, ch_full_hash_hex, sizeof(ch_full_hash));
	qsctest_tls_stage10_from_hex(expected_cets, cets_hex, sizeof(expected_cets));

	binderlen = 0U;
	res = true;
	status = qsc_tls_keyschedule_state_initialize(&ks, qsc_tls_hash_sha256);
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		status = qsc_tls_keyschedule_extract_early_secret(&ks, psk, sizeof(psk));

		res = (status == qsc_tls_status_success) &&
			qsc_memutils_are_equal(expected_early, ks.earlysecret, sizeof(expected_early));
	}

	if (res == true)
	{
		status = qsc_tls_keyschedule_derive_binder_key(&ks, false);

		res = (status == qsc_tls_status_success) &&
			qsc_memutils_are_equal(expected_binder_key, ks.binderkey, sizeof(expected_binder_key));
	}

	if (res == true)
	{
		status = qsc_tls_keyschedule_compute_psk_binder(qsc_tls_hash_sha256,
			ks.binderkey, ks.digestsize, ch_trunc_hash, sizeof(ch_trunc_hash), binder, sizeof(binder), &binderlen);

		res = (status == qsc_tls_status_success) && (binderlen == sizeof(binder)) &&
			qsc_memutils_are_equal(expected_binder, binder, sizeof(expected_binder));
	}

	if (res == true)
	{
		status = qsc_tls_keyschedule_derive_client_early_traffic_secret(&ks, ch_full_hash, sizeof(ch_full_hash));

		res = (status == qsc_tls_status_success) &&
			qsc_memutils_are_equal(expected_cets, ks.clientearlytrafficsecret, sizeof(expected_cets));
	}

	qsc_tls_keyschedule_state_dispose(&ks);

	return res;
}

bool qsctest_tls_stage10_0rtt_early_exporter(void)
{
	static const char* psk_hex = "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3";
	static const char* ch_full_hash_hex = "08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913";
	qsc_tls_key_schedule_state ks = { 0 };
	uint8_t ch_full_hash[32U] = { 0U };
	uint8_t psk[32U] = { 0U };
	qsc_tls_status status;
	bool res;

	qsctest_tls_stage10_from_hex(psk, psk_hex, sizeof(psk));
	qsctest_tls_stage10_from_hex(ch_full_hash, ch_full_hash_hex, sizeof(ch_full_hash));

	status = qsc_tls_keyschedule_state_initialize(&ks, qsc_tls_hash_sha256);
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		status = qsc_tls_keyschedule_extract_early_secret(&ks, psk, sizeof(psk));
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		status = qsc_tls_keyschedule_derive_early_exporter_secret(&ks, ch_full_hash, sizeof(ch_full_hash));
		res = (status == qsc_tls_status_success);
	}

	qsc_tls_keyschedule_state_dispose(&ks);

	return res;
}

bool qsctest_tls_stage10_0rtt_early_data_extension(void)
{
	uint8_t buffer[32U] = { 0U };
	uint32_t decoded_max;
	size_t offset;
	qsc_tls_status status;
	bool res;

	decoded_max = 0U;
	offset = 0U;
	res = true;

	status = qsc_tls_extensions_encode_early_data_empty(buffer, sizeof(buffer), &offset);
	res = (status == qsc_tls_status_success) && (offset == 4U);

	if (res == true)
	{
		offset = 0U;
		status = qsc_tls_extensions_encode_early_data_max(buffer, sizeof(buffer), &offset, 16384U);
		res = (status == qsc_tls_status_success) && (offset == 8U);
	}

	if (res == true)
	{
		status = qsc_tls_extensions_decode_early_data_max(buffer + 4U, 4U, &decoded_max);
		res = (status == qsc_tls_status_success) && (decoded_max == 16384U);
	}

	return res;
}

bool qsctest_tls_stage10_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage10_0rtt_rfc8448_vectors() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 10 0-RTT RFC 8448 vector test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 10 0-RTT RFC 8448 vector test.");
		res = false;
	}

	if (qsctest_tls_stage10_0rtt_early_exporter() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 10 early exporter derivation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 10 early exporter derivation test.");
		res = false;
	}

	if (qsctest_tls_stage10_0rtt_early_data_extension() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 10 early_data extension round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 10 early_data extension round-trip test.");
		res = false;
	}

	return res;
}
