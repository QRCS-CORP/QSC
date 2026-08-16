#include "tls_stage8_vector_tests.h"
#include "../testutils.h"
#include "tlskeyschedule.h"
#include "tlstranscript.h"
#include "memutils.h"
#include <string.h>

static bool qsctest_tls_stage8_hex_nibble(char c, uint8_t* value)
{
	bool res;

	res = true;

	if (c >= '0' && c <= '9')
	{
		*value = (uint8_t)(c - '0');
	}
	else if (c >= 'a' && c <= 'f')
	{
		*value = (uint8_t)(10 + (c - 'a'));
	}
	else if (c >= 'A' && c <= 'F')
	{
		*value = (uint8_t)(10 + (c - 'A'));
	}
	else
	{
		*value = 0U;
		res = false;
	}

	return res;
}

static bool qsctest_tls_stage8_from_hex(uint8_t* output, const char* hex, size_t expected_bytes)
{
	bool res;
	size_t i;
	uint8_t hi;
	uint8_t lo;

	res = (output != NULL && hex != NULL);

	if (res == true)
	{
		for (i = 0U; i < expected_bytes; ++i)
		{
			if (qsctest_tls_stage8_hex_nibble(hex[(2U * i)], &hi) == false ||
				qsctest_tls_stage8_hex_nibble(hex[(2U * i) + 1U], &lo) == false)
			{
				res = false;
				break;
			}

			output[i] = (uint8_t)((hi << 4) | lo);
		}
	}

	return res;
}

static bool qsctest_tls_stage8_fixed_vectors_rfc8448(void)
{
	static const char* ch_hex =
		"010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7"
		"000006130113031302010000910000000b0009000006736572766572ff01000100000a001400"
		"12001d0017001800190100010101020103010400230000003300260024001d002099381de560"
		"e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020"
		"001e040305030603020308040805080604010501060102010402050206020202002d0002010100"
		"1c00024001";
	static const char* sh_hex =
		"020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800"
		"130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"
		"002b00020304";
	static const char* dhe_hex = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
	static const char* early_hex = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
	static const char* hs_hex = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
	static const char* ms_hex = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
	static const char* chts_hex = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
	static const char* shts_hex = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
	static const char* cats_hex = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
	static const char* sats_hex = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
	static const char* ems_hex = "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50";
	static const char* hs_hash_hex = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
	static const char* fin_transcript_hex = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";
	static const char* shts_key_hex = "3fce516009c21727d0f2e4e86ee403bc";
	static const char* shts_iv_hex = "5d313eb2671276ee13000b30";
	static const char* cv_label = "TLS 1.3, server CertificateVerify";
	qsc_tls_transcript_state transcript = { 0 };
	qsc_tls_key_schedule_state ks = { 0 };
	uint8_t ch[1024U] = { 0U };
	uint8_t sh[256U] = { 0U };
	uint8_t dhe[32U] = { 0U };
	uint8_t expected_early[32U] = { 0U };
	uint8_t expected_hs[32U] = { 0U };
	uint8_t expected_ms[32U] = { 0U };
	uint8_t expected_chts[32U] = { 0U };
	uint8_t expected_shts[32U] = { 0U };
	uint8_t expected_cats[32U] = { 0U };
	uint8_t expected_sats[32U] = { 0U };
	uint8_t expected_ems[32U] = { 0U };
	uint8_t expected_hs_hash[32U] = { 0U };
	uint8_t thash_hs[32U] = { 0U };
	uint8_t thash_fin[32U] = { 0U };
	uint8_t expected_key[16U] = { 0U };
	uint8_t expected_iv[12U] = { 0U };
	uint8_t got_key[16U] = { 0U };
	uint8_t got_iv[12U] = { 0U };
	uint8_t cv_input[256U] = { 0U };
	size_t ch_len;
	size_t sh_len;
	size_t tlen;
	size_t cv_written;
	size_t i;
	bool res;

	res = true;
	ch_len = strlen(ch_hex) / 2U;
	sh_len = strlen(sh_hex) / 2U;

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(ch, ch_hex, ch_len);
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(sh, sh_hex, sh_len);
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(dhe, dhe_hex, sizeof(dhe));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_early, early_hex, sizeof(expected_early));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_hs, hs_hex, sizeof(expected_hs));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_ms, ms_hex, sizeof(expected_ms));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_chts, chts_hex, sizeof(expected_chts));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_shts, shts_hex, sizeof(expected_shts));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_cats, cats_hex, sizeof(expected_cats));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_sats, sats_hex, sizeof(expected_sats));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_ems, ems_hex, sizeof(expected_ems));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_hs_hash, hs_hash_hex, sizeof(expected_hs_hash));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(thash_fin, fin_transcript_hex, sizeof(thash_fin));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_key, shts_key_hex, sizeof(expected_key));
	}

	if (res == true)
	{
		res = qsctest_tls_stage8_from_hex(expected_iv, shts_iv_hex, sizeof(expected_iv));
	}

	if (res == true)
	{
		qsc_tls_transcript_initialize(&transcript, qsc_tls_hash_sha256);
		qsc_tls_transcript_update(&transcript, ch, ch_len);
		qsc_tls_transcript_update(&transcript, sh, sh_len);
		qsc_tls_transcript_snapshot(&transcript, thash_hs, sizeof(thash_hs), &tlen);
		res = (tlen == sizeof(thash_hs)) && qsc_memutils_are_equal(thash_hs, expected_hs_hash, sizeof(thash_hs));
		qsc_tls_transcript_dispose(&transcript);
	}

	if (res == true)
	{
		qsc_tls_keyschedule_state_initialize(&ks, qsc_tls_hash_sha256);
		qsc_tls_keyschedule_extract_early_secret(&ks, NULL, 0U);
		res = qsc_memutils_are_equal(ks.earlysecret, expected_early, sizeof(expected_early));
	}

	if (res == true)
	{
		qsc_tls_keyschedule_extract_handshake_secret(&ks, dhe, sizeof(dhe));
		res = qsc_memutils_are_equal(ks.handshakesecret, expected_hs, sizeof(expected_hs));
	}

	if (res == true)
	{
		qsc_tls_keyschedule_derive_handshake_traffic_secrets(&ks, thash_hs, sizeof(thash_hs));
		res = qsc_memutils_are_equal(ks.clienthandshaketrafficsecret, expected_chts, sizeof(expected_chts)) &&
			qsc_memutils_are_equal(ks.serverhandshaketrafficsecret, expected_shts, sizeof(expected_shts));
	}

	if (res == true)
	{
		qsc_tls_keyschedule_extract_master_secret(&ks);
		res = qsc_memutils_are_equal(ks.mastersecret, expected_ms, sizeof(expected_ms));
	}

	if (res == true)
	{
		qsc_tls_keyschedule_derive_application_traffic_secrets(&ks, thash_fin, sizeof(thash_fin));
		res = qsc_memutils_are_equal(ks.clientapplicationtrafficsecret, expected_cats, sizeof(expected_cats)) &&
			qsc_memutils_are_equal(ks.serverapplicationtrafficsecret, expected_sats, sizeof(expected_sats));
	}

	if (res == true)
	{
		qsc_tls_keyschedule_derive_exporter_master_secret(&ks, thash_fin, sizeof(thash_fin));
		res = qsc_memutils_are_equal(ks.exportermastersecret, expected_ems, sizeof(expected_ems));
	}

	if (res == true)
	{
		qsc_tls_keyschedule_derive_traffic_keys(qsc_tls_hash_sha256, ks.serverhandshaketrafficsecret,
			sizeof(expected_shts), sizeof(expected_key), sizeof(expected_iv), got_key, got_iv);
		res = qsc_memutils_are_equal(got_key, expected_key, sizeof(expected_key)) &&
			qsc_memutils_are_equal(got_iv, expected_iv, sizeof(expected_iv));
	}

	if (res == true)
	{
		qsc_tls_keyschedule_build_certificate_verify_input(cv_label, thash_hs, sizeof(thash_hs), cv_input, sizeof(cv_input), &cv_written);
		res = (cv_written == 130U);
	}

	if (res == true)
	{
		for (i = 0U; i < 64U; ++i)
		{
			if (cv_input[i] != 0x20U)
			{
				res = false;
				break;
			}
		}
	}

	if (res == true)
	{
		res = (cv_input[97U] == 0x00U);
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal((const uint8_t*)(cv_input + 64U), (const uint8_t*)cv_label, 33U);
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal((const uint8_t*)(cv_input + 98U), thash_hs, sizeof(thash_hs));
	}

	qsc_tls_keyschedule_state_dispose(&ks);

	return res;
}

bool qsctest_tls_stage8_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage8_fixed_vectors_rfc8448() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 8 fixed-vector RFC 8448 derivation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 8 fixed-vector RFC 8448 derivation test.");
		res = false;
	}

	return res;
}
