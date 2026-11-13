#include "hcg_test.h"
#include "hcg.h"
#include "memutils.h"
#include "qsctestcommon.h"
#include "testutils.h"

/**
 * \brief Produce a reproducible 32-bit test-case value using a non-cryptographic LCG.
 * \param value Mutable sequence state; must not be NULL.
 * \return Next test-case value.
 * \note This is never used as DRBG seed entropy in production; tests only, not thread safe.
 */
static uint32_t hcg_test_next(uint32_t* value)
{
	*value = (*value * 1664525U) + 1013904223U;

	return *value;
}

/**
 * \brief Report the first failed fuzz iteration with a reproducible case index.
 * \param phase Short diagnostic phase name.
 * \param iteration Zero-based failure index.
 * \note Console output only; does not modify crypto state.
 */
static void hcg_test_fuzz_failure(const char* phase, size_t iteration)
{
	qsctest_print_safe("[FAIL] HCG SHA-512 fuzz phase: ");
	qsctest_print_safe(phase);
	qsctest_print_safe("; case=");
	qsctest_print_ulong((uint64_t)iteration);
	qsctest_print_line("");
}

bool qsctest_hcg_basic_kat(void)
{
	uint8_t entropy[32U] = { 0U };
	uint8_t nonce[16U] = { 0U };
	uint8_t expected[128U] = { 0U };
	uint8_t output[128U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(entropy); ++i)
	{
		entropy[i] = (uint8_t)(i + 0U);
	}

	for (i = 0U; i < sizeof(nonce); ++i)
	{
		nonce[i] = (uint8_t)(i + 32U);
	}

	qsctest_hex_to_bin(
		"5a947e2ec811344b506f321e3f1fbde3fde96845301a7c1793e72b2071e1d984"
		"846eda8ee0e97301da2e6d07c4937b7a50c729a1ad16e594ab3dd96561709270"
		"7e563ead288ded338afa7141ffe8ff4c78608db673d3f16588672bed86718446"
		"9a91a147c31a3cfb04747adb3a08f6ccba85d2f1ab4ed2f9821235d9c1fecc93", expected, sizeof(expected));
	res = qsc_hcg_instantiate(&ctx, entropy, sizeof(entropy), nonce, sizeof(nonce), NULL, 0U);

	if (res == true)
	{
		res = qsc_hcg_generate(&ctx, output, sizeof(output));
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal(output, expected, sizeof(expected));
	}

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 instantiate and generate KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 instantiate and generate KAT; SP 800-90A output mismatch or operation failed.");
	}

	qsc_hcg_dispose(&ctx);

	return res;
}

bool qsctest_hcg_additional_kat(void)
{
	uint8_t entropy[32U] = { 0U };
	uint8_t nonce[16U] = { 0U };
	uint8_t personalization[32U] = { 0U };
	uint8_t additional1[32U] = { 0U };
	uint8_t additional2[32U] = { 0U };
	uint8_t expected[128U] = { 0U };
	uint8_t output[128U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(entropy); ++i)
	{
		entropy[i] = (uint8_t)(i + 0U);
	}

	for (i = 0U; i < sizeof(nonce); ++i)
	{
		nonce[i] = (uint8_t)(i + 32U);
	}

	for (i = 0U; i < sizeof(personalization); ++i)
	{
		personalization[i] = (uint8_t)(i + 80U);
	}

	for (i = 0U; i < sizeof(additional1); ++i)
	{
		additional1[i] = (uint8_t)(i + 96U);
	}

	for (i = 0U; i < sizeof(additional2); ++i)
	{
		additional2[i] = (uint8_t)(i + 128U);
	}

	qsctest_hex_to_bin("1af2f3a67602ea95f07cdd155e4c9d5ec896d1a537a7a2302cdbfde969e86d87"
		"e4848b75061fafad41b62917a26ce7659b1eff61fc0d6f2deaf2cfda16518803"
		"0ec15832789c7f1a0f0f70febf49619a4718213a6803c2f1d58edd8929025774"
		"ffcf75664f84b806336a61657293362c1652cf6dee7d59318eb04b005a430f62", expected, sizeof(expected));

	res = qsc_hcg_instantiate(&ctx, entropy, sizeof(entropy), nonce, sizeof(nonce), personalization, sizeof(personalization));

	if (res == true)
	{
		res = qsc_hcg_generate_ex(&ctx, output, sizeof(output), additional1, sizeof(additional1));
		if (res == true)
		{
			res = qsc_hcg_generate_ex(&ctx, output, sizeof(output), additional2, sizeof(additional2));
		}
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal(output, expected, sizeof(expected));
	}

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 additional input KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 additional input KAT; SP 800-90A output mismatch or operation failed.");
	}

	qsc_hcg_dispose(&ctx);

	return res;
}

bool qsctest_hcg_reseed_kat(void)
{
	uint8_t entropy[32U] = { 0U };
	uint8_t nonce[16U] = { 0U };
	uint8_t personalization[32U] = { 0U };
	uint8_t additional1[32U] = { 0U };
	uint8_t additional2[32U] = { 0U };
	uint8_t reseed_entropy[32U] = { 0U };
	uint8_t reseed_additional[32U] = { 0U };
	uint8_t expected[128U] = { 0U };
	uint8_t output[128U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(entropy); ++i)
	{
		entropy[i] = (uint8_t)(i + 0U);
	}

	for (i = 0U; i < sizeof(nonce); ++i)
	{
		nonce[i] = (uint8_t)(i + 32U);
	}

	for (i = 0U; i < sizeof(personalization); ++i)
	{
		personalization[i] = (uint8_t)(i + 80U);
	}

	for (i = 0U; i < sizeof(additional1); ++i)
	{
		additional1[i] = (uint8_t)(i + 96U);
	}

	for (i = 0U; i < sizeof(additional2); ++i)
	{
		additional2[i] = (uint8_t)(i + 128U);
	}

	for (i = 0U; i < sizeof(reseed_entropy); ++i)
	{
		reseed_entropy[i] = (uint8_t)(i + 160U);
	}

	for (i = 0U; i < sizeof(reseed_additional); ++i)
	{
		reseed_additional[i] = (uint8_t)(i + 192U);
	}

	qsctest_hex_to_bin("a9518b38aa42096c117efec11cacec21477113626e06722c0e2b2ebf0b0ce9db"
		"9b756a44047f77c224e4a51b264b74374c457c53777e4a69036d971dee61cf89"
		"f0b7acc2122007d81f6b3ad43df66b30bd27734d5aa48c42bb4e7aac87e7ba1b"
		"992e6b2fde6fc7b4ff39fb5886add2f8a62902a9df8045a16aacd6a41f3c9910", expected, sizeof(expected));

	res = qsc_hcg_instantiate(&ctx, entropy, sizeof(entropy), nonce, sizeof(nonce), personalization, sizeof(personalization));

	if (res == true)
	{
		res = qsc_hcg_generate_ex(&ctx, output, sizeof(output), additional1, sizeof(additional1));
		if (res == true)
		{
			res = qsc_hcg_reseed(&ctx, reseed_entropy, sizeof(reseed_entropy), reseed_additional, sizeof(reseed_additional));
		}
		if (res == true)
		{
			res = qsc_hcg_generate_ex(&ctx, output, sizeof(output), additional2, sizeof(additional2));
		}
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal(output, expected, sizeof(expected));
	}

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 explicit reseed KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 explicit reseed KAT; SP 800-90A output mismatch or operation failed.");
	}

	qsc_hcg_dispose(&ctx);

	return res;
}

bool qsctest_hcg_prediction_resistance_kat(void)
{
	uint8_t entropy[32U] = { 0U };
	uint8_t nonce[16U] = { 0U };
	uint8_t personalization[32U] = { 0U };
	uint8_t reseed_entropy[32U] = { 0U };
	uint8_t reseed_additional[32U] = { 0U };
	uint8_t expected[128U] = { 0U };
	uint8_t output[128U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(entropy); ++i)
	{
		entropy[i] = (uint8_t)(i + 0U);
	}

	for (i = 0U; i < sizeof(nonce); ++i)
	{
		nonce[i] = (uint8_t)(i + 32U);
	}

	for (i = 0U; i < sizeof(personalization); ++i)
	{
		personalization[i] = (uint8_t)(i + 80U);
	}

	for (i = 0U; i < sizeof(reseed_entropy); ++i)
	{
		reseed_entropy[i] = (uint8_t)(i + 160U);
	}

	for (i = 0U; i < sizeof(reseed_additional); ++i)
	{
		reseed_additional[i] = (uint8_t)(i + 192U);
	}

	qsctest_hex_to_bin("439409def02f1d55224602d07957edc54c1e396cdd1a9725888972ab6ac2afd3"
		"a16cc9bdb634ca4f984fe200dc43486f2785fbb81176f4d02b177a3f42261393"
		"9d5bb228132c271f4ee0ccb1ca911cfbe28935e86a339b59927a0352aea7474c"
		"5e7754a77399501e63fe43cd80bbc5fda37c6ee48f638aac9e85bfd5ed45c87d", expected, sizeof(expected));

	res = qsc_hcg_instantiate(&ctx, entropy, sizeof(entropy), nonce, sizeof(nonce), personalization, sizeof(personalization));

	if (res == true)
	{
		res = qsc_hcg_reseed(&ctx, reseed_entropy, sizeof(reseed_entropy), reseed_additional, sizeof(reseed_additional));
		if (res == true)
		{
			res = qsc_hcg_generate_ex(&ctx, output, sizeof(output), NULL, 0U);
		}
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal(output, expected, sizeof(expected));
	}

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 deterministic prediction-resistance KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 deterministic prediction-resistance KAT; SP 800-90A output mismatch or operation failed.");
	}

	qsc_hcg_dispose(&ctx);

	return res;
}

bool qsctest_hcg_boundaries(void)
{
	uint8_t seed[QSC_HCG_SEED_SIZE] = { 0U };
	uint8_t output[1U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	bool res;

	res = (qsc_hcg_instantiate(&ctx, seed, 31U, seed + 32U, 16U, NULL, 0U) == false);
	res = (qsc_hcg_instantiate(&ctx, seed, 32U, seed + 32U, 15U, NULL, 0U) == false) && res;
	res = (qsc_hcg_instantiate(&ctx, seed, 47U, NULL, 0U, NULL, 0U) == false) && res;
	res = (qsc_hcg_instantiate(&ctx, seed, 48U, NULL, 0U, NULL, 0U) == true) && res;
	res = (qsc_hcg_reseed(&ctx, seed, 31U, NULL, 0U) == false) && res;
	res = (qsc_hcg_generate(&ctx, output, QSC_HCG_MAX_REQUEST_SIZE + 1U) == false) && res;
	res = (qsc_hcg_generate_ex(&ctx, output, sizeof(output), NULL, 1U) == false) && res;
	ctx.reseed_counter = QSC_HCG_RESEED_INTERVAL + 1U;
	res = (qsc_hcg_generate(&ctx, output, sizeof(output)) == false) && res;
	res = (ctx.initialized == true) && res;
	res = (qsc_hcg_reseed(&ctx, seed, QSC_HCG_MIN_ENTROPY_SIZE, NULL, 0U) == true) && res;
	res = (qsc_hcg_generate(&ctx, output, sizeof(output)) == true) && res;
	qsc_hcg_dispose(&ctx);
	res = (ctx.initialized == false && qsc_memutils_zeroed(&ctx, sizeof(ctx)) == true) && res;

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 boundary and zeroization tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 invalid input acceptance, reseed interval or state zeroization.");
	}

	return res;
}

bool qsctest_hcg_auto_seed(void)
{
	uint8_t output[64U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	bool res;

	res = qsc_hcg_initialize_auto(&ctx, NULL, 0U, false);

	if (res == true)
	{
		res = qsc_hcg_generate(&ctx, output, sizeof(output));
	}

	if (res == true)
	{
		ctx.generated_bytes = QSC_HCG_RESEED_THRESHOLD;
		res = qsc_hcg_generate(&ctx, output, sizeof(output));
		res = (ctx.generated_bytes == sizeof(output) && ctx.reseed_counter == 2U) && res;
	}

	qsc_hcg_dispose(&ctx);

	if (res == true)
	{
		res = qsc_hcg_initialize_auto(&ctx, NULL, 0U, true);
	}

	if (res == true)
	{
		res = qsc_hcg_generate(&ctx, output, sizeof(output));
	}

	if (res == true)
	{
		res = qsc_hcg_generate(&ctx, output, sizeof(output));
		res = (ctx.reseed_counter == 2U) && res;
	}

	qsc_hcg_dispose(&ctx);

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 ACP automatic seeding and prediction resistance.");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 ACP entropy acquisition, periodic reseed or prediction-resistance reseed.");
	}

	return res;
}

bool qsctest_hcg_wellness(void)
{
	uint8_t entropy[QSC_HCG_MIN_SEED_SIZE] = { 0U };
	uint8_t sample[QSC_HCG_MAX_REQUEST_SIZE] = { 0U };
	uint32_t histogram[256U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	size_t ones;
	size_t i;
	size_t j;
	size_t run;
	bool res;

	for (i = 0U; i < sizeof(entropy); ++i)
	{
		entropy[i] = (uint8_t)(i + 3U);
	}

	res = qsc_hcg_instantiate(&ctx, entropy, sizeof(entropy), NULL, 0U, NULL, 0U);

	if (res == true)
	{
		res = qsc_hcg_generate(&ctx, sample, sizeof(sample));
	}

	if (res == true)
	{
		ones = 0U;
		run = 1U;

		for (i = 0U; i < sizeof(sample) && res == true; ++i)
		{
			++histogram[sample[i]];

			for (j = 0U; j < 8U; ++j)
			{
				ones += (size_t)((sample[i] >> j) & 1U);
			}

			if (i != 0U)
			{
				if (sample[i] == sample[i - 1U])
				{
					++run;
				}
				else
				{
					run = 1U;
				}

				if (run >= 12U)
				{
					qsctest_print_line("[FAIL] HCG wellness: excessive identical-byte run.");
					res = false;
				}
			}
		}

		if (res == true && (ones < ((sizeof(sample) * 8U * 48U) / 100U) || ones > ((sizeof(sample) * 8U * 52U) / 100U)))
		{
			qsctest_print_line("[FAIL] HCG wellness: gross bit-balance deviation.");
			res = false;
		}

		for (i = 0U; i < 256U && res == true; ++i)
		{
			if (histogram[i] < 120U || histogram[i] > 400U)
			{
				qsctest_print_line("[FAIL] HCG wellness: anomalous byte histogram bin.");
				res = false;
			}
		}

		for (i = QSC_HCG_KEY_SIZE; i < sizeof(sample) && res == true; i += QSC_HCG_KEY_SIZE)
		{
			if (qsc_memutils_are_equal(sample + i, sample + i - QSC_HCG_KEY_SIZE, QSC_HCG_KEY_SIZE) == true)
			{
				qsctest_print_line("[FAIL] HCG wellness: consecutive 512-bit blocks are identical.");
				res = false;
			}
		}
	}
	else
	{
		qsctest_print_line("[FAIL] HCG wellness: deterministic instantiation/generation failed.");
	}

	qsc_hcg_dispose(&ctx);
	qsc_memutils_secure_erase(sample, sizeof(sample));

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 output wellness smoke tests.");
	}

	return res;
}

/**
 * \brief Check state transitions, reseed reset, legacy entry point and the largest valid request.
 * \return True if all expected counter, output and lifetime invariants hold; false otherwise.
 */
bool qsctest_hcg_state_wellness(void)
{
	uint8_t entropy[QSC_HCG_SEED_SIZE] = { 0U };
	uint8_t output[QSC_HCG_MAX_REQUEST_SIZE + 1U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(entropy); ++i)
	{
		entropy[i] = (uint8_t)(i + 11U);
	}

	res = qsc_hcg_instantiate(&ctx, entropy, QSC_HCG_MIN_ENTROPY_SIZE, entropy + QSC_HCG_MIN_ENTROPY_SIZE, QSC_HCG_NONCE_SIZE, NULL, 0U);

	if (res == true)
	{
		res = (ctx.initialized == true && ctx.reseed_counter == 1U && ctx.generated_bytes == 0U);
	}

	if (res == true)
	{
		res = qsc_hcg_generate(&ctx, output, 1U);
		res = (ctx.reseed_counter == 2U && ctx.generated_bytes == 1U) && res;
	}

	if (res == true)
	{
		res = qsc_hcg_reseed(&ctx, entropy + 8U, QSC_HCG_MIN_ENTROPY_SIZE, NULL, 0U);
		res = (ctx.reseed_counter == 1U && ctx.generated_bytes == 0U) && res;
	}

	if (res == true)
	{
		output[QSC_HCG_MAX_REQUEST_SIZE] = 0xA5U;
		res = qsc_hcg_generate(&ctx, output, QSC_HCG_MAX_REQUEST_SIZE);
		res = (output[QSC_HCG_MAX_REQUEST_SIZE] == 0xA5U && ctx.reseed_counter == 2U && ctx.generated_bytes == QSC_HCG_MAX_REQUEST_SIZE) && res;
	}

	if (res == true)
	{
		res = (qsc_hcg_generate(&ctx, output, QSC_HCG_MAX_REQUEST_SIZE + 1U) == false);
		res = (output[QSC_HCG_MAX_REQUEST_SIZE] == 0xA5U && ctx.reseed_counter == 2U) && res;
	}

	qsc_hcg_dispose(&ctx);

	if (res == true)
	{
		qsc_hcg_initialize(&ctx, entropy, sizeof(entropy), NULL, 0U, false);
		res = (ctx.initialized == true && ctx.reseed_counter == 1U);
	}

	if (res == true)
	{
		res = qsc_hcg_generate(&ctx, output, 33U);
	}

	qsc_hcg_dispose(&ctx);
	res = (qsc_memutils_zeroed(&ctx, sizeof(ctx)) == true) && res;

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 state progression, reseed, maximum request and legacy initialization.");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 state progression, reseed, maximum request or legacy initialization.");
	}

	return res;
}

/**
 * \brief Fuzz legal entropy/nonce/personalization/additional-input combinations reproducibly.
 * \return True when matching state sequences agree and mutated inputs produce different output.
 * \note Exactly 256 deterministic cases; input synthesis is noncryptographic and tests only.
 */
bool qsctest_hcg_fuzz(void)
{
	uint8_t entropy[64U] = { 0U };
	uint8_t nonce[32U] = { 0U };
	uint8_t personalization[64U] = { 0U };
	uint8_t additional[65U] = { 0U };
	uint8_t mutated[65U] = { 0U };
	uint8_t reseed_entropy[64U] = { 0U };
	uint8_t output_a[4097U] = { 0U };
	uint8_t output_b[4097U] = { 0U };
	uint8_t output_c[4097U] = { 0U };
	qsc_hcg_state a = { 0U };
	qsc_hcg_state b = { 0U };
	qsc_hcg_state c = { 0U };
	uint32_t rng;
	size_t entlen;
	size_t noncelen;
	size_t perslen;
	size_t addlen;
	size_t mutlen;
	size_t otplen;
	size_t i;
	size_t j;
	const char* phase;
	bool res;

	rng = 0x48C69A31U;
	res = true;
	phase = "";

	for (i = 0U; i < 256U && res == true; ++i)
	{
		entlen = 32U + (size_t)(hcg_test_next(&rng) % 33U);
		noncelen = 16U + (size_t)(hcg_test_next(&rng) % 17U);
		perslen = (size_t)(hcg_test_next(&rng) % 65U);
		addlen = (size_t)(hcg_test_next(&rng) % 65U);
		otplen = 64U + (size_t)(hcg_test_next(&rng) % 4033U);

		for (j = 0U; j < sizeof(entropy); ++j)
		{
			entropy[j] = (uint8_t)(hcg_test_next(&rng) >> 24U);
			reseed_entropy[j] = (uint8_t)(hcg_test_next(&rng) >> 24U);
		}

		for (j = 0U; j < sizeof(nonce); ++j)
		{
			nonce[j] = (uint8_t)(hcg_test_next(&rng) >> 24U);
		}

		for (j = 0U; j < sizeof(personalization); ++j)
		{
			personalization[j] = (uint8_t)(hcg_test_next(&rng) >> 24U);
		}

		for (j = 0U; j < sizeof(additional); ++j)
		{
			additional[j] = (uint8_t)(hcg_test_next(&rng) >> 24U);
		}

		qsc_memutils_copy(mutated, additional, sizeof(mutated));
		mutlen = (addlen == 0U) ? 1U : addlen;
		mutated[0U] ^= 0x01U;
		phase = "instantiate";
		res = qsc_hcg_instantiate(&a, entropy, entlen, nonce, noncelen, personalization, perslen);

		if (res == true)
		{
			res = qsc_hcg_instantiate(&b, entropy, entlen, nonce, noncelen, personalization, perslen);
		}

		if (res == true)
		{
			qsc_memutils_copy(&c, &a, sizeof(c));
		}

		if (res == true && (i % 4U) == 0U)
		{
			phase = "reseed";
			res = qsc_hcg_reseed(&a, reseed_entropy, 32U + (i % 33U), additional, addlen);
			res = qsc_hcg_reseed(&b, reseed_entropy, 32U + (i % 33U), additional, addlen) && res;
			res = qsc_hcg_reseed(&c, reseed_entropy, 32U + (i % 33U), additional, addlen) && res;
		}

		if (res == true)
		{
			output_a[otplen] = 0xA5U;
			output_b[otplen] = 0xA5U;
			output_c[otplen] = 0xA5U;
			phase = "generate";
			res = qsc_hcg_generate_ex(&a, output_a, otplen, additional, addlen);
			res = qsc_hcg_generate_ex(&b, output_b, otplen, additional, addlen) && res;
			res = qsc_hcg_generate_ex(&c, output_c, otplen, mutated, mutlen) && res;
		}

		if (res == true)
		{
			phase = "determinism or mutation";
			res = qsc_memutils_are_equal(output_a, output_b, otplen);
			res = (qsc_memutils_are_equal(output_a, output_c, otplen) == false) && res;
			res = (output_a[otplen] == 0xA5U && output_b[otplen] == 0xA5U && output_c[otplen] == 0xA5U) && res;
			res = (a.reseed_counter == b.reseed_counter && a.generated_bytes == b.generated_bytes) && res;
		}

		if (res == true && (i % 3U) == 0U)
		{
			phase = "next generation";
			res = qsc_hcg_generate(&a, output_a, otplen);
			res = qsc_hcg_generate(&b, output_b, otplen) && res;
			res = qsc_memutils_are_equal(output_a, output_b, otplen) && res;
		}

		qsc_hcg_dispose(&a);
		qsc_hcg_dispose(&b);
		qsc_hcg_dispose(&c);

		if (res == false)
		{
			hcg_test_fuzz_failure(phase, i);
		}
	}

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 deterministic valid-input fuzz (256 cases).");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 deterministic valid-input fuzz.");
	}

	return res;
}

bool qsctest_hcg_invalid_fuzz(void)
{
	uint8_t entropy[QSC_HCG_SEED_SIZE] = { 0U };
	uint8_t output[4097U] = { 0U };
	qsc_hcg_state ctx = { 0U };
	qsc_hcg_state before = { 0U };
	uint32_t rng;
	size_t i;
	size_t length;
	const char* phase;
	bool res;

	rng = 0xD5E4831BU;
	phase = "instantiate";
	res = qsc_hcg_instantiate(&ctx, entropy, 32U, entropy + 32U, 16U, NULL, 0U);

	for (i = 0U; i < 256U && res == true; ++i)
	{
		length = 1U + (size_t)(hcg_test_next(&rng) % 4096U);
		qsc_memutils_copy(&before, &ctx, sizeof(before));
		qsc_memutils_set_value(output, sizeof(output), 0xA5U);

		if ((i % 4U) == 0U)
		{
			phase = "null additional input";
			res = (qsc_hcg_generate_ex(&ctx, output, length, NULL, 1U) == false);
			res = qsc_memutils_zeroed(output, length) && res;
			res = (output[length] == 0xA5U) && res;
		}
		else if ((i % 4U) == 1U)
		{
			phase = "short reseed entropy";
			res = (qsc_hcg_reseed(&ctx, entropy, 31U, NULL, 0U) == false);
			res = (output[0U] == 0xA5U && output[length] == 0xA5U) && res;
		}
		else if ((i % 4U) == 2U)
		{
			phase = "oversized additional input";
			res = (qsc_hcg_generate_ex(&ctx, output, length, entropy, QSC_HCG_MAX_INPUT_SIZE + 1U) == false);
			res = qsc_memutils_zeroed(output, length) && res;
			res = (output[length] == 0xA5U) && res;
		}
		else
		{
			phase = "oversized output request";
			res = (qsc_hcg_generate(&ctx, output, QSC_HCG_MAX_REQUEST_SIZE + 1U) == false);
			res = (output[0U] == 0xA5U && output[length] == 0xA5U) && res;
		}

		res = qsc_memutils_are_equal((const uint8_t*)&ctx, (const uint8_t*)&before, sizeof(ctx)) && res;

		if (res == false)
		{
			hcg_test_fuzz_failure(phase, i);
		}
	}

	qsc_hcg_dispose(&ctx);
	qsc_hcg_dispose(&before);

	if (res == true)
	{
		qsctest_print_line("[PASS] HCG SHA-512 malformed-request fuzz (256 cases).");
	}
	else
	{
		qsctest_print_line("[FAIL] HCG SHA-512 malformed-request fuzz.");
	}

	return res;
}

void qsctest_hcg_run(void)
{
	bool status;

	status = true;

	if (qsctest_hcg_basic_kat() == false)
	{
		status = false;
	}

	if (qsctest_hcg_additional_kat() == false)
	{
		status = false;
	}

	if (qsctest_hcg_reseed_kat() == false)
	{
		status = false;
	}

	if (qsctest_hcg_prediction_resistance_kat() == false)
	{
		status = false;
	}

	if (qsctest_hcg_boundaries() == false)
	{
		status = false;
	}

	if (qsctest_hcg_auto_seed() == false)
	{
		status = false;
	}

	if (qsctest_hcg_wellness() == false)
	{
		status = false;
	}

	if (qsctest_hcg_state_wellness() == false)
	{
		status = false;
	}

	if (qsctest_hcg_fuzz() == false)
	{
		status = false;
	}

	if (qsctest_hcg_invalid_fuzz() == false)
	{
		status = false;
	}

	if (status == true)
	{
		qsctest_print_line("Success! Passed all HCG SHA-512 KAT, wellness and fuzz tests.");
	}
	else
	{
		qsctest_print_line("Failure! HCG SHA-512 KAT, wellness or fuzz test failed.");
	}
}
