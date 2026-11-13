#include "csg_test.h"
#include "csg.h"
#include "intutils.h"
#include "memutils.h"
#include "qsctestcommon.h"
#include "sha3.h"
#include "testutils.h"

static uint32_t csg_test_next(uint32_t* state)
{
	uint32_t x;

	x = *state;
	x ^= x << 13U;
	x ^= x >> 17U;
	x ^= x << 5U;
	*state = x;

	return x;
}

static void csg_test_failure(const char* phase, size_t index)
{
	qsctest_print_safe("[FAIL] CSG XDRBG fuzz mismatch at ");
	qsctest_print_safe(phase);
	qsctest_print_safe(" (case ");
	qsctest_print_ulong((uint64_t)index);
	qsctest_print_line("");
}

bool qsctest_csg_author_kat(void)
{
	uint8_t input[QSC_CSG_STATE_SIZE + 1U] = { 0U };
	uint8_t state[QSC_CSG_STATE_SIZE] = { 0U };
	uint8_t sample[QSC_CSG_STATE_SIZE + 32U] = { 0U };
	uint8_t expected_state[QSC_CSG_STATE_SIZE] = { 0U };
	uint8_t expected_output[32U] = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < 9U; ++i)
	{
		input[i] = (uint8_t)i;
	}

	/* Instantiate: seed || byte(0). */
	qsc_shake256_compute(state, sizeof(state), input, 10U);
	qsctest_hex_to_bin("7d53858aa0f74d9cff5209e923b12c1060763bb6cffc255d17b1c9a0d0353d75881dddcf2a546dcd0a676f5765ea7cb48c2751bb2240c7216ce14211c36f4d0b", expected_state, sizeof(expected_state));
	res = qsc_memutils_are_equal(state, expected_state, sizeof(state));

	/* Generate: V || byte(170); first 64 bytes form the next state. */
	qsc_memutils_copy(input, state, sizeof(state));
	input[QSC_CSG_STATE_SIZE] = 170U;
	qsc_shake256_compute(sample, sizeof(sample), input, sizeof(input));
	qsctest_hex_to_bin("1ad2cb763c716df0792cc0697d566a65b836be7d09127c6547fc3058aa243952", expected_output, sizeof(expected_output));
	res = qsc_memutils_are_equal(sample + QSC_CSG_STATE_SIZE, expected_output, sizeof(expected_output)) && res;

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG published author SHAKE-256 KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG published author SHAKE-256 KAT.");
	}

	qsc_memutils_secure_erase(input, sizeof(input));
	qsc_memutils_secure_erase(state, sizeof(state));
	qsc_memutils_secure_erase(sample, sizeof(sample));

	return res;
}

bool qsctest_csg_generate_kat(void)
{
	uint8_t seed[48U] = { 0U };
	uint8_t expected[32U] = { 0U };
	uint8_t output[32U] = { 0U };
	uint8_t value[QSC_CSG_STATE_SIZE] = { 0U };
	qsc_csg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	res = qsc_csg_instantiate(&ctx, seed, sizeof(seed), NULL, 0U);
	qsctest_hex_to_bin("9ef877fddbe8891c6e4e79eaf022e563defaca6b152161b9a423e8fe96a403e774b2d352cf74c934069c9de74757f505aaf9baf4ae72c4c9b48efd574140a7bc", value, sizeof(value));
	res = qsc_memutils_are_equal(ctx.value, value, sizeof(value)) && res;

	qsctest_hex_to_bin("6ca71751f16b1cae6bb896b7ef716306b1e6062967d0f8399b76738d473befe7", expected, sizeof(expected));
	res = qsc_csg_generate_ex(&ctx, output, sizeof(output), NULL, 0U) && res;
	res = qsc_memutils_are_equal(output, expected, sizeof(output)) && res;
	qsctest_hex_to_bin("ab81e08ce92d9423f7fa558681a39d74202f6ef788c882e36aa816d306c64f7c037c523bcce7286e2cba7e6bcd61dd06e2159cfd4f696092b5516b18269a4523", value, sizeof(value));
	res = qsc_memutils_are_equal(ctx.value, value, sizeof(value)) && res;

	qsctest_hex_to_bin("ff3ffaf9a677331361ebd4a7c8abfc320c318971d8a2b3e5f642de79f5e1e90b", expected, sizeof(expected));
	res = qsc_csg_generate_ex(&ctx, output, sizeof(output), NULL, 0U) && res;
	res = qsc_memutils_are_equal(output, expected, sizeof(output)) && res;
	qsctest_hex_to_bin("fb5eea084de14879c8493c4fbaa2a8d83b5b1878685dd3bc1be689125a06a13f687331f650c8377c2d21e03a41861ddcde3bbf777f82c6442db1265088bed5d9", value, sizeof(value));
	res = qsc_memutils_are_equal(ctx.value, value, sizeof(value)) && res;
	res = (ctx.reseed_counter == 3U) && res;

	qsc_csg_dispose(&ctx);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG instantiate and successive Generate KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG instantiate and successive Generate KAT.");
	}

	return res;
}

/** \brief Verify candidate state transitions with personalization, additional input, and reseeding.
 * \return True if independently generated states and outputs match.
 */
bool qsctest_csg_reseed_kat(void)
{
	uint8_t seed[48U] = { 0U };
	uint8_t reseed[32U] = { 0U };
	uint8_t personal[16U] = { 0U };
	uint8_t extra[16U] = { 0U };
	uint8_t rextra[8U] = { 0U };
	uint8_t output[64U] = { 0U };
	uint8_t expected[64U] = { 0U };
	uint8_t value[QSC_CSG_STATE_SIZE] = { 0U };
	qsc_csg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (i = 0U; i < sizeof(reseed); ++i)
	{
		reseed[i] = (uint8_t)(0x80U + i);
	}

	for (i = 0U; i < sizeof(personal); ++i)
	{
		personal[i] = (uint8_t)(0xC0U + i);
		extra[i] = (uint8_t)i;
	}

	for (i = 0U; i < sizeof(rextra); ++i)
	{
		rextra[i] = (uint8_t)(0xF0U + i);
	}

	res = qsc_csg_instantiate(&ctx, seed, sizeof(seed), personal, sizeof(personal));
	qsctest_hex_to_bin("cd9c84bc51dc18327a63706836c42629d855114939194e0ce58a5954a41e6555efea8902ff43e45e67650320459b9eef5e850a54adc2b8afee252433ac962f51", value, sizeof(value));
	res = qsc_memutils_are_equal(ctx.value, value, sizeof(value)) && res;

	qsctest_hex_to_bin("8ea74ba28ee51a250fed79a98d1b2dceeb32390d1cde91decffefb36a9f0671e7d6e4c42b329eee6ff4c445e9fef66b385dab9124b8d4375094f4b4b1ddbc6e4", expected, sizeof(expected));
	res = qsc_csg_generate_ex(&ctx, output, sizeof(output), extra, sizeof(extra)) && res;
	res = qsc_memutils_are_equal(output, expected, sizeof(output)) && res;
	qsctest_hex_to_bin("c89ba73d61f989ce64c0fc27a172a692b929343a42937ed8ab1b5f3b7aa62cabcf8a1e0699237c74cd5f706724c16afb55f9b18204c553529725e997df070d86", value, sizeof(value));
	res = qsc_memutils_are_equal(ctx.value, value, sizeof(value)) && res;

	res = qsc_csg_reseed(&ctx, reseed, sizeof(reseed), rextra, sizeof(rextra)) && res;
	qsctest_hex_to_bin("029d40f1aa311bee76a2ab73ca38594ad1f01deb4c4484547457084f4c0199a3b289298fd733a8c083fd81b3d2b55bc257640e63280492bc16632f3e071701b8", value, sizeof(value));
	res = qsc_memutils_are_equal(ctx.value, value, sizeof(value)) && res;
	res = (ctx.reseed_counter == 1U && ctx.generated_bytes == 0U) && res;

	qsctest_hex_to_bin("c7cc0bffabeef369fc947a2f10c53c46835037c6000878eb6686e0e8051f9de5303da9441641b96e64c239ca3ede542f1294a43e07ba3c95fd49345c7d962318", expected, sizeof(expected));
	res = qsc_csg_generate_ex(&ctx, output, sizeof(output), extra, sizeof(rextra)) && res;
	res = qsc_memutils_are_equal(output, expected, sizeof(output)) && res;
	qsctest_hex_to_bin("533c769d540860c552bec1f206a67a3dbe56922eafa9b2a4bd9376fbbefd111b757c19745fe3a775b32eea385ca30c955e374e76cc128c9c592de2f7169a3e1a", value, sizeof(value));
	res = qsc_memutils_are_equal(ctx.value, value, sizeof(value)) && res;

	qsc_csg_dispose(&ctx);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG personalization and reseeding KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG personalization and reseeding KAT.");
	}

	return res;
}

bool qsctest_csg_maximum_kat(void)
{
	uint8_t seed[64U] = { 0U };
	uint8_t extra[QSC_CSG_MAX_ADDITIONAL_SIZE] = { 0U };
	uint8_t expected[QSC_CSG_MAX_REQUEST_SIZE] = { 0U };
	uint8_t output[QSC_CSG_MAX_REQUEST_SIZE] = { 0U };
	qsc_csg_state ctx = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (i = 0U; i < sizeof(extra); ++i)
	{
		extra[i] = (uint8_t)i;
	}

	qsctest_hex_to_bin("e93643229150b1a1f5024a29d25d327beae10fe01f9d88bf72b3b7703414f968822465766d9acb4c4c90f974d415030e"
		"2a783c9fa5a7fe3117b5eaed41143a84cf4ab495d173ac1f28575ce51cb26adda3a33f1cc124e401f1d058777a18ec30"
		"7a38a5b38757cd33a8a7ad9d99fb84310c404aff3238a3b3145bb137e09b334cc7d6768fc26a5509ea4efa067a799db4"
		"a0186c5efdd1dca9eeccdf234590d1bc74edd058c75d9c564b67572d73c573c60e45c0dfac178e1067fdd2161aef0e70"
		"fb45cacd804d660d1593259bde2da7dac768edf223e3fdd386c17364401ac4970bf7e627d51e9bd8526b9320b01f5004"
		"99fbe185c4a4f80cc91ff8f1bcc2a93b8d186c8357d33a026dd71c028490b184b0a7021843e5e0fb5a5d5e98aaac0c02"
		"a9a9ebecffc72c4096b4c3f03ce41df706bcc802b44e5e223b16fda0c04f2a774424362be5119a84fdbf097f4f38b76e"
		"a08071ec6d62ff5b", expected, sizeof(expected));
	res = qsc_csg_instantiate(&ctx, seed, sizeof(seed), extra, sizeof(extra));
	res = qsc_csg_generate_ex(&ctx, output, sizeof(output), extra, sizeof(extra)) && res;
	res = qsc_memutils_are_equal(output, expected, sizeof(output)) && res;
	qsc_csg_dispose(&ctx);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG maximum encoding and output KAT.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG maximum encoding and output KAT.");
	}

	return res;
}

bool qsctest_csg_boundaries(void)
{
	uint8_t seed[64U] = { 0U };
	uint8_t extra[85U] = { 0U };
	uint8_t output[QSC_CSG_MAX_REQUEST_SIZE + 1U] = { 0U };
	qsc_csg_state ctx = { 0U };
	qsc_csg_state before = { 0U };
	bool res;

	res = (qsc_csg_instantiate(&ctx, seed, 32U, NULL, 0U) == false);
	res = (ctx.initialized == false) && res;
	res = qsc_csg_instantiate(&ctx, seed, 48U, NULL, 0U) && res;
	qsc_memutils_copy(&before, &ctx, sizeof(before));
	res = (qsc_csg_generate_ex(&ctx, output, sizeof(output), NULL, 0U) == false) && res;
	res = qsc_memutils_are_equal((const uint8_t*)&ctx, (const uint8_t*)&before, sizeof(ctx)) && res;
	res = (qsc_csg_generate_ex(&ctx, output, 16U, extra, 85U) == false) && res;
	res = qsc_memutils_are_equal((const uint8_t*)&ctx, (const uint8_t*)&before, sizeof(ctx)) && res;
	res = (qsc_csg_reseed(&ctx, seed, 31U, NULL, 0U) == false) && res;
	res = qsc_memutils_are_equal((const uint8_t*)&ctx, (const uint8_t*)&before, sizeof(ctx)) && res;
	res = (qsc_csg_reseed(&ctx, seed, 32U, extra, 85U) == false) && res;
	res = qsc_memutils_are_equal((const uint8_t*)&ctx, (const uint8_t*)&before, sizeof(ctx)) && res;
	ctx.reseed_counter = QSC_CSG_RESEED_INTERVAL + 1U;
	res = (qsc_csg_generate_ex(&ctx, output, 16U, NULL, 0U) == false) && res;
	res = (ctx.initialized == true && ctx.reseed_counter > QSC_CSG_RESEED_INTERVAL) && res;
	res = qsc_csg_reseed(&ctx, seed, 32U, NULL, 0U) && res;
	res = (ctx.reseed_counter == 1U && ctx.legacy_seed == false) && res;
	qsc_csg_dispose(&ctx);
	res = qsc_memutils_zeroed(&ctx, sizeof(ctx)) && res;

	qsc_csg_initialize(&ctx, seed, 32U, NULL, 0U, false);
	res = (ctx.initialized == true && ctx.legacy_seed == true) && res;
	res = qsc_csg_generate(&ctx, output, sizeof(output)) && res;
	qsc_csg_dispose(&ctx);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG strict limits, erasure, legacy compatibility.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG strict limits, erasure, legacy compatibility.");
	}

	return res;
}

bool qsctest_csg_auto_seed(void)
{
	uint8_t output[64U] = { 0U };
	qsc_csg_state ctx = { 0U };
	bool res;

	res = qsc_csg_initialize_auto(&ctx, NULL, 0U, false);

	if (res == true)
	{
		res = (ctx.initialized == true && ctx.auto_reseed == true) && res;
		ctx.generated_bytes = QSC_CSG_RESEED_THRESHOLD;
		res = qsc_csg_generate_ex(&ctx, output, sizeof(output), NULL, 0U) && res;
		res = (ctx.reseed_counter == 2U && ctx.generated_bytes == sizeof(output)) && res;
	}

	qsc_csg_dispose(&ctx);
	res = qsc_csg_initialize_auto(&ctx, NULL, 0U, true) && res;

	if (res == true)
	{
		res = qsc_csg_generate_ex(&ctx, output, sizeof(output), NULL, 0U) && res;
		res = (ctx.reseed_counter == 2U && ctx.pres == true) && res;
	}

	qsc_csg_dispose(&ctx);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG ACP auto-seeding, reseeding and PR.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG ACP auto-seeding, reseeding and PR.");
	}

	return res;
}

bool qsctest_csg_wellness(void)
{
	uint8_t seed[48U] = { 0U };
	uint8_t output[4096U] = { 0U };
	qsc_csg_state ctx = { 0U };
	size_t bitcount;
	size_t i;
	size_t j;
	bool res;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	res = qsc_csg_instantiate(&ctx, seed, sizeof(seed), NULL, 0U);
	res = qsc_csg_generate(&ctx, output, sizeof(output)) && res;
	res = (ctx.reseed_counter > 2U) && res;
	res = (qsc_memutils_zeroed(output, sizeof(output)) == false) && res;
	bitcount = 0U;

	for (i = 0U; i < sizeof(output); ++i)
	{
		for (j = 0U; j < 8U; ++j)
		{
			bitcount += (size_t)((output[i] >> j) & 1U);
		}
	}

	res = (bitcount > 13000U && bitcount < 19700U) && res;
	res = (qsc_memutils_are_equal(output, output + 64U, 64U) == false) && res;
	qsc_csg_dispose(&ctx);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG output and state wellness checks.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG output and state wellness checks.");
	}

	return res;
}

bool qsctest_csg_fuzz(void)
{
	uint8_t seed[48U] = { 0U };
	uint8_t reseed[32U] = { 0U };
	uint8_t additional[QSC_CSG_MAX_ADDITIONAL_SIZE] = { 0U };
	uint8_t a[QSC_CSG_MAX_REQUEST_SIZE] = { 0U };
	uint8_t b[QSC_CSG_MAX_REQUEST_SIZE] = { 0U };
	qsc_csg_state ctxa = { 0U };
	qsc_csg_state ctxb = { 0U };
	uint32_t rng;
	size_t i;
	size_t j;
	size_t length;
	size_t addlen;
	bool res;

	rng = 0x92C701E3U;
	res = true;

	for (j = 0U; j < sizeof(seed); ++j)
	{
		seed[j] = (uint8_t)csg_test_next(&rng);
	}

	res = qsc_csg_instantiate(&ctxa, seed, sizeof(seed), NULL, 0U) && res;
	res = qsc_csg_instantiate(&ctxb, seed, sizeof(seed), NULL, 0U) && res;

	for (i = 0U; i < 256U && res == true; ++i)
	{
		length = 1U + (size_t)(csg_test_next(&rng) % QSC_CSG_MAX_REQUEST_SIZE);
		addlen = (size_t)(csg_test_next(&rng) % (QSC_CSG_MAX_ADDITIONAL_SIZE + 1U));

		for (j = 0U; j < addlen; ++j)
		{
			additional[j] = (uint8_t)csg_test_next(&rng);
		}

		res = qsc_csg_generate_ex(&ctxa, a, length, additional, addlen) && res;
		res = qsc_csg_generate_ex(&ctxb, b, length, additional, addlen) && res;
		res = qsc_memutils_are_equal(a, b, length) && res;
		res = qsc_memutils_are_equal((const uint8_t*)&ctxa, (const uint8_t*)&ctxb, sizeof(ctxa)) && res;

		if ((i % 17U) == 0U && res == true)
		{
			for (j = 0U; j < sizeof(reseed); ++j)
			{
				reseed[j] = (uint8_t)csg_test_next(&rng);
			}

			res = qsc_csg_reseed(&ctxa, reseed, sizeof(reseed), additional, addlen) && res;
			res = qsc_csg_reseed(&ctxb, reseed, sizeof(reseed), additional, addlen) && res;
		}

		if (res == false)
		{
			csg_test_failure("valid-input state progression", i);
		}
	}

	qsc_csg_dispose(&ctxa);
	qsc_csg_dispose(&ctxb);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG valid-input deterministic fuzz (256 cases).");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG valid-input deterministic fuzz.");
	}

	return res;
}

/** \brief Fuzz malformed Generate/reseed requests without advancing DRBG state.
 * \return True if all 256 invalid requests are rejected without state mutation.
 */
bool qsctest_csg_invalid_fuzz(void)
{
	uint8_t seed[48U] = { 0U };
	uint8_t output[QSC_CSG_MAX_REQUEST_SIZE + 2U] = { 0U };
	uint8_t additional[85U] = { 0U };
	qsc_csg_state ctx = { 0U };
	qsc_csg_state before = { 0U };
	uint32_t rng;
	size_t i;
	size_t length;
	bool res;

	rng = 0x6CC2EA55U;
	res = qsc_csg_instantiate(&ctx, seed, sizeof(seed), NULL, 0U);

	for (i = 0U; i < 256U && res == true; ++i)
	{
		length = 1U + (size_t)(csg_test_next(&rng) % QSC_CSG_MAX_REQUEST_SIZE);
		qsc_memutils_copy(&before, &ctx, sizeof(before));
		qsc_memutils_set_value(output, sizeof(output), 0xA5U);

		if ((i % 4U) == 0U)
		{
			res = (qsc_csg_generate_ex(&ctx, output, length, NULL, 1U) == false);
			res = (output[length] == 0xA5U) && res;
		}
		else if ((i % 4U) == 1U)
		{
			res = (qsc_csg_reseed(&ctx, seed, 31U, NULL, 0U) == false);
			res = (output[0U] == 0xA5U) && res;
		}
		else if ((i % 4U) == 2U)
		{
			res = (qsc_csg_generate_ex(&ctx, output, length, additional, 85U) == false);
			res = (output[length] == 0xA5U) && res;
		}
		else
		{
			res = (qsc_csg_generate_ex(&ctx, output, QSC_CSG_MAX_REQUEST_SIZE + 1U, NULL, 0U) == false);
			res = (output[sizeof(output) - 1U] == 0xA5U) && res;
		}

		res = qsc_memutils_are_equal((const uint8_t*)&ctx, (const uint8_t*)&before, sizeof(ctx)) && res;

		if (res == false)
		{
			csg_test_failure("invalid-input state preservation", i);
		}
	}

	qsc_csg_dispose(&ctx);
	qsc_csg_dispose(&before);

	if (res == true)
	{
		qsctest_print_line("[PASS] CSG XDRBG malformed-request fuzz (256 cases).");
	}
	else
	{
		qsctest_print_line("[FAIL] CSG XDRBG malformed-request fuzz.");
	}

	return res;
}

void qsctest_csg_run(void)
{
	bool status;

	status = true;

	if (qsctest_csg_author_kat() == false)
	{
		status = false;
	}

	if (qsctest_csg_generate_kat() == false)
	{
		status = false;
	}

	if (qsctest_csg_reseed_kat() == false)
	{
		status = false;
	}

	if (qsctest_csg_maximum_kat() == false)
	{
		status = false;
	}

	if (qsctest_csg_boundaries() == false)
	{
		status = false;
	}

	if (qsctest_csg_auto_seed() == false)
	{
		status = false;
	}

	if (qsctest_csg_wellness() == false)
	{
		status = false;
	}

	if (qsctest_csg_fuzz() == false)
	{
		status = false;
	}

	if (qsctest_csg_invalid_fuzz() == false)
	{
		status = false;
	}

	if (status == true)
	{
		qsctest_print_line("Success! Passed all CSG XDRBG-SHAKE-256 provisional tests.");
	}
	else
	{
		qsctest_print_line("Failure! CSG XDRBG-SHAKE-256 provisional tests failed.");
	}
}
