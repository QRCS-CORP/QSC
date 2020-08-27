#include "rhx_test.h"
#include "../QSC/intutils.h"
#include "../QSC/rhx.h"
#include "../QSC/sha2.h"
#include "../QSC/sha3.h"
#include "../QSC/csp.h"
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef QSC_SYSTEM_AESNI_ENABLED
#	if defined(_MSC_VER)
#		include <intrin.h>
#	elif defined(__GNUC__)
#		include <x86intrin.h>
#	endif
#endif

static bool aes128_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][QSC_RHX_BLOCK_SIZE], const uint8_t expected[4][QSC_RHX_BLOCK_SIZE])
{
	uint8_t ivc[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t expf[4 * QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t inpf[4 * QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t outf[4 * QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	/* copy iv to local */
	memcpy(ivc, iv, QSC_RHX_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const qsc_rhx_keyparams kp = { key, QSC_AES128_KEY_SIZE, ivc };

	status = true;

	/* test the simplified api */

	/* copy split message and expected arrays to full input */
	for (i = 0; i < 4; ++i)
	{
		memcpy(inpf + (i * QSC_RHX_BLOCK_SIZE), message[i], QSC_RHX_BLOCK_SIZE);
		memcpy(expf + (i * QSC_RHX_BLOCK_SIZE), expected[i], QSC_RHX_BLOCK_SIZE);
	}

	/* initialize the state */
	qsc_rhx_initialize(&state, &kp, true, AES128);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_cbc_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the iv and test the cbc decryption function */
	memcpy(kp.nonce, iv, QSC_RHX_BLOCK_SIZE);
	qsc_rhx_initialize(&state, &kp, false, AES128);

	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_cbc_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

static bool aes256_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][QSC_RHX_BLOCK_SIZE], const uint8_t expected[4][QSC_RHX_BLOCK_SIZE])
{
	uint8_t ivc[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	memcpy(ivc, iv, QSC_RHX_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const qsc_rhx_keyparams kp = { key, QSC_AES256_KEY_SIZE, ivc };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, AES256);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_cbc_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the iv and test decryption */
	memcpy(ivc, iv, QSC_RHX_BLOCK_SIZE);
	qsc_rhx_initialize(&state, &kp, false, AES256);

	/* test the cbc decryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_cbc_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

static bool aes128_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t message[4][QSC_RHX_BLOCK_SIZE], const uint8_t expected[4][QSC_RHX_BLOCK_SIZE])
{
	uint8_t nce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct with key and nonce, info not used in AES */
	memcpy(nce, nonce, QSC_RHX_BLOCK_SIZE);
	const qsc_rhx_keyparams kp = { key, QSC_AES128_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, AES128);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ctr_transform(&state, out, message[i], QSC_RHX_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	memcpy(state.nonce, nonce, QSC_RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	qsc_rhx_initialize(&state, &kp, true, AES128);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ctr_transform(&state, out, expected[i], QSC_RHX_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, message[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

static bool aes256_ctr_monte_carlo(uint8_t* key, const uint8_t* nonce, const uint8_t message[4][QSC_RHX_BLOCK_SIZE], const uint8_t expected[4][QSC_RHX_BLOCK_SIZE])
{
	uint8_t nce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct with key and nonce, info is optional */
	memcpy(nce, nonce, QSC_RHX_BLOCK_SIZE);
	qsc_rhx_keyparams kp = { key, QSC_AES256_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, AES256);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ctr_transform(&state, out, message[i], QSC_RHX_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	memcpy(state.nonce, nonce, QSC_RHX_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	qsc_rhx_initialize(&state, &kp, true, AES256);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ctr_transform(&state, out, expected[i], QSC_RHX_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, message[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

static bool aes128_ecb_monte_carlo(uint8_t* key, const uint8_t message[4][QSC_RHX_BLOCK_SIZE], const uint8_t expected[4][QSC_RHX_BLOCK_SIZE])
{
	uint8_t out[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_AES128_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, AES128);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ecb_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state */
	qsc_rhx_initialize(&state, &kp, false, AES128);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ecb_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

static bool aes256_ecb_monte_carlo(uint8_t* key, const uint8_t message[4][QSC_RHX_BLOCK_SIZE], const uint8_t expected[4][QSC_RHX_BLOCK_SIZE])
{
	uint8_t out[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_AES256_KEY_SIZE };
	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, AES256);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ecb_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state  */
	qsc_rhx_initialize(&state, &kp, false, AES256);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_rhx_ecb_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_RHX_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

static void print_array8(const uint8_t* a, size_t count, size_t line)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		if (i != 0 && i % line == 0)
		{
			printf_s("\n");
		}

		printf_s("0x%02X, ", a[i]);
	}
}

static void print_array32(const uint32_t* a, size_t count, size_t line)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		if (i != 0 && i % line == 0)
		{
			printf_s("\n");
		}

		printf_s("%d ", a[i]);
	}
}

static bool rhx256_ecb_monte_carlo(uint8_t* key, const uint8_t* message, const uint8_t* expected)
{
	uint8_t dec[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_RHX256_KEY_SIZE };

	memcpy(msg, message, QSC_RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, RHX256);

	/* test the ecb encryption function */
	for (i = 0; i != QSCTEST_MONTE_CARLO_CYCLES; ++i)
	{
		qsc_rhx_ecb_encrypt_block(&state, enc, msg);
		memcpy(msg, enc, QSC_RHX_BLOCK_SIZE);
	}

	if (qsc_intutils_are_equal8(expected, enc, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	qsc_rhx_initialize(&state, &kp, false, RHX256);

	/* test the ecb decryption function */
	for (i = 0; i != QSCTEST_MONTE_CARLO_CYCLES; ++i)
	{
		qsc_rhx_ecb_decrypt_block(&state, msg, enc);
		memcpy(enc, msg, QSC_RHX_BLOCK_SIZE);
	}

	if (qsc_intutils_are_equal8(message, msg, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

static bool rhx512_ecb_monte_carlo(uint8_t* key, const uint8_t* message, const uint8_t* expected)
{
	uint8_t dec[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_RHX512_KEY_SIZE };

	memcpy(msg, message, QSC_RHX_BLOCK_SIZE);
	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, RHX512);

	/* test the ecb encryption function */
	for (i = 0; i != QSCTEST_MONTE_CARLO_CYCLES; ++i)
	{
		qsc_rhx_ecb_encrypt_block(&state, enc, msg);
		memcpy(msg, enc, QSC_RHX_BLOCK_SIZE);
	}

	if (qsc_intutils_are_equal8(expected, enc, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	qsc_rhx_initialize(&state, &kp, false, RHX512);

	/* test the ecb decryption function */
	for (i = 0; i != QSCTEST_MONTE_CARLO_CYCLES; ++i)
	{
		qsc_rhx_ecb_decrypt_block(&state, msg, enc);
		memcpy(enc, msg, QSC_RHX_BLOCK_SIZE);
	}

	if (qsc_intutils_are_equal8(message, msg, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

bool qsctest_aes128_cbc_fips()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F2.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_RHX_BLOCK_SIZE);
	hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_RHX_BLOCK_SIZE);

	hex_to_bin("7649ABAC8119B246CEE98E9B12E9197D", exp[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("5086CB9B507219EE95DB113A917678B2", exp[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("73BED6B8E3C1743B7116E69E22229516", exp[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("3FF1CAA1681FAC09120ECA307586E1A7", exp[3], QSC_RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes128_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_aes256_cbc_fips()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F2.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_RHX256_KEY_SIZE);
	hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_RHX_BLOCK_SIZE);

	hex_to_bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6", exp[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("9CFC4E967EDB808D679F777BC6702C7D", exp[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("39F23369A9D9BACFA530E26304231461", exp[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("B2EB05E2C39BE9FCDA6C19078C6A9D1B", exp[3], QSC_RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes256_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_aes128_ctr_fips()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_RHX_BLOCK_SIZE);

	hex_to_bin("874D6191B620E3261BEF6864990DB6CE", exp[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("9806F66B7970FDFF8617187BB9FFFDFF", exp[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("5AE4DF3EDBD5D35E5B4F09020DB03EAB", exp[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("1E031DDA2FBE03D1792170A0F3009CEE", exp[3], QSC_RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes128_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_aes256_ctr_fips()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_RHX256_KEY_SIZE);
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_RHX_BLOCK_SIZE);

	hex_to_bin("601EC313775789A5B7A7F504BBF3D228", exp[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F443E3CA4D62B59ACA84E990CACAF5C5", exp[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("2B0930DAA23DE94CE87017BA2D84988D", exp[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("DFC9C58DB67AADA613C2DD08457941A6", exp[3], QSC_RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes256_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_aes128_ecb_fips()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F1.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_RHX_BLOCK_SIZE);

	hex_to_bin("3AD77BB40D7A3660A89ECAF32466EF97", exp[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F5D3D58503B9699DE785895A96FDBAAF", exp[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("43B1CD7F598ECE23881B00E3ED030688", exp[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("7B0C785E27E8AD3F8223207104725DD4", exp[3], QSC_RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes128_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_aes256_ecb_fips()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F1.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_RHX256_KEY_SIZE);

	hex_to_bin("F3EED1BDB5D2A03C064B5A7E3DB181F8", exp[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("591CCB10D410ED26DC5BA74A31362870", exp[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("B6ED21B99CA6F4F9F153E7B1BEAFED1D", exp[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("23304B7A39F9F3FF067D8D8F9E24ECC7", exp[3], QSC_RHX_BLOCK_SIZE);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes256_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_rhx256_ctr_stress()
{
	uint8_t dec[QSCTEST_CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t enc[QSCTEST_CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 1 };
	uint8_t msg[QSCTEST_CTR_OUTPUT_LENGTH] = { 128 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_RHX256_KEY_SIZE, nonce, NULL, 0 };

	status = true;

	/* initialize the state */
	qsc_rhx_initialize(&state, &kp, true, RHX256);

	/* encrypt the array */
	qsc_rhx_ctr_transform(&state, enc, msg, QSCTEST_CTR_OUTPUT_LENGTH);

	/* reset the nonce */
	memset(state.nonce, 0x00, QSC_RHX_BLOCK_SIZE);

	/* initialize the state; CTR mode is always initialized as encrypt equals true */
	qsc_rhx_initialize(&state, &kp, true, RHX256);

	/* test decryption by using ciphertest as input */
	qsc_rhx_ctr_transform(&state, dec, enc, QSCTEST_CTR_OUTPUT_LENGTH);

	if (qsc_intutils_are_equal8(dec, msg, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

bool qsctest_rhx512_ctr_stress()
{
	uint8_t dec[QSCTEST_CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t enc[QSCTEST_CTR_OUTPUT_LENGTH] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 1 };
	uint8_t msg[QSCTEST_CTR_OUTPUT_LENGTH] = { 128 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	bool status;
	qsc_rhx_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_RHX512_KEY_SIZE, nonce, NULL, 0 };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, RHX512);

	/* encrypt the array */
	qsc_rhx_ctr_transform(&state, enc, msg, QSCTEST_CTR_OUTPUT_LENGTH);

	/* reset the nonce */
	memset(state.nonce, 0x00, QSC_RHX_BLOCK_SIZE);

	/* initialize the state; CTR mode is always initialized as encrypt equals true */
	qsc_rhx_initialize(&state, &kp, true, RHX512);

	/* test decryption by using ciphertest as input */
	qsc_rhx_ctr_transform(&state, dec, enc, QSCTEST_CTR_OUTPUT_LENGTH);

	if (qsc_intutils_are_equal8(dec, msg, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

bool qsctest_rhx256_ecb_kat()
{
	uint8_t dec[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t otp[QSC_RHX_BLOCK_SIZE] = { 0 };
	bool status;
	qsc_rhx_state state;

	/* vectors from CEX */
#ifdef QSC_RHX_SHAKE_EXTENSION
	hex_to_bin("B93AF9A0635964EE2DD1600A95C56905", exp, QSC_RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("356FE2F76E8954C8292C4FE4EFD52A2C", exp, QSC_RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX256_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_RHX256_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, RHX256);

	/* test encryption */
	qsc_rhx_ecb_encrypt_block(&state, otp, msg);

	if (qsc_intutils_are_equal8(otp, exp, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state */
	qsc_rhx_initialize(&state, &kp, false, RHX256);

	/* test decryption */
	qsc_rhx_ecb_decrypt_block(&state, dec, otp);

	if (qsc_intutils_are_equal8(dec, msg, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

bool qsctest_rhx512_ecb_kat()
{
	uint8_t dec[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t otp[QSC_RHX_BLOCK_SIZE] = { 0 };
	bool status;
	qsc_rhx_state state;

	/* vectors from CEX */
#ifdef QSC_RHX_SHAKE_EXTENSION
	hex_to_bin("4F9D61042EC51DADAB25F081A3E79AF1", exp, QSC_RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	hex_to_bin("C23E5C88453124D46B81D7229C6A409F", exp, QSC_RHX_BLOCK_SIZE);
#endif

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX512_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { key, QSC_RHX512_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rhx_initialize(&state, &kp, true, RHX512);

	/* test encryption */
	qsc_rhx_ecb_encrypt_block(&state, otp, msg);

	if (qsc_intutils_are_equal8(otp, exp, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* initialize the state for encryption */
	qsc_rhx_initialize(&state, &kp, false, RHX512);

	/* test decryption */
	qsc_rhx_ecb_decrypt_block(&state, dec, otp);

	if (qsc_intutils_are_equal8(dec, msg, QSC_RHX_BLOCK_SIZE) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_rhx_dispose(&state);

	return status;
}

bool qsctest_rhx256_monte_carlo()
{
	uint8_t exp[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[QSC_RHX_BLOCK_SIZE] = { 0 };
	bool status;

	/* original vectors */

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX256_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

#ifdef QSC_RHX_SHAKE_EXTENSION
	hex_to_bin("6DED2973243BCD846C4D98C1BF636FB3", exp, QSC_RHX_BLOCK_SIZE);
#else
	hex_to_bin("C4E3D76961144D5F1BAC6C0DE5078597", exp, QSC_RHX_BLOCK_SIZE);
#endif

	status = rhx256_ecb_monte_carlo(key, msg, exp);

	return status;
}

bool qsctest_rhx512_monte_carlo()
{
	uint8_t exp[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[QSC_RHX_BLOCK_SIZE] = { 0 };
	bool status;

	/* original vectors */

	hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX512_KEY_SIZE);
	hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

#ifdef QSC_RHX_SHAKE_EXTENSION
	hex_to_bin("FB8977B80F5B0B7C2E4048DF590EB2F6", exp, QSC_RHX_BLOCK_SIZE);
#else
	hex_to_bin("3CC3EB49D4328762000EB0D6DB3924E1", exp, QSC_RHX_BLOCK_SIZE);
#endif

	status = rhx512_ecb_monte_carlo(key, msg, exp);

	return status;
}

bool qsctest_hba_rhx256_kat()
{
	uint8_t aad1[20] = { 0 };
	uint8_t aad2[20] = { 0 };
	uint8_t aad3[20] = { 0 };
	uint8_t dec1[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec2[QSC_RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t dec3[QSC_RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t exp1[QSC_RHX_BLOCK_SIZE + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t exp2[(QSC_RHX_BLOCK_SIZE * 2) + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t exp3[(QSC_RHX_BLOCK_SIZE * 4) + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg1[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg2[QSC_RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t msg3[QSC_RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t nce1[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce2[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce3[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t n1copy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t n2copy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t n3copy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc1[QSC_RHX_BLOCK_SIZE + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t enc2[(QSC_RHX_BLOCK_SIZE * 2) + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t enc3[(QSC_RHX_BLOCK_SIZE * 4) + QSC_HBA256_MAC_LENGTH] = { 0 };
	bool status;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#ifdef QSC_HBA_KMAC_AUTH
	hex_to_bin("D1B1C7A44B0360C5B32F36865ABE458023175AA63B8F049D3256E14AE28319D8B5704C4DAE9BECFEEC6DC90F4290CA50", exp1, sizeof(exp1));
	hex_to_bin("72266262C11A694A022786517D1222C693EDB6D3F8FB4BD557D7DDEFB11AFC9E3FD3A186C91928B4641B5F7306FC3870831D62BC870667A243A46CEAE418DC35", exp2, sizeof(exp2));
	hex_to_bin("1B593A4FD95A25ED8EA645199BB5A4421F3B371354B83F78F1D97F42B882CBA2B245B310890BCE02AB5E86745837B447FED07B28F812FD16A8B32D9B65996E95"
		"F0C9C030776AC405E87C0E8D61DB7B70A4D24F0B301CBA7445D9FF4DBF75B598", exp3, sizeof(exp3));
#else
	hex_to_bin("2FC12BD6A4C0E6C8B6460A8AD6E3A751AD1A07E84E8EA48C85D235E5D8588DA88C511E2D9803FB2EE9512DC82578C765", exp1, sizeof(exp1));
	hex_to_bin("F905E342002A902C2F0EAAE6342292279C1D8780EAC682F5C0F7F92BA9BFAF6E402FA3E736ED76548B0A1BF2D58E201F448370906EAD11BC5D27B19EEC637DE4", exp2, sizeof(exp2));
	hex_to_bin("E71C0802B27B73EA162E507D2CC351D3B19A1C592D47A862CA90341CE2EA2C71B4A9F28769426F14E4D2C6427C7650195795E7C34BFFBB31F8832B79447B0015"
		"F939B976B33FF47AFDA3F83A73B28B7F27EBB66EE3C2A8397202D1A2E288A553", exp3, sizeof(exp3));
#endif
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

	status = true;
	memcpy(n1copy, nce1, QSC_RHX_BLOCK_SIZE);
	memcpy(n2copy, nce2, QSC_RHX_BLOCK_SIZE);
	memcpy(n3copy, nce3, QSC_RHX_BLOCK_SIZE);

	/* first KAT vector */

	qsc_hba_state state;

	const qsc_rhx_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0 };

	qsc_hba_rhx256_initialize(&state, &kp1, true);
	qsc_hba_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_hba_rhx256_transform(&state, enc1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp1.nonce, n1copy, QSC_RHX_BLOCK_SIZE);

	qsc_hba_rhx256_initialize(&state, &kp1, false);
	qsc_hba_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_hba_rhx256_transform(&state, dec1, enc1, sizeof(enc1) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const qsc_rhx_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0 };
	qsc_hba_rhx256_initialize(&state, &kp2, true);
	qsc_hba_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_hba_rhx256_transform(&state, enc2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp2.nonce, n2copy, QSC_RHX_BLOCK_SIZE);

	qsc_hba_rhx256_initialize(&state, &kp2, false);
	qsc_hba_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_hba_rhx256_transform(&state, dec2, enc2, sizeof(enc2) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const qsc_rhx_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0 };
	qsc_hba_rhx256_initialize(&state, &kp3, true);
	qsc_hba_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_hba_rhx256_transform(&state, enc3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp3.nonce, n3copy, QSC_RHX_BLOCK_SIZE);

	qsc_hba_rhx256_initialize(&state, &kp3, false);
	qsc_hba_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_hba_rhx256_transform(&state, dec3, enc3, sizeof(enc3) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	return status;
}

bool qsctest_hba_rhx512_kat()
{
	uint8_t aad1[20] = { 0 };
	uint8_t aad2[20] = { 0 };
	uint8_t aad3[20] = { 0 };
	uint8_t dec1[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t dec2[QSC_RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t dec3[QSC_RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t exp1[QSC_RHX_BLOCK_SIZE + QSC_HBA512_MAC_LENGTH] = { 0 };
	uint8_t exp2[(QSC_RHX_BLOCK_SIZE * 2) + QSC_HBA512_MAC_LENGTH] = { 0 };
	uint8_t exp3[(QSC_RHX_BLOCK_SIZE * 4) + QSC_HBA512_MAC_LENGTH] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg1[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg2[QSC_RHX_BLOCK_SIZE * 2] = { 0 };
	uint8_t msg3[QSC_RHX_BLOCK_SIZE * 4] = { 0 };
	uint8_t nce1[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce2[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nce3[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t n1copy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t n2copy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t n3copy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t enc1[QSC_RHX_BLOCK_SIZE + QSC_HBA512_MAC_LENGTH] = { 0 };
	uint8_t enc2[(QSC_RHX_BLOCK_SIZE * 2) + QSC_HBA512_MAC_LENGTH] = { 0 };
	uint8_t enc3[(QSC_RHX_BLOCK_SIZE * 4) + QSC_HBA512_MAC_LENGTH] = { 0 };
	bool status;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#ifdef QSC_HBA_KMAC_AUTH
	hex_to_bin("3445EEABB15B39077D7A6FB7E7055FE49435BCA7CEAC9A834698FD26D60214AC4BC2146F9BD943044FAF62FA2185736D1CA3E09132C99604F620D000BE22331A"
		"23A4BD7D4C62EBF155EE63994C185976", exp1, sizeof(exp1));
	hex_to_bin("8238DFB8B88897E4C92490148AAFDB22C824FB1C7BD443FA0510D45BDFDFEC2EE89F3B64D4FF5FC5EC66FF81EAD38ADF73D45AE4E6D604FF8CE6FC7801805B3E"
		"2101B8E403B6516A95AA9650524B1E94E6850A2E886099EF87CAF0D783482F3E", exp2, sizeof(exp2));
	hex_to_bin("2CDC038A38D27F58B38AA2130D1AA61D525DD09ABCCCBBD7B45FB40851626482555B352F57B2913EFD722E2A4A3E525CD053C90B1DF89B212A0226D2BE3F7D77"
		"83B37EC9E7DF54B4538BCF45EFCB4C5FC6D941154468894D15F1D2FE9216938768D388F9FACCF1BECAB4418BFC68F67C0CF800F438A3FF9BCA1F24166F772319", exp3, sizeof(exp3));
#else
	hex_to_bin("84F2B6F882E63894ABA11DC69CCFF2E5F49A083459B0210B3C7E5CF9FF099E78389294F9936CFDDD6BDD31513F69C0AABF2E6A714A9547CCB3347B3944C8CBA0"
		"DF7F24AC4B107738E601886FE27AA20E", exp1, sizeof(exp1));
	hex_to_bin("84F547ECA80F39410F913EC877C1B8C53858A933C74C1F2011EF755CD97307A4339C1E42E6A93377101540B51C9CF585F33E04F779EB7FA06C1D2D6AC3166A0F"
		"7C5BC0EE36FCA7C69DA799B2E308EF8362C74EBEFFFBACE4D0AE7D0778C1242C", exp2, sizeof(exp2));
	hex_to_bin("3DC9E0B3539CF48827B5E9F0F789256E51083EDCF697D7277ADD38754BB5E23D5614425612B2ECF7B46E0E9D9D82853385D5E89191238BFB766D076260BB1613"
		"C67C6AB107988892FA1A255A0DBA710FB49C2F485F1ACBC968D5D39D94C4990FED9284E62FF306ECC87FB8DE4C762F359B3D6B46686F2DB15C44B82C43BDFBCE", exp3, sizeof(exp3));
#endif
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

	status = true;
	memcpy(n1copy, nce1, QSC_RHX_BLOCK_SIZE);
	memcpy(n2copy, nce2, QSC_RHX_BLOCK_SIZE);
	memcpy(n3copy, nce3, QSC_RHX_BLOCK_SIZE);

	/* first KAT vector */

	qsc_hba_state state;

	const qsc_rhx_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0 };

	qsc_hba_rhx512_initialize(&state, &kp1, true);
	qsc_hba_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_hba_rhx512_transform(&state, enc1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp1.nonce, n1copy, QSC_RHX_BLOCK_SIZE);

	qsc_hba_rhx512_initialize(&state, &kp1, false);
	qsc_hba_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_hba_rhx512_transform(&state, dec1, enc1, sizeof(enc1) - QSC_HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const qsc_rhx_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0 };
	qsc_hba_rhx512_initialize(&state, &kp2, true);
	qsc_hba_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_hba_rhx512_transform(&state, enc2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp2.nonce, n2copy, QSC_RHX_BLOCK_SIZE);

	qsc_hba_rhx512_initialize(&state, &kp2, false);
	qsc_hba_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_hba_rhx512_transform(&state, dec2, enc2, sizeof(enc2) - QSC_HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const qsc_rhx_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0 };
	qsc_hba_rhx512_initialize(&state, &kp3, true);
	qsc_hba_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_hba_rhx512_transform(&state, enc3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp3.nonce, n3copy, QSC_RHX_BLOCK_SIZE);

	qsc_hba_rhx512_initialize(&state, &kp3, false);
	qsc_hba_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_hba_rhx512_transform(&state, dec3, enc3, sizeof(enc3) - QSC_HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	return status;
}

bool qsctest_hba_rhx256_stress()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	qsc_hba_state state;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad, sizeof(aad));
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", ncopy, sizeof(ncopy));

	tctr = 0;
	status = true;

	while (tctr < QSCTEST_HBA_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen + QSC_HBA256_MAC_LENGTH);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen + QSC_HBA256_MAC_LENGTH);
			qsc_intutils_clear8(msg, mlen);
			memcpy(nonce, ncopy, QSC_RHX_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			qsc_hba_rhx256_initialize(&state, &kp1, true);
			qsc_hba_set_associated(&state, aad, sizeof(aad));

			if (qsc_hba_rhx256_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, QSC_RHX_BLOCK_SIZE);

			/* decrypt the message */
			qsc_hba_rhx256_initialize(&state, &kp1, false);
			qsc_hba_set_associated(&state, aad, sizeof(aad));

			if (qsc_hba_rhx256_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}


			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, sizeof(msg)) == false)
			{
				status = false;
			}

			free(dec);
			free(enc);
			free(msg);

			++tctr;
		}
		else
		{
			status = false;
			break;
		}
	}

	return status;
}

bool qsctest_hba_rhx512_stress()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	qsc_hba_state state;

	/* vectors from CEX */
	hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad, sizeof(aad));
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", ncopy, sizeof(ncopy));

	tctr = 0;
	status = true;

	while (tctr < QSCTEST_HBA_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen + QSC_HBA512_MAC_LENGTH);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen + QSC_HBA512_MAC_LENGTH);
			qsc_intutils_clear8(msg, mlen);
			memcpy(nonce, ncopy, QSC_RHX_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			qsc_hba_rhx512_initialize(&state, &kp1, true);
			qsc_hba_set_associated(&state, aad, sizeof(aad));

			if (qsc_hba_rhx512_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, QSC_RHX_BLOCK_SIZE);

			/* decrypt the message */
			qsc_hba_rhx512_initialize(&state, &kp1, false);
			qsc_hba_set_associated(&state, aad, sizeof(aad));

			if (qsc_hba_rhx512_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}


			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, sizeof(msg)) == false)
			{
				status = false;
			}

			free(dec);
			free(enc);
			free(msg);

			++tctr;
		}
		else
		{
			status = false;
			break;
		}
	}

	return status;
}

void qsctest_rhx_run()
{
	if (qsctest_aes128_cbc_fips() == true)
	{
		printf_s("Success! Passed the FIPS 197 CBC(AES-128) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the FIPS 197 CBC(AES-128) CBC KAT test. \n");
	}

	if (qsctest_aes256_cbc_fips() == true)
	{
		printf_s("Success! Passed the FIPS 197 CBC(AES-256) CBC KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the FIPS 197 CBC(AES-256) CBC KAT test. \n");
	}

	if (qsctest_aes128_ctr_fips() == true)
	{
		printf_s("Success! Passed the FIPS 197 CTR(AES-128) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the FIPS 197 CTR(AES-128) KAT test. \n");
	}

	if (qsctest_aes256_ctr_fips() == true)
	{
		printf_s("Success! Passed the FIPS 197 CTR(AES-256) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the FIPS 197 CTR(AES-256) KAT test. \n");
	}

	if (qsctest_aes128_ecb_fips() == true)
	{
		printf_s("Success! Passed the FIPS 197 ECB(AES-128) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the FIPS 197 ECB(AES-128) KAT test. \n");
	}

	if (qsctest_aes256_ecb_fips() == true)
	{
		printf_s("Success! Passed the FIPS 197 ECB(AES-256) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the FIPS 197 ECB(AES-256) KAT test. \n");
	}

	if (qsctest_rhx256_ecb_kat() == true)
	{
		printf_s("Success! Passed the ECB(RHX-256) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the ECB(RHX-256) KAT test. \n");
	}

	if (qsctest_rhx512_ecb_kat() == true)
	{
		printf_s("Success! Passed the ECB(RHX-512) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the ECB(RHX-512) KAT test. \n");
	}

	if (qsctest_rhx256_ctr_stress() == true)
	{
		printf_s("Success! Passed the CTR(RHX-256) stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the CTR(RHX-256) stress test. \n");
	}

	if (qsctest_rhx512_ctr_stress() == true)
	{
		printf_s("Success! Passed the CTR(RHX-512) stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the CTR(RHX-512) stress test. \n");
	}

	if (qsctest_rhx256_monte_carlo() == true)
	{
		printf_s("Success! Passed the RHX-256 Monte Carlo test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX-256 Monte Carlo test. \n");
	}

	if (qsctest_rhx512_monte_carlo() == true)
	{
		printf_s("Success! Passed the RHX-512 Monte Carlo test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX-512 Monte Carlo test. \n");
	}

	if (qsctest_hba_rhx256_kat() == true)
	{
		printf_s("Success! Passed the RHX-256 HBA AEAD mode KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX-256 HBA AEAD mode KAT test. \n");
	}

	if (qsctest_hba_rhx512_kat() == true)
	{
		printf_s("Success! Passed the RHX-512 HBA AEAD mode KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX-512 HBA AEAD mode KAT test. \n");
	}
	if (qsctest_hba_rhx256_stress() == true)
	{
		printf_s("Success! Passed the RHX-256 HBA AEAD mode stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX-256 HBA AEAD mode stress test. \n");
	}

	if (qsctest_hba_rhx512_stress() == true)
	{
		printf_s("Success! Passed the RHX-512 HBA AEAD mode stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RHX-512 HBA AEAD mode stress test. \n");
	}
}
