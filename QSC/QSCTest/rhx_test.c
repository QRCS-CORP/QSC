#include "rhx_test.h"
#include "../RHX/intutils.h"
#include "../RHX/sha2.h"
#include "../RHX/sha3.h"
#include "../RHX/csp.h"
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTR_OUTPUT_LENGTH 33
#define MONTE_CARLO_CYCLES 10000
#define HBA_TEST_CYCLES 100
#define RHX_TEST_CYCLES 100


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
		qsc_rhx_ctrbe_transform(&state, out, message[i], QSC_RHX_BLOCK_SIZE);

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
		qsc_rhx_ctrbe_transform(&state, out, expected[i], QSC_RHX_BLOCK_SIZE);

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
		qsc_rhx_ctrbe_transform(&state, out, message[i], QSC_RHX_BLOCK_SIZE);

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
		qsc_rhx_ctrbe_transform(&state, out, expected[i], QSC_RHX_BLOCK_SIZE);

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
			printf("\n");
		}

		printf("0x%02X, ", a[i]);
	}
}

static void print_array32(const uint32_t* a, size_t count, size_t line)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		if (i != 0 && i % line == 0)
		{
			printf("\n");
		}

		printf("%d ", a[i]);
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
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
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
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
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
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
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
	for (i = 0; i != MONTE_CARLO_CYCLES; ++i)
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

bool qsctest_fips_aes128_cbc()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F2.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("7649ABAC8119B246CEE98E9B12E9197D", exp[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("5086CB9B507219EE95DB113A917678B2", exp[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("73BED6B8E3C1743B7116E69E22229516", exp[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("3FF1CAA1681FAC09120ECA307586E1A7", exp[3], QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes128_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_fips_aes256_cbc()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F2.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6", exp[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("9CFC4E967EDB808D679F777BC6702C7D", exp[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("39F23369A9D9BACFA530E26304231461", exp[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("B2EB05E2C39BE9FCDA6C19078C6A9D1B", exp[3], QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes256_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_fips_aes128_ctr()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("874D6191B620E3261BEF6864990DB6CE", exp[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("9806F66B7970FDFF8617187BB9FFFDFF", exp[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("5AE4DF3EDBD5D35E5B4F09020DB03EAB", exp[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("1E031DDA2FBE03D1792170A0F3009CEE", exp[3], QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes128_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_fips_aes256_ctr()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("601EC313775789A5B7A7F504BBF3D228", exp[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F443E3CA4D62B59ACA84E990CACAF5C5", exp[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("2B0930DAA23DE94CE87017BA2D84988D", exp[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("DFC9C58DB67AADA613C2DD08457941A6", exp[3], QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes256_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_fips_aes128_ecb()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX_BLOCK_SIZE] = { 0 };

	/* SP800-38a F1.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("3AD77BB40D7A3660A89ECAF32466EF97", exp[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F5D3D58503B9699DE785895A96FDBAAF", exp[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("43B1CD7F598ECE23881B00E3ED030688", exp[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("7B0C785E27E8AD3F8223207104725DD4", exp[3], QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes128_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_fips_aes256_ecb()
{
	uint8_t exp[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };

	/* SP800-38a F1.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_RHX256_KEY_SIZE);

	qsctest_hex_to_bin("F3EED1BDB5D2A03C064B5A7E3DB181F8", exp[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("591CCB10D410ED26DC5BA74A31362870", exp[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("B6ED21B99CA6F4F9F153E7B1BEAFED1D", exp[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("23304B7A39F9F3FF067D8D8F9E24ECC7", exp[3], QSC_RHX_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_RHX_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_RHX_BLOCK_SIZE);

	return aes256_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_rhx256_cbc_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t ivcopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mlen;
	size_t elen;
	size_t outlen;
	size_t tctr;
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;
		outlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));

			if (mlen < QSC_RHX_BLOCK_SIZE)
			{
				mlen = 0;
			}
		}
		while (mlen == 0);

		elen = (mlen % QSC_RHX_BLOCK_SIZE) == 0 ? mlen : mlen + (QSC_RHX_BLOCK_SIZE - (mlen % QSC_RHX_BLOCK_SIZE));
		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(elen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, elen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and iv */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ivcopy, sizeof(ivcopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			memcpy(iv, ivcopy, sizeof(ivcopy));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), iv, NULL, 0 };

			/* encrypt the message */
			qsc_rhx_initialize(&state1, &kp1, true, RHX256);
			qsc_rhx_cbc_encrypt(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the iv */
			memcpy(iv, ivcopy, sizeof(ivcopy));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), iv, NULL, 0 };

			/* decrypt the message */
			qsc_rhx_initialize(&state2, &kp2, false, RHX256);
			qsc_rhx_cbc_decrypt(&state2, dec, &outlen, enc, elen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_cbc_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ivcopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mlen;
	size_t elen;
	size_t outlen;
	size_t tctr;
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;
		outlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));

			if (mlen < QSC_RHX_BLOCK_SIZE)
			{
				mlen = 0;
			}
		} 
		while (mlen == 0);

		elen = (mlen % QSC_RHX_BLOCK_SIZE) == 0 ? mlen : mlen + (QSC_RHX_BLOCK_SIZE - (mlen % QSC_RHX_BLOCK_SIZE));
		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(elen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, elen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and iv */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ivcopy, sizeof(ivcopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			memcpy(iv, ivcopy, sizeof(ivcopy));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), iv, NULL, 0 };

			/* encrypt the message */
			qsc_rhx_initialize(&state1, &kp1, true, RHX512);
			qsc_rhx_cbc_encrypt(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the iv */
			memcpy(iv, ivcopy, sizeof(ivcopy));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), iv, NULL, 0 };

			/* decrypt the message */
			qsc_rhx_initialize(&state2, &kp2, false, RHX512);
			qsc_rhx_cbc_decrypt(&state2, dec, &outlen, enc, elen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx256_ctr_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			qsc_rhx_initialize(&state1, &kp1, true, RHX256);

			/* encrypt the array */
			qsc_rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			qsc_rhx_initialize(&state2, &kp2, true, RHX256);

			/* test decryption by using ciphertest as input */
			qsc_rhx_ctrbe_transform(&state2, dec, enc, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_ctr_stress()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			qsc_rhx_initialize(&state1, &kp1, true, RHX512);

			/* encrypt the array */
			qsc_rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			qsc_rhx_initialize(&state2, &kp2, true, RHX512);

			/* test decryption by using ciphertest as input */
			qsc_rhx_ctrbe_transform(&state2, dec, enc, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

#if defined(WIDE_BLOCK_TESTS)

bool qsctest_rhx256_ctrbe_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			qsc_rhx_initialize(&state1, &kp1, true, RHX256);

			/* encrypt the array */
			qsc_rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			qsc_rhx_initialize(&state2, &kp2, true, RHX256);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = qsc_intutils_min(QSC_RHX_BLOCK_SIZE, mctr);
				qsc_rhx_ctrbe_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_ctrbe_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			qsc_rhx_initialize(&state1, &kp1, true, RHX512);

			/* encrypt the array */
			qsc_rhx_ctrbe_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			qsc_rhx_initialize(&state2, &kp2, true, RHX512);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = qsc_intutils_min(QSC_RHX_BLOCK_SIZE, mctr);
				qsc_rhx_ctrbe_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx256_ctrle_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			qsc_rhx_initialize(&state1, &kp1, true, RHX256);

			/* encrypt the array */
			qsc_rhx_ctrle_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			qsc_rhx_initialize(&state2, &kp2, true, RHX256);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = qsc_intutils_min(QSC_RHX_BLOCK_SIZE, mctr);
				qsc_rhx_ctrle_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

bool qsctest_rhx512_ctrle_wide_equality()
{
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t ncopy[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state state1;
	qsc_rhx_state state2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < RHX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen == 0);

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen);
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct, info is optional */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state */
			qsc_rhx_initialize(&state1, &kp1, true, RHX512);

			/* encrypt the array */
			qsc_rhx_ctrle_transform(&state1, enc, msg, mlen);

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rhx_keyparams kp2 = { key, sizeof(key), nonce, NULL, 0 };

			/* initialize the state; CTR mode is always initialized as encrypt equals true */
			qsc_rhx_initialize(&state2, &kp2, true, RHX512);

			/* decrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = qsc_intutils_min(QSC_RHX_BLOCK_SIZE, mctr);
				qsc_rhx_ctrle_transform(&state2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the round-key array and reset the state */
			qsc_rhx_dispose(&state2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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

#endif

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
#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsctest_hex_to_bin("B93AF9A0635964EE2DD1600A95C56905", exp, QSC_RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	qsctest_hex_to_bin("356FE2F76E8954C8292C4FE4EFD52A2C", exp, QSC_RHX_BLOCK_SIZE);
#endif

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

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
#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsctest_hex_to_bin("4F9D61042EC51DADAB25F081A3E79AF1", exp, QSC_RHX_BLOCK_SIZE);
#else
	/* HKDF extension */
	qsctest_hex_to_bin("C23E5C88453124D46B81D7229C6A409F", exp, QSC_RHX_BLOCK_SIZE);
#endif

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX512_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

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

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX256_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsctest_hex_to_bin("6DED2973243BCD846C4D98C1BF636FB3", exp, QSC_RHX_BLOCK_SIZE);
#else
	qsctest_hex_to_bin("C4E3D76961144D5F1BAC6C0DE5078597", exp, QSC_RHX_BLOCK_SIZE);
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

	qsctest_hex_to_bin("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386", key, QSC_RHX512_KEY_SIZE);
	qsctest_hex_to_bin("00000000000000000000000000000000", msg, QSC_RHX_BLOCK_SIZE);

#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsctest_hex_to_bin("FB8977B80F5B0B7C2E4048DF590EB2F6", exp, QSC_RHX_BLOCK_SIZE);
#else
	qsctest_hex_to_bin("3CC3EB49D4328762000EB0D6DB3924E1", exp, QSC_RHX_BLOCK_SIZE);
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
	qsctest_hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	qsctest_hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	qsctest_hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#if defined(QSC_HBA_KMAC_AUTH)
	qsctest_hex_to_bin("D1B1C7A44B0360C5B32F36865ABE458023175AA63B8F049D3256E14AE28319D8B5704C4DAE9BECFEEC6DC90F4290CA50", exp1, sizeof(exp1));
	qsctest_hex_to_bin("72266262C11A694A022786517D1222C644FEAD9ECF3C15C5914989BFCD54A6C23286294733E95E8E53E0D405339EBAF9906B498B7B6489DEE62AF84A6073E5E3", exp2, sizeof(exp2));
	qsctest_hex_to_bin("1B593A4FD95A25ED8EA645199BB5A442E110CF2177C7209D5D3C2DE9FAAFCE5225B8E933B7611B89005FB5C0880E33A0E7FC77B9BE73611F94E6A431473B440F"
		"D44E6FA650CFF592073B9B915727BF6A5D380C40DA5F46808E2E787AB974BCBA", exp3, sizeof(exp3));
#else
	qsctest_hex_to_bin("3196573F11BDE0E265BCDA83836062B676AEFC22DA61C488DC2585B36DB5B6A9430263A14393C1EA38ED5281EAFABC94", exp1, sizeof(exp1));
	qsctest_hex_to_bin("5654C0DD29C2DDAF228D6B135133927FAF440C356CAA2A14AF3BC907B20D5AA4AEFB348484F4D4D6A5AC545C790EB99A3BF3FF3E533703A07632B108B811B1C8", exp2, sizeof(exp2));
	qsctest_hex_to_bin("58EE8ED312CECC334CDD4065282E1D129884D265B841F87173E133EEE2FEC531C1AEC335567F1D0AF5DA85993B8A86385A5827AB0B563C5153C3DFA6097FA48E"
		"C9FBEAD189BC77072BDA2D510FF166B3C5E0BB9C3A1DD3EBB5459361BD0D8ED3", exp3, sizeof(exp3));
#endif
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsctest_hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	qsctest_hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	qsctest_hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	qsctest_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	qsctest_hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	qsctest_hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

	status = true;
	memcpy(n1copy, nce1, QSC_RHX_BLOCK_SIZE);
	memcpy(n2copy, nce2, QSC_RHX_BLOCK_SIZE);
	memcpy(n3copy, nce3, QSC_RHX_BLOCK_SIZE);

	/* first KAT vector */

	qsc_rhx_hba256_state state;

	const qsc_rhx_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0 };

	qsc_rhx_hba256_initialize(&state, &kp1, true);
	qsc_rhx_hba256_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_rhx_hba256_transform(&state, enc1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp1.nonce, n1copy, QSC_RHX_BLOCK_SIZE);

	qsc_rhx_hba256_initialize(&state, &kp1, false);
	qsc_rhx_hba256_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_rhx_hba256_transform(&state, dec1, enc1, sizeof(enc1) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const qsc_rhx_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0 };
	qsc_rhx_hba256_initialize(&state, &kp2, true);
	qsc_rhx_hba256_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_rhx_hba256_transform(&state, enc2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp2.nonce, n2copy, QSC_RHX_BLOCK_SIZE);

	qsc_rhx_hba256_initialize(&state, &kp2, false);
	qsc_rhx_hba256_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_rhx_hba256_transform(&state, dec2, enc2, sizeof(enc2) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const qsc_rhx_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0 };
	qsc_rhx_hba256_initialize(&state, &kp3, true);
	qsc_rhx_hba256_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_rhx_hba256_transform(&state, enc3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp3.nonce, n3copy, QSC_RHX_BLOCK_SIZE);

	qsc_rhx_hba256_initialize(&state, &kp3, false);
	qsc_rhx_hba256_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_rhx_hba256_transform(&state, dec3, enc3, sizeof(enc3) - QSC_HBA256_MAC_LENGTH) == false)
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
	qsctest_hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	qsctest_hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	qsctest_hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#if defined(QSC_HBA_KMAC_AUTH)
	qsctest_hex_to_bin("3445EEABB15B39077D7A6FB7E7055FE49435BCA7CEAC9A834698FD26D60214AC4BC2146F9BD943044FAF62FA2185736D1CA3E09132C99604F620D000BE22331A"
		"23A4BD7D4C62EBF155EE63994C185976", exp1, sizeof(exp1));
	qsctest_hex_to_bin("8238DFB8B88897E4C92490148AAFDB224127D53C84736E9124DDB0899662358B311AFF28414E352CEE8DB1D0FE4D956E01CA37CAF4EB3AE72D0939CE0FCD9279"
		"9AC66DDCEA05F84DFB59A5AA804C4703BAC8F7B93527C3943B01FFCD48050120", exp2, sizeof(exp2));
	qsctest_hex_to_bin("2CDC038A38D27F58B38AA2130D1AA61D3C837DC2BF645D8379813A7C05B98DD6E3C5844840F12E6AC1D7483C714D8FAF5DD0849C1E6CDE208BE7BA83F12762DC"
		"2F9E1D7C10CBCA7338590E98E190A7F025B8AE1B03B731DC98BEB572E30F674E88F3099932ED7BA7EC20CBA8EEE11166109596CBCC76BA23D32B7A8CF65D0D80", exp3, sizeof(exp3));
#else
	qsctest_hex_to_bin("E6A77A113818FA8B56B834C3DCC48DF644566AB1E7D2887A3237BB66AD64DC2D85434BA39178EEDDB5A74063666FE3160E1E609D743CD1020A3403611EC20650"
		"30C29A27F13003F58FBE1A3DE1393C4B", exp1, sizeof(exp1));
	qsctest_hex_to_bin("9C00C33391FED7C439295DB6D9F6CC895867F904DFD4705225CC1585C87990A76D2012B322E49A138066780F345EFAC118B87BC610CA6649E2168F284A8F63B0"
		"8CEDFC79C03DA00ECBFE651366DE59DB5DA4859F5846F4CEDD057285F4657C9D", exp2, sizeof(exp2));
	qsctest_hex_to_bin("BC4B2C1333F04897B68FF8E60F7742A7F7320B478C0D11E95972F5FD78F3029EE8F27D11E66BD0C3543D56EE6F3962D6E749CA1F9C424AED232337A72BB766FD"
		"BADFB673AF27B237F7857B83E03BCEA7DBEF6C24C166811C6C9AD486792782037A1AC8F20863BB7ADA44C98AC9446D466D1EA1F14B4A69DF52E7DA2628C84345", exp3, sizeof(exp3));
#endif
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsctest_hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	qsctest_hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	qsctest_hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	qsctest_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	qsctest_hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	qsctest_hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

	status = true;
	memcpy(n1copy, nce1, QSC_RHX_BLOCK_SIZE);
	memcpy(n2copy, nce2, QSC_RHX_BLOCK_SIZE);
	memcpy(n3copy, nce3, QSC_RHX_BLOCK_SIZE);

	/* first KAT vector */

	qsc_rhx_hba512_state state;

	const qsc_rhx_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0 };

	qsc_rhx_hba512_initialize(&state, &kp1, true);
	qsc_rhx_hba512_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_rhx_hba512_transform(&state, enc1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp1.nonce, n1copy, QSC_RHX_BLOCK_SIZE);

	qsc_rhx_hba512_initialize(&state, &kp1, false);
	qsc_rhx_hba512_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_rhx_hba512_transform(&state, dec1, enc1, sizeof(enc1) - QSC_HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const qsc_rhx_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0 };
	qsc_rhx_hba512_initialize(&state, &kp2, true);
	qsc_rhx_hba512_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_rhx_hba512_transform(&state, enc2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp2.nonce, n2copy, QSC_RHX_BLOCK_SIZE);

	qsc_rhx_hba512_initialize(&state, &kp2, false);
	qsc_rhx_hba512_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_rhx_hba512_transform(&state, dec2, enc2, sizeof(enc2) - QSC_HBA512_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const qsc_rhx_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0 };
	qsc_rhx_hba512_initialize(&state, &kp3, true);
	qsc_rhx_hba512_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_rhx_hba512_transform(&state, enc3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	memcpy(kp3.nonce, n3copy, QSC_RHX_BLOCK_SIZE);

	qsc_rhx_hba512_initialize(&state, &kp3, false);
	qsc_rhx_hba512_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_rhx_hba512_transform(&state, dec3, enc3, sizeof(enc3) - QSC_HBA512_MAC_LENGTH) == false)
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
	qsc_rhx_hba256_state state;

	/* vectors from CEX */
	qsctest_hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad, sizeof(aad));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsctest_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", ncopy, sizeof(ncopy));

	tctr = 0;
	status = true;

	while (tctr < HBA_TEST_CYCLES)
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
			qsc_rhx_hba256_initialize(&state, &kp1, true);
			qsc_rhx_hba256_set_associated(&state, aad, sizeof(aad));

			if (qsc_rhx_hba256_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, QSC_RHX_BLOCK_SIZE);

			/* decrypt the message */
			qsc_rhx_hba256_initialize(&state, &kp1, false);
			qsc_rhx_hba256_set_associated(&state, aad, sizeof(aad));

			if (qsc_rhx_hba256_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
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
	qsc_rhx_hba512_state state;

	/* vectors from CEX */
	qsctest_hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad, sizeof(aad));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsctest_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", ncopy, sizeof(ncopy));

	tctr = 0;
	status = true;

	while (tctr < HBA_TEST_CYCLES)
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
			qsc_rhx_hba512_initialize(&state, &kp1, true);
			qsc_rhx_hba512_set_associated(&state, aad, sizeof(aad));

			if (qsc_rhx_hba512_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, QSC_RHX_BLOCK_SIZE);

			/* decrypt the message */
			qsc_rhx_hba512_initialize(&state, &kp1, false);
			qsc_rhx_hba512_set_associated(&state, aad, sizeof(aad));

			if (qsc_rhx_hba512_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
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

void qsctest_aes_run()
{
	if (qsctest_fips_aes128_cbc() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CBC(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CBC(AES-128) CBC KAT test. \n");
	}

	if (qsctest_fips_aes256_cbc() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CBC(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CBC(AES-256) CBC KAT test. \n");
	}

	if (qsctest_fips_aes128_ctr() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CTR(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CTR(AES-128) KAT test. \n");
	}

	if (qsctest_fips_aes256_ctr() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 CTR(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 CTR(AES-256) KAT test. \n");
	}

	if (qsctest_fips_aes128_ecb() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 ECB(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 ECB(AES-128) KAT test. \n");
	}

	if (qsctest_fips_aes256_ecb() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 ECB(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 ECB(AES-256) KAT test. \n");
	}
}

void qsctest_rhx_run()
{
	if (qsctest_rhx256_ecb_kat() == true)
	{
		qsctest_print_safe("Success! Passed the ECB(RHX-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECB(RHX-256) KAT test. \n");
	}

	if (qsctest_rhx512_ecb_kat() == true)
	{
		qsctest_print_safe("Success! Passed the ECB(RHX-512) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECB(RHX-512) KAT test. \n");
	}

	if (qsctest_rhx256_cbc_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CBC(RHX-256) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CBC(RHX-256) stress test. \n");
	}

	if (qsctest_rhx512_cbc_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CBC(RHX-512) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CBC(RHX-512) stress test. \n");
	}

	if (qsctest_rhx256_ctr_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CTR(RHX-256) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR(RHX-256) stress test. \n");
	}

	if (qsctest_rhx512_ctr_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CTR(RHX-512) stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR(RHX-512) stress test. \n");
	}

#if defined(WIDE_BLOCK_TESTS)

	if (qsctest_rhx256_ctrbe_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-BE(RHX-256) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-BE(RHX-256) AVX512 equality test. \n");
	}

	if (qsctest_rhx512_ctrbe_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-BE(RHX-512) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-BE(RHX-512) AVX512 equality test. \n");
	}

	if (qsctest_rhx256_ctrle_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-LE(RHX-256) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-LE(RHX-256) AVX512 equality test. \n");
	}

	if (qsctest_rhx512_ctrle_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CTR-LE(RHX-512) AVX512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CTR-LE(RHX-512) AVX512 equality test. \n");
	}

#endif

	if (qsctest_rhx256_monte_carlo() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-256 Monte Carlo test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-256 Monte Carlo test. \n");
	}

	if (qsctest_rhx512_monte_carlo() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-512 Monte Carlo test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-512 Monte Carlo test. \n");
	}

	if (qsctest_hba_rhx256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-256 HBA AEAD mode KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-256 HBA AEAD mode KAT test. \n");
	}

	if (qsctest_hba_rhx512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-512 HBA AEAD mode KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-512 HBA AEAD mode KAT test. \n");
	}

	if (qsctest_hba_rhx256_stress() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-256 HBA AEAD mode stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-256 HBA AEAD mode stress test. \n");
	}

	if (qsctest_hba_rhx512_stress() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-512 HBA AEAD mode stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-512 HBA AEAD mode stress test. \n");
	}
}
