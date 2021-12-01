#include "selftest.h"
#include "aes.h"
#include "chacha.h"
#include "consoleutils.h"
#include "csp.h"
#include "csx.h"
#include "intutils.h"
#include "memutils.h"
#include "poly1305.h"
#include "rcs.h"
#include "sha2.h"
#include "sha3.h"
#include <stdio.h>

/*** AES ***/

static bool aes128_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][16], const uint8_t expected[4][16])
{
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t expf[4 * QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t inpf[4 * QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* copy iv to local */
	qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE, ivc };

	status = true;

	/* test the simplified api */

	/* copy split message and expected arrays to full input */
	for (i = 0; i < 4; ++i)
	{
		qsc_memutils_copy(inpf + (i * QSC_AES_BLOCK_SIZE), message[i], QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy(expf + (i * QSC_AES_BLOCK_SIZE), expected[i], QSC_AES_BLOCK_SIZE);
	}

	/* initialize the state */
	qsc_aes_initialize(&state, &kp, true, AES128);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_cbc_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the iv and test the cbc decryption function */
	qsc_memutils_copy(kp.nonce, iv, QSC_AES_BLOCK_SIZE);
	qsc_aes_initialize(&state, &kp, false, AES128);

	for (i = 0; i < 4; ++i)
	{
		qsc_aes_cbc_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_aes_dispose(&state);

	return status;
}

static bool aes256_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][16], const uint8_t expected[4][16])
{
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, ivc };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_aes_initialize(&state, &kp, true, AES256);

	/* test the cbc encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_cbc_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the iv and test decryption */
	qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
	qsc_aes_initialize(&state, &kp, false, AES256);

	/* test the cbc decryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_cbc_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_aes_dispose(&state);

	return status;
}

static bool aes128_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t message[4][16], const uint8_t expected[4][16])
{
	uint8_t nce[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* initialize the key parameters struct with key and nonce, info not used in AES */
	qsc_memutils_copy(nce, nonce, QSC_AES_BLOCK_SIZE);
	const qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	qsc_aes_initialize(&state, &kp, true, AES128);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ctrbe_transform(&state, out, message[i], QSC_AES_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	qsc_memutils_copy(state.nonce, nonce, QSC_AES_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	qsc_aes_initialize(&state, &kp, true, AES128);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ctrbe_transform(&state, out, expected[i], QSC_AES_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, message[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_aes_dispose(&state);

	return status;
}

static bool aes256_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t message[4][16], const uint8_t expected[4][16])
{
	uint8_t nce[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* initialize the key parameters struct with key and nonce, info is optional */
	qsc_memutils_copy(nce, nonce, QSC_AES_BLOCK_SIZE);
	qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE, nce };
	status = true;

	/* initialize the state and create the round-keys */
	qsc_aes_initialize(&state, &kp, true, AES256);

	/* test the ctr encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ctrbe_transform(&state, out, message[i], QSC_AES_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* reset the nonce */
	qsc_memutils_copy(state.nonce, nonce, QSC_AES_BLOCK_SIZE);

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	qsc_aes_initialize(&state, &kp, true, AES256);

	/* test the ctr decryption */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ctrbe_transform(&state, out, expected[i], QSC_AES_BLOCK_SIZE);

		if (qsc_intutils_are_equal8(out, message[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_aes_dispose(&state);

	return status;
}

static bool aes128_ecb_monte_carlo(const uint8_t* key, const uint8_t message[4][16], const uint8_t expected[4][16])
{
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_aes_keyparams kp = { key, QSC_AES128_KEY_SIZE };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_aes_initialize(&state, &kp, true, AES128);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ecb_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state */
	qsc_aes_initialize(&state, &kp, false, AES128);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ecb_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_aes_dispose(&state);

	return status;
}

static bool aes256_ecb_monte_carlo(const uint8_t* key, const uint8_t message[4][16], const uint8_t expected[4][16])
{
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_aes_keyparams kp = { key, QSC_AES256_KEY_SIZE };
	status = true;

	/* initialize the state and create the round-keys */
	qsc_aes_initialize(&state, &kp, true, AES256);

	/* test the ecb encryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ecb_encrypt_block(&state, out, message[i]);

		if (qsc_intutils_are_equal8(out, expected[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* initialize the state  */
	qsc_aes_initialize(&state, &kp, false, AES256);

	/* test the ecb decryption function */
	for (i = 0; i < 4; ++i)
	{
		qsc_aes_ecb_decrypt_block(&state, out, expected[i]);

		if (qsc_intutils_are_equal8(out, message[i], QSC_AES_BLOCK_SIZE) == false)
		{
			status = false;
		}
	}

	/* erase the round-key array and reset the state */
	qsc_aes_dispose(&state);

	return status;
}

static bool fips_aes128_cbc()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F2.1 */

	qsc_consoleutils_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("7649ABAC8119B246CEE98E9B12E9197D", exp[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("5086CB9B507219EE95DB113A917678B2", exp[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("73BED6B8E3C1743B7116E69E22229516", exp[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("3FF1CAA1681FAC09120ECA307586E1A7", exp[3], QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes128_cbc_monte_carlo(key, iv, msg, exp);
}

static bool fips_aes256_cbc()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };

	/* SP800-38a F2.5 */

	qsc_consoleutils_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_AES256_KEY_SIZE);
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6", exp[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("9CFC4E967EDB808D679F777BC6702C7D", exp[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("39F23369A9D9BACFA530E26304231461", exp[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("B2EB05E2C39BE9FCDA6C19078C6A9D1B", exp[3], QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes256_cbc_monte_carlo(key, iv, msg, exp);
}

static bool fips_aes128_ctr()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.1 */

	qsc_consoleutils_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("874D6191B620E3261BEF6864990DB6CE", exp[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("9806F66B7970FDFF8617187BB9FFFDFF", exp[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("5AE4DF3EDBD5D35E5B4F09020DB03EAB", exp[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("1E031DDA2FBE03D1792170A0F3009CEE", exp[3], QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes128_ctr_monte_carlo(key, nonce, msg, exp);
}

static bool fips_aes256_ctr()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.5 */

	qsc_consoleutils_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_AES256_KEY_SIZE);
	qsc_consoleutils_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("601EC313775789A5B7A7F504BBF3D228", exp[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F443E3CA4D62B59ACA84E990CACAF5C5", exp[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("2B0930DAA23DE94CE87017BA2D84988D", exp[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("DFC9C58DB67AADA613C2DD08457941A6", exp[3], QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes256_ctr_monte_carlo(key, nonce, msg, exp);
}

static bool fips_aes128_ecb()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F1.1 */

	qsc_consoleutils_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("3AD77BB40D7A3660A89ECAF32466EF97", exp[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F5D3D58503B9699DE785895A96FDBAAF", exp[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("43B1CD7F598ECE23881B00E3ED030688", exp[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("7B0C785E27E8AD3F8223207104725DD4", exp[3], QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes128_ecb_monte_carlo(key, msg, exp);
}

static bool fips_aes256_ecb()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };

	/* SP800-38a F1.5 */

	qsc_consoleutils_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_AES256_KEY_SIZE);

	qsc_consoleutils_hex_to_bin("F3EED1BDB5D2A03C064B5A7E3DB181F8", exp[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("591CCB10D410ED26DC5BA74A31362870", exp[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("B6ED21B99CA6F4F9F153E7B1BEAFED1D", exp[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("23304B7A39F9F3FF067D8D8F9E24ECC7", exp[3], QSC_AES_BLOCK_SIZE);

	qsc_consoleutils_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsc_consoleutils_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes256_ecb_monte_carlo(key, msg, exp);
}

static bool aes256_hba_kat()
{
	uint8_t aad1[20] = { 0 };
	uint8_t aad2[20] = { 0 };
	uint8_t aad3[20] = { 0 };
	uint8_t dec1[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t dec2[QSC_AES_BLOCK_SIZE * 2] = { 0 };
	uint8_t dec3[QSC_AES_BLOCK_SIZE * 4] = { 0 };
	uint8_t exp1[QSC_AES_BLOCK_SIZE + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t exp2[(QSC_AES_BLOCK_SIZE * 2) + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t exp3[(QSC_AES_BLOCK_SIZE * 4) + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg1[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg2[QSC_AES_BLOCK_SIZE * 2] = { 0 };
	uint8_t msg3[QSC_AES_BLOCK_SIZE * 4] = { 0 };
	uint8_t nce1[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t nce2[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t nce3[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t n1copy[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t n2copy[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t n3copy[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t enc1[QSC_AES_BLOCK_SIZE + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t enc2[(QSC_AES_BLOCK_SIZE * 2) + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t enc3[(QSC_AES_BLOCK_SIZE * 4) + QSC_HBA256_MAC_LENGTH] = { 0 };
	bool status;

	/* vectors from CEX */
	qsc_consoleutils_hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	qsc_consoleutils_hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	qsc_consoleutils_hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#if defined(QSC_HBA_KMAC_AUTH)
	qsc_consoleutils_hex_to_bin("B9121B5448F0C737C9D1CB5DDF465CB3904D9ADC483352C11AEB4BF6C79EE81D0BF06A96DFA43A6278484BA791F90D55", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("C266FF3A9FD867F245C06B2A326784A076D26965F56B26BDBF084A17CD29D99A0D77B1A30DF708C1E4D421666279EA779FA7F05A78F52F8F488197B74563BA85", exp2, sizeof(exp2));
	qsc_consoleutils_hex_to_bin("85B9D4BC71D2DA86E1B46547C5DAC28A811510357F3AE7F0A89AC35CFDB9FD91B1FD0FEA03ACAD19E449EDA57CCFB5D7C5DADF1902868F49A978A769A1939792"
		"3D2F5AF93DCE9C070695D298D94D5AE015579AF8FED2FBB7100F97DA2F10E45D", exp3, sizeof(exp3));
#else
	qsc_consoleutils_hex_to_bin("092A9F2D02A0020AC9B0963AA081349A36BA8596C961C96B5CA0F385F6C4F9A13F80BEE20461E3B94A8AD696D7B971E2", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("64B05F05D96C40E4860733BB055076BF52E57086125C4C11CC6EC558C40E25E6636973BDB1D89701F9A5E94B785EC88B86717893F07A089C8DD87319B6168210", exp2, sizeof(exp2));
	qsc_consoleutils_hex_to_bin("072B28CEA1AD0EF851E005D8925C55E7CEDF3ECB6B7E0FA54808E86CEE32CCC300C462505C3D97B9CC4F746DBBF4D4F8EEE7D4A016FC27C56AAA975815516C3A"
		"C06F0FF880A783102703462DF71B45D5F0A52670EE48A7CDBED063AB7980047B", exp3, sizeof(exp3));
#endif
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsc_consoleutils_hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	qsc_consoleutils_hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	qsc_consoleutils_hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	qsc_consoleutils_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	qsc_consoleutils_hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	qsc_consoleutils_hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

	status = true;
	qsc_memutils_copy(n1copy, nce1, QSC_AES_BLOCK_SIZE);
	qsc_memutils_copy(n2copy, nce2, QSC_AES_BLOCK_SIZE);
	qsc_memutils_copy(n3copy, nce3, QSC_AES_BLOCK_SIZE);

	/* first KAT vector */

	qsc_aes_hba256_state state;

	const qsc_aes_keyparams kp1 = { key, sizeof(key), nce1, NULL, 0 };

	qsc_aes_hba256_initialize(&state, &kp1, true);
	qsc_aes_hba256_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_aes_hba256_transform(&state, enc1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	qsc_memutils_copy(kp1.nonce, n1copy, QSC_AES_BLOCK_SIZE);

	qsc_aes_hba256_initialize(&state, &kp1, false);
	qsc_aes_hba256_set_associated(&state, aad1, sizeof(aad1));

	if (qsc_aes_hba256_transform(&state, dec1, enc1, sizeof(enc1) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const qsc_aes_keyparams kp2 = { key, sizeof(key), nce2, NULL, 0 };
	qsc_aes_hba256_initialize(&state, &kp2, true);
	qsc_aes_hba256_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_aes_hba256_transform(&state, enc2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	qsc_memutils_copy(kp2.nonce, n2copy, QSC_AES_BLOCK_SIZE);

	qsc_aes_hba256_initialize(&state, &kp2, false);
	qsc_aes_hba256_set_associated(&state, aad2, sizeof(aad2));

	if (qsc_aes_hba256_transform(&state, dec2, enc2, sizeof(enc2) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const qsc_aes_keyparams kp3 = { key, sizeof(key), nce3, NULL, 0 };
	qsc_aes_hba256_initialize(&state, &kp3, true);
	qsc_aes_hba256_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_aes_hba256_transform(&state, enc3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(enc3, exp3, sizeof(exp3)) == false)
	{
		status = false;
	}

	/* reset the nonce for decryption */
	qsc_memutils_copy(kp3.nonce, n3copy, QSC_AES_BLOCK_SIZE);

	qsc_aes_hba256_initialize(&state, &kp3, false);
	qsc_aes_hba256_set_associated(&state, aad3, sizeof(aad3));

	if (qsc_aes_hba256_transform(&state, dec3, enc3, sizeof(enc3) - QSC_HBA256_MAC_LENGTH) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec3, msg3, sizeof(msg3)) == false)
	{
		status = false;
	}

	return status;
}

/*** CHACHA ***/

static bool chacha128_kat()
{
	uint8_t exp[2][64] = { 0 };
	uint8_t msg[64] = { 0 };
	uint8_t out[64] = { 0 };
	uint8_t key[2][QSC_CHACHA_KEY128_SIZE] = { 0 };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	bool status;

	status = true;
	qsc_intutils_clear8(msg, 64);
	qsc_intutils_clear8(nonce, 8);
	qsc_intutils_clear8(out, 64);

	qsc_consoleutils_hex_to_bin("FBB87FBB8395E05DAA3B1D683C422046F913985C2AD9B23CFC06C1D8D04FF213D44A7A7CDB84929F915420A8A3DC58BF0F7ECB4B1F167BB1A5E6153FDAF4493D", exp[0], sizeof(exp[0]));
	qsc_consoleutils_hex_to_bin("A276339F99316A913885A0A4BE870F0691E72B00F1B3F2239F714FE81E88E00CBBE52B4EBBE1EA15894E29658C4CB145E6F89EE4ABB045A78514482CE75AFB7C", exp[1], sizeof(exp[1]));

	qsc_consoleutils_hex_to_bin("80000000000000000000000000000000", key[0], sizeof(key[0]));
	qsc_consoleutils_hex_to_bin("00400000000000000000000000000000", key[1], sizeof(key[1]));

	qsc_chacha_state ctx;

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp1 = { key[0], QSC_CHACHA_KEY128_SIZE, nonce };

	qsc_chacha_initialize(&ctx, &kp1);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[0], 64) == false)
	{
		qsc_consoleutils_print_safe("Failure! chacha128_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 64);

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp2 = { key[1], QSC_CHACHA_KEY128_SIZE, nonce };

	qsc_chacha_initialize(&ctx, &kp2);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[1], 64) == false)
	{
		qsc_consoleutils_print_safe("Failure! chacha128_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	return status;
}

static bool chacha256_kat()
{
	uint8_t exp[2][64] = { 0 };
	uint8_t msg[64] = { 0 };
	uint8_t out[64] = { 0 };
	uint8_t key[2][QSC_CHACHA_KEY256_SIZE] = { 0 };
	uint8_t nonce[2][QSC_CHACHA_NONCE_SIZE] = { 0 };
	bool status;

	status = true;
	qsc_intutils_clear8(msg, 64);
	qsc_intutils_clear8(out, 64);

	qsc_consoleutils_hex_to_bin("57459975BC46799394788DE80B928387862985A269B9E8E77801DE9D874B3F51AC4610B9F9BEE8CF8CACD8B5AD0BF17D3DDF23FD7424887EB3F81405BD498CC3", exp[0], sizeof(exp[0]));
	qsc_consoleutils_hex_to_bin("92A2508E2C4084567195F2A1005E552B4874EC0504A9CD5E4DAF739AB553D2E783D79C5BA11E0653BEBB5C116651302E8D381CB728CA627B0B246E83942A2B99", exp[1], sizeof(exp[1]));

	qsc_consoleutils_hex_to_bin("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D", key[0], sizeof(key[0]));
	qsc_consoleutils_hex_to_bin("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", key[1], sizeof(key[1]));

	qsc_consoleutils_hex_to_bin("0D74DB42A91077DE", nonce[0], sizeof(nonce[0]));
	qsc_consoleutils_hex_to_bin("167DE44BB21980E7", nonce[1], sizeof(nonce[1]));

	qsc_chacha_state ctx;

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp1 = { key[0], QSC_CHACHA_KEY256_SIZE, nonce[0] };

	qsc_chacha_initialize(&ctx, &kp1);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[0], 64) == false)
	{
		qsc_consoleutils_print_safe("Failure! chacha256_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 64);

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp2 = { key[1], QSC_CHACHA_KEY256_SIZE, nonce[1] };

	qsc_chacha_initialize(&ctx, &kp2);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[1], 64) == false)
	{
		qsc_consoleutils_print_safe("Failure! Failure! chacha256_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	return status;
}

/*** CSX ***/

static bool csx512_kat()
{
	uint8_t ad[20] = { 0 };
	uint8_t dec[128] = { 0 };
#if defined(QSC_CSX_AUTHENTICATED)
	uint8_t enc1[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t enc2[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t exp1[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t exp2[128 + QSC_CSX_MAC_SIZE] = { 0 };
#else
	uint8_t enc1[128] = { 0 };
	uint8_t enc2[128] = { 0 };
	uint8_t exp1[128] = { 0 };
	uint8_t exp2[128] = { 0 };
#endif
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t msg[128] = { 0 };
	uint8_t nce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t ncpy[QSC_CSX_NONCE_SIZE] = { 0 };
	bool status;
	qsc_csx_state state;

	/* vectors from CEX */
#if defined(QSC_CSX_AUTHENTICATED)
#	if defined(QSC_CSX_AUTH_KMACR12)
	/* csxc512p512 */
	qsc_consoleutils_hex_to_bin("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F"
		"842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
		"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD"
		"1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
		"5FCF2735ADF4D7A22FB2EA72172F0E06173C56991CA24C7927A213F4D548F155"
		"4240A769A599A75A8A2DA332B260FECC1B0F30E74990AF855F0D3DB5041947E9", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("379E86BCE2F0BE6DF0BAA8FEC403C6A7244B21D1D5B9193FCE79510FF2633893"
		"F58D57DABBEF0424E1E8D5ED7B485EB7381CC7235350220CA03F1D107A102BD3"
		"5FAB74869AB656D35E0F40950E1564DBDC37ECFD6C50BEE201BFA0F953AEC0A2"
		"9B063993F5D019CDDE4A8AA02D440C19A4A08AD7A0CD3F2FDFEF61D0383314B5"
		"17EE1D270EE97F7443D8334024FA3A656395B240328DFDD87293457F11074ED9"
		"4A9A3D32F48CD88EC4550531B0B6B36413622BBC27570828E054FC2CF15BD998", exp2, sizeof(exp2));
#	else
	/* csxc512k512 */
	qsc_consoleutils_hex_to_bin("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F"
		"842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
		"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD"
		"1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
		"2EC8B5F4E79AD2F7A86140499FB479E9BD0EEB065E91E4F7F53953E970AA13DC"
		"96172F398E598FF7169C41A8D8E51FAF297004B2B1F242706EE34680CF9A9F9A", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("379E86BCE2F0BE6DF0BAA8FEC403C6A7244B21D1D5B9193FCE79510FF2633893"
		"F58D57DABBEF0424E1E8D5ED7B485EB7381CC7235350220CA03F1D107A102BD3"
		"5FAB74869AB656D35E0F40950E1564DBDC37ECFD6C50BEE201BFA0F953AEC0A2"
		"9B063993F5D019CDDE4A8AA02D440C19A4A08AD7A0CD3F2FDFEF61D0383314B5"
		"FCDFC3F96D8A40E41B35A35D4E2AFB81E0C054BA4DBC7FC183DA37E45ADA60F8"
		"F77303C276C7E3A33327EB5E481E4A8886E2E76100434D92384943C7D648C0A5", exp2, sizeof(exp2));
#	endif
	qsc_memutils_setvalue(ad, 0x01, sizeof(ad));
#else
	qsc_consoleutils_hex_to_bin("E1E27CD3CF085080363AC3903D31C2AE5E51D4CCF8FB9278FEFB24077A72C2AC671249C32DED5F96CBC31702CED6B3575F3B562BA9FF9E6467DE7C687AEDA54C"
		"7043FC912BF57B4892FED02E5F4D67C2404DCF99B6021FDBD1B241DBD8673F96D67A15AC380946EBE5287C61F74C8ECD6A34AF7499D145F1B74BED2A5A7CA631", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("026FE8D3D224909030939FF99D7308ACFF9472A3656193CFDA3991C87E955E3FE2A1C1983FF3E7D7E6B9E646F161765F70D14E2A52312E60C6EC3C774FDC1985"
		"9AE0B3C43F93F0A9900693F451D4B7A342CEB9F0BE047AE7D64C16001843B7A80F7EC32CC7A4FF745DBF1700390017B357DF27B1CE2CC44515F2D392AE20E4A8", exp2, sizeof(exp2));
#endif

	qsc_consoleutils_hex_to_bin("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", key, sizeof(key));
	qsc_consoleutils_hex_to_bin("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", msg, sizeof(msg));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F", nce, sizeof(nce));

	qsc_memutils_setvalue(ad, 0x01, sizeof(ad));

	/* copy the nonce */
	qsc_memutils_copy(ncpy, nce, sizeof(nce));

	/* initialize the key parameters struct, info is optional */
	qsc_csx_keyparams kp = { key, QSC_CSX_KEY_SIZE, nce };

	status = true;

	/* initialize the state */
	qsc_csx_initialize(&state, &kp, true);

#if defined(QSC_CSX_AUTHENTICATED)
	/* set associated data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption */
	qsc_csx_transform(&state, enc1, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		qsc_consoleutils_print_safe("Failure! csx512_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

#if defined(QSC_CSX_AUTHENTICATED)
	/* set associated data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption and chaining */
	qsc_csx_transform(&state, enc2, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	qsc_csx_initialize(&state, &kp, false);

#if defined(QSC_CSX_AUTHENTICATED)
	/* set associated data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));
#endif

	/* test decryption */
	if (qsc_csx_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		qsc_consoleutils_print_safe("Failure! csx512_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, msg, sizeof(dec)) == false)
	{
		qsc_consoleutils_print_safe("Failure! csx512_kat: output does not match the expected answer -CK3 \n");
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_csx_dispose(&state);

	return status;
}

/*** POLY1305 ***/

static bool poly1305_kat()
{
	uint8_t exp[4][16] = { 0 };
	uint8_t key[4][32] = { 0 };
	uint8_t out[16] = { 0 };
	uint8_t msg1[34] = { 0 };
	uint8_t msg2[12] = { 0 };
	uint8_t msg3[64] = { 0 };
	uint8_t msg4[64] = { 0 };
	size_t i;
	bool status;

	status = true;

	qsc_consoleutils_hex_to_bin("A8061DC1305136C6C22B8BAF0C0127A9", exp[0], sizeof(exp[0]));
	qsc_consoleutils_hex_to_bin("A6F745008F81C916A20DCC74EEF2B2F0", exp[1], sizeof(exp[1]));
	qsc_consoleutils_hex_to_bin("00000000000000000000000000000000", exp[2], sizeof(exp[2]));
	qsc_consoleutils_hex_to_bin("36E5F6B5C5E06070F0EFCA96227A863E", exp[3], sizeof(exp[3]));

	qsc_consoleutils_hex_to_bin("85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B", key[0], sizeof(key[0]));
	qsc_consoleutils_hex_to_bin("746869732069732033322D62797465206B657920666F7220506F6C7931333035", key[1], sizeof(key[1]));
	qsc_consoleutils_hex_to_bin("0000000000000000000000000000000000000000000000000000000000000000", key[2], sizeof(key[2]));
	qsc_consoleutils_hex_to_bin("0000000000000000000000000000000036E5F6B5C5E06070F0EFCA96227A863E", key[3], sizeof(key[3]));

	qsc_consoleutils_hex_to_bin("43727970746F6772617068696320466F72756D2052657365617263682047726F7570", msg1, sizeof(msg1));
	qsc_consoleutils_hex_to_bin("48656C6C6F20776F726C6421", msg2, sizeof(msg2));
	qsc_consoleutils_hex_to_bin("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", msg3, sizeof(msg3));
	qsc_consoleutils_hex_to_bin("416E79207375626D697373696F6E20746F20746865204945544620696E74656E6465642062792074686520436F6E7472696275746F7220666F72207075626C69", msg4, sizeof(msg4));

	/* compact api */

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg1, 34, key[0]);

	if (qsc_intutils_are_equal8(out, exp[0], 16) == false)
	{
		qsc_consoleutils_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK1 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg2, 12, key[1]);

	if (qsc_intutils_are_equal8(out, exp[1], 16) == false)
	{
		qsc_consoleutils_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK2 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg3, 34, key[2]);

	if (qsc_intutils_are_equal8(out, exp[2], 16) == false)
	{
		qsc_consoleutils_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK3 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_compute(out, msg4, 34, key[3]);

	if (qsc_intutils_are_equal8(out, exp[3], 16) == false)
	{
		qsc_consoleutils_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK4 \n");
		status = false;
	}

	/* long-form api */

	qsc_intutils_clear8(out, 16);
	qsc_poly1305_state ctx;

	qsc_poly1305_initialize(&ctx, key[0]);

	for (i = 0; i < 32; i += QSC_POLY1305_BLOCK_SIZE)
	{
		qsc_poly1305_blockupdate(&ctx, msg1 + i);
	}

	qsc_poly1305_update(&ctx, msg1 + i, 2);
	qsc_poly1305_finalize(&ctx, out);

	if (qsc_intutils_are_equal8(out, exp[0], 16) == false)
	{
		qsc_consoleutils_print_safe("Failure! poly1305_kat: MAC output does not match the known answer -PK5 \n");
		status = false;
	}

	return status;
}

/*** RCS ***/

bool rcs256_kat()
{
#if defined(QSC_RCS_AUTHENTICATED)
	uint8_t ad[20] = { 0 };
	uint8_t dec[32] = { 0 };
	uint8_t enc1[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t enc2[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t exp1[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t exp2[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t ncpy[QSC_RCS_NONCE_SIZE] = { 0 };
#else
	uint8_t enc1[32] = { 0 };
	uint8_t exp1[32] = { 0 };
#endif
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0 };
	uint8_t msg[32] = { 0 };
	uint8_t nce[QSC_RCS_NONCE_SIZE] = { 0 };

	bool status;
	qsc_rcs_state state;

	/* vectors from CEX */

	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));
	qsc_consoleutils_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0", nce, sizeof(nce));

#if defined(QSC_RCS_AUTHENTICATED)
#	if defined(QSC_RCS_AUTH_KMACR12)
	/* rcsc256p256 */
	qsc_consoleutils_hex_to_bin("7940917E9219A31248946F71647B15421535941574F84F79F6110C1F2F776D03"
		"225B05B1FB100A4D9208522BACB1AEBEE62A94D19BFF53B41ACE75D031926707", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("ABF3574126DAA563B423B0EEEE9970FD0C8F060F65CB00CDC05BB0DC047DB2AD"
		"009BDF7169E5FBDFDEBB1CE9E01B6FEA7E9E36E33C3E885B28EEA26D4F14CE3D", exp2, sizeof(exp2));
#	else
	/* rcsc256k256 */
	qsc_consoleutils_hex_to_bin("7940917E9219A31248946F71647B15421535941574F84F79F"
		"6110C1F2F776D03F38582F301390A6B8807C75914CE0CF410051D73CAE97D1D295CB0420146E179", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("ABF3574126DAA563B423B0EEEE9970FD0C8F060F65CB00CDC"
		"05BB0DC047DB2ADA2A39BEB441FCD4C5F83F1142F264EEFCBAAA51D7874A0E7DA0A7B285DFD55AA", exp2, sizeof(exp2));
#	endif

	qsc_memutils_setvalue(ad, 0x01, sizeof(ad));
	qsc_memutils_copy(ncpy, nce, QSC_RCS_NONCE_SIZE);
#else
	qsc_consoleutils_hex_to_bin("9EF7D04279C5277366D2DDD3FBB47F0DFCB3994D6F43D7F3A782778838C56DB3", exp1, sizeof(exp1));
#endif

	/* initialize the key parameters struct, info is optional */
	qsc_rcs_keyparams kp = { key, QSC_RCS256_KEY_SIZE, nce };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rcs_initialize(&state, &kp, true);

#if defined(QSC_RCS_AUTHENTICATED)
	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption */
	qsc_rcs_transform(&state, enc1, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs256_kat: cipher output does not match the known answer -RK1 \n");
		status = false;
	}

#if defined(QSC_RCS_AUTHENTICATED)
	/* test encryption and mac chaining */
	qsc_rcs_transform(&state, enc2, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs256_kat: cipher output does not match the known answer -RK2 \n");
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	qsc_rcs_initialize(&state, &kp, false);

	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));

	/* test decryption */
	if (qsc_rcs_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs256_kat: authentication failure -RK3 \n");
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, msg, sizeof(dec)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs256_kat: cipher output does not match the known answer -RK4 \n");
		status = false;
	}
#endif

	/* erase the round-key array and reset the state */
	qsc_rcs_dispose(&state);

	return status;
}

bool rcs512_kat()
{
#if defined(QSC_RCS_AUTHENTICATED)
	uint8_t ad[20] = { 0 };
	uint8_t dec[64] = { 0 };
	uint8_t enc1[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t enc2[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t exp1[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t exp2[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t ncpy[QSC_RCS_NONCE_SIZE] = { 0 };
#else
	uint8_t enc1[64] = { 0 };
	uint8_t exp1[64] = { 0 };
#endif
	uint8_t key[QSC_RCS512_KEY_SIZE] = { 0 };
	uint8_t msg[64] = { 0 };
	uint8_t nce[QSC_RCS_NONCE_SIZE] = { 0 };
	bool status;
	qsc_rcs_state state;

	/* vectors from CEX */

	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
		"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F", msg, sizeof(msg));
	qsc_consoleutils_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0", nce, sizeof(nce));

#if defined(QSC_RCS_AUTHENTICATED)
#	if defined(QSC_RCS_AUTH_KMACR12)
	/* rcsc512p512 */
	qsc_consoleutils_hex_to_bin("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8"
		"A1CF250F2EC948D5985B92667349B72EFA751048AF0B919AE9E16F177F5C97F2"
		"2B1CF7254DEB7659203F37CCBB9D55C4DF916C06ACEC3FF684F47DB1802F2A2B"
		"F433F1A838872DD8AD9C889D570F4CF801B15A2B84C069F5C8DF77E130B3CDDF", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("388270BF8DF03483BB287FFA527D81403F0362210FD525657C8541250DFFE3BA"
		"D1285FAB37A6821DA524F3F7FF7EFCB39C5B59E3897B177E45D6AA7F4BB5BE77"
		"864E82FC36E22E830EBCC10DF875CFA126070CAFAC402113167920E0EC9E0D12"
		"1FCCDEBF7112496AF04FD8FB6E83137666167FDDF9E0983ADA3AD179FDCF220A", exp2, sizeof(exp2));
#	else
	/* rcsc512k512 */
	qsc_consoleutils_hex_to_bin("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8"
		"A1CF250F2EC948D5985B92667349B72EFA751048AF0B919AE9E16F177F5C97F2"
		"C40E0D50727DC9528664F656270E99A4857D7A2C28F965EB9956658145AC9868"
		"F3FDE25C39EC9EEF0C6A7ED955CB3C2F44286CD253C9BE0CF3F389313C47E4B2", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("388270BF8DF03483BB287FFA527D81403F0362210FD525657C8541250DFFE3BA"
		"D1285FAB37A6821DA524F3F7FF7EFCB39C5B59E3897B177E45D6AA7F4BB5BE77"
		"9CB2429F4693DF70D38DBBCB00EE86172435C117D442171A8485A87BF1D7282F"
		"2D69032C85F1CD1A1FEE794843E0CED7616722A4B0937210E9023220B085EA18", exp2, sizeof(exp2));
#	endif

	qsc_memutils_setvalue(ad, 0x01, sizeof(ad));
	qsc_memutils_copy(ncpy, nce, sizeof(nce));
#else
	qsc_consoleutils_hex_to_bin("8643251F3880261010BF195886C0496CC2EB07BB68D9F13BCBD266890467F47F"
		"57FA98C08031903D6539AC94B4F17E3A45A741159FF929B0540436FFE7A77E01", exp1, sizeof(exp1));
#endif

	/* initialize the key parameters struct, info is optional */
	qsc_rcs_keyparams kp = { key, QSC_RCS512_KEY_SIZE, nce };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rcs_initialize(&state, &kp, true);

#if defined(QSC_RCS_AUTHENTICATED)
	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption */
	qsc_rcs_transform(&state, enc1, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs512_kat: cipher output does not match the known answer -RK1 \n");
		status = false;
	}

#if defined(QSC_RCS_AUTHENTICATED)
	/* test encryption and mac chaining */
	qsc_rcs_transform(&state, enc2, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs512_kat: cipher output does not match the known answer -RK2 \n");
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	qsc_rcs_initialize(&state, &kp, false);

	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));

	/* test decryption */
	if (qsc_rcs_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs512_kat: authentication failure -RK3 \n");
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, msg, sizeof(dec)) == false)
	{
		qsc_consoleutils_print_safe("Failure! rcs512_kat: cipher output does not match the known answer -RK4 \n");
		status = false;
	}
#endif

	/* erase the round-key array and reset the state */
	qsc_rcs_dispose(&state);

	return status;
}

/*** SHA2 ***/

static bool sha2_256_kat()
{
	uint8_t exp0[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp1[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp2[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t exp3[QSC_SHA2_256_HASH_SIZE] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[QSC_SHA2_256_HASH_SIZE] = { 0 };
	qsc_sha256_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1", exp2, sizeof(exp2));
	qsc_consoleutils_hex_to_bin("CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1", exp3, sizeof(exp3));

	qsc_consoleutils_hex_to_bin("00", msg0, sizeof(msg0));
	qsc_consoleutils_hex_to_bin("616263", msg1, sizeof(msg1));
	qsc_consoleutils_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	qsc_consoleutils_hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	qsc_sha256_compute(otp, msg0, 0);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_compute(otp, msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_compute(otp, msg2, sizeof(msg2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_compute(otp, msg3, sizeof(msg3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));

	qsc_sha256_initialize(&state);
	qsc_sha256_update(&state, msg0, 0);
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_initialize(&state);
	qsc_sha256_update(&state, msg1, sizeof(msg1));
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_initialize(&state);
	qsc_sha256_update(&state, msg2, sizeof(msg2));
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha256_initialize(&state);

	/* absorb a the message */
	qsc_sha256_update(&state, msg3, sizeof(msg3));

	/* finalize the hash */
	qsc_sha256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, QSC_SHA2_256_HASH_SIZE) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_256_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

static bool sha2_512_kat()
{
	uint8_t exp0[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp1[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp2[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t exp3[QSC_SHA2_512_HASH_SIZE] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[QSC_SHA2_512_HASH_SIZE] = { 0 };
	qsc_sha512_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE"
		"47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
		"2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C335"
		"96FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445", exp2, sizeof(exp2));
	qsc_consoleutils_hex_to_bin("8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018"
		"501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909", exp3, sizeof(exp3));

	qsc_consoleutils_hex_to_bin("00", msg0, sizeof(msg0));
	qsc_consoleutils_hex_to_bin("616263", msg1, sizeof(msg1));
	qsc_consoleutils_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	qsc_consoleutils_hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	qsc_sha512_compute(otp, msg0, 0);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_compute(otp, msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_compute(otp, msg2, sizeof(msg2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_compute(otp, msg3, sizeof(msg3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state);
	qsc_sha512_update(&state, msg0, 0);
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state);
	qsc_sha512_update(&state, msg1, sizeof(msg1));
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state);
	qsc_sha512_update(&state, msg2, sizeof(msg2));
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_sha512_initialize(&state);
	qsc_sha512_update(&state, msg3, sizeof(msg3));
	qsc_sha512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsc_consoleutils_print_safe("Failure! sha2_512_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

static bool hkdf_256_kat()
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	qsc_consoleutils_hex_to_bin("D03C9AB82C884B1DCFD3F4CFFD0E4AD1501915E5D72DF0E6D846D59F6CF78047"
		"39958B5DF06BDE49DB6D", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("24B29E50BD5B2968A8FC1B030B52A07B3B87C45603AAA046D649CD3CAAE06D5C"
		"B029960513275DF28548068821DF861904F0C095D063097A61EF571687217603"
		"E7D7673A7F98AEC538879E81E80864A91BCC", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	qsc_consoleutils_hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	qsc_consoleutils_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	qsc_hkdf256_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (qsc_intutils_are_equal8(otp0, exp0, sizeof(otp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hkdf_256_kat: output does not match the known answer -HK1 \n");
		status = false;
	}

	qsc_hkdf256_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (qsc_intutils_are_equal8(otp1, exp1, sizeof(otp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hkdf_256_kat: output does not match the known answer -HK2 \n");
		status = false;
	}

	return status;
}

static bool hkdf_512_kat()
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	qsc_consoleutils_hex_to_bin("7CE212EEB2A92270C4460A4728944B9B0EE9E060DE13C197853D37A20CE7184F"
		"94390EAEA4C18CEF989D", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("C66BAAA5CFB588D3B99CCC193005CD39C7CBAB0E6682F95E4E7D8B5A92EE3031"
		"6D59BC93F6E2BAC696A05BF448E2C088632691CC9CD3B238042FE564439B9074"
		"5DD4E27DC0E6D779129657F3CF424CA207F3", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	qsc_consoleutils_hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	qsc_consoleutils_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	qsc_hkdf512_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (qsc_intutils_are_equal8(otp0, exp0, sizeof(otp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hkdf_512_kat: output does not match the known answer -HK1 \n");
		status = false;
	}

	qsc_hkdf512_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (qsc_intutils_are_equal8(otp1, exp1, sizeof(otp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hkdf_512_kat: output does not match the known answer -HK2 \n");
		status = false;
	}

	return status;
}

static bool hmac_256_kat()
{
	uint8_t exp0[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp1[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp2[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp3[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t exp4[QSC_HMAC_256_MAC_SIZE] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t key4[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t msg4[152] = { 0 };
	uint8_t otp[QSC_HMAC_256_MAC_SIZE] = { 0 };
	qsc_hmac256_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B", exp2, sizeof(exp2));
	qsc_consoleutils_hex_to_bin("60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54", exp3, sizeof(exp3));
	qsc_consoleutils_hex_to_bin("9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2", exp4, sizeof(exp4));

	qsc_consoleutils_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsc_consoleutils_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	qsc_consoleutils_hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	qsc_consoleutils_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key3, sizeof(key3));
	qsc_consoleutils_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key4, sizeof(key4));

	qsc_consoleutils_hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	qsc_consoleutils_hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	qsc_consoleutils_hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	qsc_consoleutils_hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));
	qsc_consoleutils_hex_to_bin("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074"
		"68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365"
		"642062792074686520484D414320616C676F726974686D2E", msg4, sizeof(msg4));

	status = true;

	/* test compact api */

	qsc_hmac256_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK4 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_compute(otp, msg4, sizeof(msg4), key4, sizeof(key4));

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK5 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key0, sizeof(key0));
	qsc_hmac256_update(&state, msg0, sizeof(msg0));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key1, sizeof(key1));
	qsc_hmac256_update(&state, msg1, sizeof(msg1));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key2, sizeof(key2));
	qsc_hmac256_update(&state, msg2, sizeof(msg2));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK8 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key3, sizeof(key3));
	qsc_hmac256_update(&state, msg3, sizeof(msg3));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK9 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac256_initialize(&state, key4, sizeof(key4));
	qsc_hmac256_update(&state, msg4, sizeof(msg4));
	qsc_hmac256_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_256_kat: output does not match the known answer -MK10 \n");
		status = false;
	}

	return status;
}

static bool hmac_512_kat()
{
	uint8_t exp0[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp1[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp2[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp3[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t exp4[QSC_HMAC_512_MAC_SIZE] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t key4[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t msg4[152] = { 0 };
	uint8_t otp[QSC_HMAC_512_MAC_SIZE] = { 0 };
	qsc_hmac512_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD", exp2, sizeof(exp2));
	qsc_consoleutils_hex_to_bin("80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598", exp3, sizeof(exp3));
	qsc_consoleutils_hex_to_bin("E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58", exp4, sizeof(exp4));

	qsc_consoleutils_hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	qsc_consoleutils_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	qsc_consoleutils_hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	qsc_consoleutils_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key3, sizeof(key3));
	qsc_consoleutils_hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key4, sizeof(key4));

	qsc_consoleutils_hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	qsc_consoleutils_hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	qsc_consoleutils_hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	qsc_consoleutils_hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));
	qsc_consoleutils_hex_to_bin("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074"
		"68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365"
		"642062792074686520484D414320616C676F726974686D2E", msg4, sizeof(msg4));

	status = true;

	/* test compact api */

	qsc_hmac512_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK1 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK2 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK3 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK4 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_compute(otp, msg4, sizeof(msg4), key4, sizeof(key4));

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK5 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key0, sizeof(key0));
	qsc_hmac512_update(&state, msg0, sizeof(msg0));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK6 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key1, sizeof(key1));
	qsc_hmac512_update(&state, msg1, sizeof(msg1));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK7 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key2, sizeof(key2));
	qsc_hmac512_update(&state, msg2, sizeof(msg2));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK8 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key3, sizeof(key3));
	qsc_hmac512_update(&state, msg3, sizeof(msg3));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK9 \n");
		status = false;
	}

	qsc_intutils_clear8(otp, sizeof(otp));
	qsc_hmac512_initialize(&state, key4, sizeof(key4));
	qsc_hmac512_update(&state, msg4, sizeof(msg4));
	qsc_hmac512_finalize(&state, otp);

	if (qsc_intutils_are_equal8(otp, exp4, sizeof(exp4)) != true)
	{
		qsc_consoleutils_print_safe("Failure! hmac_512_kat: output does not match the known answer -MK10 \n");
		status = false;
	}

	return status;
}

/*** SHA3 ***/

static bool sha3_256_kat()
{
	uint8_t exp0[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t exp24[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t exp448[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t exp1600[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t hash[200] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg24[3] = { 0 };
	uint8_t msg448[56] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[QSC_SHA3_256_HASH_SIZE] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532", exp24, sizeof(exp24));
	qsc_consoleutils_hex_to_bin("41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376", exp448, sizeof(exp448));
	qsc_consoleutils_hex_to_bin("79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787", exp1600, sizeof(exp1600));

	qsc_consoleutils_hex_to_bin("616263", msg24, sizeof(msg24));
	qsc_consoleutils_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg448, sizeof(msg448));
	qsc_consoleutils_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg24, sizeof(msg24));

	if (qsc_intutils_are_equal8(output, exp24, sizeof(exp24)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg448, sizeof(msg448));

	if (qsc_intutils_are_equal8(output, exp448, sizeof(exp448)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state structure */
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg0, 0);
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp0, sizeof(exp0)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg24, sizeof(msg24));
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp24, sizeof(exp24)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	/* absorb the message */
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg448, sizeof(msg448));
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp448, sizeof(exp448)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state structure */
	qsc_sha3_initialize(&state);
	/* absorb the message */
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600));
	/* finalize the message */
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

static bool sha3_512_kat()
{
	uint8_t exp0[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t exp24[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t exp448[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t exp1600[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t hash[200] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg24[3] = { 0 };
	uint8_t msg448[56] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[QSC_SHA3_512_HASH_SIZE] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A6"
		"15B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E"
		"10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0", exp24, sizeof(exp24));
	qsc_consoleutils_hex_to_bin("04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636D"
		"EE691FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E", exp448, sizeof(exp448));
	qsc_consoleutils_hex_to_bin("E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA8"
		"1B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00", exp1600, sizeof(exp1600));

	qsc_consoleutils_hex_to_bin("616263", msg24, sizeof(msg24));
	qsc_consoleutils_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg448, sizeof(msg448));
	qsc_consoleutils_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg24, sizeof(msg24));

	if (qsc_intutils_are_equal8(output, exp24, sizeof(exp24)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg448, sizeof(msg448));

	if (qsc_intutils_are_equal8(output, exp448, sizeof(exp448)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state structure */
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg0, 0);
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp0, sizeof(exp0)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg24, sizeof(msg24));
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp24, sizeof(exp24)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg448, sizeof(msg448));
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp448, sizeof(exp448)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state*/
	qsc_sha3_initialize(&state);
	/* absorb the message */
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg1600, sizeof(msg1600));
	/* finalize the message */
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

static bool shake_128_kat()
{
	uint8_t exp0[512] = { 0 };
	uint8_t exp1600[512] = { 0 };
	uint8_t hash[qsc_keccak_rate_128 * 4] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[512] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF26"
		"3CB1EEA988004B93103CFB0AEEFD2A686E01FA4A58E8A3639CA8A1E3F9AE57E2"
		"35B8CC873C23DC62B8D260169AFA2F75AB916A58D974918835D25E6A435085B2"
		"BADFD6DFAAC359A5EFBB7BCC4B59D538DF9A04302E10C8BC1CBF1A0B3A5120EA"
		"17CDA7CFAD765F5623474D368CCCA8AF0007CD9F5E4C849F167A580B14AABDEF"
		"AEE7EEF47CB0FCA9767BE1FDA69419DFB927E9DF07348B196691ABAEB580B32D"
		"EF58538B8D23F87732EA63B02B4FA0F4873360E2841928CD60DD4CEE8CC0D4C9"
		"22A96188D032675C8AC850933C7AFF1533B94C834ADBB69C6115BAD4692D8619"
		"F90B0CDF8A7B9C264029AC185B70B83F2801F2F4B3F70C593EA3AEEB613A7F1B"
		"1DE33FD75081F592305F2E4526EDC09631B10958F464D889F31BA010250FDA7F"
		"1368EC2967FC84EF2AE9AFF268E0B1700AFFC6820B523A3D917135F2DFF2EE06"
		"BFE72B3124721D4A26C04E53A75E30E73A7A9C4A95D91C55D495E9F51DD0B5E9"
		"D83C6D5E8CE803AA62B8D654DB53D09B8DCFF273CDFEB573FAD8BCD45578BEC2"
		"E770D01EFDE86E721A3F7C6CCE275DABE6E2143F1AF18DA7EFDDC4C7B70B5E34"
		"5DB93CC936BEA323491CCB38A388F546A9FF00DD4E1300B9B2153D2041D205B4"
		"43E41B45A653F2A5C4492C1ADD544512DDA2529833462B71A41A45BE97290B6F", exp0, sizeof(exp0));

	qsc_consoleutils_hex_to_bin("131AB8D2B594946B9C81333F9BB6E0CE75C3B93104FA3469D3917457385DA037"
		"CF232EF7164A6D1EB448C8908186AD852D3F85A5CF28DA1AB6FE343817197846"
		"7F1C05D58C7EF38C284C41F6C2221A76F12AB1C04082660250802294FB871802"
		"13FDEF5B0ECB7DF50CA1F8555BE14D32E10F6EDCDE892C09424B29F597AFC270"
		"C904556BFCB47A7D40778D390923642B3CBD0579E60908D5A000C1D08B98EF93"
		"3F806445BF87F8B009BA9E94F7266122ED7AC24E5E266C42A82FA1BBEFB7B8DB"
		"0066E16A85E0493F07DF4809AEC084A593748AC3DDE5A6D7AAE1E8B6E5352B2D"
		"71EFBB47D4CAEED5E6D633805D2D323E6FD81B4684B93A2677D45E7421C2C6AE"
		"A259B855A698FD7D13477A1FE53E5A4A6197DBEC5CE95F505B520BCD9570C4A8"
		"265A7E01F89C0C002C59BFEC6CD4A5C109258953EE5EE70CD577EE217AF21FA7"
		"0178F0946C9BF6CA8751793479F6B537737E40B6ED28511D8A2D7E73EB75F8DA"
		"AC912FF906E0AB955B083BAC45A8E5E9B744C8506F37E9B4E749A184B30F43EB"
		"188D855F1B70D71FF3E50C537AC1B0F8974F0FE1A6AD295BA42F6AEC74D123A7"
		"ABEDDE6E2C0711CAB36BE5ACB1A5A11A4B1DB08BA6982EFCCD716929A7741CFC"
		"63AA4435E0B69A9063E880795C3DC5EF3272E11C497A91ACF699FEFEE206227A"
		"44C9FB359FD56AC0A9A75A743CFF6862F17D7259AB075216C0699511643B6439", exp1600, sizeof(exp1600));

	qsc_consoleutils_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake128_compute(output, sizeof(output), msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_128_kat: output does not match the known answer -DK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake128_compute(output, sizeof(output), msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_128_kat: output does not match the known answer -DK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_shake_initialize(&state, qsc_keccak_rate_128, msg1600, sizeof(msg1600));
	qsc_shake_squeezeblocks(&state, qsc_keccak_rate_128, hash, 4);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_128_kat: output does not match the known answer -DK3 \n");
		status = false;
	}

	return status;
}

static bool shake_256_kat()
{
	uint8_t exp0[512] = { 0 };
	uint8_t exp1600[512] = { 0 };
	uint8_t hash[qsc_keccak_rate_256 * 4] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[512] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F"
		"D75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE"
		"141E96616FB13957692CC7EDD0B45AE3DC07223C8E92937BEF84BC0EAB862853"
		"349EC75546F58FB7C2775C38462C5010D846C185C15111E595522A6BCD16CF86"
		"F3D122109E3B1FDD943B6AEC468A2D621A7C06C6A957C62B54DAFC3BE87567D6"
		"77231395F6147293B68CEAB7A9E0C58D864E8EFDE4E1B9A46CBE854713672F5C"
		"AAAE314ED9083DAB4B099F8E300F01B8650F1F4B1D8FCF3F3CB53FB8E9EB2EA2"
		"03BDC970F50AE55428A91F7F53AC266B28419C3778A15FD248D339EDE785FB7F"
		"5A1AAA96D313EACC890936C173CDCD0FAB882C45755FEB3AED96D477FF96390B"
		"F9A66D1368B208E21F7C10D04A3DBD4E360633E5DB4B602601C14CEA737DB3DC"
		"F722632CC77851CBDDE2AAF0A33A07B373445DF490CC8FC1E4160FF118378F11"
		"F0477DE055A81A9EDA57A4A2CFB0C83929D310912F729EC6CFA36C6AC6A75837"
		"143045D791CC85EFF5B21932F23861BCF23A52B5DA67EAF7BAAE0F5FB1369DB7"
		"8F3AC45F8C4AC5671D85735CDDDB09D2B1E34A1FC066FF4A162CB263D6541274"
		"AE2FCC865F618ABE27C124CD8B074CCD516301B91875824D09958F341EF274BD"
		"AB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A", exp0, sizeof(exp0));

	qsc_consoleutils_hex_to_bin("CD8A920ED141AA0407A22D59288652E9D9F1A7EE0C1E7C1CA699424DA84A904D"
		"2D700CAAE7396ECE96604440577DA4F3AA22AEB8857F961C4CD8E06F0AE6610B"
		"1048A7F64E1074CD629E85AD7566048EFC4FB500B486A3309A8F26724C0ED628"
		"001A1099422468DE726F1061D99EB9E93604D5AA7467D4B1BD6484582A384317"
		"D7F47D750B8F5499512BB85A226C4243556E696F6BD072C5AA2D9B69730244B5"
		"6853D16970AD817E213E470618178001C9FB56C54FEFA5FEE67D2DA524BB3B0B"
		"61EF0E9114A92CDBB6CCCB98615CFE76E3510DD88D1CC28FF99287512F24BFAF"
		"A1A76877B6F37198E3A641C68A7C42D45FA7ACC10DAE5F3CEFB7B735F12D4E58"
		"9F7A456E78C0F5E4C4471FFFA5E4FA0514AE974D8C2648513B5DB494CEA84715"
		"6D277AD0E141C24C7839064CD08851BC2E7CA109FD4E251C35BB0A04FB05B364"
		"FF8C4D8B59BC303E25328C09A882E952518E1A8AE0FF265D61C465896973D749"
		"0499DC639FB8502B39456791B1B6EC5BCC5D9AC36A6DF622A070D43FED781F5F"
		"149F7B62675E7D1A4D6DEC48C1C7164586EAE06A51208C0B791244D307726505"
		"C3AD4B26B6822377257AA152037560A739714A3CA79BD605547C9B78DD1F596F"
		"2D4F1791BC689A0E9B799A37339C04275733740143EF5D2B58B96A363D4E0807"
		"6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB", exp1600, sizeof(exp1600));

	qsc_consoleutils_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake256_compute(output, sizeof(output), msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_256_kat: output does not match the known answer -DK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake256_compute(output, sizeof(output), msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_256_kat: output does not match the known answer -DK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_shake_initialize(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_256, hash, 4);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_256_kat: output does not match the known answer -DK3 \n");
		status = false;
	}

	return status;
}

static bool shake_512_kat()
{
	uint8_t exp1[512] = { 0 };
	uint8_t exp2[512] = { 0 };
	uint8_t hash[qsc_keccak_rate_512 * 8] = { 0 };
	uint8_t msg1[64] = { 0 };
	uint8_t msg2[200] = { 0 };
	uint8_t output[512] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("D6DEAAF94A391E987698B17E0AE2D8C6C96BEAC5DD2FFCB20F45665EFE39CFFE"
		"7ED119E38899BD3E8FD206A1A77B74F435D405BB837E61A62D97D5BAA203300A"
		"E689BA5F3B6659355964FED145065B3B0371C6CA4E466942B81BBD47CB2AE373"
		"8D630EFC00CBBBC0B11FF56C6AD16E1500980D94112F039003F9F36A3D05567B"
		"A3810BA76EC6E5893E3B2A0CBAFA9EEE123ED1BB64AA7AD4DD21A540EA14810D"
		"73611D6C1852A9726445199856CD52C054FBB92EE8A0BF83FB6BFCA5FA05C290"
		"AC2F58868140A07E23EE1634097E0414661352CAA4E4EDC88BF0D00AC6022C49"
		"A3AB60B1393C3FB56E668FD504C8D74F747E1C84DEB34C5560F5A421CB3F87CC"
		"741A380403378E7C7BE009724149FAB8F95BCBA485D7F45303E9DBF0B4596F60"
		"731FCF11DD90112670572964F2CFA72168212B41A640140253E55C09043CAEE3"
		"96C461B0B8C386329710BB0C562963D3C919A20A5BFA7310271319CB086C12F6"
		"7F62C4F6BECB52F8953688CE215436D53A0516F31C994AF16C121297385B6D83"
		"94875A3FB64A5CD9BC2004F319D358C37302E2524736F32DAEE5F2F09D6DFCC1"
		"1FCAE121536A1428D79F246E1FEFED8619E652BC1BA0CA8D840E624F5245E7CB"
		"F2A15CAA8880653B3746807CB83F52A6B2FBCFBA9E708702F5A8E68D79FCE865"
		"898CB646F40CC3CBAC51CC94729EDFD1754298B3AAEAE94D090240A7BBFE3FBA", exp1, sizeof(exp1));

	qsc_consoleutils_hex_to_bin("9701303D390F51968C25B6EEE54816D19AB149A1C06B0625940BB8E04A1CECCD"
		"D88010234F53ABBBAF181F49761A3ECEFAEE56DE7B59B5AAF0031E3C1552C9AC"
		"40DFAF6AAC934FD644DBC4A3D753E1F3845A5901F415DFF2A88440F6A8F5688F"
		"F26E68ECC6AD23ACF18E0A54BE745DB919FAB01F77A251D5F66B01E2426BF020"
		"BC27A6DFF274DC987313A42F1AC159F481A46F5BFB53914C7E79191F491C7808"
		"DE0EDF3BCA24FD7DFD713806C062326C16FFAC00D1F8E94BA2DA0DE06D5F1826"
		"A5AE881313AAD40FD0F260822ABB83ACC72E86006B1B04C28A0A30EAEB39040E"
		"BD0D4ADB76263BD1186464A5CBA30B4332C1ACC5328B989A998B5F5CA5184AE6"
		"DDAD039A3117C05C9CB2EA4DF5F8A2E8BD945EE42CE1789CE568D2BD7263DDF5"
		"6520D040BB406AD2D10DE2E3714D049381737CEA1AE05062650AFCE1B1DE1F77"
		"B418C7F7C4B1A5C233EF78FFC1D67215BEFDDCFA8E4C1CA64FF547B21DE12E20"
		"11D8214D0BBAB6645ED240313C4D86646BEC8F9D58B788227B535BFCB8B75448"
		"94E4A4BCD6DA9BF182DCEDD60348BD62579C898DBA9A6B6AA9E87E9C29F5855F"
		"57F138ACA68EB7B89DBE7DD09B217E94C4E57974E96A28868202D643F08DF096"
		"21AE714C2B47365DC44F608B97B5C5E0791EBE3C245CCCC1B537030EEDAA096F"
		"EF24013B7D401C9C7470375D97A6A26066CFB7B88E72F6D6B635E9F09DB2C007", exp2, sizeof(exp2));

	qsc_consoleutils_hex_to_bin("9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"
		"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10", msg1, sizeof(msg1));

	qsc_consoleutils_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg2, sizeof(msg2));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake512_compute(output, sizeof(output), msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(output, exp1, sizeof(exp1)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_512_kat: output does not match the known answer -DK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake512_compute(output, sizeof(output), msg2, sizeof(msg2));

	if (qsc_intutils_are_equal8(output, exp2, sizeof(exp2)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_512_kat: output does not match the known answer -DK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_shake_initialize(&state, qsc_keccak_rate_512, msg1, sizeof(msg1));
	qsc_shake_squeezeblocks(&state, qsc_keccak_rate_512, hash, 8);

	if (qsc_intutils_are_equal8(hash, exp1, sizeof(exp1)) == false)
	{
		qsc_consoleutils_print_safe("Failure! shake_512_kat: output does not match the known answer -DK3 \n");
		status = false;
	}

	return status;
}

static bool cshake_128_kat()
{
	uint8_t cust[15] = { 0 };
	uint8_t exp256a[32] = { 0 };
	uint8_t exp256b[32] = { 0 };
	uint8_t hashb[qsc_keccak_rate_128] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t name[1] = { 0 };
	uint8_t output[32] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsc_consoleutils_hex_to_bin("C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5", exp256a, sizeof(exp256a));
	qsc_consoleutils_hex_to_bin("C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B", exp256b, sizeof(exp256b));

	qsc_consoleutils_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_cshake128_compute(output, sizeof(output), msg32, sizeof(msg32), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp256a, sizeof(exp256a)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_128_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_cshake128_compute(output, sizeof(output), msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp256b, sizeof(exp256b)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_128_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_cshake_initialize(&state, qsc_keccak_rate_128, msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_128, hashb, 1);

	if (qsc_intutils_are_equal8(hashb, exp256b, sizeof(exp256b)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_128_kat: output does not match the known answer -CK3 \n");
		status = false;
	}

	return status;
}

static bool cshake_256_kat()
{
	uint8_t cust[15] = { 0 };
	uint8_t exp512a[64] = { 0 };
	uint8_t exp512b[64] = { 0 };
	uint8_t hashb[qsc_keccak_rate_256] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t name[1] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsc_consoleutils_hex_to_bin("D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1"
		"64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C", exp512a, sizeof(exp512a));
	qsc_consoleutils_hex_to_bin("07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917"
		"27F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB", exp512b, sizeof(exp512b));

	qsc_consoleutils_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_cshake256_compute(output, sizeof(output), msg32, sizeof(msg32), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp512a, sizeof(exp512a)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_cshake256_compute(output, sizeof(output), msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp512b, sizeof(exp512b)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	/* test long-form api */


	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_cshake_initialize(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_256, hashb, 1);

	if (qsc_intutils_are_equal8(hashb, exp512b, sizeof(exp512b)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK3 \n");
		status = false;
	}

	return status;
}

static bool cshake_512_kat()
{
	uint8_t exp512[64] = { 0 };
	uint8_t cust[15] = { 0 };
	uint8_t hashb[qsc_keccak_rate_512] = { 0 };
	uint8_t msg512[64] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsc_consoleutils_hex_to_bin("EF4BDC1F2B91B44C51048C81F5499DAC46F38C6E9CD81CEA3CB85E3A1913F8C4"
		"54CFE40F05370F7DE24E50FC49BBD188F42D2439F25DC2B3DB7CA2E38DC7E4A6", exp512, sizeof(exp512));

	qsc_consoleutils_hex_to_bin("9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"
		"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10", msg512, sizeof(msg512));

	status = true;

	/* test compact api */

	qsc_cshake512_compute(output, sizeof(output), msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp512, sizeof(exp512)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_512_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);

	qsc_cshake_initialize(&state, qsc_keccak_rate_512, msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_512, hashb, 1);

	if (qsc_intutils_are_equal8(hashb, exp512, sizeof(exp512)) == false)
	{
		qsc_consoleutils_print_safe("Failure! cshake_512_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	return status;
}

static bool kmac_128_kat()
{
	uint8_t cust0[1] = { 0 };
	uint8_t cust168[21] = { 0 };
	uint8_t exp256a[32] = { 0 };
	uint8_t exp256b[32] = { 0 };
	uint8_t exp256c[32] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t key256[32] = { 0 };
	uint8_t output[32] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));

	qsc_consoleutils_hex_to_bin("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E", exp256a, sizeof(exp256a));
	qsc_consoleutils_hex_to_bin("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5", exp256b, sizeof(exp256b));
	qsc_consoleutils_hex_to_bin("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230", exp256c, sizeof(exp256c));

	qsc_consoleutils_hex_to_bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", key256, sizeof(key256));

	qsc_consoleutils_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_kmac128_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust0, 0);

	if (qsc_intutils_are_equal8(output, exp256a, sizeof(exp256a)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac128_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256b, sizeof(exp256b)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac128_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_intutils_clear8(output, sizeof(output));

	qsc_kmac_initialize(&state, qsc_keccak_rate_128, key256, sizeof(key256), cust168, sizeof(cust168));
	qsc_kmac_update(&state, qsc_keccak_rate_128, msg1600, sizeof(msg1600));
	qsc_kmac_finalize(&state, qsc_keccak_rate_128, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

static bool kmac_256_kat()
{
	uint8_t cust0[1] = { 0 };
	uint8_t cust168[21] = { 0 };
	uint8_t exp256a[64] = { 0 };
	uint8_t exp256b[64] = { 0 };
	uint8_t exp256c[64] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t key256[32] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));

	qsc_consoleutils_hex_to_bin("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
		"F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD", exp256a, sizeof(exp256a));
	qsc_consoleutils_hex_to_bin("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691"
		"589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69", exp256b, sizeof(exp256b));
	qsc_consoleutils_hex_to_bin("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D9"
		"70FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965", exp256c, sizeof(exp256c));

	qsc_consoleutils_hex_to_bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", key256, sizeof(key256));

	qsc_consoleutils_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_kmac256_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256a, sizeof(exp256a)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust0, 0);

	if (qsc_intutils_are_equal8(output, exp256b, sizeof(exp256b)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_intutils_clear8(output, sizeof(output));

	qsc_kmac_initialize(&state, qsc_keccak_rate_256, key256, sizeof(key256), cust168, sizeof(cust168));
	qsc_kmac_update(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600));
	qsc_kmac_finalize(&state, qsc_keccak_rate_256, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

static bool kmac_512_kat()
{
	uint8_t cust0[21] = { 0 };
	uint8_t cust1[42] = { 0 };
	uint8_t cust2[45] = { 0 };
	uint8_t exp0[64] = { 0 };
	uint8_t exp1[64] = { 0 };
	uint8_t exp2[64] = { 0 };
	uint8_t key0[21] = { 0 };
	uint8_t key1[60] = { 0 };
	uint8_t msg0[42] = { 0 };
	uint8_t msg1[84] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust0, sizeof(cust0));
	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", cust1, sizeof(cust1));
	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920", cust2, sizeof(cust2));

	qsc_consoleutils_hex_to_bin("C41F31CEE9851BAA915716C16F7670C7C137C1908BD9694DA80C679AA6EB5964"
		"E76AD91F2018DE576524D84E0B0FC586C06B110ED6DB273A921FFC86D1C20CE8", exp0, sizeof(exp0));
	qsc_consoleutils_hex_to_bin("6535FB96EAB4F831D801E6C3C6E71755F4A56E8E711D376DDC564F5C6DACB8B5"
		"91EEF0503F433872B401FCEF8F05DA42FB950176C10FDB59395273FB9EDA39B8", exp1, sizeof(exp1));
	qsc_consoleutils_hex_to_bin("7BA4F7EE765960E6DA15D2CB51775DBA3E7B9279E5740469EF9FFD04C5246091"
		"9A99BEE5BFDA27163E2729A8E3B663BD963EF067C7CCABDE6F6EFFF9093E2A2F", exp2, sizeof(exp2));

	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E", key0, sizeof(key0));
	qsc_consoleutils_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B", key1, sizeof(key1));

	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", msg0, sizeof(msg0));
	qsc_consoleutils_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920546167676564204170706C69636174696F6E4D"
		"7920546167676564204170706C69636174696F6E", msg1, sizeof(msg1));
	status = true;

	/* test compact api */

	qsc_kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key0, sizeof(key0), cust0, sizeof(cust0));

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key1, sizeof(key1), cust2, sizeof(cust2));

	if (qsc_intutils_are_equal8(output, exp1, sizeof(exp1)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac512_compute(output, sizeof(output), msg1, sizeof(msg1), key0, sizeof(key0), cust1, sizeof(cust1));

	if (qsc_intutils_are_equal8(output, exp2, sizeof(exp2)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_intutils_clear8(output, sizeof(output));

	qsc_kmac_initialize(&state, qsc_keccak_rate_512, key0, sizeof(key0), cust1, sizeof(cust1));
	qsc_kmac_update(&state, qsc_keccak_rate_512, msg1, sizeof(msg1));
	qsc_kmac_finalize(&state, qsc_keccak_rate_512, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp2, sizeof(exp2)) == false)
	{
		qsc_consoleutils_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

/*** Public Tests ***/

bool qsc_selftest_aes_test()
{
	bool res;

	if (fips_aes128_cbc() == false)
	{
		res = false;
	}
	else if (fips_aes256_cbc() == false)
	{
		res = false;
	}
	else if (fips_aes128_ctr() == false)
	{
		res = false;
	}
	else if (fips_aes256_ctr() == false)
	{
		res = false;
	}
	else if (fips_aes128_ecb() == false)
	{
		res = false;
	}
	else if (fips_aes256_ecb() == false)
	{
		res = false;
	}
	else if (aes256_hba_kat() == false)
	{
		res = false;
	}
	else
	{
		res = true;
	}

	return res;
}

bool qsc_selftest_chacha_test()
{
	bool res;

	if (chacha128_kat() == false)
	{
		res = false;
	}
	else if (chacha256_kat() == false)
	{
		res = false;
	}
	else
	{
		res = true;
	}

	return res;
}

bool qsc_selftest_csx_test()
{
	bool res;

	res = csx512_kat();

	return res;
}

bool qsc_selftest_poly1305_test()
{
	bool res;

	res = poly1305_kat();

	return res;
}

bool qsc_selftest_rcs_test()
{
	bool res;

	if (rcs256_kat() == false)
	{
		res = false;
	}
	else if (rcs512_kat() == false)
	{
		res = false;
	}
	else
	{
		res = true;
	}

	return res;
}

bool qsc_selftest_sha2_test()
{
	bool res;

	if (sha2_256_kat() == false)
	{
		res = false;
	}
	else if (sha2_512_kat() == false)
	{
		res = false;
	}
	else if (hkdf_256_kat() == false)
	{
		res = false;
	}
	else if (hkdf_512_kat() == false)
	{
		res = false;
	}
	else if (hmac_256_kat() == false)
	{
		res = false;
	}
	else if (hmac_512_kat() == false)
	{
		res = false;
	}
	else
	{
		res = true;
	}

	return res;
}

bool qsc_selftest_sha3_test()
{
	bool res;

	if (sha3_256_kat() == false)
	{
		res = false;
	}
	else if (sha3_512_kat() == false)
	{
		res = false;
	}
	else if (shake_128_kat() == false)
	{
		res = false;
	}
	else if (shake_256_kat() == false)
	{
		res = false;
	}
	else if (shake_512_kat() == false)
	{
		res = false;
	}
	else if (cshake_128_kat() == false)
	{
		res = false;
	}
	else if (cshake_256_kat() == false)
	{
		res = false;
	}
	else if (cshake_512_kat() == false)
	{
		res = false;
	}
	else if (kmac_128_kat() == false)
	{
		res = false;
	}
	else if (kmac_256_kat() == false)
	{
		res = false;
	}
	else if (kmac_512_kat() == false)
	{
		res = false;
	}
	else
	{
		res = true;
	}

	return res;
}

bool qsc_selftest_symmetric_run()
{
	bool res;

	if (qsc_selftest_aes_test() == false)
	{
		res = false;
	}
	else if (qsc_selftest_chacha_test() == false)
	{
		res = false;
	}
	else if (qsc_selftest_csx_test() == false)
	{
		res = false;
	}
	else if (qsc_selftest_poly1305_test() == false)
	{
		res = false;
	}
	else if (qsc_selftest_rcs_test() == false)
	{
		res = false;
	}
	else if (qsc_selftest_sha2_test() == false)
	{
		res = false;
	}
	else if (qsc_selftest_sha3_test() == false)
	{
		res = false;
	}
	else
	{
		res = true;
	}

	return res;
}
