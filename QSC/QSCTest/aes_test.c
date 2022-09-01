#include "aes_test.h"
#include "../QSC/csp.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha2.h"
#include "../QSC/sha3.h"
#include "testutils.h"

#define AES_TEST_CYCLES 100
#define CTR_OUTPUT_LENGTH 33
#define HBA_TEST_CYCLES 100
#define MONTE_CARLO_CYCLES 10000

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
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

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
	qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);

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
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

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
	qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);

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
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

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

	qsc_memutils_copy(nce, nonce, QSC_AES_BLOCK_SIZE);
	state.nonce = nce;

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

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
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

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
	qsc_memutils_copy(nce, nonce, QSC_AES_BLOCK_SIZE);
	state.nonce = nce;

	/* initialize the state and create the round-keys; encrypt always equals true with ctr mode */
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

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
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_128);

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
	qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_128);

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
	qsc_aes_initialize(&state, &kp, true, qsc_aes_cipher_256);

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
	qsc_aes_initialize(&state, &kp, false, qsc_aes_cipher_256);

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

bool qsctest_fips_aes128_cbc()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F2.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("7649ABAC8119B246CEE98E9B12E9197D", exp[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("5086CB9B507219EE95DB113A917678B2", exp[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("73BED6B8E3C1743B7116E69E22229516", exp[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("3FF1CAA1681FAC09120ECA307586E1A7", exp[3], QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes128_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_fips_aes256_cbc()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };

	/* SP800-38a F2.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_AES256_KEY_SIZE);
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6", exp[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("9CFC4E967EDB808D679F777BC6702C7D", exp[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("39F23369A9D9BACFA530E26304231461", exp[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("B2EB05E2C39BE9FCDA6C19078C6A9D1B", exp[3], QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes256_cbc_monte_carlo(key, iv, msg, exp);
}

bool qsctest_fips_aes128_ctr()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("874D6191B620E3261BEF6864990DB6CE", exp[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("9806F66B7970FDFF8617187BB9FFFDFF", exp[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("5AE4DF3EDBD5D35E5B4F09020DB03EAB", exp[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("1E031DDA2FBE03D1792170A0F3009CEE", exp[3], QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes128_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_fips_aes256_ctr()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F5.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_AES256_KEY_SIZE);
	qsctest_hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("601EC313775789A5B7A7F504BBF3D228", exp[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F443E3CA4D62B59ACA84E990CACAF5C5", exp[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("2B0930DAA23DE94CE87017BA2D84988D", exp[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("DFC9C58DB67AADA613C2DD08457941A6", exp[3], QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes256_ctr_monte_carlo(key, nonce, msg, exp);
}

bool qsctest_fips_aes128_ecb()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES_BLOCK_SIZE] = { 0 };

	/* SP800-38a F1.1 */

	qsctest_hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("3AD77BB40D7A3660A89ECAF32466EF97", exp[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F5D3D58503B9699DE785895A96FDBAAF", exp[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("43B1CD7F598ECE23881B00E3ED030688", exp[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("7B0C785E27E8AD3F8223207104725DD4", exp[3], QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes128_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_fips_aes256_ecb()
{
	uint8_t exp[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t msg[4][QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };

	/* SP800-38a F1.5 */

	qsctest_hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, QSC_AES256_KEY_SIZE);

	qsctest_hex_to_bin("F3EED1BDB5D2A03C064B5A7E3DB181F8", exp[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("591CCB10D410ED26DC5BA74A31362870", exp[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("B6ED21B99CA6F4F9F153E7B1BEAFED1D", exp[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("23304B7A39F9F3FF067D8D8F9E24ECC7", exp[3], QSC_AES_BLOCK_SIZE);

	qsctest_hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], QSC_AES_BLOCK_SIZE);
	qsctest_hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], QSC_AES_BLOCK_SIZE);

	return aes256_ecb_monte_carlo(key, msg, exp);
}

bool qsctest_aes256_hba_kat()
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
	qsctest_hex_to_bin("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED", aad1, sizeof(aad1));
	qsctest_hex_to_bin("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2", aad2, sizeof(aad2));
	qsctest_hex_to_bin("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE", aad3, sizeof(aad3));
#if defined(QSC_HBA_KMAC_AUTH)
	qsctest_hex_to_bin("B9121B5448F0C737C9D1CB5DDF465CB3904D9ADC483352C11AEB4BF6C79EE81D0BF06A96DFA43A6278484BA791F90D55", exp1, sizeof(exp1));
	qsctest_hex_to_bin("C266FF3A9FD867F245C06B2A326784A076D26965F56B26BDBF084A17CD29D99A0D77B1A30DF708C1E4D421666279EA779FA7F05A78F52F8F488197B74563BA85", exp2, sizeof(exp2));
	qsctest_hex_to_bin("85B9D4BC71D2DA86E1B46547C5DAC28A811510357F3AE7F0A89AC35CFDB9FD91B1FD0FEA03ACAD19E449EDA57CCFB5D7C5DADF1902868F49A978A769A1939792"
		"3D2F5AF93DCE9C070695D298D94D5AE015579AF8FED2FBB7100F97DA2F10E45D", exp3, sizeof(exp3));
#else
	qsctest_hex_to_bin("092A9F2D02A0020AC9B0963AA081349A36BA8596C961C96B5CA0F385F6C4F9A13F80BEE20461E3B94A8AD696D7B971E2", exp1, sizeof(exp1));
	qsctest_hex_to_bin("64B05F05D96C40E4860733BB055076BF52E57086125C4C11CC6EC558C40E25E6636973BDB1D89701F9A5E94B785EC88B86717893F07A089C8DD87319B6168210", exp2, sizeof(exp2));
	qsctest_hex_to_bin("072B28CEA1AD0EF851E005D8925C55E7CEDF3ECB6B7E0FA54808E86CEE32CCC300C462505C3D97B9CC4F746DBBF4D4F8EEE7D4A016FC27C56AAA975815516C3A"
		"C06F0FF880A783102703462DF71B45D5F0A52670EE48A7CDBED063AB7980047B", exp3, sizeof(exp3));
#endif
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsctest_hex_to_bin("00000000000000000000000000000001", msg1, sizeof(msg1));
	qsctest_hex_to_bin("1000000000000000000000000000000000000000000000000000000000000000", msg2, sizeof(msg2));
	qsctest_hex_to_bin("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255", msg3, sizeof(msg3));
	qsctest_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0", nce1, sizeof(nce1));
	qsctest_hex_to_bin("10000000000000000000000000000000", nce2, sizeof(nce2));
	qsctest_hex_to_bin("00000000000000000000000000000001", nce3, sizeof(nce3));

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

bool qsctest_aes256_hba_stress()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	qsc_aes_hba256_state state;

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
			qsc_memutils_copy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)qsc_memutils_malloc(mlen);
		enc = (uint8_t*)qsc_memutils_malloc((size_t)mlen + QSC_HBA256_MAC_LENGTH);
		msg = (uint8_t*)qsc_memutils_malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, (size_t)mlen + QSC_HBA256_MAC_LENGTH);
			qsc_intutils_clear8(msg, mlen);
			qsc_memutils_copy(nonce, ncopy, QSC_AES_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_aes_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			qsc_aes_hba256_initialize(&state, &kp1, true);
			qsc_aes_hba256_set_associated(&state, aad, sizeof(aad));

			if (qsc_aes_hba256_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			qsc_memutils_copy(kp1.nonce, ncopy, QSC_AES_BLOCK_SIZE);

			/* decrypt the message */
			qsc_aes_hba256_initialize(&state, &kp1, false);
			qsc_aes_hba256_set_associated(&state, aad, sizeof(aad));

			if (qsc_aes_hba256_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
			}

			qsc_memutils_alloc_free(dec);
			qsc_memutils_alloc_free(enc);
			qsc_memutils_alloc_free(msg);

			++tctr;
		}
		else
		{
			status = false;
		}
	}

	return status;
}

bool qsctest_aes256_padding_test()
{
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[1] = { 0 };
	size_t mlen;
	size_t tctr;
	bool status;

	tctr = 0;
	status = true;
	mlen = 0;

	/* test padding random iv sizes */

	while (tctr < AES_TEST_CYCLES)
	{
		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			qsc_memutils_copy(&mlen, pmcnt, sizeof(uint8_t));

			while (mlen >= QSC_AES_BLOCK_SIZE)
			{
				mlen >>= 1;
			} 
		} 
		while (mlen == 0);

		qsc_intutils_clear8(iv, sizeof(iv));
		qsc_csp_generate(iv, mlen);

		qsc_pkcs7_add_padding(iv, QSC_AES_BLOCK_SIZE - mlen);

		if (qsc_pkcs7_padding_length(iv) != QSC_AES_BLOCK_SIZE - mlen)
		{
			status = false;
			break;
		}

		++tctr;
	}

	/* test coincidental occurences */

	/* note that on an unpadded block, if the last byte in that block is coincidentally set to one,
	the padding will be counted, this is an expected limitation of the PKCS7 padding mode */

	for (size_t i = 2; i < QSC_AES_BLOCK_SIZE; ++i)
	{
		qsc_csp_generate(iv, sizeof(iv));
		iv[QSC_AES_BLOCK_SIZE - 1] = (uint8_t)i;

		if (qsc_pkcs7_padding_length(iv) != 0)
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
		qsctest_print_safe("Success! Passed the FIPS 197 qsc_aes_mode_cbc(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 qsc_aes_mode_cbc(AES-128) qsc_aes_mode_cbc KAT test. \n");
	}

	if (qsctest_fips_aes256_cbc() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 qsc_aes_mode_cbc(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 qsc_aes_mode_cbc(AES-256) qsc_aes_mode_cbc KAT test. \n");
	}

	if (qsctest_fips_aes128_ctr() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 qsc_aes_mode_ctr(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 qsc_aes_mode_ctr(AES-128) KAT test. \n");
	}

	if (qsctest_fips_aes256_ctr() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 qsc_aes_mode_ctr(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 qsc_aes_mode_ctr(AES-256) KAT test. \n");
	}

	if (qsctest_fips_aes128_ecb() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 qsc_aes_mode_ecb(AES-128) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 qsc_aes_mode_ecb(AES-128) KAT test. \n");
	}

	if (qsctest_fips_aes256_ecb() == true)
	{
		qsctest_print_safe("Success! Passed the FIPS 197 qsc_aes_mode_ecb(AES-256) KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the FIPS 197 qsc_aes_mode_ecb(AES-256) KAT test. \n");
	}

	if (qsctest_aes256_hba_kat() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-256 HBA AEAD mode KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-256 HBA AEAD mode KAT test. \n");
	}

	if (qsctest_aes256_hba_stress() == true)
	{
		qsctest_print_safe("Success! Passed the RHX-256 HBA AEAD mode stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RHX-256 HBA AEAD mode stress test. \n");
	}

	if (qsctest_aes256_padding_test() == true)
	{
		qsctest_print_safe("Success! Passed the PKCS7 padding mode stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the PKCS7 padding mode stress test. \n");
	}
}
