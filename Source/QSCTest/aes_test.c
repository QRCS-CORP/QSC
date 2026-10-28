/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "aes_test.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"
#include "sha3.h"
#include "testutils.h"

#define AES_TEST_CYCLES 100
#define CTR_OUTPUT_SIZE 33
#define HBA_TEST_CYCLES 100
#define MONTE_CARLO_CYCLES 10000

static bool aes128_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t (*message)[16], const uint8_t (*expected)[16])
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
	const qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES128_KEY_SIZE, .nonce = ivc, .noncelen = QSC_AES_BLOCK_SIZE };

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

static bool aes256_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t (*message)[16], const uint8_t (*expected)[16])
{
	uint8_t ivc[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	qsc_memutils_copy(ivc, iv, QSC_AES_BLOCK_SIZE);
	/* initialize the key parameters struct, info is optional */
	const qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES256_KEY_SIZE, .nonce = ivc, .noncelen = QSC_AES_BLOCK_SIZE };

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

static bool aes128_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t (*message)[16], const uint8_t (*expected)[16])
{
	uint8_t nce[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* initialize the key parameters struct with key and nonce, info not used in AES */
	qsc_memutils_copy(nce, nonce, QSC_AES_BLOCK_SIZE);
	const qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES128_KEY_SIZE, .nonce = nce, .noncelen = QSC_AES_BLOCK_SIZE };
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

static bool aes256_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t (*message)[16], const uint8_t (*expected)[16])
{
	uint8_t nce[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* initialize the key parameters struct with key and nonce, info is optional */
	qsc_memutils_copy(nce, nonce, QSC_AES_BLOCK_SIZE);
	qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES256_KEY_SIZE, .nonce = nce, .noncelen = QSC_AES_BLOCK_SIZE };
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

static bool aes128_ecb_monte_carlo(const uint8_t* key, const uint8_t (*message)[16], const uint8_t (*expected)[16])
{
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	status = true;

	/* initialize the key parameters struct, info is optional */
	qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES128_KEY_SIZE };

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

static bool aes256_ecb_monte_carlo(const uint8_t* key, const uint8_t (*message)[16], const uint8_t (*expected)[16])
{
	uint8_t out[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	bool status;
	qsc_aes_state state;

	/* initialize the key parameters struct, info is optional */
	qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES256_KEY_SIZE };
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

/**
 * \brief Check the AES-128-GCM four-block GHASH path against an independent
 * OpenSSL reference tag, including AAD, in-place decryption and rejection.
 * \param length: [size_t] Plaintext byte count, at most 4096 bytes.
 * \param ivlen: [size_t] Nonce length, either 12 or 17 bytes.
 * \param hex_tag: [const char*] Expected 16-byte OpenSSL AES-GCM tag in hex.
 * \return [bool] True only if encryption, authentication, in-place recovery,
 * and bad-tag rejection all behave correctly.
 * \note No ownership transfer, no heap allocation, separate initialization
 * for each operation. The test ciphertext is deterministic test material only.
 */
static bool aes_gcm128_fold_case(size_t length, size_t ivlen, const char* hex_tag)
{
	qsc_aes_gcm128_state state = { 0 };
	uint8_t aad[23U] = { 0U };
	uint8_t buf[4096U + QSC_GCM128_MAC_SIZE] = { 0U };
	uint8_t ciphertext[4096U + QSC_GCM128_MAC_SIZE] = { 0U };
	uint8_t tag[QSC_GCM128_MAC_SIZE] = { 0U };
	uint8_t iv[17U] = { 0U };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0U };
	qsc_aes_keyparams kp;
	size_t i;
	bool result;

	result = length <= 4096U && ivlen <= sizeof(iv);
	for (i = 0U; i < sizeof(key); ++i)
	{
		key[i] = (uint8_t)(i * 7U + 2U);
	}
	for (i = 0U; i < sizeof(iv); ++i)
	{
		iv[i] = (uint8_t)(i * 11U + 3U);
	}
	for (i = 0U; i < sizeof(aad); ++i)
	{
		aad[i] = (uint8_t)(i * 5U + 4U);
	}
	for (i = 0U; i < length && result; ++i)
	{
		buf[i] = (uint8_t)(i * 29U + 1U);
	}
	if (result)
	{
		qsctest_hex_to_bin(hex_tag, tag, sizeof(tag));
		kp.key = key;
		kp.keylen = sizeof(key);
		kp.nonce = iv;
		kp.noncelen = ivlen;
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_aes_gcm128_initialize(&state, &kp, true);
		qsc_aes_gcm128_set_associated(&state, aad, sizeof(aad));
		qsc_aes_gcm128_encrypt(&state, buf, buf, length);
		result = qsc_intutils_are_equal8(buf + length, tag, sizeof(tag));
		qsc_memutils_copy(ciphertext, buf, length + sizeof(tag));
		qsc_aes_gcm128_dispose(&state);
	}
	if (result)
	{
		qsc_aes_gcm128_initialize(&state, &kp, false);
		qsc_aes_gcm128_set_associated(&state, aad, sizeof(aad));
		result = qsc_aes_gcm128_decrypt(&state, buf, buf, length + sizeof(tag));
		qsc_aes_gcm128_dispose(&state);
	}
	for (i = 0U; i < length && result; ++i)
	{
		if (buf[i] != (uint8_t)(i * 29U + 1U))
		{
			result = false;
		}
	}
	if (result)
	{
		ciphertext[length + sizeof(tag) - 1U] ^= 0x01U;
		qsc_aes_gcm128_initialize(&state, &kp, false);
		qsc_aes_gcm128_set_associated(&state, aad, sizeof(aad));
		result = !qsc_aes_gcm128_decrypt(&state, buf, ciphertext, length + sizeof(tag));
		qsc_aes_gcm128_dispose(&state);
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	qsc_memutils_secure_erase(buf, sizeof(buf));
	qsc_memutils_secure_erase(ciphertext, sizeof(ciphertext));
	return result;
}

/**
 * \brief Check the AES-256-GCM four-block GHASH path against an independent
 * OpenSSL reference tag, including AAD, in-place decryption and rejection.
 * \param length: [size_t] Plaintext byte count, at most 4096 bytes.
 * \param ivlen: [size_t] Nonce length, either 12 or 17 bytes.
 * \param hex_tag: [const char*] Expected 16-byte OpenSSL AES-GCM tag in hex.
 * \return [bool] True only if encryption, authentication, in-place recovery,
 * and bad-tag rejection all behave correctly.
 * \note No ownership transfer, no heap allocation, separate initialization
 * for each operation. The test ciphertext is deterministic test material only.
 */
static bool aes_gcm256_fold_case(size_t length, size_t ivlen, const char* hex_tag)
{
	qsc_aes_gcm256_state state = { 0 };
	uint8_t aad[23U] = { 0U };
	uint8_t buf[4096U + QSC_GCM256_MAC_SIZE] = { 0U };
	uint8_t ciphertext[4096U + QSC_GCM256_MAC_SIZE] = { 0U };
	uint8_t tag[QSC_GCM256_MAC_SIZE] = { 0U };
	uint8_t iv[17U] = { 0U };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
	qsc_aes_keyparams kp;
	size_t i;
	bool result;

	result = length <= 4096U && ivlen <= sizeof(iv);
	for (i = 0U; i < sizeof(key); ++i)
	{
		key[i] = (uint8_t)(i * 7U + 2U);
	}
	for (i = 0U; i < sizeof(iv); ++i)
	{
		iv[i] = (uint8_t)(i * 11U + 3U);
	}
	for (i = 0U; i < sizeof(aad); ++i)
	{
		aad[i] = (uint8_t)(i * 5U + 4U);
	}
	for (i = 0U; i < length && result; ++i)
	{
		buf[i] = (uint8_t)(i * 29U + 1U);
	}
	if (result)
	{
		qsctest_hex_to_bin(hex_tag, tag, sizeof(tag));
		kp.key = key;
		kp.keylen = sizeof(key);
		kp.nonce = iv;
		kp.noncelen = ivlen;
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_aes_gcm256_initialize(&state, &kp, true);
		qsc_aes_gcm256_set_associated(&state, aad, sizeof(aad));
		qsc_aes_gcm256_encrypt(&state, buf, buf, length);
		result = qsc_intutils_are_equal8(buf + length, tag, sizeof(tag));
		qsc_memutils_copy(ciphertext, buf, length + sizeof(tag));
		qsc_aes_gcm256_dispose(&state);
	}
	if (result)
	{
		qsc_aes_gcm256_initialize(&state, &kp, false);
		qsc_aes_gcm256_set_associated(&state, aad, sizeof(aad));
		result = qsc_aes_gcm256_decrypt(&state, buf, buf, length + sizeof(tag));
		qsc_aes_gcm256_dispose(&state);
	}
	for (i = 0U; i < length && result; ++i)
	{
		if (buf[i] != (uint8_t)(i * 29U + 1U))
		{
			result = false;
		}
	}
	if (result)
	{
		ciphertext[length + sizeof(tag) - 1U] ^= 0x01U;
		qsc_aes_gcm256_initialize(&state, &kp, false);
		qsc_aes_gcm256_set_associated(&state, aad, sizeof(aad));
		result = !qsc_aes_gcm256_decrypt(&state, buf, ciphertext, length + sizeof(tag));
		qsc_aes_gcm256_dispose(&state);
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	qsc_memutils_secure_erase(buf, sizeof(buf));
	qsc_memutils_secure_erase(ciphertext, sizeof(ciphertext));
	return result;
}

bool qsctest_aes128_gcm_kat()
{
	/* Test vector parameters from NIST SP800-38D for AES-128 GCM (Test Case 2) */
	qsc_aes_gcm128_state state = { 0 };
	uint8_t ctxt[QSC_AES_BLOCK_SIZE + QSC_GCM128_MAC_SIZE] = { 0 };
	uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t exp[QSC_AES_BLOCK_SIZE + QSC_GCM128_MAC_SIZE] = { 0 };
	uint8_t exp2[QSC_AES_BLOCK_SIZE + QSC_GCM128_MAC_SIZE] = { 0 };
	uint8_t iv[QSC_GCM_NONCE_SIZE] = { 0 };        /* 96-bit IV */
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t shdr[QSC_AES128_KEY_SIZE] = { 0x80 };  /* 16-byte AAD: 0x80 followed by zeros */
	uint8_t ptxt[QSC_AES_BLOCK_SIZE] = { 0 };      /* 16-byte plaintext (all zeros) */
	bool status;

	status = true;

	qsctest_hex_to_bin("00000000000000000000000000000000", key, sizeof(key));
	qsctest_hex_to_bin("000000000000000000000000", iv, sizeof(iv));
	qsctest_hex_to_bin("00000000000000000000000000000000", ptxt, sizeof(ptxt));
	/* CT = 0388DACE60B6A392F328C2B971B2FE78, Tag = AB6E47D42CEC13BDF53A67B21257BDDF */
	qsctest_hex_to_bin("0388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257BDDF", exp, sizeof(exp));
	/* CT = 0388DACE60B6A392F328C2B971B2FE78, Tag (with AAD) = 7004A3BB7A214A7B8691637A5D86179D */
	qsctest_hex_to_bin("0388DACE60B6A392F328C2B971B2FE787004A3BB7A214A7B8691637A5D86179D", exp2, sizeof(exp2));

	qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES128_KEY_SIZE, .nonce = iv, .noncelen = QSC_GCM_NONCE_SIZE, .info = NULL, .infolen = 0 };

	/* encryption test */
	qsc_aes_gcm128_initialize(&state, &kp, true);
	qsc_aes_gcm128_encrypt(&state, ctxt, ptxt, sizeof(ptxt));

	if (qsc_intutils_are_equal8(ctxt, exp, sizeof(exp)) == false)
	{
		status = false;
	}

	qsc_aes_gcm128_dispose(&state);

	/* decryption test */

	/* reinitialize the state (to reset the counter) for decryption */
	qsc_memutils_clear(iv, sizeof(iv));
	qsc_aes_gcm128_initialize(&state, &kp, false);

	if (qsc_aes_gcm128_decrypt(&state, dec, ctxt, sizeof(ctxt)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, ptxt, sizeof(ptxt)) == false)
	{
		status = false;
	}

	/* test the AEAD function */

	/* encryption test */
	qsc_aes_gcm128_initialize(&state, &kp, true);
	qsc_aes_gcm128_set_associated(&state, shdr, sizeof(shdr));
	qsc_aes_gcm128_transform(&state, ctxt, ptxt, sizeof(ptxt));

	if (qsc_intutils_are_equal8(ctxt, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	qsc_aes_gcm128_dispose(&state);

	/* decryption test */
	qsc_memutils_clear(iv, sizeof(iv));
	qsc_aes_gcm128_initialize(&state, &kp, false);
	qsc_aes_gcm128_set_associated(&state, shdr, sizeof(shdr));

	if (qsc_aes_gcm128_transform(&state, dec, ctxt, sizeof(ptxt)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, ptxt, sizeof(ptxt)) == false)
	{
		status = false;
	}

	return status;
}

bool qsctest_aes256_gcm_kat()
{
    /* Test vector parameters from NIST SP800-38D for AES-256 GCM */
	qsc_aes_gcm256_state state = { 0 };
    uint8_t ctxt[QSC_AES_BLOCK_SIZE + QSC_GCM256_MAC_SIZE] = { 0 };
    uint8_t dec[QSC_AES_BLOCK_SIZE] = { 0 };
    uint8_t exp[QSC_AES_BLOCK_SIZE + QSC_GCM256_MAC_SIZE] = { 0 };
	uint8_t exp2[QSC_AES_BLOCK_SIZE + QSC_GCM256_MAC_SIZE] = { 0 };
    uint8_t iv[QSC_GCM_NONCE_SIZE] = { 0 }; /* 96-bit IV */
    uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t shdr[QSC_AES256_KEY_SIZE] = { 0x80 };
    uint8_t ptxt[QSC_AES_BLOCK_SIZE] = { 0 }; /* 16-byte plaintext (all zeros) */
    bool status;

	status = true;

    qsctest_hex_to_bin("0000000000000000000000000000000000000000000000000000000000000000", key, sizeof(key));
    qsctest_hex_to_bin("000000000000000000000000", iv, sizeof(iv));
    qsctest_hex_to_bin("00000000000000000000000000000000", ptxt, sizeof(ptxt));
    qsctest_hex_to_bin("CEA7403D4D606B6E074EC5D3BAF39D18D0D1C8A799996BF0265B98B5D48AB919", exp, sizeof(exp));
	qsctest_hex_to_bin("CEA7403D4D606B6E074EC5D3BAF39D180839260DFD972BAAF4E6D9D37948C842", exp2, sizeof(exp2));

	qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES256_KEY_SIZE, .nonce = iv, .noncelen = QSC_GCM_NONCE_SIZE, .info = NULL, .infolen = 0 };

    /* encryption test */
    qsc_aes_gcm256_initialize(&state, &kp, true);
    qsc_aes_gcm256_encrypt(&state, ctxt, ptxt, sizeof(ptxt));

    if (qsc_intutils_are_equal8(ctxt, exp, sizeof(exp)) == false)
    {
        status = false;
    }

	qsc_aes_gcm256_dispose(&state);

    /* decryption test */

    /* reinitialize the state (to reset the counter) for decryption */
	qsc_memutils_clear(iv, sizeof(iv));
    qsc_aes_gcm256_initialize(&state, &kp, false);

    if (qsc_aes_gcm256_decrypt(&state, dec, ctxt, sizeof(ctxt)) == false)
    {
        status = false;
    }

    if (qsc_intutils_are_equal8(dec, ptxt, sizeof(ptxt)) == false)
    {
        status = false;
    }

	/* test the AEAD function */

	/* encryption test */
	qsc_aes_gcm256_initialize(&state, &kp, true);
	qsc_aes_gcm256_set_associated(&state, shdr, sizeof(shdr));
	qsc_aes_gcm256_transform(&state, ctxt, ptxt, sizeof(ptxt));

	if (qsc_intutils_are_equal8(ctxt, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	qsc_aes_gcm256_dispose(&state);

	/* decryption test */

	qsc_memutils_clear(iv, sizeof(iv));
	qsc_aes_gcm256_initialize(&state, &kp, false);
	qsc_aes_gcm256_set_associated(&state, shdr, sizeof(shdr));

	if (qsc_aes_gcm256_transform(&state, dec, ctxt, sizeof(ptxt)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, ptxt, sizeof(ptxt)) == false)
	{
		status = false;
	}

    return status;
}

bool qsctest_aes256_hba_kat()
{
	uint8_t aad1[20] = { 0 };
	uint8_t aad2[20] = { 0 };
	uint8_t aad3[20] = { 0 };
	uint8_t dec1[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t dec2[QSC_AES_BLOCK_SIZE * 2] = { 0 };
	uint8_t dec3[QSC_AES_BLOCK_SIZE * 4] = { 0 };
	uint8_t exp1[QSC_AES_BLOCK_SIZE + QSC_HBA256_MAC_SIZE] = { 0 };
	uint8_t exp2[(QSC_AES_BLOCK_SIZE * 2) + QSC_HBA256_MAC_SIZE] = { 0 };
	uint8_t exp3[(QSC_AES_BLOCK_SIZE * 4) + QSC_HBA256_MAC_SIZE] = { 0 };
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
	uint8_t enc1[QSC_AES_BLOCK_SIZE + QSC_HBA256_MAC_SIZE] = { 0 };
	uint8_t enc2[(QSC_AES_BLOCK_SIZE * 2) + QSC_HBA256_MAC_SIZE] = { 0 };
	uint8_t enc3[(QSC_AES_BLOCK_SIZE * 4) + QSC_HBA256_MAC_SIZE] = { 0 };
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

	const qsc_aes_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = nce1, .noncelen = sizeof(nce1) };

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

	if (qsc_aes_hba256_transform(&state, dec1, enc1, sizeof(enc1) - QSC_HBA256_MAC_SIZE) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec1, msg1, sizeof(msg1)) == false)
	{
		status = false;
	}

	/* second KAT vector */

	const qsc_aes_keyparams kp2 = { .key = key, .keylen = sizeof(key), .nonce = nce2, .noncelen = sizeof(nce2) };
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

	if (qsc_aes_hba256_transform(&state, dec2, enc2, sizeof(enc2) - QSC_HBA256_MAC_SIZE) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec2, msg2, sizeof(msg2)) == false)
	{
		status = false;
	}

	/* third KAT vector */

	const qsc_aes_keyparams kp3 = { .key = key, .keylen = sizeof(key), .nonce = nce3, .noncelen = sizeof(nce3) };
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

	if (qsc_aes_hba256_transform(&state, dec3, enc3, sizeof(enc3) - QSC_HBA256_MAC_SIZE) == false)
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
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t ncopy[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t* msg;
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
		enc = (uint8_t*)qsc_memutils_malloc((size_t)mlen + QSC_HBA256_MAC_SIZE);
		msg = (uint8_t*)qsc_memutils_malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, (size_t)mlen + QSC_HBA256_MAC_SIZE);
			qsc_intutils_clear8(msg, mlen);
			qsc_memutils_copy(nonce, ncopy, QSC_AES_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_aes_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = nonce, .noncelen = sizeof(nonce) };

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

/*!
 * \brief Verify CTR counter rollover against independent ECB-block expansion.
 * \details Exercises either endian convention and verifies the complete
 * 128-bit caller-owned nonce, including carry between 64-bit words. This
 * check has no OpenSSL build dependency.
 * \param length: [size_t] Number of input bytes, up to 257.
 * \param bigendian: [bool] Counter byte order.
 * \param aes128: [bool] AES-128 when true, otherwise AES-256.
 * \param rollover: [uint8_t] Zero: ordinary; one: 64-bit carry; two: 128-bit wrap;
 * three: low word UINT64_MAX-8; four: low word UINT64_MAX-7.
 * \return [bool] True if output and final counter match independent reference.
 */
static bool aes_ctr_boundary_case(size_t length, bool bigendian, bool aes128, uint8_t rollover)
{
	const uint8_t key[QSC_AES256_KEY_SIZE] = { 0x10U, 0x21U, 0x32U, 0x43U, 0x54U, 0x65U, 0x76U, 0x87U,
		0x98U, 0xA9U, 0xBAU, 0xCBU, 0xDCU, 0xEDU, 0xFEU, 0x0FU,
		0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
		0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0U };
	uint8_t refnonce[QSC_AES_BLOCK_SIZE] = { 0U };
	uint8_t input[257U] = { 0U };
	uint8_t output[257U] = { 0U };
	uint8_t expected[257U] = { 0U };
	uint8_t keystream[QSC_AES_BLOCK_SIZE] = { 0U };
	qsc_aes_state ctx = { 0U };
	qsc_aes_keyparams kp = { 0U };
	bool status;
	size_t i;
	size_t j;
	size_t n;

	status = (length > 0U && length <= sizeof(input));

	if (status == true)
	{
		for (i = 0U; i < sizeof(nonce); ++i)
		{
			nonce[i] = (uint8_t)(0x20U + i);
		}

		if (rollover != 0U)
		{
			if (rollover == 2U)
			{
				qsc_memutils_set_value(nonce, sizeof(nonce), 0xFFU);
			}

			if (bigendian == true)
			{
				nonce[8U] = 0xFFU;
				nonce[9U] = 0xFFU;
				nonce[10U] = 0xFFU;
				nonce[11U] = 0xFFU;
				nonce[12U] = 0xFFU;
				nonce[13U] = 0xFFU;
				nonce[14U] = 0xFFU;
				nonce[15U] = 0xFEU;
			}
			else
			{
				nonce[0U] = 0xFEU;
				nonce[1U] = 0xFFU;
				nonce[2U] = 0xFFU;
				nonce[3U] = 0xFFU;
				nonce[4U] = 0xFFU;
				nonce[5U] = 0xFFU;
				nonce[6U] = 0xFFU;
				nonce[7U] = 0xFFU;
			}

			if (rollover == 3U || rollover == 4U)
			{
				/* Exercise both sides of the fast/slow carry threshold. */
				if (bigendian == true)
				{
					nonce[15U] = (rollover == 3U) ? 0xF7U : 0xF8U;
				}
				else
				{
					nonce[0U] = (rollover == 3U) ? 0xF7U : 0xF8U;
				}
			}
		}

		qsc_memutils_copy(refnonce, nonce, sizeof(nonce));

		for (i = 0U; i < length; ++i)
		{
			input[i] = (uint8_t)(i * 17U + 3U);
		}

		kp.key = key;
		kp.keylen = (aes128 == true) ? QSC_AES128_KEY_SIZE : QSC_AES256_KEY_SIZE;
		kp.nonce = nonce;
		kp.noncelen = sizeof(nonce);
		qsc_aes_initialize(&ctx, &kp, true, (aes128 == true) ? qsc_aes_cipher_128 : qsc_aes_cipher_256);

		if (bigendian == true)
		{
			qsc_aes_ctrbe_transform(&ctx, output, input, length);
		}
		else
		{
			qsc_aes_ctrle_transform(&ctx, output, input, length);
		}

		for (i = 0U; i < length; i += QSC_AES_BLOCK_SIZE)
		{
			n = ((length - i) < QSC_AES_BLOCK_SIZE) ? (length - i) : QSC_AES_BLOCK_SIZE;
			qsc_aes_ecb_encrypt_block(&ctx, keystream, refnonce);

			for (j = 0U; j < n; ++j)
			{
				expected[i + j] = (uint8_t)(input[i + j] ^ keystream[j]);
			}

			if (bigendian == true)
			{
				qsc_intutils_be8increment(refnonce, sizeof(refnonce));
			}
			else
			{
				qsc_intutils_le8increment(refnonce, sizeof(refnonce));
			}
		}

		status = qsc_intutils_are_equal8(output, expected, length) &&
			qsc_intutils_are_equal8(nonce, refnonce, sizeof(nonce));
		qsc_aes_dispose(&ctx);
		qsc_memutils_secure_erase(keystream, sizeof(keystream));
	}

	return status;
}

void qsctest_aes_run()
{
	qsctest_print_line("AES-CTR 128-bit carry and four-block regression stage:");

	if (aes_ctr_boundary_case(17U, true, true, 1U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-BE low-64 rollover at 17 bytes.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-BE low-64 rollover at 17 bytes.");
	}

	if (aes_ctr_boundary_case(64U, true, false, 1U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-BE low-64 rollover across four blocks.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-BE low-64 rollover across four blocks.");
	}

	if (aes_ctr_boundary_case(257U, true, false, 0U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-BE partial tail and multi-block nonce advancement.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-BE partial tail and multi-block nonce advancement.");
	}

	if (aes_ctr_boundary_case(17U, false, true, 1U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-LE low-64 rollover at 17 bytes.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-LE low-64 rollover at 17 bytes.");
	}

	if (aes_ctr_boundary_case(64U, false, false, 1U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-LE low-64 rollover across four blocks.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-LE low-64 rollover across four blocks.");
	}

	if (aes_ctr_boundary_case(64U, true, false, 2U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-BE complete 128-bit counter wrap.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-BE complete 128-bit counter wrap.");
	}

	if (aes_ctr_boundary_case(64U, false, false, 2U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-LE complete 128-bit counter wrap.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-LE complete 128-bit counter wrap.");
	}

	if (aes_ctr_boundary_case(257U, false, false, 0U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-LE partial tail and multi-block nonce advancement.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-LE partial tail and multi-block nonce advancement.");
	}

	qsctest_print_line("AES-CTR eight-chain fast/rollover carry-threshold regression stage:");

	if (aes_ctr_boundary_case(128U, true, true, 3U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-BE fast-limit threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-BE fast-limit threshold.");
	}

	if (aes_ctr_boundary_case(129U, true, true, 4U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-BE rollover threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-BE rollover threshold.");
	}

	if (aes_ctr_boundary_case(128U, true, false, 3U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-BE fast-limit threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-BE fast-limit threshold.");
	}

	if (aes_ctr_boundary_case(129U, true, false, 4U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-BE rollover threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-BE rollover threshold.");
	}

	if (aes_ctr_boundary_case(128U, false, true, 3U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-LE fast-limit threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-LE fast-limit threshold.");
	}

	if (aes_ctr_boundary_case(129U, false, true, 4U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-LE rollover threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-LE rollover threshold.");
	}

	if (aes_ctr_boundary_case(128U, false, false, 3U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-LE fast-limit threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-LE fast-limit threshold.");
	}

	if (aes_ctr_boundary_case(129U, false, false, 4U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-LE rollover threshold.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-LE rollover threshold.");
	}

	qsctest_print_line("AES-CTR eight-chain intrinsic regression stage:");

	if (aes_ctr_boundary_case(128U, true, true, 0U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-BE eight-block exact boundary.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-BE eight-block exact boundary.");
	}

	if (aes_ctr_boundary_case(129U, true, false, 0U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-BE eight-block plus tail.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-BE eight-block plus tail.");
	}

	if (aes_ctr_boundary_case(256U, true, false, 1U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-BE carry across two eight-block groups.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-BE carry across two eight-block groups.");
	}

	if (aes_ctr_boundary_case(257U, true, true, 2U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-BE complete wrap with partial tail.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-BE complete wrap with partial tail.");
	}

	if (aes_ctr_boundary_case(128U, false, true, 0U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-LE eight-block exact boundary.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-LE eight-block exact boundary.");
	}

	if (aes_ctr_boundary_case(129U, false, false, 0U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-LE eight-block plus tail.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-LE eight-block plus tail.");
	}

	if (aes_ctr_boundary_case(256U, false, false, 1U) == true)
	{
		qsctest_print_line("PASS: AES-256 CTR-LE carry across two eight-block groups.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256 CTR-LE carry across two eight-block groups.");
	}

	if (aes_ctr_boundary_case(257U, false, true, 2U) == true)
	{
		qsctest_print_line("PASS: AES-128 CTR-LE complete wrap with partial tail.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128 CTR-LE complete wrap with partial tail.");
	}

	if (qsctest_fips_aes128_cbc() == true)
	{
		qsctest_print_line("Success! Passed the FIPS 197 CBC(AES-128) KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the FIPS 197 CBC(AES-128) CBC KAT test.");
	}

	if (qsctest_fips_aes256_cbc() == true)
	{
		qsctest_print_line("Success! Passed the FIPS 197 CBC(AES-256) KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the FIPS 197 CBC(AES-256) CBC KAT test.");
	}

	if (qsctest_fips_aes128_ctr() == true)
	{
		qsctest_print_line("Success! Passed the FIPS 197 CTR(AES-128) KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the FIPS 197 CTR(AES-128) KAT test.");
	}

	if (qsctest_fips_aes256_ctr() == true)
	{
		qsctest_print_line("Success! Passed the FIPS 197 CTR(AES-256) KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the FIPS 197 CTR(AES-256) KAT test.");
	}

	if (qsctest_fips_aes128_ecb() == true)
	{
		qsctest_print_line("Success! Passed the FIPS 197 ECB(AES-128) KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the FIPS 197 ECB(AES-128) KAT test.");
	}

	if (qsctest_fips_aes256_ecb() == true)
	{
		qsctest_print_line("Success! Passed the FIPS 197 ECB(AES-256) KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the FIPS 197 ECB(AES-256) KAT test.");
	}

	if (qsctest_aes128_gcm_kat() == true)
	{
		qsctest_print_line("Success! Passed the GCM-AES-128 AEAD mode KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the GCM-AES-128 AEAD mode KAT test.");
	}

	if (qsctest_aes256_gcm_kat() == true)
	{
		qsctest_print_line("Success! Passed the GCM-AES-256 AEAD mode KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the GCM-AES-256 AEAD mode KAT test.");
	}

	qsctest_print_line("AES-GCM four-block SHA-independent known-answer regression stage:");
	if (aes_gcm128_fold_case(255U, 12U, "785802d31601f73d655faaef7935b9aa") == true)
	{
		qsctest_print_line("PASS: AES-128-GCM 255-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128-GCM 255-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm128_fold_case(256U, 12U, "ee8c9e75b67f46c5c7170dc5b5fb5244") == true)
	{
		qsctest_print_line("PASS: AES-128-GCM 256-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128-GCM 256-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm128_fold_case(257U, 12U, "42a712c252df6410ce1e84015b46e83d") == true)
	{
		qsctest_print_line("PASS: AES-128-GCM 257-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128-GCM 257-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm128_fold_case(1024U, 12U, "37c77b0e83f789401bcdef9299ce70bc") == true)
	{
		qsctest_print_line("PASS: AES-128-GCM 1024-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128-GCM 1024-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm128_fold_case(4096U, 17U, "ce86e80811974c75b877647e6b96693d") == true)
	{
		qsctest_print_line("PASS: AES-128-GCM 4096-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-128-GCM 4096-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm256_fold_case(255U, 12U, "390024927f148803be5adef4a027769f") == true)
	{
		qsctest_print_line("PASS: AES-256-GCM 255-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256-GCM 255-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm256_fold_case(256U, 12U, "829f1f27eb973d6e82fd4ca9327d9626") == true)
	{
		qsctest_print_line("PASS: AES-256-GCM 256-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256-GCM 256-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm256_fold_case(257U, 12U, "6b2071a63c9f6c05e239265334cfef94") == true)
	{
		qsctest_print_line("PASS: AES-256-GCM 257-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256-GCM 257-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm256_fold_case(1024U, 12U, "f2af1f07e35f0289405afa249802b770") == true)
	{
		qsctest_print_line("PASS: AES-256-GCM 1024-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256-GCM 1024-byte folded GHASH reference and tamper test.");
	}

	if (aes_gcm256_fold_case(4096U, 17U, "6b53413828ad1b837cb668822195281e") == true)
	{
		qsctest_print_line("PASS: AES-256-GCM 4096-byte folded GHASH reference and tamper test.");
	}
	else
	{
		qsctest_print_line("FAIL: AES-256-GCM 4096-byte folded GHASH reference and tamper test.");
	}

	if (qsctest_aes256_hba_kat() == true)
	{
		qsctest_print_line("Success! Passed the HBA-AES-256 AEAD mode KAT test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the HBA-AES-256 AEAD mode KAT test.");
	}

	if (qsctest_aes256_hba_stress() == true)
	{
		qsctest_print_line("Success! Passed the HBA-AES-256 AEAD mode stress test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the HBA-AES-256 AEAD mode stress test.");
	}

	if (qsctest_aes256_padding_test() == true)
	{
		qsctest_print_line("Success! Passed the PKCS7 padding mode stress test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the PKCS7 padding mode stress test.");
	}
}
