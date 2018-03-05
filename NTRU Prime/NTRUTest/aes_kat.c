#include "aes_kat.h"
#include "../NTRU/rsx.h"
#include <stdio.h>
#include <string.h>

#ifdef RSX_AESNI_ENABLED
#	if defined(_MSC_VER)
#		include <intrin.h>
#	elif defined(__GNUC__)
#		include <x86intrin.h>
#	endif
#endif

static bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < length; ++i)
	{
		if (a[i] != b[i])
		{
			status = false;
			break;
		}
	}

	return status;
}

static void hex_to_bin(const char* str, uint8_t* output, size_t length)
{
	uint8_t  pos;
	uint8_t  idx0;
	uint8_t  idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	memset(output, 0, length);

	for (pos = 0; (pos < (length * 2)); pos += 2)
	{
		idx0 = ((uint8_t)str[pos + 0] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)str[pos + 1] & 0x1F) ^ 0x10;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
}

static bool aes128_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[AES128_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES128_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	uint8_t ivc[16];
	size_t i;
	bool state;

	memcpy(&ivc[0], &iv[0], 16);
	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, AES128) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_cbc_encrypt(out, ivc, message[i], rks, AES128_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	memcpy(&ivc[0], &iv[0], 16);

	/* test decryption */
	if (rsx_initialize(rks, key, false, AES128) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_cbc_decrypt(out, ivc, expected[i], rks, AES128_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

static bool aes256_cbc_monte_carlo(const uint8_t* key, const uint8_t* iv, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[AES256_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES256_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	uint8_t ivc[16];
	size_t i;
	bool state;

	memcpy(&ivc[0], &iv[0], 16);
	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, AES256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_cbc_encrypt(out, ivc, message[i], rks, AES256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	memcpy(&ivc[0], &iv[0], 16);

	/* test decryption */
	if (rsx_initialize(rks, key, false, AES256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_cbc_decrypt(out, ivc, expected[i], rks, AES256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

static bool aes128_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[AES128_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES128_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	uint8_t ncc[16];
	size_t i;
	bool state;

	memcpy(&ncc[0], &nonce[0], 16);
	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, AES128) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ctr_transform(out, ncc, message[i], rks, AES128_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	memcpy(&ncc[0], &nonce[0], 16);

	/* test decryption */
	if (rsx_initialize(rks, key, true, AES128) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ctr_transform(out, ncc, expected[i], rks, AES128_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

static bool aes256_ctr_monte_carlo(const uint8_t* key, const uint8_t* nonce, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[AES256_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES256_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	uint8_t ncc[16];
	size_t i;
	bool state;

	memcpy(&ncc[0], &nonce[0], 16);
	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, AES256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ctr_transform(out, ncc, message[i], rks, AES256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	memcpy(&ncc[0], &nonce[0], 16);

	/* test decryption */
	if (rsx_initialize(rks, key, true, AES256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ctr_transform(out, ncc, expected[i], rks, AES256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

static bool aes128_ecb_monte_carlo(const uint8_t* key, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[AES128_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES128_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	size_t i;
	bool state;

	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, AES128) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ecb_encrypt(out, message[i], rks, AES128_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	/* test decryption */
	if (rsx_initialize(rks, key, false, AES128) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ecb_decrypt(out, expected[i], rks, AES128_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

static bool aes256_ecb_monte_carlo(const uint8_t* key, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[AES256_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES256_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	size_t i;
	bool state;

	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, AES256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ecb_encrypt(out, message[i], rks, AES256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	/* test decryption */
	if (rsx_initialize(rks, key, false, AES256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ecb_decrypt(out, expected[i], rks, AES256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

static bool rsx256_ecb_monte_carlo(const uint8_t* key, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[RSX256_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[RSX256_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	size_t i;
	bool state;

	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, RSX256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}
	//for (size_t i = 0; i < RSX256_ROUNDKEY_DIMENSION; i++)
	//	print_array32(rks[i].m128i_u32, 4, 4);
	for (i = 0; i < 4; i++)
	{
		rsx_ecb_encrypt(out, message[i], rks, RSX256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	/* test decryption */
	if (rsx_initialize(rks, key, false, RSX256) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ecb_decrypt(out, expected[i], rks, RSX256_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

static bool rsx512_ecb_monte_carlo(const uint8_t* key, const uint8_t message[4][16], const uint8_t expected[4][16])
{
#if defined(RSX_AESNI_ENABLED)
	__m128i rks[RSX512_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[RSX512_ROUNDKEY_DIMENSION];
#endif
	uint8_t out[16];
	size_t i;
	bool state;

	state = true;

	/* test encryption */
	if (rsx_initialize(rks, key, true, RSX512) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ecb_encrypt(out, message[i], rks, RSX512_ROUNDKEY_DIMENSION);

		if (are_equal8(out, expected[i], 16) == false)
		{
			state = false;
		}
	}

	/* test decryption */
	if (rsx_initialize(rks, key, false, RSX512) != QCC_STATUS_SUCCESS)
	{
		state = false;
	}

	for (i = 0; i < 4; i++)
	{
		rsx_ecb_decrypt(out, expected[i], rks, RSX512_ROUNDKEY_DIMENSION);

		if (are_equal8(out, message[i], 16) == false)
		{
			state = false;
		}
	}

	return state;
}

bool aes128_cbc_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t iv[16];
	uint8_t key[16];

	/* SP800-38a F2.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
	hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, 16);

	hex_to_bin("7649ABAC8119B246CEE98E9B12E9197D", exp[0], 16);
	hex_to_bin("5086CB9B507219EE95DB113A917678B2", exp[1], 16);
	hex_to_bin("73BED6B8E3C1743B7116E69E22229516", exp[2], 16);
	hex_to_bin("3FF1CAA1681FAC09120ECA307586E1A7", exp[3], 16);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], 16);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], 16);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], 16);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], 16);

	return aes128_cbc_monte_carlo(key, iv, msg, exp);
}

bool aes256_cbc_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t iv[16];
	uint8_t key[32];

	/* SP800-38a F2.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, 32);
	hex_to_bin("000102030405060708090A0B0C0D0E0F", iv, 16);

	hex_to_bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6", exp[0], 16);
	hex_to_bin("9CFC4E967EDB808D679F777BC6702C7D", exp[1], 16);
	hex_to_bin("39F23369A9D9BACFA530E26304231461", exp[2], 16);
	hex_to_bin("B2EB05E2C39BE9FCDA6C19078C6A9D1B", exp[3], 16);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], 16);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], 16);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], 16);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], 16);

	return aes256_cbc_monte_carlo(key, iv, msg, exp);
}

bool aes128_ctr_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t key[16];
	uint8_t nonce[16];

	/* SP800-38a F5.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, 16);

	hex_to_bin("874D6191B620E3261BEF6864990DB6CE", exp[0], 16);
	hex_to_bin("9806F66B7970FDFF8617187BB9FFFDFF", exp[1], 16);
	hex_to_bin("5AE4DF3EDBD5D35E5B4F09020DB03EAB", exp[2], 16);
	hex_to_bin("1E031DDA2FBE03D1792170A0F3009CEE", exp[3], 16);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], 16);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], 16);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], 16);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], 16);

	return aes128_ctr_monte_carlo(key, nonce, msg, exp);
}

bool aes256_ctr_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t key[32];
	uint8_t nonce[16];

	/* SP800-38a F5.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, 32);
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", nonce, 16);

	hex_to_bin("601EC313775789A5B7A7F504BBF3D228", exp[0], 16);
	hex_to_bin("F443E3CA4D62B59ACA84E990CACAF5C5", exp[1], 16);
	hex_to_bin("2B0930DAA23DE94CE87017BA2D84988D", exp[2], 16);
	hex_to_bin("DFC9C58DB67AADA613C2DD08457941A6", exp[3], 16);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], 16);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], 16);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], 16);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], 16);

	return aes256_ctr_monte_carlo(key, nonce, msg, exp);
}

bool aes128_ecb_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t key[16];

	/* SP800-38a F1.1 */

	hex_to_bin("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);

	hex_to_bin("3AD77BB40D7A3660A89ECAF32466EF97", exp[0], 16);
	hex_to_bin("F5D3D58503B9699DE785895A96FDBAAF", exp[1], 16);
	hex_to_bin("43B1CD7F598ECE23881B00E3ED030688", exp[2], 16);
	hex_to_bin("7B0C785E27E8AD3F8223207104725DD4", exp[3], 16);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], 16);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], 16);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], 16);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], 16);

	return aes128_ecb_monte_carlo(key, msg, exp);
}

bool aes256_ecb_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t key[32];

	/* SP800-38a F1.5 */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, 32);

	hex_to_bin("F3EED1BDB5D2A03C064B5A7E3DB181F8", exp[0], 16);
	hex_to_bin("591CCB10D410ED26DC5BA74A31362870", exp[1], 16);
	hex_to_bin("B6ED21B99CA6F4F9F153E7B1BEAFED1D", exp[2], 16);
	hex_to_bin("23304B7A39F9F3FF067D8D8F9E24ECC7", exp[3], 16);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], 16);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], 16);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], 16);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], 16);

	return aes256_ecb_monte_carlo(key, msg, exp);
}

bool rsx256_ecb_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t key[32];

	/* original vectors */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, 32);

	hex_to_bin("96F1D94485D82839DFFF58207735DC7E", exp[0], 16);
	hex_to_bin("DA4E17AB1DC12A83F54C95B29D5261D7", exp[1], 16);
	hex_to_bin("972DD4D197F31884948E79A1C080A6AD", exp[2], 16);
	hex_to_bin("3645DA587089306B6A8707A6360F376A", exp[3], 16);

	hex_to_bin("6BC1BEE22E409F96E93D7E117393172A", msg[0], 16);
	hex_to_bin("AE2D8A571E03AC9C9EB76FAC45AF8E51", msg[1], 16);
	hex_to_bin("30C81C46A35CE411E5FBC1191A0A52EF", msg[2], 16);
	hex_to_bin("F69F2445DF4F9B17AD2B417BE66C3710", msg[3], 16);

	return rsx256_ecb_monte_carlo(key, msg, exp);
}

bool rsx512_ecb_kat_test()
{
	uint8_t exp[4][16];
	uint8_t msg[4][16];
	uint8_t key[64];

	/* original vectors */

	hex_to_bin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", key, 64);

	hex_to_bin("CDE464407453F20A42C6E6C6927443A6", exp[0], 16);
	hex_to_bin("A35BEB852A0123361518DC4DDEA325DE", exp[1], 16);
	hex_to_bin("94137F843F04CD4ACBB3E13D79C02EC1", exp[2], 16);
	hex_to_bin("FBBF334DFC250E0538F6599F70C264FE", exp[3], 16);

	hex_to_bin("8B7971E2BBF5BFD6224791BF10A88A26", msg[0], 16);
	hex_to_bin("487399BD175914436349E00DC63A08C9", msg[1], 16);
	hex_to_bin("C750E4D28CAA89CACC849D5BF5760EE6", msg[2], 16);
	hex_to_bin("30F0C6AAB240E6CF389F1E09B469DCFA", msg[3], 16);

	return rsx512_ecb_monte_carlo(key, msg, exp);
}
