#include "params.h"
#include "kem.h"
#include "rng.h"
#include "sysrand.h"
#include "util.h"
#include <string.h>
#include <cstdbool>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _DEBUG
#define MCELIECE_NTESTS 1
#else
#define MCELIECE_NTESTS 4
#endif

/**
* \brief Get a char from console input.
* \return Returns one user input char
*/
static void get_response()
{
	/*lint -e586 */
	getwchar();
}

/**
* \brief Stress test the key generation, encryption, and decryption functions in a loop.
* \return Returns true for test success
*/
bool test_operations()
{
	uint8_t keya[MCELIECE_KEY_SIZE];
	uint8_t keyb[MCELIECE_KEY_SIZE];
	uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[MCELIECE_SECRETKEY_SIZE];
	size_t i;
	bool ret;

#ifdef MQC_COMPILER_GCC
	uint8_t* pk[MCELIECE_PUBLICKEY_SIZE];
#else
	uint8_t* pk = malloc(MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		clear8(keya, MCELIECE_KEY_SIZE);
		clear8(keyb, MCELIECE_KEY_SIZE);
		clear8(pk, MCELIECE_PUBLICKEY_SIZE);
		clear8(sendb, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sk, MCELIECE_SECRETKEY_SIZE);

		/* alice generates public and secret keys */
		if (crypto_kem_keypair(pk, sk) != true)
		{
			ret = false;
			break;
		}

		/* bob derives a shared-secret key and creates a response (in: pk | out: sendb and keyb) */
		crypto_kem_enc(sendb, keyb, pk);

		/* alice uses bobs response to get the shared-secret key (in: sendb, sk | out: keya) */
		if (crypto_kem_dec(keya, sendb, sk) != true)
		{
			ret = false;
			break;
		}

		/* compare the two keys for equality */
		if (are_equal8(keya, keyb, MCELIECE_KEY_SIZE) != true)
		{
			ret = false;
			break;
		}
	}

#ifndef MQC_COMPILER_GCC
	free(pk);
#endif

	return ret;
}

/**
* \brief Test the validity of a mutated public key in a loop.
* \return Returns true for test success
*/
bool test_invalid_publickey()
{
	uint8_t keya[MCELIECE_KEY_SIZE];
	uint8_t keyb[MCELIECE_KEY_SIZE];
	uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[MCELIECE_SECRETKEY_SIZE];
	size_t i;
	bool ret;

#ifdef MQC_COMPILER_GCC
	uint8_t* pk[MCELIECE_PUBLICKEY_SIZE];
#else
	uint8_t* pk = malloc(MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		clear8(keya, MCELIECE_KEY_SIZE);
		clear8(keyb, MCELIECE_KEY_SIZE);
		clear8(pk, MCELIECE_PUBLICKEY_SIZE);
		clear8(sendb, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sk, MCELIECE_SECRETKEY_SIZE);

		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* replace public key bytes with random values */
		if (sysrand_getbytes(pk, 10240) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* bob generates a shared-secret key and creates the response */
		crypto_kem_enc(sendb, keyb, pk);

		/* invalid secret key generated, should return fail */
		if (crypto_kem_dec(keya, sendb, sk) == MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* fail if output keys are equal */
		if (are_equal8(keya, keyb, MCELIECE_KEY_SIZE) == true)
		{
			ret = false;
			break;
		}
	}

#ifndef MQC_COMPILER_GCC
	free(pk);
#endif

	return ret;
}

/**
* \brief Test the validity of a mutated cipher-text in a loop.
* \return Returns true for test success
*/
bool test_invalid_ciphertext()
{
	uint8_t keya[MCELIECE_KEY_SIZE];
	uint8_t keyb[MCELIECE_KEY_SIZE];
	uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[MCELIECE_SECRETKEY_SIZE];
	bool ret;
	size_t i;

#ifdef MQC_COMPILER_GCC
	uint8_t* pk[MCELIECE_PUBLICKEY_SIZE];
#else
	uint8_t* pk = malloc(MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		clear8(keya, MCELIECE_KEY_SIZE);
		clear8(keyb, MCELIECE_KEY_SIZE);
		clear8(pk, MCELIECE_PUBLICKEY_SIZE);
		clear8(sendb, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sk, MCELIECE_SECRETKEY_SIZE);

		/* alice generates a public/secret key-pair */
		if (crypto_kem_keypair(pk, sk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* bob derives the shared-secret key and creates a response */
		crypto_kem_enc(sendb, keyb, pk);

		/* replace some ciphertext bytes with random values */
		sysrand_getbytes(sendb, 8);

		/* invalid ciphertext, authentication should fail */
		if (crypto_kem_dec(keya, sendb, sk) == MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* fail if equal */
		if (are_equal8(keya, keyb, MCELIECE_KEY_SIZE) == true)
		{
			ret = false;
			break;
		}
	}

#ifndef MQC_COMPILER_GCC
	free(pk);
#endif

	return ret;
}

bool mceliece_kat_test()
{
	uint8_t seed[48];
	uint8_t expct[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t expss[MCELIECE_KEY_SIZE];
	uint8_t keya[MCELIECE_KEY_SIZE];
	uint8_t keyb[MCELIECE_KEY_SIZE];
	uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[MCELIECE_SECRETKEY_SIZE];
	size_t i;
	bool ret;
#ifdef MQC_COMPILER_GCC
	uint8_t* pk[MCELIECE_PUBLICKEY_SIZE] = { 0 };
#else
	uint8_t* pk = malloc(MCELIECE_PUBLICKEY_SIZE);
	clear8(pk, MCELIECE_PUBLICKEY_SIZE);
#endif

	// Note: this is the old shared-key expected when using the first seed of the Nist PQ round 1 version:
	// old shared-key: E1ED829F7190FF7932035761BBA154AB36BE888349FC6684FD15A50A1D82E179
	// I am using the newer version of the cipher as posted to SuperCop version 2019-01-10.
	// Significant changes were made to the secret-key generation by the authors in this newer version,
	// which has caused the cipher outputs to change.
	// However, this latest version is recommended by the authors.
	// The authors website: https://classic.mceliece.org/software.html
	// There is yet a third version of these ciphers as recently posted to the Nist PQ Round 2 forum,
	// but as this seems to be at least temporarily unstable as it undergoes improvements through round 2,
	// I have at least for the time being decided to use the SuperCop version of the cipher.
	// rng seed: 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
	// new shared-key for nist seed-0
	// 179C2314367D02DCC0CF1C1CCF7055FB870CB26F529BBD4A393D6603FE70AE95

	hex_to_bin("056DACA18318D82849759ED3C816C45821186E6AA763A018C5A40AA29593A6C312A30CE36FB3C30BC4E2A4AFD1C7B065"
		"14E9FE59678A0F2A14F09B0645F9EC980D406790DE6775781E3136A248D4588D60344F73CB4E3C567DE64BBE588C7C54"
		"9A9E3585EF98A5F55C3B9BAD7418932CB8966EC08B28B3A2A30B5C9067DFC854935DD0410D19BB24BF7086C0BCAB2DD0"
		"A69D25A15B5A685936855F05BFA7CA9CF9E58557B3AE8D4EBC8853B32FD52AD1DF66D6576CB69D58CFC8915BCC9D1C10"
		"1602430E3F44F48135F4370B0959B02E891F597C5BFBD340154BA8E9233DE6CE1FAF", expct, sizeof(expct));
	hex_to_bin("179C2314367D02DCC0CF1C1CCF7055FB870CB26F529BBD4A393D6603FE70AE95", expss, 32);
	hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, 48);

	ret = true;
	randombytes_init(seed, NULL, 256);

	/* alice generates public and secret keys */
	if (crypto_kem_keypair(pk, sk) != true)
	{
		ret = false;
	}

	/* bob derives a shared-secret key and creates a response (in: pk | out: sendb and keyb) */
	if (crypto_kem_enc(sendb, keyb, pk) != true)
	{
		ret = false;
	}

	/* compare the cipher-text to the expected output */
	if (are_equal8(sendb, expct, MCELIECE_CIPHERTEXT_SIZE) != true)
	{
		ret = false;
	}

	/* alice uses bobs response to get the shared-secret key (in: sendb, sk | out: keya) */
	if (crypto_kem_dec(keya, sendb, sk) != true)
	{
		ret = false;
	}

	/* compare the two keys for equality */
	if (are_equal8(keya, keyb, MCELIECE_KEY_SIZE) != true)
	{
		ret = false;
	}

	/* compare the key to the expected output */
	if (are_equal8(keya, expss, MCELIECE_KEY_SIZE) != true)
	{
		ret = false;
	}

#ifndef MQC_COMPILER_GCC
	free(pk);
#endif

	return ret;
}

/**
* \brief Run the McEliece implementation stress and correctness tests tests
*/
void mceliece_test_run()
{
	if (mceliece_kat_test() == true)
	{
		printf_s("Success! Passed key generation, encryption, and decryption known answer test. \n");
	}
	else
	{
		printf_s("Failure! Failed the known answer test. \n \n");
	}

	if (test_operations() == true)
	{
		printf_s("Success! Passed key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the encryption stress tests. \n \n");
	}

	if (test_invalid_publickey() == true)
	{
		printf_s("Success! Passed public key tamper test. \n");
	}
	else
	{
		printf_s("Failure! Failed public key tamper test. \n");
	}

	if (test_invalid_ciphertext() == true)
	{
		printf_s("Success! Passed cipher-text tamper test. \n");
	}
	else
	{
		printf_s("Failure! Failed cipher-text tamper test. \n");
	}
}

/**
* \brief Runs the SHA3 and McEliece tests
*/
int main(void)
{
	printf_s("*** Running McEliece implementation stress and validity tests *** \n");
	printf_s("\n");
	mceliece_test_run();
	printf_s("\n");

	printf_s("\n");
	printf_s("Completed! Press any key to close..");
	get_response();

	return 0;
}