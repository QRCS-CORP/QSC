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
#define MCELIECE_NTESTS 1
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
	// DD1A7EC5E1026D5A77210F1374219018FC1C6CFD6BADF848A860C4749424D344

	hex_to_bin("9583F9C0E887851BE079E0AEF65CC7F6C11482AA537E99EAD8865C3B5E65821468C4687CDF017C9FCF2B318238A97519"
		"9D05E7FE51034585B26B54F3E3E99C410BCDC090A736BDBFC34C400402A9860E39438DEA312379EFE4DAE5CFCD7280CA"
		"978F8A96B96397C02B8518D11615FFA8B26D74A85406138199E6F4B8B4A683FB966398F5EDAC38557D73A127816B0644"
		"3BDE6524A936C2C0DA8EFDDDB3850F522F0A26FC3DC3BCBBFFB32A0AD0FD156A8F3192D45B10B48647C546F8C5DB3F0D"
		"1AEAA192D88493AE6C1F1E9C253342551094F5643697600DCB99758E6D06375DCA20005FEBABBDC3A894CF676EB51992", expct, sizeof(expct));
	hex_to_bin("DD1A7EC5E1026D5A77210F1374219018FC1C6CFD6BADF848A860C4749424D344", expss, 32);
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

	/*unsigned char tmpk[32];
	bin_to_hex(keya, tmpk, 32);
	printf(tmpk);

	unsigned char tmpc[MCELIECE_CIPHERTEXT_SIZE * 2];
	bin_to_hex(sendb, tmpc, MCELIECE_CIPHERTEXT_SIZE);
	printf(tmpc);*/

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