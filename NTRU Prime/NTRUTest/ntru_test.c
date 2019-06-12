/**
* \file ntrue_test.c
* \brief <b>NTRU test functions</b> \n
* Contains the NTRU implementation wellness test functions.
*
* \author John Underhill
* \date March 5, 2018
*/

#include "common.h"
#include "aes_kat.h"
#include "sha3_kat.h"
#include "../NTRU/kem.h"
#include "../NTRU/params.h"
#include "../NTRU/sysrand.h"
#include "../NTRU/sha3.h"
#include <stdio.h>

#define NTRU_NTESTS 10

/* AES-NI Detection */

#if defined(_MSC_VER)

#include <intrin.h>
#pragma intrinsic(__cpuid)

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	__cpuid(info, 1);

	if (info[2] != 0)
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#elif defined(__GNUC__)

#include <cpuid.h>
#pragma GCC target ("ssse3")
#pragma GCC target ("sse4.1")
#pragma GCC target ("aes")
#include <x86intrin.h>

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	if (__get_cpuid(1, &info[0], &info[1], &info[2], &info[3]))
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#else

static int has_aes_ni()
{
	return 0;
}

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
* \brief Test the AES implementation with vectors from Fips197 and
* new vectors for the extended modes RSX256 and RSX512
*/
void aes_test_run()
{
	if (aes128_cbc_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 CBC KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 CBC KAT test. \n \n");
	}

	if (aes256_cbc_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 CBC KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 CBC KAT test. \n \n");
	}

	if (aes128_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 ECB KAT test. \n \n");
	}

	if (aes256_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 ECB KAT test. \n \n");
	}
}

/**
* \brief Run the SHA3, SHAKE, cSHAKE, simple cSHAKE, and KMAC KAT tests
*/
void sha3_test_run()
{
	if (sha3_256_kat_test() == true)
	{
		printf_s("Success! passed sha3-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed sha3-256 known answer tests \n");
	}

	if (sha3_512_kat_test() == true)
	{
		printf_s("Success! passed sha3-512 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed sha3-512 known answer tests \n");
	}

	if (shake_128_kat_test() == true)
	{
		printf_s("Success! passed shake-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed shake-128 known answer tests \n");
	}

	if (shake_256_kat_test() == true)
	{
		printf_s("Success! passed shake-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed shake-256 known answer tests \n");
	}

	if (cshake_128_kat_test() == true)
	{
		printf_s("Success! passed cshake-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed cshake-128 known answer tests \n");
	}

	if (cshake_256_kat_test() == true)
	{
		printf_s("Success! passed cshake-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed cshake-256 known answer tests \n");
	}

	if (cshake_simple_128_kat_test() == true)
	{
		printf_s("Success! passed simple cshake-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed simple cshake-128 known answer tests \n");
	}

	if (cshake_simple_256_kat_test() == true)
	{
		printf_s("Success! passed simple cshake-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed simple cshake-256 known answer tests \n");
	}

	if (kmac_128_kat_test() == true)
	{
		printf_s("Success! passed kmac-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed kmac-128 known answer tests \n");
	}

	if (kmac_256_kat_test() == true)
	{
		printf_s("Success! passed kmac-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed kmac-256 known answer tests \n");
	}
}

/**
* \brief Stress test the key generation, encryption, and decryption functions in a 100 round loop.
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool test_keys()
{
	uint8_t key_a[NTRU_SEED_SIZE];
	uint8_t key_b[NTRU_SEED_SIZE];
	uint8_t ctxt[NTRU_CIPHERTEXT_SIZE];
	uint8_t sk[NTRU_PRIVATEKEY_SIZE];
	uint8_t pk[NTRU_PUBLICKEY_SIZE];
	size_t i;
	bool state;

	state = true;

	for (i = 0; i < NTRU_NTESTS; i++)
	{
		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* bob derives a secret key and creates a response */
		if (crypto_kem_enc(ctxt, key_b, pk) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* alice uses Bobs response to get her secret key */
		if (crypto_kem_dec(key_a, ctxt, sk) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		if (memcmp(key_a, key_b, NTRU_SEED_SIZE) != 0)
		{
			state = false;
			break;
		}
	}

	return state;
}

/**
* \brief Test the validity of a mutated secret key in a 100 round loop.
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool test_invalid_sk_a()
{
	uint8_t key_a[NTRU_SEED_SIZE];
	uint8_t key_b[NTRU_SEED_SIZE];
	uint8_t ctxt[NTRU_CIPHERTEXT_SIZE];
	uint8_t sk[NTRU_PRIVATEKEY_SIZE];
	uint8_t pk[NTRU_PUBLICKEY_SIZE];
	size_t i;
	bool state;

	state = true;

	for (i = 0; i < NTRU_NTESTS; i++)
	{
		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* bob derives a secret key and creates a response */
		if (crypto_kem_enc(ctxt, key_b, pk) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* replace secret key with random values */
		if (sysrand_getbytes(sk, NTRU_SEED_SIZE) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* invalid secret key, should fail */
		if (crypto_kem_dec(key_a, ctxt, sk) == QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* fail if equal */
		if (memcmp(key_a, key_b, NTRU_SEED_SIZE) == 0)
		{
			state = false;
			break;
		}
	}

	return state;
}

/**
* \brief Test the validity of a mutated cipher-text in a 100 round loop.
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool test_invalid_ciphertext()
{
	uint8_t key_a[NTRU_SEED_SIZE];
	uint8_t key_b[NTRU_SEED_SIZE];
	uint8_t ctxt[NTRU_CIPHERTEXT_SIZE];
	uint8_t sk[NTRU_PRIVATEKEY_SIZE];
	uint8_t pk[NTRU_PUBLICKEY_SIZE];
	size_t i;
	size_t pos;
	bool state;

	state = true;

	for (i = 0; i < NTRU_NTESTS; i++)
	{
		if (sysrand_getbytes((uint8_t*)&pos, sizeof(size_t)) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* bob derives a secret key and creates a response */
		if (crypto_kem_enc(ctxt, key_b, pk) != QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* change some byte in the ciphertext (i.e., encapsulated key) */
		ctxt[pos % NTRU_CIPHERTEXT_SIZE] ^= 23;

		/* invalid ciphertext, auth should fail */
		if (crypto_kem_dec(key_a, ctxt, sk) == QCC_STATUS_SUCCESS)
		{
			state = false;
			break;
		}

		/* fail if equal */
		if (memcmp(key_a, key_b, NTRU_SEED_SIZE) == 0)
		{
			state = false;
			break;
		}
	}

	return state;
}

/**
* \brief Run the NTRU implementation stress and correctness tests tests
*/
void ntru_test_run()
{
	if (test_keys() == true)
	{
		printf_s("Success! Passed key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the encryption stress tests. \n \n");
	}

	if (test_invalid_sk_a() == true)
	{
		printf_s("Success! Passed secret key tamper test. \n");
	}
	else
	{
		printf_s("Failure! Failed secret key tamper test. \n");
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
* \brief Runs the SHA3 and NTRU tests
*/
int main(void)
{
	int valid = 1;

	if (has_aes_ni() == 1)
	{
		printf_s("AES-NI is available on this system. \n");
		printf_s("Add the RSX_AESNI_ENABLED flag to the preprocessor definitions to test AES-NI implementation. \n");
		printf_s("\n");
	}
	else
	{
		printf_s("AES-NI was not detected on this system. \n");
#if defined(RSX_AESNI_ENABLED)
		printf_s("Remove the RSX_AESNI_ENABLED flag from the preprocessor definitions to test the standard implementation. \n");
		printf_s("The test can not proceed! Press any key to close..");
		ret = get_response();
		valid = 0;
#endif
	}

	if (valid == 1)
	{
		printf_s("*** Test using the NIST SP800-38a Known Answer Tests *** \n");
		printf_s("\n");
		aes_test_run();
		printf_s("\n");
	}

	printf_s("*** The SHA3 digest and SHAKE Known Answer Tests *** \n");
	printf_s("\n");
	sha3_test_run();
	printf_s("\n");

	printf_s("*** The NTRU implementations stress and validity tests *** \n");
	printf_s("\n");
	ntru_test_run();
	printf_s("\n");

	printf_s("\n");
	printf_s("Completed! Press any key to close..");
	get_response();

	return 0;
}
