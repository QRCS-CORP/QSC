/**
* \file kyber_test.c
* \brief <b>Kyber test functions</b> \n
* Contains the Kyber implementation wellness test functions.
*
* \author John Underhill
* \date January 06, 2018
*/

#include "../Kyber/kem.h"
#include "../Kyber/poly.h"
#include "../Kyber/sysrand.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define KYBER_NTESTS 100

/*! \enum KYBER_TEST_STATUS
* The test function result state
*/
enum KYBER_TEST_STATUS
{
	KYBER_STATUS_FAILURE = 0, /*!< signals test failure */
	KYBER_STATUS_SUCCESS = 1  /*!< signals test success */
};

/**
* \brief Get a char from console input.
* \return Returns one user input char
*/
char get_response()
{
	return getchar();
}

/**
* \brief Stress test the key generation, encryption, and decryption functions in a 100 round loop.
* \return Returns one (KYBER_STATUS_SUCCESS) for test success
*/
int32_t test_keys()
{
	uint8_t key_a[KYBER_SYMBYTES];
	uint8_t key_b[KYBER_SYMBYTES];
	uint8_t pk[KYBER_PUBLICKEYBYTES];
	uint8_t sendb[KYBER_CIPHERTEXTBYTES];
	uint8_t sk_a[KYBER_SECRETKEYBYTES];
	uint8_t state;
	size_t i;

	state = KYBER_STATUS_SUCCESS;

	for (i = 0; i < KYBER_NTESTS; i++)
	{
		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk_a) == KYBER_CRYPTO_FAILURE)
		{
			state = KYBER_STATUS_FAILURE;
			return state;
		}

		/* bob derives a secret key and creates a response */
		if (crypto_kem_enc(sendb, key_b, pk) == KYBER_CRYPTO_FAILURE)
		{
			state = KYBER_STATUS_FAILURE;
			return state;
		}

		/* alice uses Bobs response to get her secret key */
		if (crypto_kem_dec(key_a, sendb, sk_a) == KYBER_CRYPTO_FAILURE)
		{
			state = KYBER_STATUS_FAILURE;
			return state;
		}

		if (memcmp(key_a, key_b, KYBER_SYMBYTES))
		{
			state = KYBER_STATUS_FAILURE;
			return state;
		}
	}

	return state;
}

/**
* \brief Test the validity of a mutated secret key in a 100 round loop.
* \return Returns one (KYBER_STATUS_SUCCESS) for test success
*/
int32_t test_invalid_sk_a()
{
	uint8_t sk_a[KYBER_SECRETKEYBYTES];
	uint8_t key_a[KYBER_SYMBYTES];
	uint8_t key_b[KYBER_SYMBYTES];
	uint8_t pk[KYBER_PUBLICKEYBYTES];
	uint8_t sendb[KYBER_CIPHERTEXTBYTES];
	uint8_t state = KYBER_STATUS_SUCCESS;
	size_t i;

	for (i = 0; i < KYBER_NTESTS; i++)
	{
		/* alice generates a public key */
		crypto_kem_keypair(pk, sk_a);
		/* bob derives a secret key and creates a response */
		crypto_kem_enc(sendb, key_b, pk);
		/* replace secret key with random values */
		sysrand_getbytes(sk_a, KYBER_SECRETKEYBYTES);
		/* alice uses Bobs response to get her secret key */
		crypto_kem_dec(key_a, sendb, sk_a);

		if (!memcmp(key_a, key_b, KYBER_SYMBYTES))
		{
			state = KYBER_STATUS_FAILURE;
			break;
		}
	}

	return state;
}

/**
* \brief Test the validity of a mutated cipher-text in a 100 round loop.
* \return Returns one (KYBER_STATUS_SUCCESS) for test success
*/
int32_t test_invalid_ciphertext()
{
	uint8_t sk_a[KYBER_SECRETKEYBYTES];
	uint8_t key_a[KYBER_SYMBYTES];
	uint8_t key_b[KYBER_SYMBYTES];
	uint8_t pk[KYBER_PUBLICKEYBYTES];
	uint8_t sendb[KYBER_CIPHERTEXTBYTES];
	uint8_t state = KYBER_STATUS_SUCCESS;
	size_t i;
	size_t pos;

	for (i = 0; i < KYBER_NTESTS; i++)
	{
		sysrand_getbytes((uint8_t*)&pos, sizeof(size_t));
		/* alice generates a public key */
		crypto_kem_keypair(pk, sk_a);
		/* bob derives a secret key and creates a response */
		crypto_kem_enc(sendb, key_b, pk);
		/* change some byte in the ciphertext (i.e., encapsulated key) */
		sendb[pos % KYBER_CIPHERTEXTBYTES] ^= 23;
		/* alice uses Bobs response to get her secre key */
		crypto_kem_dec(key_a, sendb, sk_a);

		if (!memcmp(key_a, key_b, KYBER_SYMBYTES))
		{
			state = KYBER_STATUS_FAILURE;
			break;
		}
	}

	return state;
}

/**
* \brief Runs the Kyber tests
*/
int main(void)
{
	printf("*** The Kyber implementations stress and validity tests *** \n");
	printf("\n");

	if (test_keys() == KYBER_STATUS_SUCCESS)
	{
		printf("Success! Passed key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		printf("Failure! Failed the encryption stress tests. \n \n");
	}

	if (test_invalid_sk_a() == KYBER_STATUS_SUCCESS)
	{
		printf("Success! Passed secret key tamper test. \n");
	}
	else
	{
		printf("Failure! Failed secret key tamper test. \n");
	}

	if (test_invalid_ciphertext() == KYBER_STATUS_SUCCESS)
	{
		printf("Success! Passed cipher-text tamper test. \n");
	}
	else
	{
		printf("Failure! Failed cipher-text tamper test. \n");
	}

	printf("\n");
	printf("Completed! Press any key to close..");
	get_response();

	return 0;
}
