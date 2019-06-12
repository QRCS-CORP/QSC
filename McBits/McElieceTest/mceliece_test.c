/**
* \file newhope_test.c
* \brief <b>McEliece test functions</b> \n
* Contains the McEliece implementation wellness test functions.
*
* \author John Underhill
* \date January 10, 2018
*/

#include "common.h"
#include "chacha_kat.h"
#include "poly1305_kat.h"
#include "sha3_kat.h"
#include "../McEliece/kem.h"
#include "../McEliece/params.h"
#include "../McEliece/sha3.h"
#include "../McEliece/sysrand.h"
#include "../McEliece/util.h"
#include <string.h>

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
* \brief Run the ChaChaP20 KAT tests
*/
void chacha_test_run()
{
	if (chacha_avx_equivalence() == true)
	{
		printf_s("Success! passed ChaCha AVX equivalence test \n");
	}
	else
	{
		printf_s("Failure! failed ChaCha AVX equivalence test \n");
	}/**/
	if (chacha256_kat_test() == true)
	{
		printf_s("Success! passed ChaCha-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed ChaCha-256 known answer tests \n");
	}
	if (chacha128_kat_test() == true)
	{
		printf_s("Success! passed ChaCha-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed ChaCha-128 known answer tests \n");
	}
}

/**
* \brief Run the Poly1305 KAT tests
*/
void poly1305_test_run()
{
	if (poly1305_kat_test() == true)
	{
		printf_s("Success! passed Poly1305 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed Poly1305 known answer tests \n");
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
	uint8_t keya[MCELIECE_KEY_SIZE];
	uint8_t keyb[MCELIECE_KEY_SIZE];
	uint8_t pk[MCELIECE_PUBLICKEY_SIZE];
	uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[MCELIECE_SECRETKEY_SIZE];
	size_t i;
	bool ret;

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		clear8(keya, MCELIECE_KEY_SIZE);
		clear8(keyb, MCELIECE_KEY_SIZE);
		clear8(pk, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sendb, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sk, MCELIECE_SECRETKEY_SIZE);

		/*lint -e534 */
		sysrand_getbytes(keyb, MCELIECE_KEY_SIZE);

		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* bob derives a secret key and creates a response */
		if (crypto_kem_enc(sendb, keyb, pk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* alice uses bobs response to get her secret key */
		if (crypto_kem_dec(keya, sendb, sk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		if (memcmp(keya, keyb, MCELIECE_KEY_SIZE) != 0)
		{
			ret = false;
			break;
		}
	}

	return ret;
}

/**
* \brief Test the validity of a mutated secret key in a 100 round loop.
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool test_invalid_secretkey()
{
	uint8_t keya[MCELIECE_KEY_SIZE];
	uint8_t keyb[MCELIECE_KEY_SIZE];
	uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[MCELIECE_SECRETKEY_SIZE];
	uint8_t pk[MCELIECE_PUBLICKEY_SIZE];
	size_t i;
	bool ret;

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		clear8(keya, MCELIECE_KEY_SIZE);
		clear8(keyb, MCELIECE_KEY_SIZE);
		clear8(pk, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sendb, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sk, MCELIECE_SECRETKEY_SIZE);

		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/*lint -e534 */
		sysrand_getbytes(keyb, MCELIECE_KEY_SIZE);// "ƒ01À\x16*¾­wóf¾ë…<ð\x17ý\x19\x19VHrÌŸÔÿƒY\x15...

		/* bob derives a secret key and creates a response */
		if (crypto_kem_enc(sendb, keyb, pk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* replace secret bytes key with random values */
		sysrand_getbytes(sk, 32);

		/* invalid secret key, should fail */
		if (crypto_kem_dec(keya, sendb, sk) == MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* fail if output keys are equal */
		if (memcmp(keya, keyb, MCELIECE_KEY_SIZE) == 0)
		{
			ret = false;
			break;
		}
	}

	return ret;
}

/**
* \brief Test the validity of a mutated cipher-text in a 100 round loop.
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
bool test_invalid_ciphertext()
{
	uint8_t keya[MCELIECE_KEY_SIZE];
	uint8_t keyb[MCELIECE_KEY_SIZE];
	uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[MCELIECE_SECRETKEY_SIZE];
	uint8_t pk[MCELIECE_PUBLICKEY_SIZE];
	size_t i;
	size_t pos;
	bool ret;

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		clear8(keya, MCELIECE_KEY_SIZE);
		clear8(keyb, MCELIECE_KEY_SIZE);
		clear8(pk, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sendb, MCELIECE_CIPHERTEXT_SIZE);
		clear8(sk, MCELIECE_SECRETKEY_SIZE);

		if (sysrand_getbytes((uint8_t*)&pos, sizeof(size_t)) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* alice generates a public key */
		if (crypto_kem_keypair(pk, sk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* bob derives a secret key and creates a response */
		if (crypto_kem_enc(sendb, keyb, pk) != MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* replace some ciphertext bytes with random values */
		sysrand_getbytes(sendb, 8);

		/* invalid ciphertext, auth should fail */
		if (crypto_kem_dec(keya, sendb, sk) == MQC_STATUS_SUCCESS)
		{
			ret = false;
			break;
		}

		/* fail if equal */
		if (memcmp(keya, keyb, MCELIECE_KEY_SIZE) == 0)
		{
			ret = false;
			break;
		}
	}

	return ret;
}

/**
* \brief Run the McEliece implementation stress and correctness tests tests
*/
void mceliece_test_run()
{
	if (test_keys() == true)
	{
		printf_s("Success! Passed key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the encryption stress tests. \n \n");
	}

	if (test_invalid_secretkey() == true)
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
* \brief Runs the SHA3 and McEliece tests
*/
int main(void)
{
	printf_s("*** Running Poly1305 Known Answer Tests *** \n");
	poly1305_test_run();
	printf_s("\n");
	printf_s("*** Running ChaCha Known Answer Tests *** \n");
	chacha_test_run();
	printf_s("\n");
	printf_s("*** Running SHA3 digest and SHAKE Known Answer Tests *** \n");
	printf_s("\n");
	sha3_test_run();
	printf_s("\n");
	printf_s("*** Running McEliece implementation stress and validity tests *** \n");
	printf_s("\n");
	mceliece_test_run();
	printf_s("\n");

	printf_s("\n");
	printf_s("Completed! Press any key to close..");
	get_response();

	return 0;
}
