#include "mceliece_test.h"
#include "testutils.h"
#include "nistrng.h"
#include "../QSC/csp.h"
#include "../QSC/intutils.h"
#include "../QSC/mceliece.h"

bool qsctest_mceliece_test_operations()
{
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE];
	size_t i;
	bool ret;

#ifdef MQC_COMPILER_GCC
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE];
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;
	
	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		qsc_intutils_clear8(keya, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(keyb, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsc_intutils_clear8(sendb, QSC_MCELIECE_CIPHERTEXT_SIZE);
		qsc_intutils_clear8(sk, QSC_MCELIECE_PRIVATEKEY_SIZE);

		/* alice generates public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* bob derives a shared-secret key and creates a response (in: pk | out: sendb and keyb) */
		qsc_mceliece_encapsulate(keyb, sendb, pk, qsctest_nistrng_prng_generate);

		/* alice uses bobs response to get the shared-secret key (in: sendb, sk | out: keya) */
		if (qsc_mceliece_decapsulate(keya, sendb, sk) != true)
		{
			ret = false;
			break;
		}

		/* compare the two keys for equality */
		if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
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

bool qsctest_mceliece_test_publickey()
{
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE];
	size_t i;
	bool ret;

#ifdef MQC_COMPILER_GCC
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE];
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		qsc_intutils_clear8(keya, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(keyb, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsc_intutils_clear8(sendb, QSC_MCELIECE_CIPHERTEXT_SIZE);
		qsc_intutils_clear8(sk, QSC_MCELIECE_PRIVATEKEY_SIZE);

		/* alice generates a public key */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* replace public key bytes with random values */
		if (qsc_csp_generate(pk, 1024) != true)
		{
			ret = false;
			break;
		}

		/* bob generates a shared-secret key and creates the response */
		qsc_mceliece_encapsulate(keyb, sendb, pk, qsctest_nistrng_prng_generate);

		/* invalid secret key generated, should return fail */
		if (qsc_mceliece_decapsulate(keya, sendb, sk) == true)
		{
			ret = false;
			break;
		}

		/* fail if output keys are equal */
		if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
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

bool qsctest_mceliece_test_ciphertext()
{
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE];
	bool ret;
	size_t i;

#ifdef MQC_COMPILER_GCC
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE];
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;

	for (i = 0; i < MCELIECE_NTESTS; i++)
	{
		qsc_intutils_clear8(keya, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(keyb, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsc_intutils_clear8(sendb, QSC_MCELIECE_CIPHERTEXT_SIZE);
		qsc_intutils_clear8(sk, QSC_MCELIECE_PRIVATEKEY_SIZE);

		/* alice generates a public/secret key-pair */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* bob derives the shared-secret key and creates a response */
		qsc_mceliece_encapsulate(keyb, sendb, pk, qsctest_nistrng_prng_generate);

		/* replace some ciphertext bytes with random values */
		if (qsc_csp_generate(sendb, 8) == false)
		{
			ret = false;
			break;
		}

		/* invalid ciphertext, authentication should fail */
		if (qsc_mceliece_decapsulate(keya, sendb, sk) == true)
		{
			ret = false;
			break;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
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

bool qsctest_mceliece_test_kats()
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE];
	uint8_t expct[QSC_MCELIECE_CIPHERTEXT_SIZE];
	uint8_t expss[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE];
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE];
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE];
	bool ret;
#ifdef MQC_COMPILER_GCC
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE] = { 0 };
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
	qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
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

#if defined(QSC_MCELIECE_N8192T128)
	hex_to_bin("9583F9C0E887851BE079E0AEF65CC7F6C11482AA537E99EAD8865C3B5E65821468C4687CDF017C9FCF2B318238A97519"
		"9D05E7FE51034585B26B54F3E3E99C410BCDC090A736BDBFC34C400402A9860E39438DEA312379EFE4DAE5CFCD7280CA"
		"978F8A96B96397C02B8518D11615FFA8B26D74A85406138199E6F4B8B4A683FB966398F5EDAC38557D73A127816B0644"
		"3BDE6524A936C2C0DA8EFDDDB3850F522F0A26FC3DC3BCBBFFB32A0AD0FD156A8F3192D45B10B48647C546F8C5DB3F0D"
		"1AEAA192D88493AE6C1F1E9C253342551094F5643697600DCB99758E6D06375DCA20005FEBABBDC3A894CF676EB51992", expct, sizeof(expct));
	hex_to_bin("DD1A7EC5E1026D5A77210F1374219018FC1C6CFD6BADF848A860C4749424D344", expss, 32);
	hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
#elif defined(QSC_MCELIECE_N6960T119)
	hex_to_bin("056DACA18318D82849759ED3C816C45821186E6AA763A018C5A40AA29593A6C312A30CE36FB3C30BC4E2A4AFD1C7B065"
		"14E9FE59678A0F2A14F09B0645F9EC980D406790DE6775781E3136A248D4588D60344F73CB4E3C567DE64BBE588C7C54"
		"9A9E3585EF98A5F55C3B9BAD7418932CB8966EC08B28B3A2A30B5C9067DFC854935DD0410D19BB24BF7086C0BCAB2DD0"
		"A69D25A15B5A685936855F05BFA7CA9CF9E58557B3AE8D4EBC8853B32FD52AD1DF66D6576CB69D58CFC8915BCC9D1C10"
		"1602430E3F44F48135F4370B0959B02E891F597C5BFBD340154BA8E9233DE6CE1FAF", expct, sizeof(expct));
	hex_to_bin("179C2314367D02DCC0CF1C1CCF7055FB870CB26F529BBD4A393D6603FE70AE95", expss, 32);
	hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
#else
#	error No McEliece implementation is defined, check common.h!
#endif

	ret = true;
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* alice generates public and secret keys */
	qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* bob derives a shared-secret key and creates a response (in: pk | out: sendb and keyb) */
	qsc_mceliece_encapsulate(keyb, sendb, pk, qsctest_nistrng_prng_generate);

	/* compare the cipher-text to the expected output */
	if (qsc_intutils_are_equal8(sendb, expct, QSC_MCELIECE_CIPHERTEXT_SIZE) != true)
	{
		ret = false;
	}

	/* alice uses bobs response to get the shared-secret key (in: sendb, sk | out: keya) */
	if (qsc_mceliece_decapsulate(keya, sendb, sk) != true)
	{
		ret = false;
	}

	/* compare the two keys for equality */
	if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
	{
		ret = false;
	}
	
	/* compare the key to the expected output */
	if (qsc_intutils_are_equal8(keya, expss, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
	{
		ret = false;
	}

#ifndef MQC_COMPILER_GCC
	free(pk);
#endif

	return ret;
}

void qsctest_mceliece_run()
{
	if (qsctest_mceliece_test_kats() == true)
	{
		printf_s("Success! Passed key generation, encryption, and decryption known answer test. \n");
	}
	else
	{
		printf_s("Failure! Failed the known answer test. \n \n");
	}

	if (qsctest_mceliece_test_operations() == true)
	{
		printf_s("Success! Passed key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the encryption stress tests. \n \n");
	}

	if (qsctest_mceliece_test_publickey() == true)
	{
		printf_s("Success! Passed public key tamper test. \n");
	}
	else
	{
		printf_s("Failure! Failed public key tamper test. \n");
	}

	if (qsctest_mceliece_test_ciphertext() == true)
	{
		printf_s("Success! Passed cipher-text tamper test. \n");
	}
	else
	{
		printf_s("Failure! Failed cipher-text tamper test. \n");
	}
}