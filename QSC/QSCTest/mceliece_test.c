#include "mceliece_test.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/csp.h"
#include "../QSC/intutils.h"
#include "../QSC/mceliece.h"

bool qsctest_mceliece_ciphertext_integrity()
{
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	bool ret;
	size_t i;

#if defined(QSC_SYSTEM_COMPILER_GCC) // TODO: change this to ifdef MSC compiler
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE] = { 0 };
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (i = 0; i < QSCTEST_MCELIECE_ITERATIONS; i++)
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
			qsctest_print_safe("Failure! mceliece_ciphertext_integrity: the random provider failed -MC1 \n");
			ret = false;
			break;
		}

		/* invalid ciphertext, authentication should fail */
		if (qsc_mceliece_decapsulate(keya, sendb, sk) == true)
		{
			qsctest_print_safe("Failure! mceliece_ciphertext_integrity: secret decapsulation failure -MC2 \n");
			ret = false;
			break;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! mceliece_ciphertext_integrity: message decrypted succesfully with altered cipher-text -MC3 \n");
			ret = false;
			break;
		}
	}

#if !defined(QSC_SYSTEM_COMPILER_GCC)
	free(pk);
#endif

	return ret;
}

bool qsctest_mceliece_kat_test()
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t expct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t expss[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	bool ret;
#if defined(QSC_SYSTEM_COMPILER_GCC)
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE] = { 0 };
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
	qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
#endif

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

#if defined(QSC_MCELIECE_S3N4608T96)
	qsctest_hex_to_bin("CF78C42A38795E0F5D6BAC38ACDEE6C4C9536F93BCC32E08B8CE0B886E737AA5AD51CC0E2E5B9176B67F0327EA117334DCD5664ADCFFB39F1932C498B210A56EB5C9E9C7C5DB03DC46C5D2450D1F05C152533BE30AA544F20FF11CAC1FFEBB919D69B033642AC0ABC1C174AFCBE9F22433A5D3E2048621A7982CC08D5D9E37BC65ABE96DF8A651758894B6E58A34E42CB82798BE3FD7B3D96DE27E651585121A060E712178A6218AF3907BC3F8BCDE02E8EAF5769C9E790274267B37", expct, sizeof(expct));
	qsctest_hex_to_bin("F6EB7975CC7AD7438DBE220C72DE9FDB7717161D8A6AA461666B767455847EE9", expss, sizeof(expss));
#elif defined(QSC_MCELIECE_S5N6688T128)
	qsctest_hex_to_bin("01278F7400972FD05AA6368A4F8662497A5A31A3E968BF81B49EBDFB8331769EA1BB5275AD46D33F8D6624C2F305F961DC8812850B20C2FE3C7E8FB0393BBBFFFC0458A01765EC519AB332DA952047B8A87C618D3BF28046B94F82872A75D1C090DBE768168DF6D7D6755FAFB5AE050AE520BF7ED641C90161DFB70E4A5EF9A8D64856CAC821D98B00E8145D3462A4DB6CF2E0C002DBA11257D7716E22F18F8E28113CDF5FE7581CC82854165AB93E36D4080F8E7B8116667E9C12D515A443EA002E609C6F5EE839FF282D8EAAF6BB8CEA79099D6282BAD1AF5B0CA919D112A35B12FD483FA90F9FD8B72D15E668E442", expct, sizeof(expct));
	qsctest_hex_to_bin("18A3E9906E03926AA87E0E910C570F5874549B0B1DE9E60D50C4031B5EB0B0F6", expss, sizeof(expss));
#elif defined(QSC_MCELIECE_S5N6960T119)
	qsctest_hex_to_bin("63C39D29314866A0FE528B3D5DE37D5C6F72279EE711036198B0C2CA1F293D3541E0D1467D63D2E5C92B8060001CF002017F60B954C5DC457BA63C59BBE330BB66BC8726E605ACD0E90CD7167376F68CC071D4F931349564EF28D7EAB3D1FF61563EE1DEFD95A548004979736AB1B39BE08D57A49F39988F23574A5A06FC4C317F08C1B842EF844773BE74701E57EC91107DE40C6EEB222630621A6FBF2A4CB8CCB9C395ABD85FDC03C0FBE0E56EC9F7052B90608E21653FA2DE1AD62C68C2656C068CC5C37FC0AFD9B145CB3C4E7C30EF4D4C9F404E6FFFFB179AED0CF18B3BDA14", expct, sizeof(expct));
	qsctest_hex_to_bin("35D4BE047205AFF8339FCF19935D5F3F3C09BAFC6E418448214D5F159915DED7", expss, sizeof(expss));
#elif defined(QSC_MCELIECE_S5N8192T128)
	qsctest_hex_to_bin("AD9728E7519C5F851FDA1148CF652893C8884288930995416F95798C4F2E0151FF617828CBCBC74BA3870D04E41FB875BE651A8070E23B89D47362833D899ABB57D25886FD9B71C2027C3F32FB5D699922053BA4E7297E9EE87838DBC06677E0B4EB4D9EDEA0945A6D0A01020BB30C33CF0498373B9AF3517DD20331FFB1F8177946251EFA80BE477E96D8ACAF5F2AB93DE67868DE506B44E0A1FA058176450A380901A5AA0E033642A7ECCD50C77916268AD225AFB3B7A1560FAF4CF476ACFFBBFA30D1EFF17FBD73B109CF9FF2ECC03EDD086216C90F28C78E03C496B56E6659DC95C5F7C51A371D36BAD9BC1757C2", expct, sizeof(expct));
	qsctest_hex_to_bin("870B2D45FA3CCEA8186F3929DE0B68798F65A34D01353B2EBFD6B1FBC2707897", expss, sizeof(expss));
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
		qsctest_print_safe("Failure! mceliece_kat_test: ciphertext does not match known answer -MK1 \n");
		ret = false;
	}

	/* alice uses bobs response to get the shared-secret key (in: sendb, sk | out: keya) */
	if (qsc_mceliece_decapsulate(keya, sendb, sk) != true)
	{
		qsctest_print_safe("Failure! mceliece_kat_test: decapsulation failure -MK2 \n");
		ret = false;
	}

	/* compare the two keys for equality */
	if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
	{
		qsctest_print_safe("Failure! mceliece_kat_test: secret keys do not match -MK3 \n");
		ret = false;
	}
	
	/* compare the key to the expected output */
	if (qsc_intutils_are_equal8(keya, expss, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
	{
		qsctest_print_safe("Failure! mceliece_kat_test: secret key does not match the known answer -MK4 \n");
		ret = false;
	}


#if !defined(QSC_SYSTEM_COMPILER_GCC)
	free(pk);
#endif

	return ret;
}

bool qsctest_mceliece_operations_test()
{
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	size_t i;
	bool ret;

#if defined(QSC_SYSTEM_COMPILER_GCC)
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE];
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;
	
	for (i = 0; i < QSCTEST_MCELIECE_ITERATIONS; i++)
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
			qsctest_print_safe("Failure! mceliece_operations_test: decapsulation failure -MO1 \n");
			ret = false;
			break;
		}

		/* compare the two keys for equality */
		if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! mceliece_operations_test: the two secret keys do not match -MO2 \n");
			ret = false;
			break;
		}
	}

#if !defined(QSC_SYSTEM_COMPILER_GCC)
	free(pk);
#endif

	return ret;
}

bool qsctest_mceliece_publickey_integrity()
{
	uint8_t keya[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t keyb[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sendb[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	size_t i;
	bool ret;

#if defined(QSC_SYSTEM_COMPILER_GCC)
	uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE] = { 0 };
#else
	uint8_t* pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
#endif

	ret = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (i = 0; i < QSCTEST_MCELIECE_ITERATIONS; i++)
	{
		qsc_intutils_clear8(keya, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(keyb, QSC_MCELIECE_SHAREDSECRET_SIZE);
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsc_intutils_clear8(sendb, QSC_MCELIECE_CIPHERTEXT_SIZE);
		qsc_intutils_clear8(sk, QSC_MCELIECE_PRIVATEKEY_SIZE);

		/* alice generates a public key */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* replace public key bytes with random values */
		if (qsc_csp_generate(pk, QSC_MCELIECE_PUBLICKEY_SIZE / 100) != true)
		{
			qsctest_print_safe("Failure! mceliece_publickey_integrity: the random provider has failed -MP1 \n");
			ret = false;
			break;
		}

		/* bob generates a shared-secret key and creates the response */
		qsc_mceliece_encapsulate(keyb, sendb, pk, qsctest_nistrng_prng_generate);

		/* invalid secret key generated, should return fail */
		if (qsc_mceliece_decapsulate(keya, sendb, sk) == true)
		{
			qsctest_print_safe("Failure! mceliece_publickey_integrity: decapsulation failure -MP2 \n");
			ret = false;
			break;
		}

		/* fail if output keys are equal */
		if (qsc_intutils_are_equal8(keya, keyb, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! mceliece_publickey_integrity: the two secret keys match with an altered public key -MP3 \n");
			ret = false;
			break;
		}
	}

#if !defined(QSC_SYSTEM_COMPILER_GCC)
	free(pk);
#endif

	return ret;
}

void qsctest_mceliece_run()
{
	if (qsctest_mceliece_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed key generation, encryption, and decryption known answer test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the known answer test. \n \n");
	}

	if (qsctest_mceliece_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the encryption stress tests. \n \n");
	}

	if (qsctest_mceliece_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed public key tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed public key tamper test. \n");
	}

	if (qsctest_mceliece_ciphertext_integrity() == true)
	{
		qsctest_print_safe("Success! Passed cipher-text tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed cipher-text tamper test. \n");
	}
}