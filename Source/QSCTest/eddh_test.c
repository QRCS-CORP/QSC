#include "eddh_test.h"
#include "nistrng.h"
#include "testutils.h"
#include "csp.h"
#include "eddh.h"
#include "intutils.h"

bool qsctest_eddh_kat_test()
{
	uint8_t kpka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t kpkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksec[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t kska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kskb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t seeda[QSC_EDDH_SEED_SIZE] = { 0 };
	uint8_t seedb[QSC_EDDH_SEED_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	bool ret;

	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", seeda, sizeof(seeda));
	qsctest_hex_to_bin("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", seedb, sizeof(seedb));

#if defined(QSC_EDDH_RFC_7748_COMPLIANT)
	qsctest_hex_to_bin("9663AA1DA97E848A914A436D04163DFBB89178F107F1B5B77ED3854203382854", ksec, sizeof(ksec));
	qsctest_hex_to_bin("8F40C5ADB68F25624AE5B214EA767A6EC94D829D3D7B5E1AD1BA6F3E2138285F", kpka, sizeof(kpka));
	qsctest_hex_to_bin("358072D6365880D1AEEA329ADF9121383851ED21A28E3B75E965D0D2CD166254", kpkb, sizeof(kpkb));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", kska, sizeof(kska));
	qsctest_hex_to_bin("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", kskb, sizeof(kskb));
#else
	qsctest_hex_to_bin("F6F92EFB32945AFF683324A1C984C5001F46AAEA513F3453138D740B3A604B7D", ksec, sizeof(ksec));
	qsctest_hex_to_bin("4701D08488451F545A409FB58AE3E58581CA40AC3F7F114698CD71DEAC73CA01", kpka, sizeof(kpka));
	qsctest_hex_to_bin("5730800AB340FCB18CE5111EDA9D705F91388B41E4544CBD103BA5942DB2233E", kpkb, sizeof(kpkb));
	qsctest_hex_to_bin("3D94EEA49C580AEF816935762BE049559D6D1440DEDE12E6A125F1841FFF8E6F", kska, sizeof(kska));
	qsctest_hex_to_bin("887AF58A36202E05C4C1CFEC5BF6C61FAD66BCA851536004074B31F1B56E4AC9", kskb, sizeof(kskb));
#endif

	ret = true;

	/* alice generates a key-pair */
	qsc_eddh_generate_seeded_keypair(pka, ska, seeda);
	/* bob generates a key-pair */
	qsc_eddh_generate_seeded_keypair(pkb, skb, seedb);

	/* test key generation */
	if (qsc_intutils_are_equal8(pka, kpka, sizeof(pka)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: public key a does not match expected -EK1 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(pkb, kpkb, sizeof(pkb)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: public key b does not match expected -EK2 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(ska, kska, sizeof(ska)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: private key a does not match expected -EK3 \n");
		ret = false;
	}
	
	if (qsc_intutils_are_equal8(skb, kskb, sizeof(skb)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: private key b does not match expected -EK4 \n");
		ret = false;
	}

	/* compare the secret key to the expected output */

	/* alice derives the secret key */
	if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: key exchange a has failed -EK5 \n");
		ret = false;
	}

	/* bob derives the secret key */
	if (qsc_eddh_key_exchange(secb, skb, pka) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: key exchange b has failed -EK6 \n");
		ret = false;
	}

	/* fail if alice and bobs secret are not equal */
	if (qsc_intutils_are_equal8(seca, secb, sizeof(seca)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: secrets for a and b do not match -EK7 \n");
		ret = false;
	}

	/* fail if secret does not match known answer */
	if (qsc_intutils_are_equal8(seca, ksec, sizeof(seca)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: secret does not match known answer -EK8 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_eddh_operations_test()
{
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSC_EDDH_SEED_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (size_t i = 0; i < QSCTEST_EDDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_eddh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_eddh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* alice derives the secret key */
		if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! eddh_test_operations: key exchange failure -EO1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_eddh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! eddh_test_operations: key exchange failure -EO2 \n");
			res = false;
			break;
		}

		/* compare them for equality*/
		if (qsc_intutils_are_equal8(seca, secb, QSC_EDDH_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! eddh_test_operations: secret keys do not match -EO3 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_eddh_privatekey_integrity()
{
	uint8_t seed[QSC_EDDH_SEED_SIZE] = { 0 };
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (size_t i = 0; i < QSCTEST_EDDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_eddh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_eddh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* flip a bit in alices private key */
		ska[1] ^= 1U;

		/* alice derives the secret key */
		if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! eddh_test_privatekey: key exchange failure -ES1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_eddh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! eddh_test_privatekey: key exchange failure -ES2 \n");
			res = false;
			break;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(seca, secb, QSC_EDDH_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! eddh_test_privatekey: altered private key did not change secret -ES3 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_eddh_publickey_integrity()
{
	uint8_t seed[QSC_EDDH_SEED_SIZE] = { 0 };
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (size_t i = 0; i < QSCTEST_EDDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_eddh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_eddh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* flip a bit in alices public key */
		pka[0] ^= 1U;

		/* alice derives the secret key */
		if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! eddh_test_publickey: key exchange failure -EP1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_eddh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! eddh_test_publickey: key exchange failure -EP2 \n");
			res = false;
			break;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(seca, secb, QSC_EDDH_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! eddh_test_publickey: altered public key did not change secret -EP3 \n");
			res = false;
			break;
		}
	}

	return res;
}

void qsctest_eddh_run()
{
	if (qsctest_eddh_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed EDDH known answer test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH known answer test. \n");
	}

	if (qsctest_eddh_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed EDDH key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH the encryption stress tests. \n");
	}

	if (qsctest_eddh_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed EDDH secret-key tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH secret-key tamper test. \n");
	}

	if (qsctest_eddh_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed EDDH public-key tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH public-key tamper test. \n");
	}
}
