#include "ecdh_test.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/csp.h"
#include "../QSC/ecdh.h"
#include "../QSC/intutils.h"

bool qsctest_ecdh_kat_test()
{
	uint8_t kpka[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t kpkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksec[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t kska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kskb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t seeda[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t seedb[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	bool ret;

	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", seeda, sizeof(seeda));
	hex_to_bin("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", seedb, sizeof(seedb));
	hex_to_bin("F6F92EFB32945AFF683324A1C984C5001F46AAEA513F3453138D740B3A604B7D", ksec, sizeof(ksec));
	hex_to_bin("4701D08488451F545A409FB58AE3E58581CA40AC3F7F114698CD71DEAC73CA01", kpka, sizeof(kpka));
	hex_to_bin("5730800AB340FCB18CE5111EDA9D705F91388B41E4544CBD103BA5942DB2233E", kpkb, sizeof(kpkb));
	hex_to_bin("3D94EEA49C580AEF816935762BE049559D6D1440DEDE12E6A125F1841FFF8E6F"
		"0000000000000000000000000000000000000000000000000000000000000000", kska, sizeof(kska));
	hex_to_bin("887AF58A36202E05C4C1CFEC5BF6C61FAD66BCA851536004074B31F1B56E4AC9"
		"0000000000000000000000000000000000000000000000000000000000000000", kskb, sizeof(kskb));

	ret = true;

	/* alice generates a key-pair */
	qsc_ecdh_generate_seeded_keypair(pka, ska, seeda);
	/* bob generates a key-pair */
	qsc_ecdh_generate_seeded_keypair(pkb, skb, seedb);

	/* test key generation */

	if (qsc_intutils_are_equal8(pka, kpka, sizeof(pka)) != true)
	{
		print_safe("Failure! ecdh_kat: public key a does not match expected -EK1 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(pkb, kpkb, sizeof(pkb)) != true)
	{
		print_safe("Failure! ecdh_kat: public key b does not match expected -EK2 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(ska, kska, sizeof(ska)) != true)
	{
		print_safe("Failure! ecdh_kat: private key a does not match expected -EK3 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(skb, kskb, sizeof(skb)) != true)
	{
		print_safe("Failure! ecdh_kat: private key b does not match expected -EK4 \n");
		ret = false;
	}

	/* compare the secret key to the expected output */

	/* alice derives the secret key */
	if (qsc_ecdh_key_exchange(seca, ska, pkb) != true)
	{
		print_safe("Failure! ecdh_kat: key exchange a has failed -EK5 \n");
		ret = false;
	}

	/* bob derives the secret key */
	if (qsc_ecdh_key_exchange(secb, skb, pka) != true)
	{
		print_safe("Failure! ecdh_kat: key exchange b has failed -EK6 \n");
		ret = false;
	}

	/* fail if alice and bobs secret are not equal */
	if (qsc_intutils_are_equal8(seca, secb, sizeof(seca)) != true)
	{
		print_safe("Failure! ecdh_kat: secrets for a and b do not match -EK7 \n");
		ret = false;
	}

	/* fail if secret does not match known answer */
	if (qsc_intutils_are_equal8(seca, ksec, sizeof(seca)) != true)
	{
		print_safe("Failure! ecdh_kat: secret does not match known answer -EK8 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_ecdh_operations_test()
{
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	size_t i;
	bool res;

	res = true;
	hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (i = 0; i < QSCTEST_ECDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_ecdh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_ecdh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* alice derives the secret key */
		if (qsc_ecdh_key_exchange(seca, ska, pkb) != true)
		{
			print_safe("Failure! ecdh_test_operations: key exchange failure -EO1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_ecdh_key_exchange(secb, skb, pka) != true)
		{
			print_safe("Failure! ecdh_test_operations: key exchange failure -EO2 \n");
			res = false;
			break;
		}

		/* compare them for equality*/
		if (qsc_intutils_are_equal8(seca, secb, QSC_ECDH_SHAREDSECRET_SIZE) != true)
		{
			print_safe("Failure! ecdh_test_operations: secret keys do not match -EO3 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_ecdh_privatekey_integrity()
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	size_t i;
	bool res;

	res = true;
	hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (i = 0; i < QSCTEST_ECDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_ecdh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_ecdh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* flip a bit in alices private key */
		ska[1] ^= 1U;

		/* alice derives the secret key */
		if (qsc_ecdh_key_exchange(seca, ska, pkb) != true)
		{
			print_safe("Failure! ecdh_test_privatekey: key exchange failure -ES1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_ecdh_key_exchange(secb, skb, pka) != true)
		{
			print_safe("Failure! ecdh_test_privatekey: key exchange failure -ES2 \n");
			res = false;
			break;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(seca, secb, QSC_ECDH_SHAREDSECRET_SIZE) == true)
		{
			print_safe("Failure! ecdh_test_privatekey: altered private key did not change secret -ES3 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_ecdh_publickey_integrity()
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	size_t i;
	bool res;

	res = true;
	hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (i = 0; i < QSCTEST_ECDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_ecdh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_ecdh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* flip a bit in alices public key */
		pka[0] ^= 1U;

		/* alice derives the secret key */
		if (qsc_ecdh_key_exchange(seca, ska, pkb) != true)
		{
			print_safe("Failure! ecdh_test_publickey: key exchange failure -EP1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_ecdh_key_exchange(secb, skb, pka) != true)
		{
			print_safe("Failure! ecdh_test_publickey: key exchange failure -EP2 \n");
			res = false;
			break;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(seca, secb, QSC_ECDH_SHAREDSECRET_SIZE) == true)
		{
			print_safe("Failure! ecdh_test_publickey: altered public key did not change secret -EP3 \n");
			res = false;
			break;
		}
	}

	return res;
}

void qsctest_ecdh_run()
{
	if (qsctest_ecdh_kat_test() == true)
	{
		print_safe("Success! Passed ECDH known answer test. \n");
	}
	else
	{
		print_safe("Failure! Failed ECDH known answer test. \n");
	}

	if (qsctest_ecdh_operations_test() == true)
	{
		print_safe("Success! Passed ECDH key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		print_safe("Failure! Failed ECDH the encryption stress tests. \n");
	}

	if (qsctest_ecdh_privatekey_integrity() == true)
	{
		print_safe("Success! Passed ECDH secret-key tamper test. \n");
	}
	else
	{
		print_safe("Failure! Failed ECDH secret-key tamper test. \n");
	}

	if (qsctest_ecdh_publickey_integrity() == true)
	{
		print_safe("Success! Passed ECDH public-key tamper test. \n");
	}
	else
	{
		print_safe("Failure! Failed ECDH public-key tamper test. \n");
	}
}
