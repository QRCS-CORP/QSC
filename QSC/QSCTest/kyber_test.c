#include "kyber_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/consoleutils.h"
#include "../QSC/csp.h"
#include "../QSC/intutils.h"
#include "../QSC/kyber.h"
#include "../QSC/memutils.h"

bool qsctest_kyber_ciphertext_integrity()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* change some bytes in the ciphertext */
	if (qsc_csp_generate(ct, 32) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber cipher-text: the random generator has failed -KCT0");
		res = false;
	}

	/* invalid ciphertext, auth should fail */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) == true)
	{
		qsc_consoleutils_print_line("Failure! kyber cipher-text: decapsulation has failed -KCT1");
		res = false;
	}

	/* fail if equal */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
	{
		qsc_consoleutils_print_line("Failure! kyber cipher-text: invalid shared secret -KCT2");
		res = false;
	}

	return res;
}

bool qsctest_kyber_kat_test()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kpk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ss1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ss2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	size_t ctlen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t sslen;
	uint32_t i;
	bool ret;

	ctlen = 0;
	i = 0;
	pklen = 0;
	seedlen = 0;
	sklen = 0;
	sslen = 0;
	ret = true;

#if defined(QSC_KYBER_FIPS203)
	/* NIST FIPS 203 KATs */
	#	if defined(QSC_KYBER_S1P1632)
	char path[] = "FIPS/kyber-1632.rsp";
#	elif defined(QSC_KYBER_S3P2400)
	char path[] = "FIPS/kyber-2400.rsp";
#	elif defined(QSC_KYBER_S5P3168)
	char path[] = "FIPS/kyber-3168.rsp";
#	elif defined(QSC_KYBER_S6P3936)
	/* Note: custom K6 parameter */
	char path[] = "FIPS/kyber-3936.rsp";
#	else
#	error The parameter set is invalid!
#	endif
#else
	/* NIST PQC Finalist KATs */
#	if defined(QSC_KYBER_S1P1632)
	char path[] = "NPQCR3/kyber-1632.rsp";
#	elif defined(QSC_KYBER_S3P2400)
	char path[] = "NPQCR3/kyber-2400.rsp";
#	elif defined(QSC_KYBER_S5P3168)
	char path[] = "NPQCR3/kyber-3168.rsp";
#	elif defined(QSC_KYBER_S6P3936)
	/* Note: custom K6 parameter */
	char path[] = "NPQCR3/kyber-3936.rsp";
#	else
#	error The parameter set is invalid!
#	endif
#endif

#if defined(QSCTEST_KYBER_FULL_KAT)
	for (i = 0; i < QSCTEST_KYBER_TEST_COUNT; ++i)
#endif
	{
		parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, i);

		qsctest_nistrng_prng_initialize(seed, NULL, 0);

		/* generate public and secret keys */
		qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* compare the public key to the expected output */
		if (qsc_intutils_are_equal8(pk, kpk, QSC_KYBER_PUBLICKEY_SIZE) != true)
		{
			qsc_consoleutils_print_line("Failure! kyber kat: public-key does not match known answer! -KAT0");
			ret = false;
		}

		/* compare the secret key to the expected output */
		if (qsc_intutils_are_equal8(sk, ksk, QSC_KYBER_PRIVATEKEY_SIZE) != true)
		{
			qsc_consoleutils_print_line("Failure! kyber kat: private-key does not match known answer! -KAT1");
			ret = false;
		}

		/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
		qsc_kyber_encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate);

		/* compare the cipher-text to the expected output */
		if (qsc_intutils_are_equal8(ct, kct, QSC_KYBER_CIPHERTEXT_SIZE) != true)
		{
			qsc_consoleutils_print_line("Failure! kyber kat: cipher-text does not match known answer! -KAT2");
			ret = false;
		}

		/* a uses b's response to get the shared-secret key (in: ct, sk | out: ss1) */
		if (qsc_kyber_decapsulate(ss1, ct, sk) != true)
		{
			qsc_consoleutils_print_line("Failure! kyber kat: decryption authentication failure! -KAT3");
			ret = false;
		}

		/* compare the two keys for equality */
		if (qsc_intutils_are_equal8(ss1, ss2, QSC_KYBER_SHAREDSECRET_SIZE) != true)
		{
			qsc_consoleutils_print_line("Failure! kyber kat: shared secrets do not match! -KAT4");
			ret = false;
		}

		/* compare the key to the expected output */
		if (qsc_intutils_are_equal8(ss1, kss, QSC_KYBER_SHAREDSECRET_SIZE) != true)
		{
			qsc_consoleutils_print_line("Failure! kyber kat: shared secret does not match known answer! -KAT5");
			ret = false;
		}
	}

	return ret;
}

bool qsctest_kyber_privatekey_integrity()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* replace secret key with random values */
	if (qsc_csp_generate(sk + QSC_KYBER_PUBLICKEY_SIZE, 32) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber_test_operations: the shared secrets are not equal -INTEG0");
		res = false;
	}

	/* invalid secret key, should fail */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) == true)
	{
		res = false;
	}

	/* fail if equal */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
	{
		res = false;
	}

	return res;
}

bool qsctest_kyber_publickey_integrity()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* replace public key with random values */
	if (qsc_csp_generate(pk, 32) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber_test_operations: the shared secrets are not equal -INTEG0");
		res = false;
	}

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* invalid secret key, should fail */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) == true)
	{
		res = false;
	}

	/* fail if equal */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
	{
		res = false;
	}

	return res;
}

bool qsctest_kyber_operations_test()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t esd[QSC_KYBER_SEED_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* decapsulate the cipher-text and extract the shared secret */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber operations: decapsulation failure -KOT1");
		res = false;
	}

	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber operations: the shared secrets are not equal -KOT2");
		res = false;
	}

	/* test encrypt/decrypt api */

	qsc_memutils_clear(ct, sizeof(ct));
	qsc_memutils_clear(ssk1, sizeof(ssk1));
	qsc_memutils_clear(ssk2, sizeof(ssk2));

	qsc_csp_generate(esd, sizeof(esd));

	qsc_kyber_encrypt(ssk1, ct, pk, esd);
	qsc_kyber_decrypt(ssk2, ct, sk);

	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber operations: the shared secrets are not equal -KOT3");
		res = false;
	}

	return res;
}

void qsctest_kyber_run()
{
	if (qsctest_kyber_kat_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the Kyber encryption, and decryption known answer test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the Kyber encryption, and decryption known answer test.");
	}

	if (qsctest_kyber_operations_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the Kyber key generation, encryption, and decryption stress test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the Kyber key generation, encryption, and decryption stress test.");
	}

	if (qsctest_kyber_privatekey_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the Kyber private-key tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the Kyber private-key tamper test.");
	}

	if (qsctest_kyber_publickey_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the Kyber public-key tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the Kyber public-key tamper test.");
	}

	if (qsctest_kyber_ciphertext_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the Kyber cipher-text tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the Kyber cipher-text tamper test.");
	}
}
