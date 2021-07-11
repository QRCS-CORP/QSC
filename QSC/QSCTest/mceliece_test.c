#include "mceliece_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/consoleutils.h"
#include "../QSC/csp.h"
#include "../QSC/intutils.h"
#include "../QSC/mceliece.h"

bool qsctest_mceliece_ciphertext_integrity()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t* pk;
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ss1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ss2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	bool ret;

	ret = false;
	pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL)
	{
		ret = true;
		qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
		qsctest_nistrng_prng_initialize(seed, NULL, 0);

		/* generate public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
		qsc_mceliece_encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate);

		/* replace some ciphertext bytes with random values */
		if (qsc_csp_generate(ct, 8) == false)
		{
			qsctest_print_safe("Failure! mceliece ciphertext integrity: the random provider failed -MCT1 \n");
			ret = false;
		}

		/* invalid ciphertext, authentication should fail */
		if (qsc_mceliece_decapsulate(ss1, ct, sk) == true)
		{
			qsctest_print_safe("Failure! mceliece ciphertext integrity: secret decapsulation failure -MCT2 \n");
			ret = false;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(ss1, ss2, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! mceliece ciphertext integrity: message decrypted succesfully with altered cipher-text -MCT3 \n");
			ret = false;
		}

		free(pk);
	}

	return ret;
}

bool qsctest_mceliece_kat_test()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t* kpk;
	uint8_t ksk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t* pk;
	uint8_t ss1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ss2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	size_t ctlen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t sslen;
	bool ret;

	ctlen = 0;
	pklen = 0;
	seedlen = 0;
	sklen = 0;
	sslen = 0;
	ret = false;
	pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);
	kpk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL && kpk != NULL)
	{
#if defined(QSC_MCELIECE_S3N4608T96)
		char path[] = "NPQCR3/mceliece-460896.rsp";
#elif defined(QSC_MCELIECE_S5N6688T128)
		char path[] = "NPQCR3/mceliece-6688128.rsp";
#elif defined(QSC_MCELIECE_S5N6960T119)
		char path[] = "NPQCR3/mceliece-6960119.rsp";
#elif defined(QSC_MCELIECE_S5N8192T128)
		char path[] = "NPQCR3/mceliece-8192128.rsp";
#else
#	error The parameter set is invalid!
#endif

		ret = true;
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsc_intutils_clear8(kpk, QSC_MCELIECE_PUBLICKEY_SIZE);

		/* NIST PQC Round 3 KATs */
		parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);

		ret = true;
		qsctest_nistrng_prng_initialize(seed, NULL, 0);

		/* alice generates public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* compare the public key to the expected output */
		if (qsc_intutils_are_equal8(pk, kpk, QSC_MCELIECE_PUBLICKEY_SIZE) != true)
		{
			qsc_consoleutils_print_line("Failure! mceliece kat: public key does not match known answer! -MKT0");
			ret = false;
		}

		/* compare the secret key to the expected output */
		if (qsc_intutils_are_equal8(sk, ksk, QSC_MCELIECE_PRIVATEKEY_SIZE) != true)
		{
			qsc_consoleutils_print_line("Failure! mceliece kat: private key does not match known answer! -MKT1");
			ret = false;
		}

		/* bob derives a shared-secret key and creates a response (in: pk | out: ct and ss2) */
		qsc_mceliece_encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate);

		/* compare the cipher-text to the expected output */
		if (qsc_intutils_are_equal8(ct, kct, QSC_MCELIECE_CIPHERTEXT_SIZE) != true)
		{
			qsctest_print_safe("Failure! mceliece kat: ciphertext does not match known answer -MKT2 \n");
			ret = false;
		}

		/* alice uses bobs response to get the shared-secret key (in: ct, sk | out: ss1) */
		if (qsc_mceliece_decapsulate(ss1, ct, sk) != true)
		{
			qsctest_print_safe("Failure! mceliece kat: decapsulation failure -MKT3 \n");
			ret = false;
		}

		/* compare the two keys for equality */
		if (qsc_intutils_are_equal8(ss1, ss2, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! mceliece kat: secret keys do not match -MKT4 \n");
			ret = false;
		}

		/* compare the key to the expected output */
		if (qsc_intutils_are_equal8(ss1, kss, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! mceliece kat: shared secret does not match the known answer -MKT5 \n");
			ret = false;
		}

		free(kpk);
		free(pk);
	}

	return ret;
}

bool qsctest_mceliece_operations_test()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t* pk;
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ss1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ss2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	bool ret;

	ret = false;
	pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL)
	{
		ret = true;
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);

		/* generate public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
		qsc_mceliece_encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate);

		/* decrypt the cipher-text */
		if (qsc_mceliece_decapsulate(ss1, ct, sk) != true)
		{
			qsctest_print_safe("Failure! mceliece operations: decapsulation failure -MOT1 \n");
			ret = false;
		}

		/* compare the two keys for equality */
		if (qsc_intutils_are_equal8(ss1, ss2, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! mceliece operations: the two secret keys do not match -MOT2 \n");
			ret = false;
		}

		free(pk);
	}

	return ret;
}

bool qsctest_mceliece_publickey_integrity()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t* pk;
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ss1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ss2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	bool ret;

	ret = false;
	pk = malloc(QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL)
	{
		ret = true;
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
		qsctest_nistrng_prng_initialize(seed, NULL, 0);

		/* generate public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* replace public key bytes with random values */
		if (qsc_csp_generate(pk, QSC_MCELIECE_PUBLICKEY_SIZE / 100) != true)
		{
			qsctest_print_safe("Failure! mceliece public-key: the random provider has failed -MPT1 \n");
			ret = false;
		}

		/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
		qsc_mceliece_encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate);

		/* invalid secret key generated, should return fail */
		if (qsc_mceliece_decapsulate(ss1, ct, sk) == true)
		{
			qsctest_print_safe("Failure! mceliece public-key: decapsulation failure -MPT2 \n");
			ret = false;
		}

		/* fail if output keys are equal */
		if (qsc_intutils_are_equal8(ss1, ss2, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! mceliece public-key: the two secret keys match with an altered public key -MPT3 \n");
			ret = false;
		}

		free(pk);
	}

	return ret;
}

void qsctest_mceliece_run()
{
	if (qsctest_mceliece_kat_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the McEliece encryption, and decryption known answer test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the McEliece encryption, and decryption known answer test.");
	}

	if (qsctest_mceliece_operations_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the McEliece key generation, encryption, and decryption stress test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the McEliece key generation, encryption, and decryption stress test.");
	}

	if (qsctest_mceliece_publickey_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the McEliece public-key tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the McEliece public-key tamper test.");
	}

	if (qsctest_mceliece_ciphertext_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the McEliece cipher-text tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the McEliece cipher-text tamper test.");
	}
}