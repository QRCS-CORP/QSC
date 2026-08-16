#include "kyber_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "consoleutils.h"
#include "csp.h"
#include "intutils.h"
#include "kyber.h"
#include "memutils.h"

bool qsctest_kyber_ciphertext_integrity()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk3[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
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

	/* FIPS 203 uses implicit rejection; invalid ciphertexts still return a shared secret. */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber cipher-text: implicit rejection returned an error -KCT1");
		res = false;
	}

	/* the rejection shared secret must differ from the valid encapsulated secret */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
	{
		qsc_consoleutils_print_line("Failure! kyber cipher-text: invalid shared secret -KCT2");
		res = false;
	}

	/* decapsulation of the same invalid ciphertext must produce the same implicit-rejection secret */
	if (qsc_kyber_decapsulate(ssk3, ct, sk) != true || qsc_intutils_are_equal8(ssk1, ssk3, QSC_KYBER_SHAREDSECRET_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! kyber cipher-text: implicit rejection is not deterministic -KCT3");
		res = false;
	}

	return res;
}

bool qsctest_kyber_kat_test()
{
	/* note: the kat files were generated using the NIST post quantum competition format, 
	   for the NIST ACVP KAT vector test, run the CAVP project. */

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
	bool ret;

	ctlen = 0;
	pklen = 0;
	seedlen = 0;
	sklen = 0;
	sslen = 0;
	ret = true;

	/* NIST FIPS 203 KATs */
#	if defined(QSC_KYBER_S1K2P512)
	char path[] = "NPQC/kyber-1632.rsp";
#	elif defined(QSC_KYBER_S3K3P768)
	char path[] = "NPQC/kyber-2400.rsp";
#	elif defined(QSC_KYBER_S5K4P1024)
	char path[] = "NPQC/kyber-3168.rsp";
#	elif defined(QSC_KYBER_S6K5P1280)
	/* Note: custom K6 parameter */
	char path[] = "NPQC/kyber-3936.rsp";
#	else
#	error The parameter set is invalid!
#	endif

	parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	if (qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate))
	{
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
		if (qsc_kyber_encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate))
		{
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
		else
		{
			qsc_consoleutils_print_line("Failure! kyber kat: encapsulation has failed! -KAT6");
			ret = false;
		}
	}
	else
	{
		qsc_consoleutils_print_line("Failure! kyber kat: key generation has failed! -KAT7");
		ret = false;
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

	/* corrupt the stored H(ek) value in the expanded decapsulation key */
	sk[QSC_KYBER_PRIVATEKEY_SIZE - (2U * QSC_KYBER_SHAREDSECRET_SIZE)] ^= 0x01U;

	/* FIPS 203 decapsulation-key input checking must reject the inconsistent key. */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) == true)
	{
		qsc_consoleutils_print_line("Failure! kyber private-key: invalid key was accepted -INTEG0");
		res = false;
	}

	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
	{
		qsc_consoleutils_print_line("Failure! kyber private-key: invalid key retained the valid shared secret -INTEG1");
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
	uint8_t ssk[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* encode the first 12-bit coefficient as q = 3329; FIPS 203 requires the modulus check to reject it */
	pk[0U] = 0x01U;
	pk[1U] = (uint8_t)((pk[1U] & 0xF0U) | 0x0DU);

	if (qsc_kyber_encapsulate(ssk, ct, pk, qsctest_nistrng_prng_generate) == true)
	{
		qsc_consoleutils_print_line("Failure! kyber public-key: invalid encapsulation key was accepted -INTEG0");
		res = false;
	}

	return res;
}

bool qsctest_kyber_operations_test()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	bool res;

	res = false;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	if (qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate))
	{
		/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
		if (qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate))
		{
			/* decapsulate the cipher-text and extract the shared secret */
			if (qsc_kyber_decapsulate(ssk1, ct, sk))
			{
				if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
				{
					res = true;
				}
				else
				{
					qsc_consoleutils_print_line("Failure! kyber operations: the shared secrets are not equal -KOT4");
				}
			}
			else
			{
				qsc_consoleutils_print_line("Failure! kyber operations: decapsulation failure -KOT3");
			}
		}
		else
		{
			qsc_consoleutils_print_line("Failure! kyber operations: encasulation failure -KOT2");
		}
	}
	else
	{
		qsc_consoleutils_print_line("Failure! kyber operations: key generation failure -KOT1");
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
