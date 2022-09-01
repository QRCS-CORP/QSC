#include "ntru_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/consoleutils.h"
#include "../QSC/csp.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/ntru.h"

bool qsctest_ntru_ciphertext_integrity()
{
	uint8_t ct[QSC_NTRU_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_NTRU_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_NTRU_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_ntru_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_ntru_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* change some bytes in the ciphertext */
	if (qsc_csp_generate(ct, 32) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru cipher-text: the random generator has failed -KCT0");
		res = false;
	}

	/* invalid ciphertext, auth should fail */
	if (qsc_ntru_decapsulate(ssk1, ct, sk) == true)
	{
		qsc_consoleutils_print_line("Failure! ntru cipher-text: decapsulation has failed -KCT1");
		res = false;
	}

	/* fail if equal */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_NTRU_SHAREDSECRET_SIZE) == true)
	{
		qsc_consoleutils_print_line("Failure! ntru cipher-text: invalid shared secret -KCT2");
		res = false;
	}

	return res;
}

bool qsctest_ntru_kat_test()
{
	uint8_t ct[QSC_NTRU_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_NTRU_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kpk[QSC_NTRU_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_NTRU_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	uint8_t pk[QSC_NTRU_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_NTRU_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ss1[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ss2[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
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

#if defined(QSC_NTRU_S1HPS2048509)
	char path[] = "NPQCR3/ntruhps-2048509.rsp";
#elif defined(QSC_NTRU_HPSS32048677)
	char path[] = "NPQCR3/ntruhps-2048677.rsp";
#elif defined(QSC_NTRU_S5HPS4096821)
	char path[] = "NPQCR3/ntruhps-4096821.rsp";
#elif defined(QSC_NTRU_S5HRSS701)
	char path[] = "NPQCR3/ntruhrss-701.rsp";
#else
#	error The parameter set is invalid!
#endif

	/* NIST PQC Round 3 KATs */
	parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_ntru_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* compare the public key to the expected output */
	if (qsc_intutils_are_equal8(pk, kpk, QSC_NTRU_PUBLICKEY_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru kat: public-key does not match known answer! -KAT0");
		ret = false;
	}

	/* compare the secret key to the expected output */
	if (qsc_intutils_are_equal8(sk, ksk, QSC_NTRU_PRIVATEKEY_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru kat: private-key does not match known answer! -KAT1");
		ret = false;
	}

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_ntru_encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate);

	/* compare the cipher-text to the expected output */
	if (qsc_intutils_are_equal8(ct, kct, QSC_NTRU_CIPHERTEXT_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru kat: cipher-text does not match known answer! -KAT2");
		ret = false;
	}

	/* a uses b's response to get the shared-secret key (in: ct, sk | out: ss1) */
	if (qsc_ntru_decapsulate(ss1, ct, sk) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru kat: decryption authentication failure! -KAT3");
		ret = false;
	}

	/* compare the two keys for equality */
	if (qsc_intutils_are_equal8(ss1, ss2, QSC_NTRU_SHAREDSECRET_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru kat: shared secrets do not match! -KAT4");
		ret = false;
	}

	/* compare the key to the expected output */
	if (qsc_intutils_are_equal8(ss1, kss, QSC_NTRU_SHAREDSECRET_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru kat: shared secret does not match known answer! -KAT5");
		ret = false;
	}

	return ret;
}

bool qsctest_ntru_privatekey_integrity()
{
	uint8_t ct[QSC_NTRU_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_NTRU_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_NTRU_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_ntru_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_ntru_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* replace secret key with random values */
	if (qsc_csp_generate(sk + QSC_NTRU_PUBLICKEY_SIZE, 32) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru_test_operations: the shared secrets are not equal -INTEG0");
		res = false;
	}

	/* invalid secret key, should fail */
	if (qsc_ntru_decapsulate(ssk1, ct, sk) == true)
	{
		res = false;
	}

	/* fail if equal */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_NTRU_SHAREDSECRET_SIZE) == true)
	{
		res = false;
	}

	return res;
}

bool qsctest_ntru_publickey_integrity()
{
	uint8_t ct[QSC_NTRU_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_NTRU_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_NTRU_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_ntru_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* replace public key with random values */
	if (qsc_csp_generate(pk, 32) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru_test_operations: the shared secrets are not equal -INTEG0");
		res = false;
	}

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_ntru_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* invalid secret key, should fail */
	if (qsc_ntru_decapsulate(ssk1, ct, sk) == true)
	{
		res = false;
	}

	/* fail if equal */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_NTRU_SHAREDSECRET_SIZE) == true)
	{
		res = false;
	}

	return res;
}

bool qsctest_ntru_operations_test()
{
	uint8_t ct[QSC_NTRU_CIPHERTEXT_SIZE] = { 0 };
	uint8_t esd[QSC_NTRU_SEED_SIZE] = { 0 };
	uint8_t pk[QSC_NTRU_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ssk1[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_NTRU_SHAREDSECRET_SIZE] = { 0 };
	uint8_t sk[QSC_NTRU_PRIVATEKEY_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_ntru_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_ntru_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* decapsulate the cipher-text and extract the shared secret */
	if (qsc_ntru_decapsulate(ssk1, ct, sk) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru operations: decapsulation failure -KOT1");
		res = false;
	}

	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_NTRU_SHAREDSECRET_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru operations: the shared secrets are not equal -KOT2");
		res = false;
	}

	/* test encrypt/decrypt api */

	qsc_memutils_clear(ct, sizeof(ct));
	qsc_memutils_clear(ssk1, sizeof(ssk1));
	qsc_memutils_clear(ssk2, sizeof(ssk2));

	qsc_csp_generate(esd, sizeof(esd));

	qsc_ntru_encrypt(ssk1, ct, pk, esd);
	qsc_ntru_decrypt(ssk2, ct, sk);

	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_NTRU_SHAREDSECRET_SIZE) != true)
	{
		qsc_consoleutils_print_line("Failure! ntru operations: the shared secrets are not equal -KOT3");
		res = false;
	}

	return res;
}

void qsctest_ntru_run()
{
	if (qsctest_ntru_kat_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the NTRU encryption, and decryption known answer test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the NTRU encryption, and decryption known answer test.");
	}

	if (qsctest_ntru_operations_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the NTRU key generation, encryption, and decryption stress test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the NTRU key generation, encryption, and decryption stress test.");
	}

	if (qsctest_ntru_privatekey_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the NTRU private-key tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the NTRU private-key tamper test.");
	}

	if (qsctest_ntru_publickey_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the NTRU public-key tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the NTRU public-key tamper test.");
	}

	if (qsctest_ntru_ciphertext_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the NTRU cipher-text tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the Kyber cipher-text tamper test.");
	}
}
