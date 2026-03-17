#include "hqc_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "consoleutils.h"
#include "csp.h"
#include "intutils.h"
#include "hqc.h"
#include "memutils.h"

bool qsctest_hqc_ciphertext_integrity(void)
{
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kpk[QSC_HQC_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_HQC_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ss1[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	size_t ctlen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t sslen;
	bool res;

	ctlen = 0U;
	pklen = 0U;
	seedlen = 0U;
	sklen = 0U;
	sslen = 0U;
	res = true;

#	if defined(QSC_HQC_S1N2321)
	char path[] = "NPQC/hqc-2321.rsp";
#	elif defined(QSC_HQC_S3N4602)
	char path[] = "NPQC/hqc-4602.rsp";
#	elif defined(QSC_HQC_S5N7333)
	char path[] = "NPQC/hqc-7333.rsp";
#	else
#	error The HQC parameter set is invalid!
#	endif

	parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);
	qsctest_nistrng2_prng_initialize(seed, NULL, 0U);

	kpk[1U] += 1U;

	if (qsc_hqc_encapsulate(ss1, ct, kpk, qsctest_nistrng2_prng_generate) == true)
	{
		if (qsc_intutils_are_equal8(ct, kct, QSC_HQC_CIPHERTEXT_SIZE) == true)
		{
			qsc_consoleutils_print_line("Failure! hqc_ciphertext_integrity: the shared secrets match! -HCKT1");
			res = false;
		}
		else if (qsc_intutils_are_equal8(ss1, kss, QSC_HQC_SHAREDSECRET_SIZE) == true)
		{
			qsc_consoleutils_print_line("Failure! hqc_ciphertext_integrity: the shared secrets match! -HCKT2");
			res = false;
		}
	}

	return res;
}

bool qsctest_hqc_kat_test(void)
{
	/* note: the HQC KAT files are from the NIST PQC Round 4 competition format. */

	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kpk[QSC_HQC_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_HQC_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	uint8_t pk[QSC_HQC_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ss1[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ss2[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	size_t ctlen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t sslen;
	bool res;

	ctlen = 0U;
	pklen = 0U;
	seedlen = 0U;
	sklen = 0U;
	sslen = 0U;
	res = true;

#	if defined(QSC_HQC_S1N2321)
	char path[] = "NPQC/hqc-2321.rsp";
#	elif defined(QSC_HQC_S3N4602)
	char path[] = "NPQC/hqc-4602.rsp";
#	elif defined(QSC_HQC_S5N7333)
	char path[] = "NPQC/hqc-7333.rsp";
#	else
#	error The HQC parameter set is invalid!
#	endif

	parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);

	for (size_t i = 0U; i < QSCTEST_HQC_TEST_COUNT; ++i)
	{
		qsctest_nistrng2_prng_initialize(seed, NULL, i);

		if (qsc_hqc_generate_keypair(pk, sk, qsctest_nistrng2_prng_generate) == true)
		{
			if (qsc_intutils_are_equal8(pk, kpk, QSC_HQC_PUBLICKEY_SIZE) != true)
			{
				qsc_consoleutils_print_line("Failure! hqc kat: public-key does not match known answer! -HKAT0");
				res = false;
			}

			if (qsc_intutils_are_equal8(sk, ksk, QSC_HQC_PRIVATEKEY_SIZE) != true)
			{
				qsc_consoleutils_print_line("Failure! hqc kat: private-key does not match known answer! -HKAT1");
				res = false;
			}

			if (qsc_hqc_encapsulate(ss2, ct, pk, qsctest_nistrng2_prng_generate) == true)
			{
				if (qsc_intutils_are_equal8(ct, kct, QSC_HQC_CIPHERTEXT_SIZE) != true)
				{
					qsc_consoleutils_print_line("Failure! hqc kat: cipher-text does not match known answer! -HKAT2");
					res = false;
				}

				if (qsc_hqc_decapsulate(ss1, ct, sk) != true)
				{
					qsc_consoleutils_print_line("Failure! hqc kat: decryption authentication failure! -HKAT3");
					res = false;
				}

				if (qsc_intutils_are_equal8(ss1, ss2, QSC_HQC_SHAREDSECRET_SIZE) != true)
				{
					qsc_consoleutils_print_line("Failure! hqc kat: shared secrets do not match! -HKAT4");
					res = false;
				}

				if (qsc_intutils_are_equal8(ss1, kss, QSC_HQC_SHAREDSECRET_SIZE) != true)
				{
					qsc_consoleutils_print_line("Failure! hqc kat: shared secret does not match known answer! -HKAT5");
					res = false;
				}
			}
			else
			{
				qsc_consoleutils_print_line("Failure! hqc kat: encapsulation has failed! -HKAT6");
				res = false;
			}
		}
		else
		{
			qsc_consoleutils_print_line("Failure! hqc kat: key generation has failed! -HKAT7");
			res = false;
		}
	}

	return res;
}

bool qsctest_hqc_privatekey_integrity(void)
{
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kpk[QSC_HQC_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_HQC_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ss1[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	size_t ctlen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t sslen;
	bool res;

	ctlen = 0U;
	pklen = 0U;
	seedlen = 0U;
	sklen = 0U;
	sslen = 0U;
	res = true;

#	if defined(QSC_HQC_S1N2321)
	char path[] = "NPQC/hqc-2321.rsp";
#	elif defined(QSC_HQC_S3N4602)
	char path[] = "NPQC/hqc-4602.rsp";
#	elif defined(QSC_HQC_S5N7333)
	char path[] = "NPQC/hqc-7333.rsp";
#	else
#	error The HQC parameter set is invalid!
#	endif

	parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);
	qsctest_nistrng2_prng_initialize(seed, NULL, 0U);

	ksk[QSC_HQC_PUBLICKEY_SIZE + 1U] += 1U;

	if (qsc_hqc_decapsulate(ss1, kct, ksk) != true)
	{
		if (qsc_intutils_are_equal8(ss1, kss, QSC_HQC_SHAREDSECRET_SIZE) == true)
		{
			qsc_consoleutils_print_line("Failure! hqc_privatekey_integrity: the shared secrets match! -HSKI1");
			res = false;
		}
	}

	return res;
}

bool qsctest_hqc_publickey_integrity(void)
{
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kpk[QSC_HQC_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_HQC_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ss1[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	size_t ctlen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t sslen;
	bool res;

	ctlen = 0U;
	pklen = 0U;
	seedlen = 0U;
	sklen = 0U;
	sslen = 0U;
	res = true;

#	if defined(QSC_HQC_S1N2321)
	char path[] = "NPQC/hqc-2321.rsp";
#	elif defined(QSC_HQC_S3N4602)
	char path[] = "NPQC/hqc-4602.rsp";
#	elif defined(QSC_HQC_S5N7333)
	char path[] = "NPQC/hqc-7333.rsp";
#	else
#	error The HQC parameter set is invalid!
#	endif

	parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);
	qsctest_nistrng2_prng_initialize(seed, NULL, 0U);

	kpk[1U] += 1U;

	if (qsc_hqc_encapsulate(ss1, ct, kpk, qsctest_nistrng2_prng_generate) == true)
	{
		if (qsc_intutils_are_equal8(ss1, kss, QSC_HQC_SHAREDSECRET_SIZE) == true)
		{
			qsc_consoleutils_print_line("Failure! hqc_privatekey_integrity: the shared secrets match! -HSKI1");
			res = false;
		}
	}

	return res;
}

bool qsctest_hqc_operations_test(void)
{
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_HQC_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ssk1[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_HQC_SHAREDSECRET_SIZE] = { 0 };
	uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE] = { 0 };
	bool res;

	res = false;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng2_prng_initialize(seed, NULL, 0);

	if (qsc_hqc_generate_keypair(pk, sk, qsctest_nistrng2_prng_generate) == true)
	{
		if (qsc_hqc_encapsulate(ssk2, ct, pk, qsctest_nistrng2_prng_generate) == true)
		{
			if (qsc_hqc_decapsulate(ssk1, ct, sk) == true)
			{
				if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_HQC_SHAREDSECRET_SIZE) == true)
				{
					res = true;
				}
				else
				{
					qsc_consoleutils_print_line("Failure! hqc operations: the shared secrets are not equal -HOT4");
				}
			}
			else
			{
				qsc_consoleutils_print_line("Failure! hqc operations: decapsulation failure -HOT3");
			}
		}
		else
		{
			qsc_consoleutils_print_line("Failure! hqc operations: encapsulation failure -HOT2");
		}
	}
	else
	{
		qsc_consoleutils_print_line("Failure! hqc operations: key generation failure -HOT1");
	}

	return res;
}

void qsctest_hqc_run(void)
{
	if (qsctest_hqc_kat_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the HQC encryption, and decryption known answer test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the HQC encryption, and decryption known answer test.");
	}

	if (qsctest_hqc_operations_test() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the HQC key generation, encryption, and decryption stress test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the HQC key generation, encryption, and decryption stress test.");
	}

	if (qsctest_hqc_privatekey_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the HQC private-key tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the HQC private-key tamper test.");
	}

	if (qsctest_hqc_publickey_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the HQC public-key tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the HQC public-key tamper test.");
	}

	if (qsctest_hqc_ciphertext_integrity() == true)
	{
		qsc_consoleutils_print_line("Success! Passed the HQC cipher-text tamper test.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Failed the HQC cipher-text tamper test.");
	}
}
