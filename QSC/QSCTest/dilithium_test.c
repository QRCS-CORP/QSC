#include "dilithium_test.h"
#include "common.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/dilithium.h"
#include "../QSC/intutils.h"

bool qsctest_dilithium_operations_test()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t kmsg[QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	uint8_t kpk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t ksig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	size_t msglen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	pklen = 0;
	seedlen = 0;
	siglen = 0;
	sklen = 0;

#if defined(QSC_DILITHIUM_S2N256Q8380417K4)
	char path[] = "NPQCR3/dilithium-2544.rsp";
#elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
	char path[] = "NPQCR3/dilithium-4016.rsp";
#elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
	char path[] = "NPQCR3/dilithium-4880.rsp";
#else
#	error The parameter set is invalid!
#endif

	/* NIST PQ Round 3 KATs */
	parse_nist_signature_kat(path, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_dilithium_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* compare the public key to the expected output */
	if (qsc_intutils_are_equal8(pk, kpk, QSC_DILITHIUM_PUBLICKEY_SIZE) != true)
	{
		qsctest_print_safe("Failure! dilithium operations: public-key does not align with the known answer -DOT1 \n");
		ret = false;
	}

	/* compare the secret key to the expected output */
	if (qsc_intutils_are_equal8(sk, ksk, QSC_DILITHIUM_PRIVATEKEY_SIZE) != true)
	{
		qsctest_print_safe("Failure! dilithium operations: private key does not align with the known answer -DOT2 \n");
		ret = false;
	}

	/* sign the message */
	qsc_dilithium_sign(sig, &siglen, kmsg, QSCTEST_DILITHIUM_MLEN0, sk, qsctest_nistrng_prng_generate);

	/* compare the signature cipher-text to the expected output */
	if (qsc_intutils_are_equal8(sig, ksig, QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0) != true)
	{
		qsctest_print_safe("Failure! dilithium operations: ciphertext does not align with the known answer -DOT3 \n");
		ret = false;
	}

	/* verify the message using the public key */
	if (qsc_dilithium_verify(msg, &msglen, sig, siglen, pk) != true)
	{
		qsctest_print_safe("Failure! dilithium operations: signature verification check failure -DOT4 \n");
		ret = false;
	}

	/* compare the two messages for equality */
	if (qsc_intutils_are_equal8(msg, kmsg, QSCTEST_DILITHIUM_MLEN0) != true)
	{
		qsctest_print_safe("Failure! dilithium operations: message does not equal to the original -DOT5 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_dilithium_privatekey_integrity()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	size_t i;
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_dilithium_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bit in the private key */
	for (i = 0; i < 32; ++i)
	{
		sk[QSC_DILITHIUM_PUBLICKEY_SIZE + i] ^= 1;
	}

	/* process message and return signed message */
	qsc_dilithium_sign(sig, &siglen, msg, QSCTEST_DILITHIUM_MLEN0, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_dilithium_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! dilithium private-key: message verification passed with altered secret key -DST1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_dilithium_publickey_integrity()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	size_t i;
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_dilithium_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bits in the public key */
	for (i = 0; i < 32; ++i)
	{
		pk[i] ^= 1;
	}

	/* process message and return signed message */
	qsc_dilithium_sign(sig, &siglen, msg, QSCTEST_DILITHIUM_MLEN0, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_dilithium_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! dilithium public-key: message verification passed with altered public key -DPT1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_dilithium_signature_integrity()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_dilithium_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* process message and return signed message */
	qsc_dilithium_sign(sig, &siglen, msg, QSCTEST_DILITHIUM_MLEN0, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the signed message */
	sig[siglen - 1] ^= 1U;

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_dilithium_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! dilithium signature: message verification passed with altered secret key -DIT1 \n");
		ret = false;
	}

	/* flip one bit per hash; the signature is entirely hashes */
	sig[32] ^= 1U;

	if (qsc_dilithium_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! dilithium signature: flipping bit did not invalidate signature -DIT2 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_dilithium_stress_test()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = QSCTEST_DILITHIUM_MLEN0;
	siglen = QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the key-pair */
	qsc_dilithium_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* sign the message and return the signed version in sig */
	qsc_dilithium_sign(sig, &siglen, msg, msglen, sk, qsctest_nistrng_prng_generate);

	if (siglen != QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN0)
	{
		qsctest_print_safe("Failure! dilithium stress: signature length is incorrect -DST1 \n");
		ret = false;
	}

	/* verify the signature in sig and copy msg to mout */
	if (qsc_dilithium_verify(mout, &msglen, sig, siglen, pk) != true)
	{
		qsctest_print_safe("Failure! dilithium stress: message verification has failed -DST2 \n");
		ret = false;
	}

	if (msglen != QSCTEST_DILITHIUM_MLEN0)
	{
		qsctest_print_safe("Failure! dilithium stress: message length is incorrect -DST3 \n");
		ret = false;
	}

	return ret;
}

void qsctest_dilithium_run()
{
	if (qsctest_dilithium_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed the Dilithium public key, private key, ciphertext, and message known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Dilithium known answer integrity tests. \n");
	}

	if (qsctest_dilithium_stress_test() == true)
	{
		qsctest_print_safe("Success! Passed the Dilithium stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Dilithium stress test has failed. \n");
	}

	if (qsctest_dilithium_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the Dilithium altered public-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Dilithium altered public-key test has failed. \n");
	}

	if (qsctest_dilithium_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the Dilithium altered secret-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Dilithium altered secret-key test has failed. \n");
	}

	if (qsctest_dilithium_signature_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the Dilithium altered signature test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Dilithium altered signature test has failed. \n");
	}
}
