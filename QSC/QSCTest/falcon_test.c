#include "falcon_test.h"
#include "common.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/falcon.h"
#include "../QSC/intutils.h"

bool qsctest_falcon_operations_test()
{
	/* note: test message size increase as the kat number increments, ex. 0=33, 1=66, 2=99...
	   If testing other kats other than zero, make sure to increase the message size accordingly. */

#define TEST_MESSAGE_LEN 33

	uint8_t msg[TEST_MESSAGE_LEN] = { 0 };
	uint8_t kmsg[TEST_MESSAGE_LEN] = { 0 };
	uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE] = { 0 };
	uint8_t kpk[QSC_FALCON_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_FALCON_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_FALCON_PRIVATEKEY_SIZE] = { 0 };
	uint8_t sig[QSC_FALCON_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0 };
	uint8_t ksig[QSC_FALCON_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0 };
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

#if defined(QSC_FALCON_S3SHAKE256F512)
	char path[] = "NPQCR3/falcon512.rsp";
#elif defined(QSC_FALCON_S5SHAKE256F1024)
	char path[] = "NPQCR3/falcon1024.rsp";
#else
#	error The parameter set is invalid!
#endif

	/* NIST PQC Round 3 KATs */
	parse_nist_signature_kat(path, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* compare the public key to the expected output */
	if (qsc_intutils_are_equal8(pk, kpk, QSC_FALCON_PUBLICKEY_SIZE) != true)
	{
		qsctest_print_safe("Failure! falcon operations: public-key does not align with the known answer -DOT1 \n");
		ret = false;
	}

	/* compare the secret key to the expected output */
	if (qsc_intutils_are_equal8(sk, ksk, QSC_FALCON_PRIVATEKEY_SIZE) != true)
	{
		qsctest_print_safe("Failure! falcon operations: private key does not align with the known answer -DOT2 \n");
		ret = false;
	}

	/* sign the message */
	qsc_falcon_sign(sig, &siglen, kmsg, TEST_MESSAGE_LEN, sk, qsctest_nistrng_prng_generate);

	/* compare the signature cipher-text to the expected output */
	if (qsc_intutils_are_equal8(sig, ksig, QSC_FALCON_SIGNATURE_SIZE + TEST_MESSAGE_LEN) != true)
	{
		qsctest_print_safe("Failure! falcon operations: ciphertext does not align with the known answer -DOT3 \n");
		ret = false;
	}

	/* verify the message using the public key */
	if (qsc_falcon_verify(msg, &msglen, sig, siglen, pk) != true)
	{
		qsctest_print_safe("Failure! falcon operations: signature verification check failure -DOT4 \n");
		ret = false;
	}

	/* compare the two messages for equality */
	if (qsc_intutils_are_equal8(msg, kmsg, TEST_MESSAGE_LEN) != true)
	{
		qsctest_print_safe("Failure! falcon operations: message does not equal to the original -DOT5 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_falcon_privatekey_integrity()
{
	uint8_t msg[QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t mout[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t sk[QSC_FALCON_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE] = { 0 };
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
	qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bit in the private key */
	for (i = 0; i < 32; ++i)
	{
		sk[QSC_FALCON_PUBLICKEY_SIZE + i] ^= 1;
	}

	/* process message and return signed message */
	qsc_falcon_sign(sig, &siglen, msg, QSCTEST_FALCON_MLEN, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! falcon private-key: message verification passed with altered secret key -DST1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_falcon_publickey_integrity()
{
	uint8_t msg[QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t mout[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t sk[QSC_FALCON_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE] = { 0 };
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
	qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bits in the public key */
	for (i = 0; i < 32; ++i)
	{
		pk[i] ^= 1;
	}

	/* process message and return signed message */
	qsc_falcon_sign(sig, &siglen, msg, QSCTEST_FALCON_MLEN, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! falcon public-key: message verification passed with altered public key -DPT1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_falcon_signature_integrity()
{
	uint8_t msg[QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t mout[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t sk[QSC_FALCON_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* process message and return signed message */
	qsc_falcon_sign(sig, &siglen, msg, QSCTEST_FALCON_MLEN, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the signed message */
	sig[siglen - 1] ^= 1U;

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! falcon signature: message verification passed with altered secret key -DIT1 \n");
		ret = false;
	}

	/* flip one bit per hash; the signature is entirely hashes */
	sig[32] ^= 1U;

	if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! falcon signature: flipping bit did not invalidate signature -DIT2 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_falcon_stress_test()
{
	uint8_t msg[QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t mout[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t sig[QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_FALCON_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = QSCTEST_FALCON_MLEN;
	siglen = QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the key-pair */
	qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* sign the message and return the signed version in sig */
	qsc_falcon_sign(sig, &siglen, msg, msglen, sk, qsctest_nistrng_prng_generate);
	
	if (siglen != QSC_FALCON_SIGNATURE_SIZE + QSCTEST_FALCON_MLEN)
	{
		qsctest_print_safe("Failure! falcon stress: signature length is incorrect -DST1 \n");
		ret = false;
	}

	/* verify the signature in sig and copy msg to mout */
	if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) != true)
	{
		qsctest_print_safe("Failure! falcon stress: message verification has failed -DST2 \n");
		ret = false;
	}

	if (msglen != QSCTEST_FALCON_MLEN)
	{
		qsctest_print_safe("Failure! falcon stress: message length is incorrect -DST3 \n");
		ret = false;
	}

	return ret;
}

void qsctest_falcon_run()
{
	if (qsctest_falcon_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed the Falcon public key, private key, ciphertext, and message known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Falcon known answer integrity tests. \n");
	}

	if (qsctest_falcon_stress_test() == true)
	{
		qsctest_print_safe("Success! Passed the Falcon stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Falcon stress test has failed. \n");
	}

	if (qsctest_falcon_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the Falcon altered public-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Falcon altered public-key test has failed. \n");
	}

	if (qsctest_falcon_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the Falcon altered secret-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Falcon altered secret-key test has failed. \n");
	}

	if (qsctest_falcon_signature_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the Falcon altered signature test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the Falcon altered signature test has failed. \n");
	}
}
