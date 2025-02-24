#include "sphincsplus_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/intutils.h"
#include "../QSC/sphincsplus.h"

#if defined(QSC_SPHINCSPLUS_EXTENDED)

bool qsctest_sphincsplus_extended_test()
{
	uint8_t msg[QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t mout[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	uint8_t* sig = malloc(QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN);

	if (sig != NULL)
	{
		ret = true;
		msglen = QSCTEST_SPHINCSPLUS_MLEN;
		siglen = QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN;

		/* generate the key-pair */
		qsc_sphincsplus_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* sign the message and return the signed version in sig */
		qsc_sphincsplus_sign(sig, &siglen, msg, msglen, sk, qsctest_nistrng_prng_generate);

		if (siglen != QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN)
		{
			qsctest_print_safe("Failure! sphincsplus stress: signature length is incorrect! - STT1 \n");
			ret = false;
		}

		/* verify the signature in sig and copy msg to mout */
		if (qsc_sphincsplus_verify(mout, &msglen, sig, siglen, pk) != true)
		{
			qsctest_print_safe("Failure! sphincsplus stress: message verification has failed! - STT2 \n");
			ret = false;
		}

		if (msglen != QSCTEST_SPHINCSPLUS_MLEN)
		{
			qsctest_print_safe("Failure! sphincsplus stress: message length is incorrect! - STT3 \n");
			ret = false;
		}

		free(sig);
	}
	else
	{
		ret = false;
	}

	return ret;
}

#else

bool qsctest_sphincsplus_operations_test()
{
	/* note: test message size increase as the kat number increments, ex. 0=33, 1=66, 2=99...
	   If testing other kats other than zero, make sure to increase the message size accordingly. */

#define TEST_MESSAGE_LEN 33

	uint8_t ksig[QSC_SPHINCSPLUS_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0 };
	uint8_t msg[QSC_SPHINCSPLUS_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0 };
	uint8_t sig[QSC_SPHINCSPLUS_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0 };
	uint8_t kmsg[TEST_MESSAGE_LEN] = { 0 };
	uint8_t kpk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	size_t msglen;
	size_t pklen;
	size_t seedlen;
	size_t siglen;
	size_t sklen;
	bool ret;

	ret = true;
	msglen = 0;
	pklen = 0;
	seedlen = 0;
	siglen = 0;
	sklen = 0;

#if defined(QSC_SPHINCSPLUS_S1S128SHAKERF)
	char path[] = "NPQCR3/sphincs-shake256-128f-robust.rsp";
#elif defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
	char path[] = "NPQCR3/sphincs-shake256-128s-robust.rsp";
#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
	char path[] = "NPQCR3/sphincs-shake256-192f-robust.rsp";
#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
	char path[] = "NPQCR3/sphincs-shake256-192s-robust.rsp";
#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
	char path[] = "NPQCR3/sphincs-shake256-256f-robust.rsp";
#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
	char path[] = "NPQCR3/sphincs-shake256-256s-robust.rsp";
#else
#	error The parameter set is invalid!
#endif

	/* NIST FIPS 205 KATs */
	parse_nist_signature_kat(path, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_sphincsplus_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* compare the public key to the expected output */
	if (qsc_intutils_are_equal8(pk, kpk, QSC_SPHINCSPLUS_PUBLICKEY_SIZE) != true)
	{
		qsctest_print_safe("Failure! sphincsplus operations: public-key does not align with the known answer! - SOT1 \n");
		ret = false;
	}

	/* compare the secret key to the expected output */
	if (qsc_intutils_are_equal8(sk, ksk, QSC_SPHINCSPLUS_PRIVATEKEY_SIZE) != true)
	{
		qsctest_print_safe("Failure! sphincsplus operations: private key does not align with the known answer! - SOT2 \n");
		ret = false;
	}

	/* sign the message */
	qsc_sphincsplus_sign(sig, &siglen, kmsg, TEST_MESSAGE_LEN, sk, qsctest_nistrng_prng_generate);

	/* compare the signature cipher-text to the expected output */
	if (qsc_intutils_are_equal8(sig, ksig, QSC_SPHINCSPLUS_SIGNATURE_SIZE + TEST_MESSAGE_LEN) != true)
	{
		qsctest_print_safe("Failure! sphincsplus operations: signature does not align with the known answer! - SOT3 \n");
		ret = false;
	}

	/* verify the message using the public key */
	if (qsc_sphincsplus_verify(msg, &msglen, sig, siglen, pk) != true)
	{
		qsctest_print_safe("Failure! sphincsplus operations: signature verification check failure! - SOT4 \n");
		ret = false;
	}

	/* compare the two messages for equality */
	if (qsc_intutils_are_equal8(msg, kmsg, TEST_MESSAGE_LEN) != true)
	{
		qsctest_print_safe("Failure! sphincsplus operations: message does not equal to the original! - SOT5 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_sphincsplus_privatekey_integrity()
{
	uint8_t msg[QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t mout[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sig[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;

	/* generate the signature key-pair */
	qsc_sphincsplus_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bits in the private key */
	for (size_t i = 0; i < 16; ++i)
	{
		sk[i] ^= 1U;
	}

	/* process message and return signed message */
	qsc_sphincsplus_sign(sig, &siglen, msg, QSCTEST_SPHINCSPLUS_MLEN, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_sphincsplus_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! sphincsplus privatekey: message verification passed with altered secret key! - SST1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_sphincsplus_publickey_integrity()
{
	uint8_t msg[QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t mout[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sig[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;

	/* generate the signature key-pair */
	qsc_sphincsplus_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the public key */
	pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE - 1] ^= 1U;

	/* process message and return signed message */
	qsc_sphincsplus_sign(sig, &siglen, msg, QSCTEST_SPHINCSPLUS_MLEN, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_sphincsplus_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! sphincsplus publickey: message verification passed with altered public key! - SPT1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_sphincsplus_signature_integrity()
{
	uint8_t msg[QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t mout[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sig[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;

	/* generate the signature key-pair */
	qsc_sphincsplus_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* process message and return signed message */
	qsc_sphincsplus_sign(sig, &siglen, msg, QSCTEST_SPHINCSPLUS_MLEN, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the signed message */
	sig[siglen - 1] ^= 1U;

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_sphincsplus_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! sphincsplus signature: message verification passed with altered signature! - SIT1 \n");
		ret = false;
	}

	sig[32] ^= 1U;

	if (qsc_sphincsplus_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! sphincsplus signature: flipping bit did not invalidate signature! - SIT2 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_sphincsplus_stress_test()
{
	uint8_t msg[QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t mout[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sig[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN] = { 0 };
	uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = QSCTEST_SPHINCSPLUS_MLEN;
	siglen = QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN;

	/* generate the key-pair */
	qsc_sphincsplus_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* sign the message and return the signed version in sig */
	qsc_sphincsplus_sign(sig, &siglen, msg, msglen, sk, qsctest_nistrng_prng_generate);

	if (siglen != QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_SPHINCSPLUS_MLEN)
	{
		qsctest_print_safe("Failure! sphincsplus stress: signature length is incorrect! - STT1 \n");
		ret = false;
	}

	/* verify the signature in sig and copy msg to mout */
	if (qsc_sphincsplus_verify(mout, &msglen, sig, siglen, pk) != true)
	{
		qsctest_print_safe("Failure! sphincsplus stress: message verification has failed! - STT2 \n");
		ret = false;
	}

	if (msglen != QSCTEST_SPHINCSPLUS_MLEN)
	{
		qsctest_print_safe("Failure! sphincsplus stress: message length is incorrect! - STT3 \n");
		ret = false;
	}

	return ret;
}

#endif

void qsctest_sphincsplus_run()
{
#if defined(QSC_SPHINCSPLUS_EXTENDED)
	if (qsctest_sphincsplus_extended_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus extended 512-bit parameter tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus extended 512-bit parameter tests. \n");
	}
#else
	if (qsctest_sphincsplus_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus public-key, private-key, cipher-text, and message known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus known answer integrity tests. \n");
	}

	if (qsctest_sphincsplus_stress_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus stress test has failed. \n");
	}

	if (qsctest_sphincsplus_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus altered public-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus altered public-key test has failed. \n");
	}

	if (qsctest_sphincsplus_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus altered secret-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus altered secret-key test has failed. \n");
	}

	if (qsctest_sphincsplus_signature_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus altered signature test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus altered signature test has failed. \n");
	}
#endif
}
