#include "ecdsa_test.h"
#include "qsctestcommon.h"
#include "nistrng.h"
#include "testutils.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"
#include "ecdsa.h"

bool qsctest_ecdsa_kat_test(void)
{
	uint8_t msg0[] = { 0x73U, 0x61U, 0x6DU, 0x70U, 0x6CU, 0x65U }; /* "sample" */
	uint8_t msg1[] = { 0x74U, 0x65U, 0x73U, 0x74U };               /* "test" */
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + 32U] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t expk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t sig0[QSC_ECDSA_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	uint8_t sig1[QSC_ECDSA_SIGNATURE_SIZE + sizeof(msg1)] = { 0U };
	uint8_t gensig[QSC_ECDSA_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	size_t mlen;
	size_t slen;
	bool res;

	mlen = 0U;
	slen = 0U;
	res = true;

	/* RFC 6979 A.2.5 private key x */
	qsctest_hex_to_bin("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", sk, 32U);

	/* RFC 6979 A.2.5 public key U = xG */
	qsctest_hex_to_bin("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", expk, 32U);
	qsctest_hex_to_bin("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", expk + 32U, 32U);

	/* RFC 6979 A.2.5 signature for SHA-256, message = "sample" */
	qsctest_hex_to_bin("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", sig0, 32U);
	qsctest_hex_to_bin("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", sig0 + 32U, 32U);
	qsc_memutils_copy(sig0 + QSC_ECDSA_SIGNATURE_SIZE, msg0, sizeof(msg0));

	/* RFC 6979 A.2.5 signature for SHA-256, message = "test" */
	qsctest_hex_to_bin("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", sig1, 32U);
	qsctest_hex_to_bin("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", sig1 + 32U, 32U);
	qsc_memutils_copy(sig1 + QSC_ECDSA_SIGNATURE_SIZE, msg1, sizeof(msg1));

	/* KAT 1: derive public key from fixed private scalar */
	if (qsc_ecdsa_publickey_from_privatekey(pk, sk) != 0)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: public-key derivation failed -EK1 \n");
		res = false;
	}
	else if (qsc_intutils_are_equal8(pk, expk, sizeof(expk)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: derived public key does not match the RFC 6979 vector -EK2 \n");
		res = false;
	}

	/* KAT 2: verify official RFC 6979 signature for message = "sample" */
	if (qsc_ecdsa_verify(mout, &mlen, sig0, sizeof(sig0), pk) == false)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification failed for sample -EK3 \n");
		res = false;
	}
	else if (mlen != sizeof(msg0) || qsc_intutils_are_equal8(mout, msg0, sizeof(msg0)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: recovered message does not match for sample -EK4 \n");
		res = false;
	}

	/* KAT 3: verify official RFC 6979 signature for message = "test" */
	qsc_memutils_clear(mout, sizeof(mout));
	mlen = 0U;

	if (qsc_ecdsa_verify(mout, &mlen, sig1, sizeof(sig1), pk) == false)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification failed for test -EK5 \n");
		res = false;
	}
	else if (mlen != sizeof(msg1) || qsc_intutils_are_equal8(mout, msg1, sizeof(msg1)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: recovered message does not match for test -EK6 \n");
		res = false;
	}

	/* KAT 4: deterministic signature generation for message = "sample"
	   Requires qsc_ecdsa_sign_scalar() to use RFC6979 with the raw scalar in sk */
	qsc_ecdsa_sign_scalar(gensig, &slen, msg0, sizeof(msg0), sk);

	if (slen != sizeof(gensig))
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: generated signature length is incorrect -EK7 \n");
		res = false;
	}
	else if (qsc_intutils_are_equal8(gensig, sig0, sizeof(sig0)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: generated signature does not match the RFC6979 vector -EK8 \n");
		res = false;
	}

	return res;
}

bool qsctest_ecdsa_privatekey_integrity(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = 0U;
	siglen = 0U;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
		"056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng_prng_initialize(seed, NULL, 0U);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bits in the private key */
	for (size_t i = 0U; i < 4U; ++i)
	{
		sk[i] ^= 1U;
	}

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered secret key, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_privatekey_integrity: ECDSA message verification passed with altered secret key -ES1 \n");
		res = false;
	}

	return res;
}

bool qsctest_ecdsa_publickey_integrity(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = 0U;
	siglen = 0U;
	
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
		"056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the public key */
	pk[QSC_ECDSA_PUBLICKEY_SIZE - 1U] ^= 1U;

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_publickey_integrity: ECDSA message verification passed with altered public key -EP1 \n");
		res = false;
	}

	return res;
}

bool qsctest_ecdsa_signature_integrity(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = 0U;
	siglen = 0U;
	
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
		"056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* flip 1 bit in the signed message */
	sig[siglen - 1U] ^= 1U;

	/* verify signed message, if successful with altered signature, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_signature_integrity: ECDSA message verification passed with altered signature -EI1 \n");
		res = false;
	}

	sig[siglen - 1U] ^= 1U;

	/* flip one bit per signature byte */
	for (size_t i = 0U; i < QSCTEST_ECDSA_ITERATIONS; ++i)
	{
		sig[i] ^= 1U;

		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_signature_integrity: ECDSA flipping bit did not invalidate signature -EI2 \n");
			sig[i] ^= 1U;
			res = false;
			break;
		}

		sig[i] ^= 1U;
	}

	return res;
}

bool qsctest_ecdsa_stress_test(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t tpk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t tsk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = QSCTEST_ECDSA_MSG0_SIZE;
	siglen = QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE;

	/* generate the key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsc_csp_generate);

	for (size_t i = 0U; i < QSCTEST_ECDSA_ITERATIONS && res == true; ++i)
	{
		/* wellness test: seeded key generation must remain deterministic */
		if (qsc_ecdsa_generate_seeded_keypair(tpk, tsk, sk) == false)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: seeded key generation is unavailable -ES2 \n");
			res = false;
			break;
		}

		/* sign the message and return the signed version in sig */
		if (qsc_ecdsa_sign(sig, &siglen, msg, msglen, sk) == false)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA signing has failed -ES3 \n");
			res = false;
			break;
		}

		if (siglen != (QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE))
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA signature length is incorrect -ES4 \n");
			res = false;
			break;
		}

		/* verify the signature in sig and copy msg to mout */
		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == false)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA message verification has failed -ES5 \n");
			res = false;
			break;
		}

		if (msglen != QSCTEST_ECDSA_MSG0_SIZE)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA message length is incorrect -ES6 \n");
			res = false;
			break;
		}

		if (qsc_intutils_are_equal8(mout, msg, msglen) != true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA recovered message does not match -ES7 \n");
			res = false;
			break;
		}

		/* wellness test: an altered signature must fail every iteration */
		sig[0U] ^= 1U;

		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: altered signature verification passed -ES8 \n");
			res = false;
			break;
		}

		sig[0U] ^= 1U;

		/* vary the message between iterations */
		msg[i % QSCTEST_ECDSA_MSG0_SIZE] ^= (uint8_t)(1U + (i & 0x0FU));
		msglen = QSCTEST_ECDSA_MSG0_SIZE;
	}

	return res;
}

void qsctest_ecdsa_run(void)
{
	if (qsctest_ecdsa_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA known answer test. \n");
	}

	if (qsctest_ecdsa_stress_test() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA stress test has failed. \n");
	}

	if (qsctest_ecdsa_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA altered public-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA altered public-key test has failed. \n");
	}

	if (qsctest_ecdsa_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA altered secret-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA altered secret-key test has failed. \n");
	}

	if (qsctest_ecdsa_signature_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA altered signature test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA altered signature test has failed. \n");
	}
}