/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "falcon_test.h"
#include "qsccommon.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/falcon.h"
#include "../QSC/falcon512.h"
#include "../QSC/falcon1024.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/csp.h"

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
	size_t expected_siglen;
	bool ret;

	ret = true;
	msglen = 0;
	pklen = 0;
	seedlen = 0;
	siglen = 0;
	sklen = 0;
	expected_siglen = 0U;

#if defined(QSC_FALCON_S3SHAKE256F512)
	char path[] = "NPQC/falcon512.rsp";
#elif defined(QSC_FALCON_S5SHAKE256F1024)
	char path[] = "NPQC/falcon1024.rsp";
#else
#	error The parameter set is invalid!
#endif

	/* NIST PQC Round 3 KATs */
	parse_nist_signature_kat(path, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

	if (seedlen != sizeof(seed) || msglen != sizeof(kmsg) || pklen != sizeof(pk) || sklen != sizeof(sk) || siglen > sizeof(ksig) || siglen < msglen + 42U)
	{
		qsctest_print_safe("FAIL: Falcon legacy KAT vector dimensions or parser output.\n");
		return false;
	}
	expected_siglen = siglen;
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	if (qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
	{
		qsctest_print_safe("FAIL: Falcon legacy KAT key generation.\n");
		return false;
	}

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
	if (qsc_falcon_sign(sig, &siglen, kmsg, TEST_MESSAGE_LEN, sk, qsctest_nistrng_prng_generate) == false)
	{
		qsctest_print_safe("FAIL: Falcon legacy KAT signing.\n");
		return false;
	}

	/* compare the signature cipher-text to the expected output */
	if (siglen != expected_siglen || qsc_intutils_are_equal8(sig, ksig, expected_siglen) != true)
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
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	if (qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
	{
		qsctest_print_safe("FAIL: Falcon private-key rejection setup key generation.\n");
		return false;
	}

	/* flip bit in the private key */
	for (size_t i = 0; i < 32; ++i)
	{
		sk[QSC_FALCON_PUBLICKEY_SIZE + i] ^= 1;
	}

	/* process message and return signed message */
	/* An invalid secret key may be rejected at signing or at verification. */
	if (qsc_falcon_sign(sig, &siglen, msg, QSCTEST_FALCON_MLEN, sk, qsctest_nistrng_prng_generate) == true)
	{
		if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) == true)
	{
			qsctest_print_safe("FAIL: Falcon altered private key incorrectly produced a valid signature.\n");
			ret = false;
		}
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
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	if (qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
	{
		qsctest_print_safe("FAIL: Falcon altered-public-key setup key generation.\n");
		return false;
	}

	/* flip bits in the public key */
	for (size_t i = 0; i < 32; ++i)
	{
		pk[i] ^= 1;
	}

	/* process message and return signed message */
	if (qsc_falcon_sign(sig, &siglen, msg, QSCTEST_FALCON_MLEN, sk, qsctest_nistrng_prng_generate) == false)
	{
		qsctest_print_safe("FAIL: Falcon altered-public-key setup signing.\n");
		return false;
	}

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

	/* Create a valid signed message before attempting any mutation. */
	if (qsc_falcon_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
	{
		qsctest_print_safe("FAIL: Falcon signature mutation setup key generation.\n");
		return false;
	}
	if (qsc_falcon_sign(sig, &siglen, msg, QSCTEST_FALCON_MLEN, sk, qsctest_nistrng_prng_generate) == false || siglen <= 2U + 40U + QSCTEST_FALCON_MLEN + 1U)
	{
		qsctest_print_safe("FAIL: Falcon signature mutation setup signing or framing.\n");
		return false;
	}

	/* Mutation 1: the encoded-signature algorithm marker must be rejected. */
	sig[2U + 40U + QSCTEST_FALCON_MLEN] ^= 1U;
	if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("FAIL: Falcon signature header mutation accepted.\n");
		ret = false;
	}
	sig[2U + 40U + QSCTEST_FALCON_MLEN] ^= 1U;

	/* Mutation 2: change the first compressed signature coefficient. */
	sig[3U + 40U + QSCTEST_FALCON_MLEN] ^= 8U;
	msglen = 0U;
	if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("FAIL: Falcon signature coefficient mutation accepted.\n");
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

	/* Signed-message overhead is variable because the signature is compressed. */
	bool signedok;
	signedok = qsc_falcon_sign(sig, &siglen, msg, msglen, sk, qsctest_nistrng_prng_generate);

	if (signedok == false || siglen < msglen + 44U || siglen > QSC_FALCON_SIGNATURE_SIZE + msglen)
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

bool qsctest_falcon_stress_test2()
{
	uint8_t sk[QSC_FALCON_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	uint32_t rndnum;
	size_t siglen;
	bool ret;

	ret = true;

	for (size_t i = 0; i < 10; ++i)
	{
		uint8_t* msg;
		uint8_t* mout;
		uint8_t* sig;

		msg = NULL;
		mout = NULL;
		sig = NULL;
		rndnum = 0U;

		if (qsc_csp_generate((uint8_t*)&rndnum, sizeof(rndnum)) == false)
		{
			ret = false;
			break;
		}

		rndnum = 16U + (rndnum % 113U);
		msglen = rndnum;
		siglen = (size_t)QSC_FALCON_SIGNATURE_SIZE + rndnum;

		msg = (uint8_t*)qsc_memutils_malloc(rndnum);
		mout = (uint8_t*)qsc_memutils_malloc((size_t)QSC_FALCON_SIGNATURE_SIZE + rndnum);
		sig = (uint8_t*)qsc_memutils_malloc((size_t)QSC_FALCON_SIGNATURE_SIZE + rndnum);

		if (msg == NULL || mout == NULL || sig == NULL)
		{
			ret = false;
		}
		else if (qsc_csp_generate(msg, rndnum) == false)
		{
			ret = false;
		}
		else
		{
			bool signedok;

			signedok = false;

			/* generate the key-pair */
			if (qsc_falcon_generate_keypair(pk, sk, qsc_csp_generate) == false)
			{
				ret = false;
			}
			else
			{
				/* Falcon signing can reject an oversized compressed signature; retry with fresh signing randomness. */
				for (size_t j = 0U; j < 16U && signedok == false; ++j)
				{
					siglen = (size_t)QSC_FALCON_SIGNATURE_SIZE + rndnum;
					signedok = qsc_falcon_sign(sig, &siglen, msg, msglen, sk, qsc_csp_generate);
				}

				if (signedok == false)
				{
					qsctest_print_safe("Failure! falcon stress: signature generation has failed -DST1 \n");
					ret = false;
				}
				else if (qsc_falcon_verify(mout, &msglen, sig, siglen, pk) != true)
				{
					qsctest_print_safe("Failure! falcon stress: message verification has failed -DST2 \n");
					ret = false;
				}
				else if (msglen != rndnum)
				{
					qsctest_print_safe("Failure! falcon stress: message length is incorrect -DST3 \n");
					ret = false;
				}
			}
		}

		if (mout != NULL)
		{
			qsc_memutils_alloc_free(mout);
		}

		if (msg != NULL)
		{
			qsc_memutils_alloc_free(msg);
		}

		if (sig != NULL)
		{
			qsc_memutils_alloc_free(sig);
		}

		if (ret == false)
		{
			break;
		}
	}

	return ret;
}


/**
* \brief Qualify the independently linked Falcon-512 API.
* \return True on successful round-trip, rejection and parameter-tag checks.
* \note Uses the production random source; no shared mutable test state.
*/
static bool qsctest_falcon_512_independent_test(void)
{
	uint8_t pk[897U] = { 0U };
	uint8_t sk[1281U] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t received[33U] = { 0U };
	uint8_t signedmsg[699U] = { 0U };
	size_t mlen;
	size_t slen;
	bool passed;
	bool signedok;
	size_t attempt;

	passed = qsc_falcon512_generate_keypair(pk, sk, qsc_csp_generate);
	signedok = false;
	slen = 0U;

	if (passed == true)
	{
		for (attempt = 0U; attempt < 16U && signedok == false; ++attempt)
		{
			signedok = qsc_falcon512_sign(signedmsg, &slen, msg, sizeof(msg), sk, qsc_csp_generate);
		}
		if (signedok == false || slen > sizeof(signedmsg))
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		mlen = 0U;
		if (qsc_falcon512_verify(received, &mlen, signedmsg, slen, pk) == false || mlen != sizeof(msg) || qsc_intutils_are_equal8(msg, received, sizeof(msg)) == false)
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		signedmsg[slen - 1U] ^= 1U;
		mlen = sizeof(received);
		if (qsc_falcon512_verify(received, &mlen, signedmsg, slen, pk) != false || mlen != 0U)
		{
			passed = false;
		}
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(signedmsg, sizeof(signedmsg));
	return passed;
}


/**
* \brief Qualify the independently linked Falcon-1024 API.
* \return True on successful round-trip, rejection and parameter-tag checks.
* \note Uses the production random source; no shared mutable test state.
*/
static bool qsctest_falcon_1024_independent_test(void)
{
	uint8_t pk[1793U] = { 0U };
	uint8_t sk[2305U] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t received[33U] = { 0U };
	uint8_t signedmsg[1313U] = { 0U };
	size_t mlen;
	size_t slen;
	bool passed;
	bool signedok;
	size_t attempt;

	passed = qsc_falcon1024_generate_keypair(pk, sk, qsc_csp_generate);
	signedok = false;
	slen = 0U;

	if (passed == true)
	{
		for (attempt = 0U; attempt < 16U && signedok == false; ++attempt)
		{
			signedok = qsc_falcon1024_sign(signedmsg, &slen, msg, sizeof(msg), sk, qsc_csp_generate);
		}
		if (signedok == false || slen > sizeof(signedmsg))
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		mlen = 0U;
		if (qsc_falcon1024_verify(received, &mlen, signedmsg, slen, pk) == false || mlen != sizeof(msg) || qsc_intutils_are_equal8(msg, received, sizeof(msg)) == false)
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		signedmsg[slen - 1U] ^= 1U;
		mlen = sizeof(received);
		if (qsc_falcon1024_verify(received, &mlen, signedmsg, slen, pk) != false || mlen != 0U)
		{
			passed = false;
		}
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(signedmsg, sizeof(signedmsg));
	return passed;
}

/**
* \brief Validate Falcon-512 against the legacy NIST Round 3 known-answer file.
* \return True when RNG-reproduced key and signed message match the vector.
* \note Reinitializes the test RNG and uses only caller-owned local buffers.
*/
static bool qsctest_falcon_512_kat_test(void)
{
	uint8_t msg[33U] = { 0U };
	uint8_t knownmsg[33U] = { 0U };
	uint8_t pk[897U] = { 0U };
	uint8_t knownpk[897U] = { 0U };
	uint8_t sk[1281U] = { 0U };
	uint8_t knownsk[1281U] = { 0U };
	uint8_t signedmsg[699U] = { 0U };
	uint8_t knownsig[699U] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	size_t mlen;
	size_t pklen;
	size_t sklen;
	size_t expectedlen;
	size_t actualen;
	size_t seedlen;
	bool passed;

	mlen = 0U;
	pklen = 0U;
	sklen = 0U;
	seedlen = 0U;
	expectedlen = 0U;
	actualen = 0U;
	passed = true;

	parse_nist_signature_kat("NPQC/falcon512.rsp", seed, &seedlen, knownmsg, &mlen, knownpk, &pklen, knownsk, &sklen, knownsig, &expectedlen, 0);
	if (mlen != sizeof(msg) || pklen != sizeof(pk) || sklen != sizeof(sk) || expectedlen > sizeof(knownsig) || seedlen != sizeof(seed))
	{
		passed = false;
	}
	if (passed == true)
	{
		qsctest_nistrng_prng_initialize(seed, NULL, 0U);
		if (qsc_falcon512_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
		{
			passed = false;
		}
		else if (qsc_intutils_are_equal8(pk, knownpk, sizeof(pk)) == false || qsc_intutils_are_equal8(sk, knownsk, sizeof(sk)) == false)
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		if (qsc_falcon512_sign(signedmsg, &actualen, knownmsg, mlen, sk, qsctest_nistrng_prng_generate) == false)
		{
			passed = false;
		}
		else if (actualen != expectedlen || qsc_intutils_are_equal8(signedmsg, knownsig, actualen) == false)
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		if (qsc_falcon512_verify(msg, &mlen, signedmsg, actualen, pk) == false || mlen != sizeof(msg) || qsc_intutils_are_equal8(msg, knownmsg, sizeof(msg)) == false)
		{
			passed = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(knownsk, sizeof(knownsk));
	return passed;
}

/**
* \brief Validate Falcon-1024 against the legacy NIST Round 3 known-answer file.
* \return True when RNG-reproduced key and signed message match the vector.
* \note Reinitializes the test RNG and uses only caller-owned local buffers.
*/
static bool qsctest_falcon_1024_kat_test(void)
{
	uint8_t msg[33U] = { 0U };
	uint8_t knownmsg[33U] = { 0U };
	uint8_t pk[1793U] = { 0U };
	uint8_t knownpk[1793U] = { 0U };
	uint8_t sk[2305U] = { 0U };
	uint8_t knownsk[2305U] = { 0U };
	uint8_t signedmsg[1313U] = { 0U };
	uint8_t knownsig[1313U] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	size_t mlen;
	size_t pklen;
	size_t sklen;
	size_t expectedlen;
	size_t actualen;
	size_t seedlen;
	bool passed;

	mlen = 0U;
	pklen = 0U;
	sklen = 0U;
	seedlen = 0U;
	expectedlen = 0U;
	actualen = 0U;
	passed = true;

	parse_nist_signature_kat("NPQC/falcon1024.rsp", seed, &seedlen, knownmsg, &mlen, knownpk, &pklen, knownsk, &sklen, knownsig, &expectedlen, 0);
	if (mlen != sizeof(msg) || pklen != sizeof(pk) || sklen != sizeof(sk) || expectedlen > sizeof(knownsig) || seedlen != sizeof(seed))
	{
		passed = false;
	}
	if (passed == true)
	{
		qsctest_nistrng_prng_initialize(seed, NULL, 0U);
		if (qsc_falcon1024_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
		{
			passed = false;
		}
		else if (qsc_intutils_are_equal8(pk, knownpk, sizeof(pk)) == false || qsc_intutils_are_equal8(sk, knownsk, sizeof(sk)) == false)
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		if (qsc_falcon1024_sign(signedmsg, &actualen, knownmsg, mlen, sk, qsctest_nistrng_prng_generate) == false)
		{
			passed = false;
		}
		else if (actualen != expectedlen || qsc_intutils_are_equal8(signedmsg, knownsig, actualen) == false)
		{
			passed = false;
		}
	}
	if (passed == true)
	{
		if (qsc_falcon1024_verify(msg, &mlen, signedmsg, actualen, pk) == false || mlen != sizeof(msg) || qsc_intutils_are_equal8(msg, knownmsg, sizeof(msg)) == false)
		{
			passed = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(knownsk, sizeof(knownsk));
	return passed;
}

/**
* \brief RNG stub for testing Falcon key generation and signing failures.
* \param output Destination random buffer (deliberately not written).
* \param length Requested number of bytes.
* \return Always false to simulate a failing entropy provider.
* \note Does not retain pointers or modify global state.
*/
static bool qsctest_falcon_rng_failure(uint8_t* output, size_t length)
{
	(void)output;
	(void)length;
	return false;
}

/**
* \brief Validate Falcon-512 failure behavior for invalid inputs and RNG failure.
* \return True when all listed malformed inputs are rejected.
* \note No global state is modified; input memory is caller-owned.
*/
static bool qsctest_falcon_512_rejection_test(void)
{
	uint8_t pk[897U] = { 0U };
	uint8_t sk[1281U] = { 0U };
	uint8_t msg[1U] = { 0U };
	uint8_t signedmsg[667U] = { 0U };
	size_t signedlen;
	size_t msglen;
	bool passed;

	passed = true;
	signedlen = 37U;
	msglen = 37U;

	if (qsc_falcon512_generate_keypair(pk, sk, qsctest_falcon_rng_failure) != false)
	{
		passed = false;
	}
	if (qsc_falcon512_generate_keypair(pk, sk, qsc_csp_generate) == false)
	{
		passed = false;
	}
	else
	{
		signedlen = 19U;
		if (qsc_falcon512_sign(signedmsg, &signedlen, msg, sizeof(msg), sk, qsctest_falcon_rng_failure) != false || signedlen != 0U)
		{
			passed = false;
		}
	}
	if (qsc_falcon512_generate_keypair(NULL, sk, qsc_csp_generate) != false)
	{
		passed = false;
	}
	if (qsc_falcon512_sign(signedmsg, &signedlen, msg, SIZE_MAX, sk, qsc_csp_generate) != false || signedlen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon512_sign(signedmsg, &signedlen, msg, sizeof(msg), sk, qsctest_falcon_rng_failure) != false || signedlen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon512_verify(msg, &msglen, signedmsg, 0U, pk) != false || msglen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon512_verify(msg, &msglen, signedmsg, 1U, pk) != false || msglen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon512_verify(NULL, &msglen, signedmsg, sizeof(signedmsg), pk) != false || msglen != 0U)
	{
		passed = false;
	}

	return passed;
}

/**
* \brief Validate Falcon-1024 failure behavior for invalid inputs and RNG failure.
* \return True when all listed malformed inputs are rejected.
* \note No global state is modified; input memory is caller-owned.
*/
static bool qsctest_falcon_1024_rejection_test(void)
{
	uint8_t pk[1793U] = { 0U };
	uint8_t sk[2305U] = { 0U };
	uint8_t msg[1U] = { 0U };
	uint8_t signedmsg[1281U] = { 0U };
	size_t signedlen;
	size_t msglen;
	bool passed;

	passed = true;
	signedlen = 37U;
	msglen = 37U;

	if (qsc_falcon1024_generate_keypair(pk, sk, qsctest_falcon_rng_failure) != false)
	{
		passed = false;
	}
	if (qsc_falcon1024_generate_keypair(pk, sk, qsc_csp_generate) == false)
	{
		passed = false;
	}
	else
	{
		signedlen = 19U;
		if (qsc_falcon1024_sign(signedmsg, &signedlen, msg, sizeof(msg), sk, qsctest_falcon_rng_failure) != false || signedlen != 0U)
		{
			passed = false;
		}
	}
	if (qsc_falcon1024_generate_keypair(NULL, sk, qsc_csp_generate) != false)
	{
		passed = false;
	}
	if (qsc_falcon1024_sign(signedmsg, &signedlen, msg, SIZE_MAX, sk, qsc_csp_generate) != false || signedlen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon1024_sign(signedmsg, &signedlen, msg, sizeof(msg), sk, qsctest_falcon_rng_failure) != false || signedlen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon1024_verify(msg, &msglen, signedmsg, 0U, pk) != false || msglen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon1024_verify(msg, &msglen, signedmsg, 1U, pk) != false || msglen != 0U)
	{
		passed = false;
	}
	if (qsc_falcon1024_verify(NULL, &msglen, signedmsg, sizeof(signedmsg), pk) != false || msglen != 0U)
	{
		passed = false;
	}

	return passed;
}

/**
* \brief Reject cross-parameter verification and signed-message mutation.
* \return True when both schemes accept their own signatures and reject
* signatures paired with keys from the other parameter set.
* \note Runs locally with independent buffers and no retained key material.
*/
static bool qsctest_falcon_cross_parameter_rejection_test(void)
{
	uint8_t pk512[897U] = { 0U };
	uint8_t sk512[1281U] = { 0U };
	uint8_t pk1024[1793U] = { 0U };
	uint8_t sk1024[2305U] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t out[33U] = { 0U };
	uint8_t sm512[699U] = { 0U };
	uint8_t sm1024[1313U] = { 0U };
	size_t smlen512;
	size_t smlen1024;
	size_t outlen;
	bool passed;

	passed = qsc_falcon512_generate_keypair(pk512, sk512, qsc_csp_generate);
	if (passed == true)
	{
		passed = qsc_falcon1024_generate_keypair(pk1024, sk1024, qsc_csp_generate);
	}
	if (passed == true)
	{
		smlen512 = 0U;
		passed = qsc_falcon512_sign(sm512, &smlen512, msg, sizeof(msg), sk512, qsc_csp_generate);
		if (passed == true)
		{
			outlen = 0U;
			passed = qsc_falcon512_verify(out, &outlen, sm512, smlen512, pk512);
			if (passed == true && outlen != sizeof(msg))
			{
				passed = false;
			}
		}
		if (passed == true)
		{
			outlen = 1U;
			if (qsc_falcon1024_verify(out, &outlen, sm512, smlen512, pk1024) != false || outlen != 0U)
			{
				passed = false;
			}
		}
		if (passed == true)
		{
			sm512[42U] ^= 1U;
			outlen = 1U;
			if (qsc_falcon512_verify(out, &outlen, sm512, smlen512, pk512) != false || outlen != 0U)
			{
				passed = false;
			}
		}
	}
	if (passed == true)
	{
		smlen1024 = 0U;
		passed = qsc_falcon1024_sign(sm1024, &smlen1024, msg, sizeof(msg), sk1024, qsc_csp_generate);
		if (passed == true)
		{
			outlen = 0U;
			passed = qsc_falcon1024_verify(out, &outlen, sm1024, smlen1024, pk1024);
			if (passed == true && outlen != sizeof(msg))
			{
				passed = false;
			}
		}
		if (passed == true)
		{
			outlen = 1U;
			if (qsc_falcon512_verify(out, &outlen, sm1024, smlen1024, pk512) != false || outlen != 0U)
			{
				passed = false;
			}
		}
		if (passed == true)
		{
			sm1024[42U] ^= 1U;
			outlen = 1U;
			if (qsc_falcon1024_verify(out, &outlen, sm1024, smlen1024, pk1024) != false || outlen != 0U)
			{
				passed = false;
			}
		}
	}
	qsc_memutils_secure_erase(sk512, sizeof(sk512));
	qsc_memutils_secure_erase(sk1024, sizeof(sk1024));
	return passed;
}

/**
* \brief Qualify Falcon-1024 legacy compressed-signature interoperability.
* \details NIST Round 3 KAT number 82 has 1,283 bytes of signing overhead,
* exceeding the maximum output of the bounded signing interface. Valid
* legacy signatures must still verify without an artificial size ceiling.
* \return True if the official signature verifies and tampering is rejected.
* \note Local buffers only; NIST vector material is securely erased.
*/
static bool qsctest_falcon_1024_long_signature_test(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t msg[2739U] = { 0U };
	uint8_t output[2739U] = { 0U };
	uint8_t pk[QSC_FALCON1024_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_FALCON1024_PRIVATEKEY_SIZE] = { 0U };
	uint8_t sm[4022U] = { 0U };
	size_t seedlen;
	size_t msglen;
	size_t pklen;
	size_t sklen;
	size_t siglen;
	size_t outlen;
	bool passed;

	seedlen = 0U;
	msglen = 0U;
	pklen = 0U;
	sklen = 0U;
	siglen = 0U;
	outlen = 0U;

	parse_nist_signature_kat("NPQC/falcon1024.rsp", seed, &seedlen, msg, &msglen, pk, &pklen, sk, &sklen, sm, &siglen, 82U);
	passed = (seedlen == sizeof(seed) && msglen == sizeof(msg) && pklen == sizeof(pk) && sklen == sizeof(sk) && siglen == sizeof(sm));

	if (passed == true)
	{
		passed = qsc_falcon1024_verify(output, &outlen, sm, siglen, pk);
		passed = passed && outlen == sizeof(msg) && qsc_intutils_are_equal8(output, msg, sizeof(msg));
	}

	if (passed == true)
	{
		sm[42U] ^= 1U;
		outlen = sizeof(output);
		passed = (qsc_falcon1024_verify(output, &outlen, sm, siglen, pk) == false && outlen == 0U);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(seed, sizeof(seed));
	return passed;
}

/**
* \brief Validate all 100 legacy NIST Round 3 Falcon-512 known-answer cases.
* \return True when all keys and signatures satisfy their documented contracts.
* \note An oversized reference signature is verified as-is; the bounded signer
* resamples instead of emitting an over-capacity signed-message buffer.
* \note Uses the deterministic test-only RNG; no persistent state is retained.
*/
static bool qsctest_falcon_512_full_vectors_test(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t original[3300U] = { 0U };
	uint8_t recovered[3300U] = { 0U };
	uint8_t pk[897U] = { 0U };
	uint8_t knownpk[897U] = { 0U };
	uint8_t sk[1281U] = { 0U };
	uint8_t knownsk[1281U] = { 0U };
	uint8_t signedmsg[3300U + 666U] = { 0U };
	uint8_t knownsig[3300U + 666U] = { 0U };
	size_t seedlen;
	size_t msglen;
	size_t pklen;
	size_t sklen;
	size_t siglen;
	size_t produced;
	size_t recoveredlen;
	uint32_t index;
	bool passed;

	passed = true;

	for (index = 0U; index < 100U && passed == true; ++index)
	{
		seedlen = 0U;
		msglen = 0U;
		pklen = 0U;
		sklen = 0U;
		siglen = 0U;
		produced = 0U;
		recoveredlen = 0U;

		/* Each KAT message is 33 * (index + 1) bytes, at most 3300. */
		parse_nist_signature_kat("NPQC/falcon512.rsp", seed, &seedlen, original, &msglen, knownpk, &pklen, knownsk, &sklen, knownsig, &siglen, index);

		if (seedlen != sizeof(seed) || msglen != 33U * (index + 1U) || pklen != sizeof(pk) || sklen != sizeof(sk))
		{
			passed = false;
		}
		else if (siglen < msglen + 42U || siglen > sizeof(knownsig))
		{
			passed = false;
		}

		if (passed == true)
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);
			passed = qsc_falcon512_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);
			if (passed == true)
			{
				passed = qsc_intutils_are_equal8(pk, knownpk, sizeof(pk));
				passed = passed && qsc_intutils_are_equal8(sk, knownsk, sizeof(sk));
			}
		}
		if (passed == true)
		{
			passed = qsc_falcon512_sign(signedmsg, &produced, original, msglen, sk, qsctest_nistrng_prng_generate);
			passed = passed && produced >= msglen + 42U && produced <= msglen + 666U;
		}
		if (passed == true && (siglen - msglen) <= 666U)
		{
			passed = (produced == siglen && qsc_intutils_are_equal8(signedmsg, knownsig, produced));
		}
		if (passed == true)
		{
			passed = qsc_falcon512_verify(recovered, &recoveredlen, signedmsg, produced, pk);
			passed = passed && recoveredlen == msglen && qsc_intutils_are_equal8(recovered, original, msglen);
		}
		if (passed == true)
		{
			recoveredlen = 0U;
			passed = qsc_falcon512_verify(recovered, &recoveredlen, knownsig, siglen, knownpk);
			passed = passed && recoveredlen == msglen && qsc_intutils_are_equal8(recovered, original, msglen);
		}
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(knownsk, sizeof(knownsk));
	qsc_memutils_secure_erase(seed, sizeof(seed));
	return passed && index == 100U;
}

/**
* \brief Validate all 100 legacy NIST Round 3 Falcon-1024 known-answer cases.
* \return True when all keys and signatures satisfy their documented contracts.
* \note An oversized reference signature is verified as-is; the bounded signer
* resamples instead of emitting an over-capacity signed-message buffer.
* \note Uses the deterministic test-only RNG; no persistent state is retained.
*/
static bool qsctest_falcon_1024_full_vectors_test(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t original[3300U] = { 0U };
	uint8_t recovered[3300U] = { 0U };
	uint8_t pk[1793U] = { 0U };
	uint8_t knownpk[1793U] = { 0U };
	uint8_t sk[2305U] = { 0U };
	uint8_t knownsk[2305U] = { 0U };
	uint8_t signedmsg[3300U + 1280U] = { 0U };
	uint8_t knownsig[3300U + 1320U] = { 0U };
	size_t seedlen;
	size_t msglen;
	size_t pklen;
	size_t sklen;
	size_t siglen;
	size_t produced;
	size_t recoveredlen;
	uint32_t index;
	bool passed;

	passed = true;

	for (index = 0U; index < 100U && passed == true; ++index)
	{
		seedlen = 0U;
		msglen = 0U;
		pklen = 0U;
		sklen = 0U;
		siglen = 0U;
		produced = 0U;
		recoveredlen = 0U;

		/* Each KAT message is 33 * (index + 1) bytes, at most 3300. */
		parse_nist_signature_kat("NPQC/falcon1024.rsp", seed, &seedlen, original, &msglen, knownpk, &pklen, knownsk, &sklen, knownsig, &siglen, index);

		if (seedlen != sizeof(seed) || msglen != 33U * (index + 1U) || pklen != sizeof(pk) || sklen != sizeof(sk))
		{
			passed = false;
		}
		else if (siglen < msglen + 42U || siglen > sizeof(knownsig))
		{
			passed = false;
		}

		if (passed == true)
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);
			passed = qsc_falcon1024_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);
			if (passed == true)
			{
				passed = qsc_intutils_are_equal8(pk, knownpk, sizeof(pk));
				passed = passed && qsc_intutils_are_equal8(sk, knownsk, sizeof(sk));
			}
		}
		if (passed == true)
		{
			passed = qsc_falcon1024_sign(signedmsg, &produced, original, msglen, sk, qsctest_nistrng_prng_generate);
			passed = passed && produced >= msglen + 42U && produced <= msglen + 1280U;
		}
		if (passed == true && (siglen - msglen) <= 1280U)
		{
			passed = (produced == siglen && qsc_intutils_are_equal8(signedmsg, knownsig, produced));
		}
		if (passed == true)
		{
			passed = qsc_falcon1024_verify(recovered, &recoveredlen, signedmsg, produced, pk);
			passed = passed && recoveredlen == msglen && qsc_intutils_are_equal8(recovered, original, msglen);
		}
		if (passed == true)
		{
			recoveredlen = 0U;
			passed = qsc_falcon1024_verify(recovered, &recoveredlen, knownsig, siglen, knownpk);
			passed = passed && recoveredlen == msglen && qsc_intutils_are_equal8(recovered, original, msglen);
		}
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(knownsk, sizeof(knownsk));
	qsc_memutils_secure_erase(seed, sizeof(seed));
	return passed && index == 100U;
}

void qsctest_falcon_run()
{
	if (qsctest_falcon_512_full_vectors_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-512 all 100 legacy reference KATs.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-512 100-vector reference qualification.\n");
	}

	if (qsctest_falcon_1024_full_vectors_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-1024 all 100 legacy KATs including oversized-signature interoperability.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-1024 100-vector reference qualification.\n");
	}

	if (qsctest_falcon_1024_long_signature_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-1024 1283-byte legacy signature verifies; tampering rejected.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-1024 long legacy compressed-signature interoperability.\n");
	}

	if (qsctest_falcon_cross_parameter_rejection_test() == true)
	{
		qsctest_print_safe("PASS: Falcon cross-parameter signatures and message mutations rejected.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon cross-parameter signature or message-mutation rejection.\n");
	}

	if (qsctest_falcon_512_rejection_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-512 null, overflow, truncated and RNG-failure rejection.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-512 null, overflow, truncated or RNG-failure rejection.\n");
	}

	if (qsctest_falcon_1024_rejection_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-1024 null, overflow, truncated and RNG-failure rejection.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-1024 null, overflow, truncated or RNG-failure rejection.\n");
	}

	if (qsctest_falcon_512_kat_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-512 Round 3 official known-answer test.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-512 Round 3 official known-answer test.\n");
	}

	if (qsctest_falcon_1024_kat_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-1024 Round 3 official known-answer test.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-1024 Round 3 official known-answer test.\n");
	}

	if (qsctest_falcon_512_independent_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-512 independent round-trip and tamper rejection.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-512 independent round-trip or tamper rejection.\n");
	}

	if (qsctest_falcon_1024_independent_test() == true)
	{
		qsctest_print_safe("PASS: Falcon-1024 independent round-trip and tamper rejection.\n");
	}
	else
	{
		qsctest_print_safe("FAIL: Falcon-1024 independent round-trip or tamper rejection.\n");
	}

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
