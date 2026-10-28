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

#include "sphincsplus_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sphincsplus.h"
#include "slhdsa.h"

#define TEST_MESSAGE_LEN 33

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
	/* note: the kat files were generated using the NIST post quantum competition format, 
	for the NIST ACVP KAT vector test, run the CAVP project. */

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

#if defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
	char path[] = "NPQC/sphincs-shake256-128s-robust.rsp";
#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
	char path[] = "NPQC/sphincs-shake256-192s-robust.rsp";
#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
	char path[] = "NPQC/sphincs-shake256-256s-robust.rsp";
#else
#	error The parameter set is not supported for testing!
#endif

	/* Original SPHINCS+ competition-format KATs; not FIPS 205 ACVP vectors. */
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

/**
 * \brief Verify legacy SPHINCS+ attached-message compatibility after SLH-DSA integration.
 * \details Checks the selected legacy parameter set using deterministic seeded key
 * generation and the context-aware attached-message API. Detects acceptance of
 * mismatched contexts, altered public keys, corrupted signatures, truncated
 * attached messages, and contexts exceeding the supported maximum.
 * \return True only if each compatibility regression passes.
 * \note Reentrant. Scratch storage is caller-owned and erased before release.
 */
bool qsctest_sphincsplus_compatibility_test(void)
{
    uint8_t seed[QSC_SPHINCSPLUS_GENERATE_SEED_SIZE] = { 0U };
    uint8_t randomness[QSC_SPHINCSPLUS_SIGN_SEED_SIZE] = { 0U };
    uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0U };
    uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0U };
    uint8_t msg[QSCTEST_SPHINCSPLUS_MLEN] = { 0U };
    uint8_t recovered[QSCTEST_SPHINCSPLUS_MLEN] = { 0U };
    uint8_t context[3U] = { 0x51U, 0x53U, 0x43U };
    uint8_t* signedmsg;
    size_t smsglen;
    size_t recoveredlen;
    bool result;

    result = true;
    smsglen = 0U;
    recoveredlen = 0U;
    signedmsg = (uint8_t*)qsc_memutils_malloc(QSC_SPHINCSPLUS_SIGNATURE_SIZE + sizeof(msg));

    if (signedmsg == NULL)
    {
        qsctest_print_safe("FAIL SPHINCS+ legacy allocation regression - LCT0\n");
        return false;
    }

    for (size_t i = 0U; i < sizeof(seed); ++i)
    {
        seed[i] = (uint8_t)i;
    }

    for (size_t i = 0U; i < sizeof(randomness); ++i)
    {
        randomness[i] = (uint8_t)(0xA0U + i);
    }

    for (size_t i = 0U; i < sizeof(msg); ++i)
    {
        msg[i] = (uint8_t)(i + 1U);
    }

    if (!qsc_sphincsplus_generate_seeded_keypair(pk, sk, seed))
    {
        qsctest_print_safe("FAIL SPHINCS+ legacy seeded keygen - LCT1\n");
        result = false;
    }
    else if (!qsc_sphincsplus_seeded_sign_ex(signedmsg, &smsglen, msg, sizeof(msg), context, sizeof(context), sk, randomness))
    {
        qsctest_print_safe("FAIL SPHINCS+ legacy context signing - LCT2\n");
        result = false;
    }
    else if (smsglen != QSC_SPHINCSPLUS_SIGNATURE_SIZE + sizeof(msg))
    {
        qsctest_print_safe("FAIL SPHINCS+ legacy attached signature length - LCT3\n");
        result = false;
    }
    else
    {
        if (!qsc_sphincsplus_verify_ex(recovered, &recoveredlen, context, sizeof(context), signedmsg, smsglen, pk) ||
            recoveredlen != sizeof(msg) || !qsc_memutils_are_equal(recovered, msg, sizeof(msg)))
        {
            qsctest_print_safe("FAIL SPHINCS+ legacy context verification - LCT4\n");
            result = false;
        }

        context[0U] ^= 1U;
        recoveredlen = 0U;

        if (qsc_sphincsplus_verify_ex(recovered, &recoveredlen, context, sizeof(context), signedmsg, smsglen, pk))
        {
            qsctest_print_safe("FAIL SPHINCS+ legacy wrong-context rejection - LCT5\n");
            result = false;
        }

        context[0U] ^= 1U;
        pk[0U] ^= 1U;

        if (qsc_sphincsplus_verify_ex(recovered, &recoveredlen, context, sizeof(context), signedmsg, smsglen, pk))
        {
            qsctest_print_safe("FAIL SPHINCS+ legacy wrong-public-key rejection - LCT6\n");
            result = false;
        }

        pk[0U] ^= 1U;
        signedmsg[0U] ^= 1U;

        if (qsc_sphincsplus_verify_ex(recovered, &recoveredlen, context, sizeof(context), signedmsg, smsglen, pk))
        {
            qsctest_print_safe("FAIL SPHINCS+ legacy altered-signature rejection - LCT7\n");
            result = false;
        }

        signedmsg[0U] ^= 1U;

        if (qsc_sphincsplus_verify_ex(recovered, &recoveredlen, context, sizeof(context), signedmsg, QSC_SPHINCSPLUS_SIGNATURE_SIZE - 1U, pk))
        {
            qsctest_print_safe("FAIL SPHINCS+ legacy truncated-signature rejection - LCT8\n");
            result = false;
        }

        if (qsc_sphincsplus_verify_ex(recovered, &recoveredlen, context, 256U, signedmsg, smsglen, pk))
        {
            qsctest_print_safe("FAIL SPHINCS+ legacy oversized-context rejection - LCT9\n");
            result = false;
        }
    }

    qsc_memutils_secure_erase(sk, sizeof(sk));
    qsc_memutils_secure_erase(randomness, sizeof(randomness));
    qsc_memutils_secure_erase(signedmsg, QSC_SPHINCSPLUS_SIGNATURE_SIZE + sizeof(msg));
    qsc_memutils_alloc_free(signedmsg);

    if (result == true)
    {
        qsctest_print_safe("PASS SPHINCS+ legacy attached-message compatibility\n");
    }
    else
    {
        qsctest_print_safe("FAIL SPHINCS+ legacy attached-message compatibility\n");
    }

    return result;
}

/** \brief FIPS 205 SHAKE SLH-DSA tests integrated with the original SPHINCS+ suite.
 * \note These tests supplement, rather than replace, historical SPHINCS+ KATs.
 */
/** \brief Produce fixed pseudorandom bytes for deterministic unit testing only.
 * \param output Output buffer, caller-owned.
 * \param length Number of test bytes requested.
 * \return True when a non-null output is supplied.
 * \note NOT a cryptographic random generator; use only for reproducible tests.
 */
static bool qsctest_sphincsplus_fixed_rng(uint8_t* output, size_t length)
{
	if (output == NULL)
	{
		return false;
	}

	for (size_t i = 0U; i < length; ++i)
	{
		output[i] = (uint8_t)(i + 0xA5U);
	}

	return true;
}

/** \brief Simulate random generator failure for negative-path testing.
 * \param output Unused destination pointer.
 * \param length Unused byte count.
 * \return Always false.
 * \note Does not write the caller-owned output.
 */
static bool qsctest_sphincsplus_failing_rng(uint8_t* output, size_t length)
{
	(void)output;
	(void)length;

	return false;
}

/** \brief Qualify the SHAKE-128s API with keygen, signing, negative and context tests.
 * \return True only when the full SHAKE-128s set passes.
 * \note Sequential and independent. No external shared state.
 */
bool qsctest_sphincsplus_shake128s_signature_test(void)
{
	uint8_t seed[QSC_SLHDSA_SHAKE128S_KEYGEN_SEED_SIZE] = { 0U };
	uint8_t pk[QSC_SLHDSA_SHAKE128S_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE128S_PRIVATEKEY_SIZE] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t ctx[3U] = { 0x51U, 0x53U, 0x43U };
	uint8_t* sig;
	size_t siglen;
	bool res;

	res = true;
	siglen = 0U;
	sig = (uint8_t*)qsc_memutils_malloc(QSC_SLHDSA_SHAKE128S_SIGNATURE_SIZE);

	if (sig == NULL)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128s allocation\n");
		return false;
	}

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (size_t i = 0U; i < sizeof(msg); ++i)
	{
		msg[i] = (uint8_t)(i + 1U);
	}

	if (!qsc_slhdsa_shake128s_generate_seeded_keypair(pk, sk, seed))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128s seeded keygen\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake128s_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128s deterministic sign\n");
		res = false;
	}
	else if (siglen != QSC_SLHDSA_SHAKE128S_SIGNATURE_SIZE)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128s signature size\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake128s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128s valid verify\n");
		res = false;
	}
	else
	{
		if (qsc_slhdsa_shake128s_verify(sig, siglen - 1U, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s truncated signature accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;

		if (qsc_slhdsa_shake128s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s incorrect context accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;
		msg[0U] ^= 1U;

		if (qsc_slhdsa_shake128s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s modified message accepted\n");
			res = false;
		}

		msg[0U] ^= 1U;
		sig[0U] ^= 1U;

		if (qsc_slhdsa_shake128s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s modified signature accepted\n");
			res = false;
		}

		sig[0U] ^= 1U;

		pk[0U] ^= 1U;

		if (qsc_slhdsa_shake128s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s incorrect public key accepted\n");
			res = false;
		}

		pk[0U] ^= 1U;

		if (!qsc_slhdsa_shake128s_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_fixed_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s hedged signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s hedged verification\n");
			res = false;
		}

		if (qsc_slhdsa_shake128s_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_failing_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s RNG failure accepted\n");
			res = false;
		}
		else if (siglen != 0U)
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s RNG failure output length\n");
			res = false;
		}

		if (!qsc_slhdsa_shake128s_sign_deterministic(sig, &siglen, NULL, 0U, NULL, 0U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s empty message sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128s_verify(sig, siglen, NULL, 0U, NULL, 0U, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s empty message verify\n");
			res = false;
		}

		if (qsc_slhdsa_shake128s_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, 256U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s oversized context accepted\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake128s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s prehash SHAKE256 sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s prehash SHAKE256 verify\n");
			res = false;
		}
		else if (qsc_slhdsa_shake128s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s accepted prehash as pure signature\n");
			res = false;
		}
		else if (qsc_slhdsa_shake128s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s accepted mismatched prehash algorithm\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake128s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s sha512 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s sha512 prehash verification\n");
			res = false;
		}
	}

	if (res == true)
	{
		if (!qsc_slhdsa_shake128s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s sha256 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s sha256 prehash verification\n");
			res = false;
		}
	}

	if (res == true)
	{
		if (!qsc_slhdsa_shake128s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s shake128 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128s shake128 prehash verification\n");
			res = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(sig, QSC_SLHDSA_SHAKE128S_SIGNATURE_SIZE);
	qsc_memutils_alloc_free(sig);

	if (res == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-128s independent sign/verify\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128s independent sign/verify\n");
	}

	return res;
}

/** \brief Qualify the SHAKE-128f API with keygen, signing, negative and context tests.
 * \return True only when the full SHAKE-128f set passes.
 * \note Sequential and independent. No external shared state.
 */
bool qsctest_sphincsplus_shake128f_signature_test(void)
{
	uint8_t seed[QSC_SLHDSA_SHAKE128F_KEYGEN_SEED_SIZE] = { 0U };
	uint8_t pk[QSC_SLHDSA_SHAKE128F_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE128F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t ctx[3U] = { 0x51U, 0x53U, 0x43U };
	uint8_t* sig;
	size_t siglen;
	bool res;

	res = true;
	siglen = 0U;
	sig = (uint8_t*)qsc_memutils_malloc(QSC_SLHDSA_SHAKE128F_SIGNATURE_SIZE);

	if (sig == NULL)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128f allocation\n");
		return false;
	}

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (size_t i = 0U; i < sizeof(msg); ++i)
	{
		msg[i] = (uint8_t)(i + 1U);
	}

	if (!qsc_slhdsa_shake128f_generate_seeded_keypair(pk, sk, seed))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128f seeded keygen\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake128f_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128f deterministic sign\n");
		res = false;
	}
	else if (siglen != QSC_SLHDSA_SHAKE128F_SIGNATURE_SIZE)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128f signature size\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake128f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128f valid verify\n");
		res = false;
	}
	else
	{
		if (qsc_slhdsa_shake128f_verify(sig, siglen - 1U, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f truncated signature accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;

		if (qsc_slhdsa_shake128f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f incorrect context accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;
		msg[0U] ^= 1U;

		if (qsc_slhdsa_shake128f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f modified message accepted\n");
			res = false;
		}

		msg[0U] ^= 1U;
		sig[0U] ^= 1U;

		if (qsc_slhdsa_shake128f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f modified signature accepted\n");
			res = false;
		}

		sig[0U] ^= 1U;

		pk[0U] ^= 1U;

		if (qsc_slhdsa_shake128f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f incorrect public key accepted\n");
			res = false;
		}

		pk[0U] ^= 1U;

		if (!qsc_slhdsa_shake128f_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_fixed_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f hedged signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f hedged verification\n");
			res = false;
		}

		if (qsc_slhdsa_shake128f_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_failing_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f RNG failure accepted\n");
			res = false;
		}
		else if (siglen != 0U)
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f RNG failure output length\n");
			res = false;
		}

		if (!qsc_slhdsa_shake128f_sign_deterministic(sig, &siglen, NULL, 0U, NULL, 0U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f empty message sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128f_verify(sig, siglen, NULL, 0U, NULL, 0U, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f empty message verify\n");
			res = false;
		}

		if (qsc_slhdsa_shake128f_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, 256U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f oversized context accepted\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake128f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f prehash SHAKE256 sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f prehash SHAKE256 verify\n");
			res = false;
		}
		else if (qsc_slhdsa_shake128f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f accepted prehash as pure signature\n");
			res = false;
		}
		else if (qsc_slhdsa_shake128f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f accepted mismatched prehash algorithm\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake128f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f sha512 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f sha512 prehash verification\n");
			res = false;
		}
	}

	if (res == true)
	{
		if (!qsc_slhdsa_shake128f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f sha256 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f sha256 prehash verification\n");
			res = false;
		}
	}

	if (res == true)
	{
		if (!qsc_slhdsa_shake128f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f shake128 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake128f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-128f shake128 prehash verification\n");
			res = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(sig, QSC_SLHDSA_SHAKE128F_SIGNATURE_SIZE);
	qsc_memutils_alloc_free(sig);

	if (res == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-128f independent sign/verify\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128f independent sign/verify\n");
	}

	return res;
}

/** \brief Qualify the SHAKE-192s API with keygen, signing, negative and context tests.
 * \return True only when the full SHAKE-192s set passes.
 * \note Sequential and independent. No external shared state.
 */
bool qsctest_sphincsplus_shake192s_signature_test(void)
{
	uint8_t seed[QSC_SLHDSA_SHAKE192S_KEYGEN_SEED_SIZE] = { 0U };
	uint8_t pk[QSC_SLHDSA_SHAKE192S_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE192S_PRIVATEKEY_SIZE] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t ctx[3U] = { 0x51U, 0x53U, 0x43U };
	uint8_t* sig;
	size_t siglen;
	bool res;

	res = true;
	siglen = 0U;
	sig = (uint8_t*)qsc_memutils_malloc(QSC_SLHDSA_SHAKE192S_SIGNATURE_SIZE);

	if (sig == NULL)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s allocation\n");
		return false;
	}

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (size_t i = 0U; i < sizeof(msg); ++i)
	{
		msg[i] = (uint8_t)(i + 1U);
	}

	if (!qsc_slhdsa_shake192s_generate_seeded_keypair(pk, sk, seed))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s seeded keygen\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake192s_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s deterministic sign\n");
		res = false;
	}
	else if (siglen != QSC_SLHDSA_SHAKE192S_SIGNATURE_SIZE)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s signature size\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake192s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s valid verify\n");
		res = false;
	}
	else
	{
		if (qsc_slhdsa_shake192s_verify(sig, siglen - 1U, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s truncated signature accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;

		if (qsc_slhdsa_shake192s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s incorrect context accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;
		msg[0U] ^= 1U;

		if (qsc_slhdsa_shake192s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s modified message accepted\n");
			res = false;
		}

		msg[0U] ^= 1U;
		sig[0U] ^= 1U;

		if (qsc_slhdsa_shake192s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s modified signature accepted\n");
			res = false;
		}

		sig[0U] ^= 1U;

		pk[0U] ^= 1U;

		if (qsc_slhdsa_shake192s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s incorrect public key accepted\n");
			res = false;
		}

		pk[0U] ^= 1U;

		if (!qsc_slhdsa_shake192s_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_fixed_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s hedged signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s hedged verification\n");
			res = false;
		}

		if (qsc_slhdsa_shake192s_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_failing_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s RNG failure accepted\n");
			res = false;
		}
		else if (siglen != 0U)
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s RNG failure output length\n");
			res = false;
		}

		if (!qsc_slhdsa_shake192s_sign_deterministic(sig, &siglen, NULL, 0U, NULL, 0U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s empty message sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192s_verify(sig, siglen, NULL, 0U, NULL, 0U, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s empty message verify\n");
			res = false;
		}

		if (qsc_slhdsa_shake192s_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, 256U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s oversized context accepted\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake192s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s prehash SHAKE256 sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s prehash SHAKE256 verify\n");
			res = false;
		}
		else if (qsc_slhdsa_shake192s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s accepted prehash as pure signature\n");
			res = false;
		}
		else if (qsc_slhdsa_shake192s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s accepted mismatched prehash algorithm\n");
			res = false;
		}
	}


	if (qsc_slhdsa_shake192s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s accepted weak SHA-256 prehash\n");
		res = false;
	}

	if (qsc_slhdsa_shake192s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s accepted weak SHAKE-128 prehash\n");
		res = false;
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake192s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s sha512 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192s sha512 prehash verification\n");
			res = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(sig, QSC_SLHDSA_SHAKE192S_SIGNATURE_SIZE);
	qsc_memutils_alloc_free(sig);

	if (res == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-192s independent sign/verify\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s independent sign/verify\n");
	}

	return res;
}

/** \brief Qualify the SHAKE-192f API with keygen, signing, negative and context tests.
 * \return True only when the full SHAKE-192f set passes.
 * \note Sequential and independent. No external shared state.
 */
bool qsctest_sphincsplus_shake192f_signature_test(void)
{
	uint8_t seed[QSC_SLHDSA_SHAKE192F_KEYGEN_SEED_SIZE] = { 0U };
	uint8_t pk[QSC_SLHDSA_SHAKE192F_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE192F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t ctx[3U] = { 0x51U, 0x53U, 0x43U };
	uint8_t* sig;
	size_t siglen;
	bool res;

	res = true;
	siglen = 0U;
	sig = (uint8_t*)qsc_memutils_malloc(QSC_SLHDSA_SHAKE192F_SIGNATURE_SIZE);

	if (sig == NULL)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f allocation\n");
		return false;
	}

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (size_t i = 0U; i < sizeof(msg); ++i)
	{
		msg[i] = (uint8_t)(i + 1U);
	}

	if (!qsc_slhdsa_shake192f_generate_seeded_keypair(pk, sk, seed))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f seeded keygen\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake192f_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f deterministic sign\n");
		res = false;
	}
	else if (siglen != QSC_SLHDSA_SHAKE192F_SIGNATURE_SIZE)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f signature size\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake192f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f valid verify\n");
		res = false;
	}
	else
	{
		if (qsc_slhdsa_shake192f_verify(sig, siglen - 1U, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f truncated signature accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;

		if (qsc_slhdsa_shake192f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f incorrect context accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;
		msg[0U] ^= 1U;

		if (qsc_slhdsa_shake192f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f modified message accepted\n");
			res = false;
		}

		msg[0U] ^= 1U;
		sig[0U] ^= 1U;

		if (qsc_slhdsa_shake192f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f modified signature accepted\n");
			res = false;
		}

		sig[0U] ^= 1U;

		pk[0U] ^= 1U;

		if (qsc_slhdsa_shake192f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f incorrect public key accepted\n");
			res = false;
		}

		pk[0U] ^= 1U;

		if (!qsc_slhdsa_shake192f_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_fixed_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f hedged signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f hedged verification\n");
			res = false;
		}

		if (qsc_slhdsa_shake192f_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_failing_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f RNG failure accepted\n");
			res = false;
		}
		else if (siglen != 0U)
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f RNG failure output length\n");
			res = false;
		}

		if (!qsc_slhdsa_shake192f_sign_deterministic(sig, &siglen, NULL, 0U, NULL, 0U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f empty message sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192f_verify(sig, siglen, NULL, 0U, NULL, 0U, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f empty message verify\n");
			res = false;
		}

		if (qsc_slhdsa_shake192f_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, 256U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f oversized context accepted\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake192f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f prehash SHAKE256 sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f prehash SHAKE256 verify\n");
			res = false;
		}
		else if (qsc_slhdsa_shake192f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f accepted prehash as pure signature\n");
			res = false;
		}
		else if (qsc_slhdsa_shake192f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f accepted mismatched prehash algorithm\n");
			res = false;
		}
	}


	if (qsc_slhdsa_shake192f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f accepted weak SHA-256 prehash\n");
		res = false;
	}

	if (qsc_slhdsa_shake192f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f accepted weak SHAKE-128 prehash\n");
		res = false;
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake192f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f sha512 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake192f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-192f sha512 prehash verification\n");
			res = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(sig, QSC_SLHDSA_SHAKE192F_SIGNATURE_SIZE);
	qsc_memutils_alloc_free(sig);

	if (res == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-192f independent sign/verify\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f independent sign/verify\n");
	}

	return res;
}

/** \brief Qualify the SHAKE-256s API with keygen, signing, negative and context tests.
 * \return True only when the full SHAKE-256s set passes.
 * \note Sequential and independent. No external shared state.
 */
bool qsctest_sphincsplus_shake256s_signature_test(void)
{
	uint8_t seed[QSC_SLHDSA_SHAKE256S_KEYGEN_SEED_SIZE] = { 0U };
	uint8_t pk[QSC_SLHDSA_SHAKE256S_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE256S_PRIVATEKEY_SIZE] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t ctx[3U] = { 0x51U, 0x53U, 0x43U };
	uint8_t* sig;
	size_t siglen;
	bool res;

	res = true;
	siglen = 0U;
	sig = (uint8_t*)qsc_memutils_malloc(QSC_SLHDSA_SHAKE256S_SIGNATURE_SIZE);

	if (sig == NULL)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s allocation\n");
		return false;
	}

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (size_t i = 0U; i < sizeof(msg); ++i)
	{
		msg[i] = (uint8_t)(i + 1U);
	}

	if (!qsc_slhdsa_shake256s_generate_seeded_keypair(pk, sk, seed))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s seeded keygen\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake256s_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s deterministic sign\n");
		res = false;
	}
	else if (siglen != QSC_SLHDSA_SHAKE256S_SIGNATURE_SIZE)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s signature size\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake256s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s valid verify\n");
		res = false;
	}
	else
	{
		if (qsc_slhdsa_shake256s_verify(sig, siglen - 1U, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s truncated signature accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;

		if (qsc_slhdsa_shake256s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s incorrect context accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;
		msg[0U] ^= 1U;

		if (qsc_slhdsa_shake256s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s modified message accepted\n");
			res = false;
		}

		msg[0U] ^= 1U;
		sig[0U] ^= 1U;

		if (qsc_slhdsa_shake256s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s modified signature accepted\n");
			res = false;
		}

		sig[0U] ^= 1U;

		pk[0U] ^= 1U;

		if (qsc_slhdsa_shake256s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s incorrect public key accepted\n");
			res = false;
		}

		pk[0U] ^= 1U;

		if (!qsc_slhdsa_shake256s_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_fixed_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s hedged signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s hedged verification\n");
			res = false;
		}

		if (qsc_slhdsa_shake256s_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_failing_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s RNG failure accepted\n");
			res = false;
		}
		else if (siglen != 0U)
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s RNG failure output length\n");
			res = false;
		}

		if (!qsc_slhdsa_shake256s_sign_deterministic(sig, &siglen, NULL, 0U, NULL, 0U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s empty message sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256s_verify(sig, siglen, NULL, 0U, NULL, 0U, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s empty message verify\n");
			res = false;
		}

		if (qsc_slhdsa_shake256s_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, 256U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s oversized context accepted\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake256s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s prehash SHAKE256 sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s prehash SHAKE256 verify\n");
			res = false;
		}
		else if (qsc_slhdsa_shake256s_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s accepted prehash as pure signature\n");
			res = false;
		}
		else if (qsc_slhdsa_shake256s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s accepted mismatched prehash algorithm\n");
			res = false;
		}
	}


	if (qsc_slhdsa_shake256s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s accepted weak SHA-256 prehash\n");
		res = false;
	}

	if (qsc_slhdsa_shake256s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s accepted weak SHAKE-128 prehash\n");
		res = false;
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake256s_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s sha512 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256s_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256s sha512 prehash verification\n");
			res = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(sig, QSC_SLHDSA_SHAKE256S_SIGNATURE_SIZE);
	qsc_memutils_alloc_free(sig);

	if (res == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-256s independent sign/verify\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s independent sign/verify\n");
	}

	return res;
}

/** \brief Qualify the SHAKE-256f API with keygen, signing, negative and context tests.
 * \return True only when the full SHAKE-256f set passes.
 * \note Sequential and independent. No external shared state.
 */
bool qsctest_sphincsplus_shake256f_signature_test(void)
{
	uint8_t seed[QSC_SLHDSA_SHAKE256F_KEYGEN_SEED_SIZE] = { 0U };
	uint8_t pk[QSC_SLHDSA_SHAKE256F_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE256F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t msg[33U] = { 0U };
	uint8_t ctx[3U] = { 0x51U, 0x53U, 0x43U };
	uint8_t* sig;
	size_t siglen;
	bool res;

	res = true;
	siglen = 0U;
	sig = (uint8_t*)qsc_memutils_malloc(QSC_SLHDSA_SHAKE256F_SIGNATURE_SIZE);

	if (sig == NULL)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f allocation\n");
		return false;
	}

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)i;
	}

	for (size_t i = 0U; i < sizeof(msg); ++i)
	{
		msg[i] = (uint8_t)(i + 1U);
	}

	if (!qsc_slhdsa_shake256f_generate_seeded_keypair(pk, sk, seed))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f seeded keygen\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake256f_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f deterministic sign\n");
		res = false;
	}
	else if (siglen != QSC_SLHDSA_SHAKE256F_SIGNATURE_SIZE)
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f signature size\n");
		res = false;
	}
	else if (!qsc_slhdsa_shake256f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f valid verify\n");
		res = false;
	}
	else
	{
		if (qsc_slhdsa_shake256f_verify(sig, siglen - 1U, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f truncated signature accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;

		if (qsc_slhdsa_shake256f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f incorrect context accepted\n");
			res = false;
		}

		ctx[0U] ^= 1U;
		msg[0U] ^= 1U;

		if (qsc_slhdsa_shake256f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f modified message accepted\n");
			res = false;
		}

		msg[0U] ^= 1U;
		sig[0U] ^= 1U;

		if (qsc_slhdsa_shake256f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f modified signature accepted\n");
			res = false;
		}

		sig[0U] ^= 1U;

		pk[0U] ^= 1U;

		if (qsc_slhdsa_shake256f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f incorrect public key accepted\n");
			res = false;
		}

		pk[0U] ^= 1U;

		if (!qsc_slhdsa_shake256f_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_fixed_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f hedged signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f hedged verification\n");
			res = false;
		}

		if (qsc_slhdsa_shake256f_sign(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_sphincsplus_failing_rng))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f RNG failure accepted\n");
			res = false;
		}
		else if (siglen != 0U)
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f RNG failure output length\n");
			res = false;
		}

		if (!qsc_slhdsa_shake256f_sign_deterministic(sig, &siglen, NULL, 0U, NULL, 0U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f empty message sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256f_verify(sig, siglen, NULL, 0U, NULL, 0U, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f empty message verify\n");
			res = false;
		}

		if (qsc_slhdsa_shake256f_sign_deterministic(sig, &siglen, msg, sizeof(msg), ctx, 256U, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f oversized context accepted\n");
			res = false;
		}
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake256f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f prehash SHAKE256 sign\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f prehash SHAKE256 verify\n");
			res = false;
		}
		else if (qsc_slhdsa_shake256f_verify(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f accepted prehash as pure signature\n");
			res = false;
		}
		else if (qsc_slhdsa_shake256f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f accepted mismatched prehash algorithm\n");
			res = false;
		}
	}


	if (qsc_slhdsa_shake256f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha256, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f accepted weak SHA-256 prehash\n");
		res = false;
	}

	if (qsc_slhdsa_shake256f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_shake128, sk))
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f accepted weak SHAKE-128 prehash\n");
		res = false;
	}


	if (res == true)
	{
		if (!qsc_slhdsa_shake256f_sign_prehash_deterministic(sig, &siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, sk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f sha512 prehash signing\n");
			res = false;
		}
		else if (!qsc_slhdsa_shake256f_verify_prehash(sig, siglen, msg, sizeof(msg), ctx, sizeof(ctx), qsc_slhdsa_prehash_sha512, pk))
		{
			qsctest_print_safe("FAIL SLH-DSA SHAKE-256f sha512 prehash verification\n");
			res = false;
		}
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(sig, QSC_SLHDSA_SHAKE256F_SIGNATURE_SIZE);
	qsc_memutils_alloc_free(sig);

	if (res == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-256f independent sign/verify\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f independent sign/verify\n");
	}

	return res;
}


/* Public NIST ACVP keyGen FIPS205 sample vectors, redistributed as test data.
 * Source: usnistgov/ACVP-Server, gen-val/json-files/SLH-DSA-keyGen-FIPS205.
 * Matching public mirror: mjosaarinen/py-acvp-pqc json-copy (NIST ACVP sample).
 * These are independent expected outputs, not QSC-generated self-tests.
 */

/** \brief Independently check NIST ACVP SHAKE-128s keyGen test 11.
 * \return True if the output matches the NIST key bytes exactly.
 * \note Reentrant; local secret key is securely erased.
 */
bool qsctest_sphincsplus_shake128s_acvp_keygen_test(void)
{
	static const uint8_t seed[QSC_SLHDSA_SHAKE128S_KEYGEN_SEED_SIZE] = { 0x2AU, 0x2CU, 0xCFU, 0x3CU, 0xD8U, 0xF9U, 0xF8U, 0x6EU, 0x13U, 0x1BU, 0xE6U, 0x54U, 0xCFU, 0xF6U, 0xC0U, 0xB4U, 0xFDU, 0xFCU, 0xEBU, 0x1AU, 0xA2U, 0xF0U, 0xBAU, 0x2CU, 0x3CU, 0x13U, 0x88U, 0x19U, 0x4FU, 0x61U, 0x16U, 0xC7U, 0x89U, 0x0CU, 0xC7U, 0xF4U, 0xA4U, 0x6FU, 0xE6U, 0xC3U, 0x4DU, 0x3FU, 0x26U, 0xA6U, 0x2FU, 0xF9U, 0x62U, 0xE1U };
	static const uint8_t expected_pk[QSC_SLHDSA_SHAKE128S_PUBLICKEY_SIZE] = { 0x89U, 0x0CU, 0xC7U, 0xF4U, 0xA4U, 0x6FU, 0xE6U, 0xC3U, 0x4DU, 0x3FU, 0x26U, 0xA6U, 0x2FU, 0xF9U, 0x62U, 0xE1U, 0xE8U, 0xC8U, 0x8DU, 0x2BU, 0xDCU, 0xBAU, 0x6FU, 0x66U, 0xE5U, 0x04U, 0x03U, 0xE7U, 0x7FU, 0xA9U, 0x2EU, 0xFEU };
	static const uint8_t expected_sk[QSC_SLHDSA_SHAKE128S_PRIVATEKEY_SIZE] = { 0x2AU, 0x2CU, 0xCFU, 0x3CU, 0xD8U, 0xF9U, 0xF8U, 0x6EU, 0x13U, 0x1BU, 0xE6U, 0x54U, 0xCFU, 0xF6U, 0xC0U, 0xB4U, 0xFDU, 0xFCU, 0xEBU, 0x1AU, 0xA2U, 0xF0U, 0xBAU, 0x2CU, 0x3CU, 0x13U, 0x88U, 0x19U, 0x4FU, 0x61U, 0x16U, 0xC7U, 0x89U, 0x0CU, 0xC7U, 0xF4U, 0xA4U, 0x6FU, 0xE6U, 0xC3U, 0x4DU, 0x3FU, 0x26U, 0xA6U, 0x2FU, 0xF9U, 0x62U, 0xE1U, 0xE8U, 0xC8U, 0x8DU, 0x2BU, 0xDCU, 0xBAU, 0x6FU, 0x66U, 0xE5U, 0x04U, 0x03U, 0xE7U, 0x7FU, 0xA9U, 0x2EU, 0xFEU };
	uint8_t pk[QSC_SLHDSA_SHAKE128S_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE128S_PRIVATEKEY_SIZE] = { 0U };
	bool result;

	result = qsc_slhdsa_shake128s_generate_seeded_keypair(pk, sk, seed);

	if (result == true)
	{
		result = qsc_memutils_are_equal(pk, expected_pk, sizeof(pk)) &&
			qsc_memutils_are_equal(sk, expected_sk, sizeof(sk));
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));

	if (result == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-128s NIST ACVP keyGen tgId=2 tcId=11\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128s NIST ACVP keyGen tgId=2 tcId=11\n");
	}

	return result;
}

/** \brief Independently check NIST ACVP SHAKE-128f keyGen test 31.
 * \return True if the output matches the NIST key bytes exactly.
 * \note Reentrant; local secret key is securely erased.
 */
bool qsctest_sphincsplus_shake128f_acvp_keygen_test(void)
{
	static const uint8_t seed[QSC_SLHDSA_SHAKE128F_KEYGEN_SEED_SIZE] = { 0xCDU, 0x4AU, 0x30U, 0x8CU, 0x03U, 0xD9U, 0x70U, 0x50U, 0x85U, 0x72U, 0xC0U, 0x81U, 0x5DU, 0x74U, 0x88U, 0xB7U, 0xF3U, 0xFDU, 0x6DU, 0x2DU, 0xCCU, 0x7EU, 0x51U, 0x20U, 0xFAU, 0x54U, 0x48U, 0x46U, 0xAEU, 0xDDU, 0xEDU, 0x81U, 0xBCU, 0x43U, 0x5CU, 0x3EU, 0x66U, 0xE4U, 0xC2U, 0xE4U, 0xFBU, 0xC0U, 0x97U, 0x79U, 0xDAU, 0x5FU, 0x74U, 0xD4U };
	static const uint8_t expected_pk[QSC_SLHDSA_SHAKE128F_PUBLICKEY_SIZE] = { 0xBCU, 0x43U, 0x5CU, 0x3EU, 0x66U, 0xE4U, 0xC2U, 0xE4U, 0xFBU, 0xC0U, 0x97U, 0x79U, 0xDAU, 0x5FU, 0x74U, 0xD4U, 0x4EU, 0xA0U, 0xE0U, 0xDFU, 0x05U, 0xC2U, 0x45U, 0x7BU, 0xCCU, 0x81U, 0xF5U, 0x99U, 0x28U, 0x43U, 0x33U, 0x90U };
	static const uint8_t expected_sk[QSC_SLHDSA_SHAKE128F_PRIVATEKEY_SIZE] = { 0xCDU, 0x4AU, 0x30U, 0x8CU, 0x03U, 0xD9U, 0x70U, 0x50U, 0x85U, 0x72U, 0xC0U, 0x81U, 0x5DU, 0x74U, 0x88U, 0xB7U, 0xF3U, 0xFDU, 0x6DU, 0x2DU, 0xCCU, 0x7EU, 0x51U, 0x20U, 0xFAU, 0x54U, 0x48U, 0x46U, 0xAEU, 0xDDU, 0xEDU, 0x81U, 0xBCU, 0x43U, 0x5CU, 0x3EU, 0x66U, 0xE4U, 0xC2U, 0xE4U, 0xFBU, 0xC0U, 0x97U, 0x79U, 0xDAU, 0x5FU, 0x74U, 0xD4U, 0x4EU, 0xA0U, 0xE0U, 0xDFU, 0x05U, 0xC2U, 0x45U, 0x7BU, 0xCCU, 0x81U, 0xF5U, 0x99U, 0x28U, 0x43U, 0x33U, 0x90U };
	uint8_t pk[QSC_SLHDSA_SHAKE128F_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE128F_PRIVATEKEY_SIZE] = { 0U };
	bool result;

	result = qsc_slhdsa_shake128f_generate_seeded_keypair(pk, sk, seed);

	if (result == true)
	{
		result = qsc_memutils_are_equal(pk, expected_pk, sizeof(pk)) &&
			qsc_memutils_are_equal(sk, expected_sk, sizeof(sk));
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));

	if (result == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-128f NIST ACVP keyGen tgId=4 tcId=31\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-128f NIST ACVP keyGen tgId=4 tcId=31\n");
	}

	return result;
}

/** \brief Independently check NIST ACVP SHAKE-192s keyGen test 51.
 * \return True if the output matches the NIST key bytes exactly.
 * \note Reentrant; local secret key is securely erased.
 */
bool qsctest_sphincsplus_shake192s_acvp_keygen_test(void)
{
	static const uint8_t seed[QSC_SLHDSA_SHAKE192S_KEYGEN_SEED_SIZE] = { 0x91U, 0x51U, 0x73U, 0xEEU, 0x0DU, 0x17U, 0xF3U, 0x08U, 0x77U, 0xE1U, 0xD4U, 0x63U, 0xE3U, 0xDEU, 0xC9U, 0x14U, 0xE7U, 0x1FU, 0x43U, 0x68U, 0x67U, 0xADU, 0x76U, 0x15U, 0xEDU, 0x78U, 0x2EU, 0x70U, 0x33U, 0xC4U, 0x96U, 0x3AU, 0x7FU, 0xF0U, 0xB6U, 0x71U, 0x81U, 0xDEU, 0x0FU, 0x0EU, 0xA7U, 0xEFU, 0xABU, 0xB3U, 0x26U, 0xD4U, 0x0AU, 0x86U, 0x52U, 0x06U, 0x60U, 0xF6U, 0x54U, 0xD5U, 0x37U, 0xDAU, 0x69U, 0x34U, 0xF9U, 0x6EU, 0x5EU, 0xE0U, 0x1BU, 0x24U, 0xA2U, 0xF3U, 0x61U, 0x02U, 0xF6U, 0x8DU, 0xCDU, 0x10U };
	static const uint8_t expected_pk[QSC_SLHDSA_SHAKE192S_PUBLICKEY_SIZE] = { 0x52U, 0x06U, 0x60U, 0xF6U, 0x54U, 0xD5U, 0x37U, 0xDAU, 0x69U, 0x34U, 0xF9U, 0x6EU, 0x5EU, 0xE0U, 0x1BU, 0x24U, 0xA2U, 0xF3U, 0x61U, 0x02U, 0xF6U, 0x8DU, 0xCDU, 0x10U, 0xAAU, 0x20U, 0x6FU, 0xC7U, 0x98U, 0x03U, 0xE6U, 0x38U, 0x50U, 0xDAU, 0x5EU, 0x86U, 0x96U, 0x95U, 0x69U, 0xFCU, 0x8FU, 0xB0U, 0x21U, 0xB6U, 0xC4U, 0x06U, 0x16U, 0xE2U };
	static const uint8_t expected_sk[QSC_SLHDSA_SHAKE192S_PRIVATEKEY_SIZE] = { 0x91U, 0x51U, 0x73U, 0xEEU, 0x0DU, 0x17U, 0xF3U, 0x08U, 0x77U, 0xE1U, 0xD4U, 0x63U, 0xE3U, 0xDEU, 0xC9U, 0x14U, 0xE7U, 0x1FU, 0x43U, 0x68U, 0x67U, 0xADU, 0x76U, 0x15U, 0xEDU, 0x78U, 0x2EU, 0x70U, 0x33U, 0xC4U, 0x96U, 0x3AU, 0x7FU, 0xF0U, 0xB6U, 0x71U, 0x81U, 0xDEU, 0x0FU, 0x0EU, 0xA7U, 0xEFU, 0xABU, 0xB3U, 0x26U, 0xD4U, 0x0AU, 0x86U, 0x52U, 0x06U, 0x60U, 0xF6U, 0x54U, 0xD5U, 0x37U, 0xDAU, 0x69U, 0x34U, 0xF9U, 0x6EU, 0x5EU, 0xE0U, 0x1BU, 0x24U, 0xA2U, 0xF3U, 0x61U, 0x02U, 0xF6U, 0x8DU, 0xCDU, 0x10U, 0xAAU, 0x20U, 0x6FU, 0xC7U, 0x98U, 0x03U, 0xE6U, 0x38U, 0x50U, 0xDAU, 0x5EU, 0x86U, 0x96U, 0x95U, 0x69U, 0xFCU, 0x8FU, 0xB0U, 0x21U, 0xB6U, 0xC4U, 0x06U, 0x16U, 0xE2U };
	uint8_t pk[QSC_SLHDSA_SHAKE192S_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE192S_PRIVATEKEY_SIZE] = { 0U };
	bool result;

	result = qsc_slhdsa_shake192s_generate_seeded_keypair(pk, sk, seed);

	if (result == true)
	{
		result = qsc_memutils_are_equal(pk, expected_pk, sizeof(pk)) &&
			qsc_memutils_are_equal(sk, expected_sk, sizeof(sk));
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));

	if (result == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-192s NIST ACVP keyGen tgId=6 tcId=51\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192s NIST ACVP keyGen tgId=6 tcId=51\n");
	}

	return result;
}

/** \brief Independently check NIST ACVP SHAKE-192f keyGen test 71.
 * \return True if the output matches the NIST key bytes exactly.
 * \note Reentrant; local secret key is securely erased.
 */
bool qsctest_sphincsplus_shake192f_acvp_keygen_test(void)
{
	static const uint8_t seed[QSC_SLHDSA_SHAKE192F_KEYGEN_SEED_SIZE] = { 0x85U, 0x50U, 0x00U, 0xFDU, 0xFFU, 0xFBU, 0xA7U, 0x69U, 0x62U, 0x80U, 0x9CU, 0x69U, 0x43U, 0x24U, 0x52U, 0xF3U, 0xDCU, 0x79U, 0x42U, 0x8FU, 0x66U, 0x2CU, 0x59U, 0xB1U, 0x43U, 0xB1U, 0xFCU, 0x38U, 0x1CU, 0x30U, 0x0BU, 0x5EU, 0xCEU, 0xC7U, 0x57U, 0x1BU, 0x5DU, 0xE2U, 0xFCU, 0xA1U, 0x67U, 0x37U, 0xE4U, 0xC1U, 0x49U, 0x11U, 0xF6U, 0x83U, 0x12U, 0x46U, 0x23U, 0xBAU, 0x6CU, 0xA1U, 0xBCU, 0x1BU, 0x0EU, 0x1AU, 0x30U, 0x30U, 0x99U, 0xE2U, 0xA6U, 0x08U, 0xB0U, 0xACU, 0x41U, 0x71U, 0x5BU, 0xC7U, 0x88U, 0xA1U };
	static const uint8_t expected_pk[QSC_SLHDSA_SHAKE192F_PUBLICKEY_SIZE] = { 0x12U, 0x46U, 0x23U, 0xBAU, 0x6CU, 0xA1U, 0xBCU, 0x1BU, 0x0EU, 0x1AU, 0x30U, 0x30U, 0x99U, 0xE2U, 0xA6U, 0x08U, 0xB0U, 0xACU, 0x41U, 0x71U, 0x5BU, 0xC7U, 0x88U, 0xA1U, 0x98U, 0x73U, 0xC7U, 0x83U, 0x37U, 0x8FU, 0x93U, 0x57U, 0x94U, 0xABU, 0xC0U, 0x31U, 0x32U, 0x43U, 0xEFU, 0xC3U, 0xF4U, 0xA1U, 0x0AU, 0x61U, 0x9CU, 0xB1U, 0xB1U, 0xFEU };
	static const uint8_t expected_sk[QSC_SLHDSA_SHAKE192F_PRIVATEKEY_SIZE] = { 0x85U, 0x50U, 0x00U, 0xFDU, 0xFFU, 0xFBU, 0xA7U, 0x69U, 0x62U, 0x80U, 0x9CU, 0x69U, 0x43U, 0x24U, 0x52U, 0xF3U, 0xDCU, 0x79U, 0x42U, 0x8FU, 0x66U, 0x2CU, 0x59U, 0xB1U, 0x43U, 0xB1U, 0xFCU, 0x38U, 0x1CU, 0x30U, 0x0BU, 0x5EU, 0xCEU, 0xC7U, 0x57U, 0x1BU, 0x5DU, 0xE2U, 0xFCU, 0xA1U, 0x67U, 0x37U, 0xE4U, 0xC1U, 0x49U, 0x11U, 0xF6U, 0x83U, 0x12U, 0x46U, 0x23U, 0xBAU, 0x6CU, 0xA1U, 0xBCU, 0x1BU, 0x0EU, 0x1AU, 0x30U, 0x30U, 0x99U, 0xE2U, 0xA6U, 0x08U, 0xB0U, 0xACU, 0x41U, 0x71U, 0x5BU, 0xC7U, 0x88U, 0xA1U, 0x98U, 0x73U, 0xC7U, 0x83U, 0x37U, 0x8FU, 0x93U, 0x57U, 0x94U, 0xABU, 0xC0U, 0x31U, 0x32U, 0x43U, 0xEFU, 0xC3U, 0xF4U, 0xA1U, 0x0AU, 0x61U, 0x9CU, 0xB1U, 0xB1U, 0xFEU };
	uint8_t pk[QSC_SLHDSA_SHAKE192F_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE192F_PRIVATEKEY_SIZE] = { 0U };
	bool result;

	result = qsc_slhdsa_shake192f_generate_seeded_keypair(pk, sk, seed);

	if (result == true)
	{
		result = qsc_memutils_are_equal(pk, expected_pk, sizeof(pk)) &&
			qsc_memutils_are_equal(sk, expected_sk, sizeof(sk));
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));

	if (result == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-192f NIST ACVP keyGen tgId=8 tcId=71\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-192f NIST ACVP keyGen tgId=8 tcId=71\n");
	}

	return result;
}

/** \brief Independently check NIST ACVP SHAKE-256s keyGen test 91.
 * \return True if the output matches the NIST key bytes exactly.
 * \note Reentrant; local secret key is securely erased.
 */
bool qsctest_sphincsplus_shake256s_acvp_keygen_test(void)
{
	static const uint8_t seed[QSC_SLHDSA_SHAKE256S_KEYGEN_SEED_SIZE] = { 0x7DU, 0x88U, 0x44U, 0x5AU, 0x7BU, 0x00U, 0x22U, 0xF1U, 0x2EU, 0x9EU, 0x2DU, 0x74U, 0x75U, 0x54U, 0x31U, 0x50U, 0x5FU, 0xF6U, 0xDBU, 0x1CU, 0x38U, 0xA8U, 0xCEU, 0x44U, 0x86U, 0x4DU, 0x34U, 0xCFU, 0xF1U, 0xA1U, 0x2CU, 0xE0U, 0xFFU, 0x2CU, 0xD1U, 0x33U, 0xADU, 0x00U, 0x72U, 0x8EU, 0xB2U, 0x9DU, 0xD0U, 0xCEU, 0x88U, 0x1CU, 0x41U, 0xC6U, 0x40U, 0xF2U, 0xE2U, 0x88U, 0x61U, 0x55U, 0x5BU, 0x59U, 0xD4U, 0xE0U, 0xBAU, 0xA0U, 0x44U, 0x7BU, 0xB5U, 0x42U, 0x87U, 0xA1U, 0x33U, 0xB9U, 0x2EU, 0xB6U, 0xC8U, 0x17U, 0x71U, 0xAEU, 0x00U, 0x28U, 0x19U, 0xB4U, 0xC0U, 0x30U, 0x0FU, 0xA6U, 0x3CU, 0xD7U, 0x18U, 0x1CU, 0x80U, 0x50U, 0x96U, 0xBFU, 0xB1U, 0x60U, 0x67U, 0xF5U, 0x2AU, 0x45U };
	static const uint8_t expected_pk[QSC_SLHDSA_SHAKE256S_PUBLICKEY_SIZE] = { 0x87U, 0xA1U, 0x33U, 0xB9U, 0x2EU, 0xB6U, 0xC8U, 0x17U, 0x71U, 0xAEU, 0x00U, 0x28U, 0x19U, 0xB4U, 0xC0U, 0x30U, 0x0FU, 0xA6U, 0x3CU, 0xD7U, 0x18U, 0x1CU, 0x80U, 0x50U, 0x96U, 0xBFU, 0xB1U, 0x60U, 0x67U, 0xF5U, 0x2AU, 0x45U, 0xCCU, 0x78U, 0x52U, 0x37U, 0xC2U, 0x4DU, 0x92U, 0x35U, 0xB6U, 0xBCU, 0x31U, 0x94U, 0xB7U, 0x9EU, 0x5AU, 0x9FU, 0x95U, 0x33U, 0x88U, 0xEAU, 0x74U, 0x5DU, 0x7CU, 0xFBU, 0x87U, 0x82U, 0x6AU, 0x94U, 0xE5U, 0xB2U, 0x71U, 0xD5U };
	static const uint8_t expected_sk[QSC_SLHDSA_SHAKE256S_PRIVATEKEY_SIZE] = { 0x7DU, 0x88U, 0x44U, 0x5AU, 0x7BU, 0x00U, 0x22U, 0xF1U, 0x2EU, 0x9EU, 0x2DU, 0x74U, 0x75U, 0x54U, 0x31U, 0x50U, 0x5FU, 0xF6U, 0xDBU, 0x1CU, 0x38U, 0xA8U, 0xCEU, 0x44U, 0x86U, 0x4DU, 0x34U, 0xCFU, 0xF1U, 0xA1U, 0x2CU, 0xE0U, 0xFFU, 0x2CU, 0xD1U, 0x33U, 0xADU, 0x00U, 0x72U, 0x8EU, 0xB2U, 0x9DU, 0xD0U, 0xCEU, 0x88U, 0x1CU, 0x41U, 0xC6U, 0x40U, 0xF2U, 0xE2U, 0x88U, 0x61U, 0x55U, 0x5BU, 0x59U, 0xD4U, 0xE0U, 0xBAU, 0xA0U, 0x44U, 0x7BU, 0xB5U, 0x42U, 0x87U, 0xA1U, 0x33U, 0xB9U, 0x2EU, 0xB6U, 0xC8U, 0x17U, 0x71U, 0xAEU, 0x00U, 0x28U, 0x19U, 0xB4U, 0xC0U, 0x30U, 0x0FU, 0xA6U, 0x3CU, 0xD7U, 0x18U, 0x1CU, 0x80U, 0x50U, 0x96U, 0xBFU, 0xB1U, 0x60U, 0x67U, 0xF5U, 0x2AU, 0x45U, 0xCCU, 0x78U, 0x52U, 0x37U, 0xC2U, 0x4DU, 0x92U, 0x35U, 0xB6U, 0xBCU, 0x31U, 0x94U, 0xB7U, 0x9EU, 0x5AU, 0x9FU, 0x95U, 0x33U, 0x88U, 0xEAU, 0x74U, 0x5DU, 0x7CU, 0xFBU, 0x87U, 0x82U, 0x6AU, 0x94U, 0xE5U, 0xB2U, 0x71U, 0xD5U };
	uint8_t pk[QSC_SLHDSA_SHAKE256S_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE256S_PRIVATEKEY_SIZE] = { 0U };
	bool result;

	result = qsc_slhdsa_shake256s_generate_seeded_keypair(pk, sk, seed);

	if (result == true)
	{
		result = qsc_memutils_are_equal(pk, expected_pk, sizeof(pk)) &&
			qsc_memutils_are_equal(sk, expected_sk, sizeof(sk));
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));

	if (result == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-256s NIST ACVP keyGen tgId=10 tcId=91\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256s NIST ACVP keyGen tgId=10 tcId=91\n");
	}

	return result;
}

/** \brief Independently check NIST ACVP SHAKE-256f keyGen test 111.
 * \return True if the output matches the NIST key bytes exactly.
 * \note Reentrant; local secret key is securely erased.
 */
bool qsctest_sphincsplus_shake256f_acvp_keygen_test(void)
{
	static const uint8_t seed[QSC_SLHDSA_SHAKE256F_KEYGEN_SEED_SIZE] = { 0x3DU, 0xE4U, 0xB5U, 0x4AU, 0x5FU, 0x5FU, 0xB9U, 0x8DU, 0x66U, 0x38U, 0xFBU, 0x3DU, 0x88U, 0x99U, 0x35U, 0x5CU, 0xC3U, 0x58U, 0x2EU, 0x8AU, 0x39U, 0x7DU, 0x09U, 0x90U, 0xCAU, 0xD0U, 0x32U, 0xD7U, 0x8EU, 0xE9U, 0xE1U, 0x99U, 0xDAU, 0x7FU, 0x71U, 0xD2U, 0x1DU, 0x01U, 0x82U, 0xA9U, 0x9DU, 0xE3U, 0x4EU, 0x27U, 0x96U, 0xFEU, 0x5DU, 0xDEU, 0x04U, 0x6DU, 0x9CU, 0x9EU, 0x96U, 0x1DU, 0xCEU, 0x24U, 0xC2U, 0x56U, 0x27U, 0x28U, 0xBEU, 0x7DU, 0x96U, 0x32U, 0xB3U, 0xEFU, 0x38U, 0x25U, 0xA5U, 0x15U, 0xE0U, 0xB2U, 0xE4U, 0x16U, 0x4DU, 0xB7U, 0xECU, 0x80U, 0x5BU, 0x4CU, 0xF1U, 0xC7U, 0xA2U, 0xDEU, 0x6EU, 0x63U, 0xD7U, 0xDFU, 0x35U, 0x9BU, 0x99U, 0xB1U, 0xF3U, 0x06U, 0x3FU, 0x25U };
	static const uint8_t expected_pk[QSC_SLHDSA_SHAKE256F_PUBLICKEY_SIZE] = { 0xB3U, 0xEFU, 0x38U, 0x25U, 0xA5U, 0x15U, 0xE0U, 0xB2U, 0xE4U, 0x16U, 0x4DU, 0xB7U, 0xECU, 0x80U, 0x5BU, 0x4CU, 0xF1U, 0xC7U, 0xA2U, 0xDEU, 0x6EU, 0x63U, 0xD7U, 0xDFU, 0x35U, 0x9BU, 0x99U, 0xB1U, 0xF3U, 0x06U, 0x3FU, 0x25U, 0xAEU, 0xC3U, 0x8FU, 0xF5U, 0x3CU, 0x46U, 0xAAU, 0xD9U, 0x30U, 0x16U, 0x69U, 0x57U, 0xCAU, 0x0DU, 0xB5U, 0xC5U, 0x46U, 0x6DU, 0x0CU, 0xBEU, 0x9AU, 0x11U, 0x97U, 0x09U, 0x87U, 0xA2U, 0x30U, 0xEBU, 0xBBU, 0x54U, 0x50U, 0xA4U };
	static const uint8_t expected_sk[QSC_SLHDSA_SHAKE256F_PRIVATEKEY_SIZE] = { 0x3DU, 0xE4U, 0xB5U, 0x4AU, 0x5FU, 0x5FU, 0xB9U, 0x8DU, 0x66U, 0x38U, 0xFBU, 0x3DU, 0x88U, 0x99U, 0x35U, 0x5CU, 0xC3U, 0x58U, 0x2EU, 0x8AU, 0x39U, 0x7DU, 0x09U, 0x90U, 0xCAU, 0xD0U, 0x32U, 0xD7U, 0x8EU, 0xE9U, 0xE1U, 0x99U, 0xDAU, 0x7FU, 0x71U, 0xD2U, 0x1DU, 0x01U, 0x82U, 0xA9U, 0x9DU, 0xE3U, 0x4EU, 0x27U, 0x96U, 0xFEU, 0x5DU, 0xDEU, 0x04U, 0x6DU, 0x9CU, 0x9EU, 0x96U, 0x1DU, 0xCEU, 0x24U, 0xC2U, 0x56U, 0x27U, 0x28U, 0xBEU, 0x7DU, 0x96U, 0x32U, 0xB3U, 0xEFU, 0x38U, 0x25U, 0xA5U, 0x15U, 0xE0U, 0xB2U, 0xE4U, 0x16U, 0x4DU, 0xB7U, 0xECU, 0x80U, 0x5BU, 0x4CU, 0xF1U, 0xC7U, 0xA2U, 0xDEU, 0x6EU, 0x63U, 0xD7U, 0xDFU, 0x35U, 0x9BU, 0x99U, 0xB1U, 0xF3U, 0x06U, 0x3FU, 0x25U, 0xAEU, 0xC3U, 0x8FU, 0xF5U, 0x3CU, 0x46U, 0xAAU, 0xD9U, 0x30U, 0x16U, 0x69U, 0x57U, 0xCAU, 0x0DU, 0xB5U, 0xC5U, 0x46U, 0x6DU, 0x0CU, 0xBEU, 0x9AU, 0x11U, 0x97U, 0x09U, 0x87U, 0xA2U, 0x30U, 0xEBU, 0xBBU, 0x54U, 0x50U, 0xA4U };
	uint8_t pk[QSC_SLHDSA_SHAKE256F_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_SLHDSA_SHAKE256F_PRIVATEKEY_SIZE] = { 0U };
	bool result;

	result = qsc_slhdsa_shake256f_generate_seeded_keypair(pk, sk, seed);

	if (result == true)
	{
		result = qsc_memutils_are_equal(pk, expected_pk, sizeof(pk)) &&
			qsc_memutils_are_equal(sk, expected_sk, sizeof(sk));
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));

	if (result == true)
	{
		qsctest_print_safe("PASS SLH-DSA SHAKE-256f NIST ACVP keyGen tgId=12 tcId=111\n");
	}
	else
	{
		qsctest_print_safe("FAIL SLH-DSA SHAKE-256f NIST ACVP keyGen tgId=12 tcId=111\n");
	}

	return result;
}


void qsctest_sphincsplus_run()
{
	if (qsctest_sphincsplus_compatibility_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus compatibility tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus compatibility tests. \n");
	}

	if (qsctest_sphincsplus_shake128s_signature_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-128s signature tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-128s signature tests. \n");
	}

	if (qsctest_sphincsplus_shake128f_signature_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-128f signature tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-128f signature tests. \n");
	}

	if (qsctest_sphincsplus_shake192s_signature_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-192s signature tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-192s signature tests. \n");
	}

	if (qsctest_sphincsplus_shake192f_signature_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-192f signature tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-192f signature tests. \n");
	}

	if (qsctest_sphincsplus_shake256s_signature_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-256s signature tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-256s signature tests. \n");
	}

	if (qsctest_sphincsplus_shake256f_signature_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-256f signature tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-256f signature tests. \n");
	}

	if (qsctest_sphincsplus_shake128s_acvp_keygen_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-128s ACVP key generation tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-128s ACVP key generation tests. \n");
	}

	if (qsctest_sphincsplus_shake128f_acvp_keygen_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-128f ACVP key generation tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-128f ACVP key generation tests. \n");
	}

	if (qsctest_sphincsplus_shake192s_acvp_keygen_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-192s ACVP key generation tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-192s ACVP key generation tests. \n");
	}

	if (qsctest_sphincsplus_shake192f_acvp_keygen_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-192f ACVP key generation tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-192f ACVP key generation tests. \n");
	}

	if (qsctest_sphincsplus_shake256s_acvp_keygen_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-256s ACVP key generation tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-256s ACVP key generation tests. \n");
	}

	if (qsctest_sphincsplus_shake256f_acvp_keygen_test() == true)
	{
		qsctest_print_safe("Success! Passed the SphincsPlus SHAKE-256f ACVP key generation tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SphincsPlus SHAKE-256f ACVP key generation tests. \n");
	}

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
