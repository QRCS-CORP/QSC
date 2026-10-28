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

#include "dilithium_test.h"
#include "qsctestcommon.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "dilithium.h"
#include "mldsa.h"
#include "intutils.h"
#include "sha2.h"
#include "memutils.h"

#define TEST_MESSAGE_LEN 33

/** \brief Execute existing qsctest_dilithium_kat_test baseline regression.
 * \return True on success; false when a test condition fails.
 * \note Uses the shared non-thread-safe QSCTest RNG fixture.
 */
bool qsctest_dilithium_kat_test()
{
	bool ret;

	ret = false;
	/* note: the kat files were generated using the NIST post quantum competition format, 
	for the NIST ACVP KAT vector test, run the CAVP project. */

#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
	qsctest_print_safe("Disable randomized signing: QSC_DILITHIUM_RANDOMIZED_SIGNING to enable tests. -DOT6 \n");

#else

	uint8_t msg[TEST_MESSAGE_LEN] = { 0 };
	uint8_t kmsg[TEST_MESSAGE_LEN] = { 0 };
	uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	uint8_t kpk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0 };
	uint8_t ksig[QSC_DILITHIUM_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0 };
	size_t msglen;
	size_t pklen;
	size_t seedlen;
	size_t sklen;
	size_t siglen;
	ret = true;
	msglen = 0;
	pklen = 0;
	seedlen = 0;
	siglen = 0;
	sklen = 0;

#if defined(QSC_DILITHIUM_S1P44)
	char path[] = "NPQC/dilithium-2544.rsp";
#elif defined(QSC_DILITHIUM_S3P65)
	char path[] = "NPQC/dilithium-4016.rsp";
#elif defined(QSC_DILITHIUM_S5P87)
	char path[] = "NPQC/dilithium-4880.rsp";
#else
#	error The parameter set is invalid!
#endif

	/* NIST FIPS 204 KATs */

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
	qsc_dilithium_sign(sig, &siglen, kmsg, msglen, sk, qsctest_nistrng_prng_generate);
	
	/* compare the signature cipher-text to the expected output */
	if (qsc_intutils_are_equal8(sig, ksig, siglen) != true)
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
	if (qsc_intutils_are_equal8(msg, kmsg, msglen) != true)
	{
		qsctest_print_safe("Failure! dilithium operations: message does not equal to the original -DOT5 \n");
		ret = false;
	}
#endif

	return ret;
}

/** \brief Verify one parameter-qualified ML-DSA KAT using its competition response file.
 * \param path Existing NIST competition-format response file.
 * \param pkbytes Public key size of selected parameter, in bytes.
 * \param skbytes Secret key size of selected parameter, in bytes.
 * \param sigbytes Detached signature size, in bytes.
 * \param keygen Parameter-qualified key-pair generator using QSCTest RNG.
 * \param signer Parameter-qualified signed-message signing callback.
 * \param verifier Parameter-qualified message recovery and verification callback.
 * \return True if keys, signature, lengths and verified message match the known answer.
 * \note The QSCTest NIST RNG has process-global state. Do not call concurrently.
 *       Vector format is older PQC competition format, not final FIPS 204 ACVP evidence.
 */
static bool qsctest_mldsa_kat_verify(const char* path, size_t pkbytes, size_t skbytes, size_t sigbytes, bool (*keygen)(uint8_t*, uint8_t*, bool (*)(uint8_t*, size_t)), bool (*signer)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, bool (*)(uint8_t*, size_t)), bool (*verifier)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*))
{
    uint8_t msg[TEST_MESSAGE_LEN] = { 0U };
    uint8_t knownmsg[TEST_MESSAGE_LEN] = { 0U };
    uint8_t pk[QSC_MLDSA87_PUBLICKEY_SIZE] = { 0U };
    uint8_t knownpk[QSC_MLDSA87_PUBLICKEY_SIZE] = { 0U };
    uint8_t sk[QSC_MLDSA87_PRIVATEKEY_SIZE] = { 0U };
    uint8_t knownsk[QSC_MLDSA87_PRIVATEKEY_SIZE] = { 0U };
    uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
    uint8_t signature[QSC_MLDSA87_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0U };
    uint8_t knownsig[QSC_MLDSA87_SIGNATURE_SIZE + TEST_MESSAGE_LEN] = { 0U };
    size_t msglen;
    size_t pklen;
    size_t seedlen;
    size_t sklen;
    size_t siglen;
    size_t actualsiglen;
    size_t verifiedlen;
    bool res;

    msglen = 0U;
    pklen = 0U;
    seedlen = 0U;
    sklen = 0U;
    siglen = 0U;
    actualsiglen = 0U;
    verifiedlen = 0U;
    res = false;

#if !defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
    parse_nist_signature_kat(path, seed, &seedlen, knownmsg, &msglen, knownpk, &pklen, knownsk, &sklen, knownsig, &siglen, 0U);

    if (seedlen == sizeof(seed) && msglen <= sizeof(msg) && pklen == pkbytes && sklen == skbytes && siglen == sigbytes + msglen)
    {
        qsctest_nistrng_prng_initialize(seed, NULL, 0U);
        res = keygen(pk, sk, qsctest_nistrng_prng_generate);

        if (res == true)
        {
            res = qsc_intutils_are_equal8(pk, knownpk, pkbytes) && qsc_intutils_are_equal8(sk, knownsk, skbytes);
        }

        if (res == true)
        {
            res = signer(signature, &actualsiglen, knownmsg, msglen, sk, qsctest_nistrng_prng_generate);
        }

        if (res == true)
        {
            res = (actualsiglen == siglen) && qsc_intutils_are_equal8(signature, knownsig, siglen);
        }

        if (res == true)
        {
            res = verifier(msg, &verifiedlen, signature, actualsiglen, pk);
        }

        if (res == true)
        {
            res = (verifiedlen == msglen) && qsc_intutils_are_equal8(msg, knownmsg, msglen);
        }
    }
#else
    (void)path;
    (void)pkbytes;
    (void)skbytes;
    (void)sigbytes;
    (void)keygen;
    (void)signer;
    (void)verifier;
#endif

    qsc_memutils_secure_erase(sk, sizeof(sk));
    return res;
}

/** \brief Verify ML-DSA-44 against its saved competition-format signature KAT.
 * \return True when vector keys, signature and recovered message all match.
 * \note Deterministic signing only; older PQC KATs are not FIPS 204 ACVP proof.
 */
bool qsctest_mldsa44_kat_test(void)
{
    bool res;

    res = qsctest_mldsa_kat_verify("NPQC/dilithium-2544.rsp", QSC_MLDSA44_PUBLICKEY_SIZE, QSC_MLDSA44_PRIVATEKEY_SIZE, QSC_MLDSA44_SIGNATURE_SIZE, qsc_mldsa44_generate_keypair, qsc_mldsa44_sign, qsc_mldsa44_verify);
    return res;
}

/** \brief Verify ML-DSA-65 against its saved competition-format signature KAT.
 * \return True when vector keys, signature and recovered message all match.
 * \note Deterministic signing only; older PQC KATs are not FIPS 204 ACVP proof.
 */
bool qsctest_mldsa65_kat_test(void)
{
    bool res;

    res = qsctest_mldsa_kat_verify("NPQC/dilithium-4016.rsp", QSC_MLDSA65_PUBLICKEY_SIZE, QSC_MLDSA65_PRIVATEKEY_SIZE, QSC_MLDSA65_SIGNATURE_SIZE, qsc_mldsa65_generate_keypair, qsc_mldsa65_sign, qsc_mldsa65_verify);
    return res;
}

/** \brief Verify ML-DSA-87 against its saved competition-format signature KAT.
 * \return True when vector keys, signature and recovered message all match.
 * \note Deterministic signing only; older PQC KATs are not FIPS 204 ACVP proof.
 */
bool qsctest_mldsa87_kat_test(void)
{
    bool res;

    res = qsctest_mldsa_kat_verify("NPQC/dilithium-4880.rsp", QSC_MLDSA87_PUBLICKEY_SIZE, QSC_MLDSA87_PRIVATEKEY_SIZE, QSC_MLDSA87_SIGNATURE_SIZE, qsc_mldsa87_generate_keypair, qsc_mldsa87_sign, qsc_mldsa87_verify);
    return res;
}

/** \brief Execute existing qsctest_dilithium_privatekey_integrity baseline regression.
 * \return True on success; false when a test condition fails.
 * \note Uses the shared non-thread-safe QSCTest RNG fixture.
 */
bool qsctest_dilithium_privatekey_integrity()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
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

	/* flip bits in the private key */
	/* Note: this used to fail if fewer bits (<=32) were flipped in the secret key, 
	   but changes to Dilithium made by NIST, have changed this behavior. */
	for (size_t i = 0; i < 64; ++i)
	{
		sk[QSC_DILITHIUM_PUBLICKEY_SIZE + i] ^= 1;
	}

	/* process message and return signed message */
	qsc_dilithium_sign(sig, &siglen, msg, QSCTEST_DILITHIUM_MLEN, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_dilithium_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! dilithium private-key: message verification passed with altered secret key -DST1 \n");
		ret = false;
	}

	return ret;
}

/** \brief Execute existing qsctest_dilithium_publickey_integrity baseline regression.
 * \return True on success; false when a test condition fails.
 * \note Uses the shared non-thread-safe QSCTest RNG fixture.
 */
bool qsctest_dilithium_publickey_integrity()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
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

	/* flip bits in the public key */
	for (size_t i = 0; i < 32; ++i)
	{
		pk[i] ^= 1;
	}

	/* process message and return signed message */
	qsc_dilithium_sign(sig, &siglen, msg, QSCTEST_DILITHIUM_MLEN, sk, qsctest_nistrng_prng_generate);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_dilithium_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! dilithium public-key: message verification passed with altered public key -DPT1 \n");
		ret = false;
	}

	return ret;
}

/** \brief Execute existing qsctest_dilithium_signature_integrity baseline regression.
 * \return True on success; false when a test condition fails.
 * \note Uses the shared non-thread-safe QSCTest RNG fixture.
 */
bool qsctest_dilithium_signature_integrity()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
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
	qsc_dilithium_sign(sig, &siglen, msg, QSCTEST_DILITHIUM_MLEN, sk, qsctest_nistrng_prng_generate);

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

/** \brief Execute existing qsctest_dilithium_stress_test baseline regression.
 * \return True on success; false when a test condition fails.
 * \note Uses the shared non-thread-safe QSCTest RNG fixture.
 */
bool qsctest_dilithium_stress_test()
{
	uint8_t msg[QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t mout[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = QSCTEST_DILITHIUM_MLEN;
	siglen = QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the key-pair */
	qsc_dilithium_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* sign the message and return the signed version in sig */
	qsc_dilithium_sign(sig, &siglen, msg, msglen, sk, qsctest_nistrng_prng_generate);

	if (siglen != QSC_DILITHIUM_SIGNATURE_SIZE + QSCTEST_DILITHIUM_MLEN)
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

	if (msglen != QSCTEST_DILITHIUM_MLEN)
	{
		qsctest_print_safe("Failure! dilithium stress: message length is incorrect -DST3 \n");
		ret = false;
	}

	return ret;
}

/** \brief Execute named ML-DSA parameter KATs and legacy integrity tests serially.
 * \note Prints distinct PASS/FAIL results; uses non-thread-safe QSCTest RNG state.
 */
void qsctest_dilithium_run(void)
{
	if (qsctest_mldsa44_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed the ML-DSA-44 competition-format known-answer test\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ML-DSA-44 competition-format known-answer test\n");
	}
	if (qsctest_mldsa65_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed the ML-DSA-65 competition-format known-answer test\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ML-DSA-65 competition-format known-answer test\n");
	}
	if (qsctest_mldsa87_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed the ML-DSA-87 competition-format known-answer test\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ML-DSA-87 competition-format known-answer test\n");
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

/** \brief Generate stable deterministic test randomness for ML-DSA boundary tests.
 * \param output Caller-owned random output buffer.
 * \param length Number of bytes to initialize.
 * \return True when the requested bytes have been initialized.
 */
static bool qsctest_mldsa_boundary_rng(uint8_t* output, size_t length)
{
    size_t i;

    for (i = 0U; i < length; ++i)
    {
        output[i] = (uint8_t)(i ^ 0xA5U);
    }

    return true;
}

/** \brief Check all parameter-specific signing and verification boundary contracts.
 * \param sigbytes Detached signature length for this ML-DSA parameter.
 * \param keygen Parameter-specific seeded key generation function.
 * \param signer Parameter-specific attached signing function.
 * \param signer_ex Context-aware signing function.
 * \param verifier Parameter-specific attached signature verification function.
 * \param verifier_ex Context-aware verification function.
 * \return True only if input rejection resets lengths and maximum-context signing succeeds.
 * \note Uses locally owned buffers; does not require an external NIST KAT file.
 */
static bool qsctest_mldsa_boundary_verify(size_t sigbytes, void (*keygen)(uint8_t*, uint8_t*, const uint8_t*), bool (*signer)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, bool (*)(uint8_t*, size_t)), bool (*signer_ex)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, bool (*)(uint8_t*, size_t)), bool (*verifier)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*), bool (*verifier_ex)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*))
{
    uint8_t pk[QSC_MLDSA87_PUBLICKEY_SIZE] = { 0U };
    uint8_t sk[QSC_MLDSA87_PRIVATEKEY_SIZE] = { 0U };
    uint8_t seed[QSC_MLDSA_SEED_SIZE] = { 0U };
    uint8_t msg[33U] = { 0U };
    uint8_t ctx[256U] = { 0U };
    uint8_t signedmsg[QSC_MLDSA87_SIGNATURE_SIZE + sizeof(msg)] = { 0U };
    uint8_t recovered[sizeof(msg)] = { 0U };
    size_t outlen;
    size_t recoveredlen;
    bool res;

    res = true;
    keygen(pk, sk, seed);

    outlen = 123U;
    res = (signer(NULL, &outlen, msg, sizeof(msg), sk, qsctest_mldsa_boundary_rng) == false && outlen == 0U) && res;
    outlen = 123U;
    res = (signer(signedmsg, &outlen, msg, sizeof(msg), NULL, qsctest_mldsa_boundary_rng) == false && outlen == 0U) && res;
    outlen = 123U;
    res = (signer(signedmsg, &outlen, msg, SIZE_MAX, sk, qsctest_mldsa_boundary_rng) == false && outlen == 0U) && res;
    outlen = 123U;
    res = (signer_ex(signedmsg, &outlen, msg, sizeof(msg), NULL, 1U, sk, qsctest_mldsa_boundary_rng) == false && outlen == 0U) && res;
    outlen = 123U;
    res = (signer_ex(signedmsg, &outlen, msg, sizeof(msg), ctx, sizeof(ctx), sk, qsctest_mldsa_boundary_rng) == false && outlen == 0U) && res;

    recoveredlen = 123U;
    res = (verifier(recovered, &recoveredlen, NULL, 0U, pk) == false && recoveredlen == 0U) && res;
    recoveredlen = 123U;
    res = (verifier(recovered, &recoveredlen, signedmsg, sigbytes, NULL) == false && recoveredlen == 0U) && res;
    recoveredlen = 123U;
    res = (verifier_ex(recovered, &recoveredlen, NULL, 1U, signedmsg, sigbytes, pk) == false && recoveredlen == 0U) && res;
    recoveredlen = 123U;
    res = (verifier_ex(recovered, &recoveredlen, ctx, sizeof(ctx), signedmsg, sigbytes, pk) == false && recoveredlen == 0U) && res;
    recoveredlen = 123U;
    res = (verifier(recovered, &recoveredlen, signedmsg, sigbytes - 1U, pk) == false && recoveredlen == 0U) && res;

    outlen = 123U;
    res = (signer_ex(signedmsg, &outlen, msg, 0U, ctx, 255U, sk, qsctest_mldsa_boundary_rng) == true && outlen == sigbytes) && res;
    recoveredlen = 123U;
    res = (verifier_ex(recovered, &recoveredlen, ctx, 255U, signedmsg, outlen, pk) == true && recoveredlen == 0U) && res;

    outlen = 123U;
    res = (signer_ex(signedmsg, &outlen, msg, sizeof(msg), ctx, 255U, sk, qsctest_mldsa_boundary_rng) == true && outlen == sigbytes + sizeof(msg)) && res;
    recoveredlen = 123U;
    res = (verifier_ex(recovered, &recoveredlen, ctx, 255U, signedmsg, outlen, pk) == true && recoveredlen == sizeof(msg) && qsc_memutils_are_equal(recovered, msg, sizeof(msg)) == true) && res;

    signedmsg[0U] ^= 1U;
    recoveredlen = 123U;
    res = (verifier_ex(recovered, &recoveredlen, ctx, 255U, signedmsg, outlen, pk) == false && recoveredlen == 0U) && res;
    signedmsg[0U] ^= 1U;

    qsc_memutils_secure_erase(sk, sizeof(sk));
    return res;
}

/** \brief Validate ML-DSA-44 pointer, length, maximum context and tamper behavior.
 * \return True only if all parameter-specific boundary cases pass.
 */
bool qsctest_mldsa44_boundary_test(void)
{
    bool res;

    res = qsctest_mldsa_boundary_verify(QSC_MLDSA44_SIGNATURE_SIZE, qsc_mldsa44_seeded_generate_keypair, qsc_mldsa44_sign, qsc_mldsa44_sign_ex, qsc_mldsa44_verify, qsc_mldsa44_verify_ex);
    return res;
}

/** \brief Validate ML-DSA-65 pointer, length, maximum context and tamper behavior.
 * \return True only if all parameter-specific boundary cases pass.
 */
bool qsctest_mldsa65_boundary_test(void)
{
    bool res;

    res = qsctest_mldsa_boundary_verify(QSC_MLDSA65_SIGNATURE_SIZE, qsc_mldsa65_seeded_generate_keypair, qsc_mldsa65_sign, qsc_mldsa65_sign_ex, qsc_mldsa65_verify, qsc_mldsa65_verify_ex);
    return res;
}

/** \brief Validate ML-DSA-87 pointer, length, maximum context and tamper behavior.
 * \return True only if all parameter-specific boundary cases pass.
 */
bool qsctest_mldsa87_boundary_test(void)
{
    bool res;

    res = qsctest_mldsa_boundary_verify(QSC_MLDSA87_SIGNATURE_SIZE, qsc_mldsa87_seeded_generate_keypair, qsc_mldsa87_sign, qsc_mldsa87_sign_ex, qsc_mldsa87_verify, qsc_mldsa87_verify_ex);
    return res;
}


/** \brief Verify a reference ML-DSA keyGen ACVP key-pair case by SHA-256 fingerprints.
 * \param seedhex NIST-provided 32-byte seed in hexadecimal.
 * \param pkhashhex SHA-256 of the complete official public key, encoded as hexadecimal.
 * \param skhashhex SHA-256 of the complete official private key, encoded as hexadecimal.
 * \param pkbytes Key size of the selected parameter.
 * \param skbytes Secret key size of the selected parameter.
 * \param keygen Seeded ML-DSA generation callback.
 * \return True if both entire generated keys hash to the published ACVP key values.
 * \note The expected key fingerprints were generated from NIST ACVP-Server
 *       ML-DSA-keyGen-FIPS204/expectedResults.json, via SHA-256; compare
 *       full keys through their independent 256-bit SHA-256 digests.
 */
static bool qsctest_mldsa_acvp_keygen_check(const char* seedhex, const char* pkhashhex, const char* skhashhex, size_t pkbytes, size_t skbytes, void (*keygen)(uint8_t*, uint8_t*, const uint8_t*))
{
    uint8_t pk[QSC_MLDSA87_PUBLICKEY_SIZE] = { 0U };
    uint8_t sk[QSC_MLDSA87_PRIVATEKEY_SIZE] = { 0U };
    uint8_t seed[QSC_MLDSA_SEED_SIZE] = { 0U };
    uint8_t expectedpk[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t expectedsk[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t actualpk[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t actualsk[QSC_SHA2_256_HASH_SIZE] = { 0U };
    bool res;

    res = false;
    qsc_intutils_hex_to_bin(seedhex, seed, sizeof(seed));
    qsc_intutils_hex_to_bin(pkhashhex, expectedpk, sizeof(expectedpk));
    qsc_intutils_hex_to_bin(skhashhex, expectedsk, sizeof(expectedsk));
    keygen(pk, sk, seed);
    qsc_sha256_compute(actualpk, pk, pkbytes);
    qsc_sha256_compute(actualsk, sk, skbytes);
    res = qsc_memutils_are_equal(actualpk, expectedpk, sizeof(actualpk)) && qsc_memutils_are_equal(actualsk, expectedsk, sizeof(actualsk));
    qsc_memutils_secure_erase(sk, sizeof(sk));
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-44 keyGen test case tcId=1.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa44_acvp_tc1_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("7194B13C95231010AFD2C909992BD2003BA6F437C3886BDBE3F6B867A14BA161", "838b88b6ac41e2c60698173e08ca173d0b0d2839205806e56a8a3d53195f3a03", "1c911d163cd0a5563e06f22403f7e16334fee17c2abb66f11ddf39ca6307ec58", QSC_MLDSA44_PUBLICKEY_SIZE, QSC_MLDSA44_PRIVATEKEY_SIZE, qsc_mldsa44_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-44 keyGen test case tcId=2.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa44_acvp_tc2_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("2EBE5A4123398DFBCD5BDF0A42EBDD03112BE3BC88A6E9B78D93120AB8D0120E", "366cdfa62052438e03a4bb70e8aaa2c31c535584ef83a926b4efa1796605dacb", "67c5410e10424bdb0a7a17755b9a08f86f52b3ebe372bb03caefd6bbfefd28a5", QSC_MLDSA44_PUBLICKEY_SIZE, QSC_MLDSA44_PRIVATEKEY_SIZE, qsc_mldsa44_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-44 keyGen test case tcId=3.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa44_acvp_tc3_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("2AA7609556919CCE9893561BB4120CDD9CFF12734267A8CCB4B2D2CA93066E1E", "075ff22d7358e8548b4c2b59681b86e790f1ef2ef4a651d977d91264b06cfcc3", "99fc3c56f5d64075d1e0d3fc71a7c1a7f29ce42e3b16ff93421ebfd1c71d9e57", QSC_MLDSA44_PUBLICKEY_SIZE, QSC_MLDSA44_PRIVATEKEY_SIZE, qsc_mldsa44_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-65 keyGen test case tcId=26.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa65_acvp_tc26_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("A991FD42B071D49C48AE3E75C647459E0DAAD1E1BA356A04801912D3294BCFF8", "b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a", "56c53ac82fbff7d81b7a8cfbbc73011ceccad677e16dc53f2ece66d49aa11edd", QSC_MLDSA65_PUBLICKEY_SIZE, QSC_MLDSA65_PRIVATEKEY_SIZE, qsc_mldsa65_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-65 keyGen test case tcId=27.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa65_acvp_tc27_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("494F29AD1C93ABB2B9545BD14CC575A98ECD3062137B439B49EB1A8CC6652FC6", "4f2a21f2bee92fc15c91ce7dc7d96f5dac1ee1f0f7eb7325823ea96dd12ecc84", "bd37a2499543695d6d31afe6c5188fe18fa16f3980d2941edae7b5dbe5c71c14", QSC_MLDSA65_PUBLICKEY_SIZE, QSC_MLDSA65_PRIVATEKEY_SIZE, qsc_mldsa65_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-65 keyGen test case tcId=28.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa65_acvp_tc28_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("C4EC434D7FEDDCBFF68B77A80E45935F3E363289A493E49ACBAE366E5C6B3D01", "01d5cc69a363d4b47fffa5a042edf4293cd5290c3f4a1b5c2f11260b6446eace", "81f88ffe05449f6ac5370d632d6e969be6028023fb81570e62d7e0e0ee963269", QSC_MLDSA65_PUBLICKEY_SIZE, QSC_MLDSA65_PRIVATEKEY_SIZE, qsc_mldsa65_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-87 keyGen test case tcId=51.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa87_acvp_tc51_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("A16F5B0796703E2D1A0140A35CBF36EFABE70E752BA59B6A9A0E9C4B05302F73", "33f49649f05ec2fc3b050007b18ade043bbc8d1c0ded03a269d540486daaa5f4", "c64e15742f27d7d8e2832f7d55a5c014f2c9536082f3a3181cfc6246908dd649", QSC_MLDSA87_PUBLICKEY_SIZE, QSC_MLDSA87_PRIVATEKEY_SIZE, qsc_mldsa87_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-87 keyGen test case tcId=52.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa87_acvp_tc52_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("E46D458A660285930D9656A88D14E751730CAE7A4975B6E4FBE69E80E3F01E7F", "f445cbb034fba125d17a8ac1be6ff617ddaca04a3e6b76ccf44e3dbc94cc7946", "d679b094bb35dfba907e45fc449b5879353d7f32c65c6fe4430f55b2cef7a2f0", QSC_MLDSA87_PUBLICKEY_SIZE, QSC_MLDSA87_PRIVATEKEY_SIZE, qsc_mldsa87_seeded_generate_keypair);
    return res;
}

/** \brief Verify NIST ACVP FIPS 204 ML-DSA-87 keyGen test case tcId=53.
 * \return True when the complete public and private key fingerprints match NIST.
 */
bool qsctest_mldsa87_acvp_tc53_test(void)
{
    bool res;

    res = qsctest_mldsa_acvp_keygen_check("719BCE87E014ABDB6A0F77EA1C84EAC7DD674D5B03B27ECE154BA7FDDE8A0458", "e0e816ae6f6cd0180674efd3191400694ab9a713e2b319de7f54ce9de45cf6ca", "5c661320f32bed1bc5fe7f732d3e8305c164584a08c04da73b6008682b150387", QSC_MLDSA87_PUBLICKEY_SIZE, QSC_MLDSA87_PRIVATEKEY_SIZE, qsc_mldsa87_seeded_generate_keypair);
    return res;
}


/** \brief Qualify signed-message framing using the supported ML-DSA public API.
 * \param sigbytes Exact signature size for the selected ML-DSA parameter set, in bytes.
 * \param keygen Deterministic key-generation callback; writes caller-owned keys.
 * \param signer Attached-message signing callback; writes caller-owned output.
 * \param verifier Public attached-message verification callback.
 * \param verifier_ex Public context-qualified verification callback.
 * \return True only when valid input verifies and malformed inputs are rejected.
 * \note This test does not link to private scalar/AVX2 ML-DSA backends.
 * \note The caller-owned test vectors and callbacks are used sequentially.
 */
static bool qsctest_mldsa_signature_format_verify(size_t sigbytes, void (*keygen)(uint8_t*, uint8_t*, const uint8_t*), bool (*signer)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, bool (*)(uint8_t*, size_t)), bool (*verifier)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*), bool (*verifier_ex)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*))
{
    uint8_t pk[QSC_MLDSA87_PUBLICKEY_SIZE] = { 0U };
    uint8_t sk[QSC_MLDSA87_PRIVATEKEY_SIZE] = { 0U };
    uint8_t seed[QSC_MLDSA_SEED_SIZE] = { 0U };
    uint8_t msg[19U] = { 0U };
    uint8_t recovered[sizeof(msg) + 1U] = { 0U };
    uint8_t signedmsg[QSC_MLDSA87_SIGNATURE_SIZE + sizeof(msg) + 1U] = { 0U };
    uint8_t oversized[sizeof(signedmsg)] = { 0U };
    uint8_t context[1U] = { 0x7FU };
    size_t recoveredlen;
    size_t signedlen;
    uint8_t originalhint;
    bool res;

    res = true;
    recoveredlen = 0U;
    signedlen = 0U;
    msg[0U] = 0x38U;
    msg[sizeof(msg) - 1U] = 0xA3U;
    keygen(pk, sk, seed);

    res = (signer(signedmsg, &signedlen, msg, sizeof(msg), sk, qsctest_mldsa_boundary_rng) == true && signedlen == sigbytes + sizeof(msg)) && res;

    if (res == true)
    {
        res = (verifier(recovered, &recoveredlen, signedmsg, signedlen, pk) == true && recoveredlen == sizeof(msg) && qsc_intutils_are_equal8(recovered, msg, sizeof(msg))) && res;

        /* Inserting a byte at the signature/message boundary must fail. */
        qsc_memutils_copy(oversized, signedmsg, sigbytes);
        oversized[sigbytes] = 0xFFU;
        qsc_memutils_copy(oversized + sigbytes + 1U, signedmsg + sigbytes, sizeof(msg));
        res = (verifier(recovered, &recoveredlen, oversized, signedlen + 1U, pk) == false) && res;

        /* A truncated signed message must not authenticate. */
        res = (verifier(recovered, &recoveredlen, signedmsg, signedlen - 1U, pk) == false) && res;

        signedmsg[0U] ^= 0x01U;
        res = (verifier(recovered, &recoveredlen, signedmsg, signedlen, pk) == false) && res;
        signedmsg[0U] ^= 0x01U;

        originalhint = signedmsg[sigbytes - 1U];
        signedmsg[sigbytes - 1U] = 0xFFU;
        res = (verifier(recovered, &recoveredlen, signedmsg, signedlen, pk) == false) && res;
        signedmsg[sigbytes - 1U] = originalhint;

        signedmsg[sigbytes] ^= 0x01U;
        res = (verifier(recovered, &recoveredlen, signedmsg, signedlen, pk) == false) && res;
        signedmsg[sigbytes] ^= 0x01U;

        pk[0U] ^= 0x01U;
        res = (verifier(recovered, &recoveredlen, signedmsg, signedlen, pk) == false) && res;
        pk[0U] ^= 0x01U;

        res = (verifier_ex(recovered, &recoveredlen, context, sizeof(context), signedmsg, signedlen, pk) == false) && res;
    }

    qsc_memutils_secure_erase(sk, sizeof(sk));
    qsc_memutils_secure_erase(recovered, sizeof(recovered));
    qsc_memutils_secure_erase(signedmsg, sizeof(signedmsg));
    qsc_memutils_secure_erase(oversized, sizeof(oversized));

    return res;
}

/** \brief Qualify ML-DSA-44 strict signature framing and malformed verification inputs.
 * \return True if every signature format and negative verification case passes.
 */
bool qsctest_mldsa44_signature_format_test(void)
{
    bool res;

    res = qsctest_mldsa_signature_format_verify(QSC_MLDSA44_SIGNATURE_SIZE, qsc_mldsa44_seeded_generate_keypair, qsc_mldsa44_sign, qsc_mldsa44_verify, qsc_mldsa44_verify_ex);
    return res;
}

/** \brief Qualify ML-DSA-65 strict signature framing and malformed verification inputs.
 * \return True if every signature format and negative verification case passes.
 */
bool qsctest_mldsa65_signature_format_test(void)
{
    bool res;

    res = qsctest_mldsa_signature_format_verify(QSC_MLDSA65_SIGNATURE_SIZE, qsc_mldsa65_seeded_generate_keypair, qsc_mldsa65_sign, qsc_mldsa65_verify, qsc_mldsa65_verify_ex);
    return res;
}

/** \brief Qualify ML-DSA-87 strict signature framing and malformed verification inputs.
 * \return True if every signature format and negative verification case passes.
 */
bool qsctest_mldsa87_signature_format_test(void)
{
    bool res;

    res = qsctest_mldsa_signature_format_verify(QSC_MLDSA87_SIGNATURE_SIZE, qsc_mldsa87_seeded_generate_keypair, qsc_mldsa87_sign, qsc_mldsa87_verify, qsc_mldsa87_verify_ex);
    return res;
}
