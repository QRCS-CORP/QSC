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

#include "QSCFeatures.h"
#include "memutils.h"
#include "sha2.h"
#include "sha3.h"
#include "kyber768.h"
#include "kyber1024.h"
#include "mldsa.h"
#include "eddh25519.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if QSC_CMAKE_HAS_SHA2
/**
 * \brief Verify the SHA-256 known-answer vector for ASCII abc.
 * \return true if the resulting 32-byte digest matches the vector.
 * \note All inputs are owned by the test and no global state is changed.
 */
static bool qsc_cmake_sha256_kat(void)
{
	static const uint8_t message[3U] = { 0x61U, 0x62U, 0x63U };
	static const uint8_t expected[32U] = {
		0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU,
		0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
		0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU,
		0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU
	};
	uint8_t digest[32U] = { 0U };
	bool passed;

	qsc_sha256_compute(digest, message, sizeof(message));
	passed = qsc_memutils_are_equal(digest, expected, sizeof(expected));
	(void)printf("[%s] QSC-CMAKE-001 SHA-256 KAT\n", passed ? "PASS" : "FAIL");
	return passed;
}
#endif

#if QSC_CMAKE_HAS_SHA3
/**
 * \brief Verify the SHA3-256 known-answer vector for ASCII abc.
 * \return true if the resulting 32-byte digest matches the vector.
 * \note All inputs are owned by the test and no global state is changed.
 */
static bool qsc_cmake_sha3_kat(void)
{
	static const uint8_t message[3U] = { 0x61U, 0x62U, 0x63U };
	static const uint8_t expected[32U] = {
		0x3AU, 0x98U, 0x5DU, 0xA7U, 0x4FU, 0xE2U, 0x25U, 0xB2U,
		0x04U, 0x5CU, 0x17U, 0x2DU, 0x6BU, 0xD3U, 0x90U, 0xBDU,
		0x85U, 0x5FU, 0x08U, 0x6EU, 0x3EU, 0x9DU, 0x52U, 0x5BU,
		0x46U, 0xBFU, 0xE2U, 0x45U, 0x11U, 0x43U, 0x15U, 0x32U
	};
	uint8_t digest[32U] = { 0U };
	bool passed;

	qsc_sha3_compute256(digest, message, sizeof(message));
	passed = qsc_memutils_are_equal(digest, expected, sizeof(expected));
	(void)printf("[%s] QSC-CMAKE-002 SHA3-256 KAT\n", passed ? "PASS" : "FAIL");
	return passed;
}
#endif

#if QSC_CMAKE_HAS_KYBER768
/**
 * \brief Test deterministic ML-KEM-768 key establishment.
 * \return true if decapsulation reproduces the encapsulated shared secret.
 * \warning Fixed test seeds must never be used for real-world cryptographic keys.
 * \note All input/output buffers are caller-owned and erased when secret.
 */
static bool qsc_cmake_mlkem768_roundtrip(void)
{
	uint8_t pk[QSC_KYBER768_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_KYBER768_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_KYBER768_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss1[QSC_KYBER768_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ss2[QSC_KYBER768_SHAREDSECRET_SIZE] = { 0U };
	uint8_t d[QSC_KYBER768_SEED_SIZE] = { 0U };
	uint8_t z[QSC_KYBER768_SEED_SIZE] = { 0U };
	uint8_t m[QSC_KYBER768_SEED_SIZE] = { 0U };
	bool passed;

	d[0U] = 0x42U;
	z[0U] = 0x33U;
	m[0U] = 0x21U;
	qsc_kyber768_generate_seeded_keypair(pk, sk, d, z);
	qsc_kyber768_seeded_encapsulate(ss1, ct, pk, m);
	passed = qsc_kyber768_decapsulate(ss2, ct, sk);
	if (passed == true)
	{
		passed = qsc_memutils_are_equal(ss1, ss2, sizeof(ss1));
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ss1, sizeof(ss1));
	qsc_memutils_secure_erase(ss2, sizeof(ss2));
	(void)printf("[%s] QSC-CMAKE-003 ML-KEM-768 roundtrip\n", passed ? "PASS" : "FAIL");
	return passed;
}
#endif

#if QSC_CMAKE_HAS_KYBER1024
/**
 * \brief Test deterministic ML-KEM-1024 key establishment.
 * \return true if decapsulation reproduces the encapsulated shared secret.
 * \warning Fixed test seeds must never be used for real-world cryptographic keys.
 * \note All input/output buffers are caller-owned and erased when secret.
 */
static bool qsc_cmake_mlkem1024_roundtrip(void)
{
	uint8_t pk[QSC_KYBER1024_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_KYBER1024_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_KYBER1024_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss1[QSC_KYBER1024_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ss2[QSC_KYBER1024_SHAREDSECRET_SIZE] = { 0U };
	uint8_t d[QSC_KYBER1024_SEED_SIZE] = { 0U };
	uint8_t z[QSC_KYBER1024_SEED_SIZE] = { 0U };
	uint8_t m[QSC_KYBER1024_SEED_SIZE] = { 0U };
	bool passed;

	d[0U] = 0x53U;
	z[0U] = 0x47U;
	m[0U] = 0x29U;
	qsc_kyber1024_generate_seeded_keypair(pk, sk, d, z);
	qsc_kyber1024_seeded_encapsulate(ss1, ct, pk, m);
	passed = qsc_kyber1024_decapsulate(ss2, ct, sk);
	if (passed == true)
	{
		passed = qsc_memutils_are_equal(ss1, ss2, sizeof(ss1));
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ss1, sizeof(ss1));
	qsc_memutils_secure_erase(ss2, sizeof(ss2));
	(void)printf("[%s] QSC-CMAKE-004 ML-KEM-1024 roundtrip\n", passed ? "PASS" : "FAIL");
	return passed;
}
#endif

#if QSC_CMAKE_HAS_MLDSA65 || QSC_CMAKE_HAS_MLDSA87
/**
 * \brief Produce insecure deterministic bytes for integration testing only.
 * \param output Caller-owned byte array with length capacity.
 * \param length Number of bytes to generate.
 * \return true if output is nonnull; otherwise false.
 * \warning Never use this routine for production key generation or signing.
 * \note Stateless; reentrant and thread-safe.
 */
static bool qsc_cmake_test_rng(uint8_t* output, size_t length)
{
	bool passed;
	size_t i;

	passed = false;
	if (output != NULL)
	{
		for (i = 0U; i < length; ++i)
		{
			output[i] = (uint8_t)((i * 13U + 19U) & 0xFFU);
		}
		passed = true;
	}
	return passed;
}
#endif

#if QSC_CMAKE_HAS_MLDSA65
/**
 * \brief Check ML-DSA-65 sign and verify integration.
 * \return true if verification recovers the original message.
 * \note No shared state; test-only deterministic signing randomness.
 */
static bool qsc_cmake_mldsa65_sign_verify(void)
{
	static const uint8_t msg[3U] = { 0x61U, 0x62U, 0x63U };
	uint8_t pk[QSC_MLDSA65_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_MLDSA65_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signed_message[QSC_MLDSA65_SIGNATURE_SIZE + sizeof(msg)] = { 0U };
	uint8_t recovered[sizeof(msg)] = { 0U };
	uint8_t seed[QSC_MLDSA_SEED_SIZE] = { 0U };
	size_t slen;
	size_t mlen;
	bool passed;

	seed[0U] = 0x77U;
	slen = 0U;
	mlen = 0U;
	qsc_mldsa65_seeded_generate_keypair(pk, sk, seed);
	passed = qsc_mldsa65_sign(signed_message, &slen, msg, sizeof(msg), sk, qsc_cmake_test_rng);
	if (passed == true)
	{
		passed = qsc_mldsa65_verify(recovered, &mlen, signed_message, slen, pk);
	}
	if (passed == true)
	{
		passed = (mlen == sizeof(msg)) && qsc_memutils_are_equal(recovered, msg, sizeof(msg));
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	(void)printf("[%s] QSC-CMAKE-005 ML-DSA-65 signing\n", passed ? "PASS" : "FAIL");
	return passed;
}
#endif

#if QSC_CMAKE_HAS_MLDSA87
/**
 * \brief Check ML-DSA-87 sign and verify integration.
 * \return true if verification recovers the original message.
 * \note No shared state; test-only deterministic signing randomness.
 */
static bool qsc_cmake_mldsa87_sign_verify(void)
{
	static const uint8_t msg[3U] = { 0x61U, 0x62U, 0x63U };
	uint8_t pk[QSC_MLDSA87_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_MLDSA87_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signed_message[QSC_MLDSA87_SIGNATURE_SIZE + sizeof(msg)] = { 0U };
	uint8_t recovered[sizeof(msg)] = { 0U };
	uint8_t seed[QSC_MLDSA_SEED_SIZE] = { 0U };
	size_t slen;
	size_t mlen;
	bool passed;

	seed[0U] = 0x88U;
	slen = 0U;
	mlen = 0U;
	qsc_mldsa87_seeded_generate_keypair(pk, sk, seed);
	passed = qsc_mldsa87_sign(signed_message, &slen, msg, sizeof(msg), sk, qsc_cmake_test_rng);
	if (passed == true)
	{
		passed = qsc_mldsa87_verify(recovered, &mlen, signed_message, slen, pk);
	}
	if (passed == true)
	{
		passed = (mlen == sizeof(msg)) && qsc_memutils_are_equal(recovered, msg, sizeof(msg));
	}
	qsc_memutils_secure_erase(sk, sizeof(sk));
	(void)printf("[%s] QSC-CMAKE-006 ML-DSA-87 signing\n", passed ? "PASS" : "FAIL");
	return passed;
}
#endif

#if QSC_CMAKE_HAS_X25519
/**
 * \brief Test deterministic two-party X25519 agreement.
 * \return true if both parties derive the same secret.
 * \note Seeds are fixed for test reproducibility; do not use in products.
 */
static bool qsc_cmake_x25519_agreement(void)
{
	uint8_t seed_a[QSC_X25519_SEED_SIZE] = { 0U };
	uint8_t seed_b[QSC_X25519_SEED_SIZE] = { 0U };
	uint8_t pk_a[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t pk_b[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk_a[QSC_X25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t sk_b[QSC_X25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ss_a[QSC_X25519_SECRET_SIZE] = { 0U };
	uint8_t ss_b[QSC_X25519_SECRET_SIZE] = { 0U };
	bool passed;

	seed_a[0U] = 0x27U;
	seed_b[0U] = 0x53U;
	qsc_x25519_generate_seeded_keypair(pk_a, sk_a, seed_a);
	qsc_x25519_generate_seeded_keypair(pk_b, sk_b, seed_b);
	passed = qsc_x25519_key_exchange(ss_a, pk_b, sk_a);
	if (passed == true)
	{
		passed = qsc_x25519_key_exchange(ss_b, pk_a, sk_b);
	}
	if (passed == true)
	{
		passed = qsc_memutils_are_equal(ss_a, ss_b, sizeof(ss_a));
	}
	qsc_memutils_secure_erase(sk_a, sizeof(sk_a));
	qsc_memutils_secure_erase(sk_b, sizeof(sk_b));
	qsc_memutils_secure_erase(ss_a, sizeof(ss_a));
	qsc_memutils_secure_erase(ss_b, sizeof(ss_b));
	(void)printf("[%s] QSC-CMAKE-007 X25519 agreement\n", passed ? "PASS" : "FAIL");
	return passed;
}
#endif

/**
 * \brief Run all enabled QSC profile tests sequentially.
 * \return 0 when all selected smoke checks pass, otherwise 1.
 * \note No interactive prompt; appropriate for CI use.
 */
int main(void)
{
	bool passed;

	passed = true;
	(void)printf("QSC CMake profile smoke tests: %s\n", QSC_CMAKE_PROFILE);
#if QSC_CMAKE_HAS_SHA2
	if (qsc_cmake_sha256_kat() == false)
	{
		passed = false;
	}
#endif
#if QSC_CMAKE_HAS_SHA3
	if (qsc_cmake_sha3_kat() == false)
	{
		passed = false;
	}
#endif
#if QSC_CMAKE_HAS_KYBER768
	if (qsc_cmake_mlkem768_roundtrip() == false)
	{
		passed = false;
	}
#endif
#if QSC_CMAKE_HAS_KYBER1024
	if (qsc_cmake_mlkem1024_roundtrip() == false)
	{
		passed = false;
	}
#endif
#if QSC_CMAKE_HAS_MLDSA65
	if (qsc_cmake_mldsa65_sign_verify() == false)
	{
		passed = false;
	}
#endif
#if QSC_CMAKE_HAS_MLDSA87
	if (qsc_cmake_mldsa87_sign_verify() == false)
	{
		passed = false;
	}
#endif
#if QSC_CMAKE_HAS_X25519
	if (qsc_cmake_x25519_agreement() == false)
	{
		passed = false;
	}
#endif
	(void)printf("[%s] QSC-CMAKE-SUMMARY\n", passed ? "PASS" : "FAIL");
	return passed == true ? 0 : 1;
}
