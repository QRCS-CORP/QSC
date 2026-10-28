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

#include "mceliece_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "consoleutils.h"
#include "csp.h"
#include "intutils.h"
#include "mceliece.h"
#include "mceliece_multi.h"
#include "memutils.h"

bool qsctest_mceliece_ciphertext_integrity()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t* pk;
	bool ret;

	ret = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL)
	{
		ret = true;
		qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
		qsctest_nistrng_prng_initialize(seed, NULL, 0);

		/* generate public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* derive a shared-secret key and creates a response (in: pk | out: ct and ssk2) */
		qsc_mceliece_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

		/* replace some ciphertext bytes with random values */
		if (qsc_csp_generate(ct, 8) == false)
		{
			qsctest_print_safe("Failure! mceliece ciphertext integrity: the random provider failed -MCT1 \n");
			ret = false;
		}

		/* Implicit rejection succeeds but derives a different shared secret. */
		if (qsc_mceliece_decapsulate(ssk1, ct, sk) != true)
		{
			qsctest_print_safe("Failure! mceliece ciphertext integrity: implicit-rejection decapsulation failed -MCT2 \n");
			ret = false;
		}

		/* fail if equal */
		if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! mceliece ciphertext integrity: message decrypted succesfully with altered cipher-text -MCT3 \n");
			ret = false;
		}

		qsc_memutils_aligned_free(pk);
	}

	return ret;
}

bool qsctest_mceliece_kat_test()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t kct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t ksk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kss[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t* kpk;
	uint8_t* pk;
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
	ret = false;

	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_PUBLICKEY_SIZE);
	kpk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL && kpk != NULL)
	{
#if defined(QSC_MCELIECE_S3N4608T96)
		char path[] = "NPQC/mceliece-460896.rsp";
#elif defined(QSC_MCELIECE_S5N6688T128)
		char path[] = "NPQC/mceliece-6688128.rsp";
#elif defined(QSC_MCELIECE_S6N6960T119)
		char path[] = "NPQC/mceliece-6960119.rsp";
#elif defined(QSC_MCELIECE_S7N8192T128)
		char path[] = "NPQC/mceliece-8192128.rsp";
#else
#	error The parameter set is invalid!
#endif

		ret = true;
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsc_intutils_clear8(kpk, QSC_MCELIECE_PUBLICKEY_SIZE);

		/* NIST PQC Round 3 KATs */
		parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen, ksk, &sklen, kct, &ctlen, kss, &sslen, 0);

		if (seedlen != QSCTEST_NIST_RNG_SEED_SIZE || pklen != QSC_MCELIECE_PUBLICKEY_SIZE || sklen != QSC_MCELIECE_PRIVATEKEY_SIZE || ctlen != QSC_MCELIECE_CIPHERTEXT_SIZE || sslen != QSC_MCELIECE_SHAREDSECRET_SIZE)
		{
			qsctest_print_line("FAIL McEliece legacy KAT: missing or incompatible ciphertext/key sizes for selected ISO profile.");
			ret = false;
		}

		qsctest_nistrng_prng_initialize(seed, NULL, 0);

		/* alice generates public and secret keys */
		if (!qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate))
		{
			qsctest_print_line("Failure! mceliece kat: key generation random generation failure! -MKT0");
			ret = false;
		}

		/* compare the public key to the expected output */
		if (qsc_intutils_are_equal8(pk, kpk, QSC_MCELIECE_PUBLICKEY_SIZE) != true)
		{
			qsctest_print_line("Failure! mceliece kat: public key does not match known answer! -MKT1");
			ret = false;
		}

		/* compare the secret key to the expected output */
		if (qsc_intutils_are_equal8(sk, ksk, QSC_MCELIECE_PRIVATEKEY_SIZE) != true)
		{
			qsctest_print_line("Failure! mceliece kat: private key does not match known answer! -MKT2");
			ret = false;
		}

		/* bob derives a shared-secret key and creates a response (in: pk | out: ct and ssk2) */
		if (!qsc_mceliece_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate))
		{
			qsctest_print_line("Failure! mceliece kat: encapsulation random generation failure! -MKT3");
			ret = false;
		}

		/* compare the cipher-text to the expected output */
		if (qsc_intutils_are_equal8(ct, kct, QSC_MCELIECE_CIPHERTEXT_SIZE) != true)
		{
			qsctest_print_line("Failure! mceliece kat: ciphertext does not match known answer -MKT4");
			ret = false;
		}

		/* alice uses bobs response to get the shared-secret key (in: ct, sk | out: ssk1) */
		if (qsc_mceliece_decapsulate(ssk1, ct, sk) != true)
		{
			qsctest_print_line("Failure! mceliece kat: decapsulation failure -MKT5");
			ret = false;
		}

		/* compare the two keys for equality */
		if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_line("Failure! mceliece kat: secret keys do not match -MKT6");
			ret = false;
		}

		/* compare the key to the expected output */
		if (qsc_intutils_are_equal8(ssk1, kss, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_line("Failure! mceliece kat: shared secret does not match the known answer -MKT7");
			ret = false;
		}

		qsc_memutils_aligned_free(kpk);
		qsc_memutils_aligned_free(pk);
	}

	return ret;
}

bool qsctest_mceliece_operations_test()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t* pk;
	bool ret;

	ret = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL)
	{
		ret = true;
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);

		/* generate public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* derive a shared-secret key and creates a response (in: pk | out: ct and ssk2) */
		qsc_mceliece_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

		/* decrypt the cipher-text */
		if (qsc_mceliece_decapsulate(ssk1, ct, sk) != true)
		{
			qsctest_print_safe("Failure! mceliece operations: decapsulation failure -MOT1 \n");
			ret = false;
		}

		/* compare the two keys for equality */
		if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_MCELIECE_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! mceliece operations: the two secret keys do not match -MOT2 \n");
			ret = false;
		}

		qsc_memutils_aligned_free(pk);
	}

	return ret;
}

bool qsctest_mceliece_publickey_integrity()
{
	uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_MCELIECE_SHAREDSECRET_SIZE] = { 0 };
	uint8_t* pk;
	bool ret;

	ret = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_PUBLICKEY_SIZE);

	if (pk != NULL)
	{
		ret = true;
		qsc_intutils_clear8(pk, QSC_MCELIECE_PUBLICKEY_SIZE);
		qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
		qsctest_nistrng_prng_initialize(seed, NULL, 0);

		/* generate public and secret keys */
		qsc_mceliece_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

		/* replace public key bytes with random values */
		if (qsc_csp_generate(pk, QSC_MCELIECE_PUBLICKEY_SIZE / 100) != true)
		{
			qsctest_print_safe("Failure! mceliece public-key: the random provider has failed -MPT1 \n");
			ret = false;
		}

		/* derive a shared-secret key and creates a response (in: pk | out: ct and ssk2) */
		qsc_mceliece_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

		/* The altered public key produces a different shared secret via implicit rejection. */
		if (qsc_mceliece_decapsulate(ssk1, ct, sk) != true)
		{
			qsctest_print_safe("Failure! mceliece public-key: implicit-rejection decapsulation failed -MPT2 \n");
			ret = false;
		}

		/* fail if output keys are equal */
		if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_MCELIECE_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! mceliece public-key: the two secret keys match with an altered public key -MPT3 \n");
			ret = false;
		}

		qsc_memutils_aligned_free(pk);
	}

	return ret;
}

/**
 * \brief Negative-test RNG that deterministically reports generation failure.
 * \param output: Unmodified caller-owned output buffer.
 * \param length: Requested number of random bytes; no bytes are written.
 * \return False for every invocation.
 * \note Stateless, reentrant, and thread-safe. Only for failure tests.
 */
static bool qsctest_mceliece_rng_failure(uint8_t* output, size_t length)
{
	(void)output;
	(void)length;

	return false;
}

/**
 * \brief Checks the 32-of-64 pivot mask in a semi-systematic private key.
 * \param privatekey: Input private key of at least 40 bytes.
 * \return True when the little-endian 64-bit mask has exactly 32 set bits.
 * \note Caller owns the key. Reentrant and free of shared mutable state.
 */
static bool qsctest_mceliece_pivots_valid(const uint8_t* privatekey)
{
	uint32_t count;
	size_t i;
	size_t j;

	count = 0U;

	for (i = 32U; i < 40U; ++i)
	{
		for (j = 0U; j < 8U; ++j)
		{
			count += (uint32_t)((privatekey[i] >> j) & 1U);
		}
	}

	return (count == 32U);
}

/**
 * \brief Independently qualifies 460896pc roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_460896pc_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_460896PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_460896PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 460896pc: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_460896pc_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pc: key generation.");
		}
		else if (qsc_mceliece_460896pc_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pc: encapsulation.");
		}
		else if (qsc_mceliece_460896pc_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pc: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pc: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_460896pc_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 460896pc: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 460896pc: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_460896pc_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null RNG accepted.");
			}
			else if (qsc_mceliece_460896pc_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_460896pc_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null ciphertext accepted.");
			}
			else if (qsc_mceliece_460896pc_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null private key accepted.");
			}
			else if (qsc_mceliece_460896pc_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_460896pc_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_460896pc_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null public key accepted.");
			}
			else if (qsc_mceliece_460896pc_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null keygen public key accepted.");
			}
			else if (qsc_mceliece_460896pc_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null keygen private key accepted.");
			}
			else if (qsc_mceliece_460896pc_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_460896pc_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: failing RNG accepted.");
			}
			else if (qsc_mceliece_460896pc_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pc: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 6688128pc roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6688128pc_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6688128PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6688128PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6688128pc: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6688128pc_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pc: key generation.");
		}
		else if (qsc_mceliece_6688128pc_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pc: encapsulation.");
		}
		else if (qsc_mceliece_6688128pc_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pc: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pc: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6688128pc_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_6688128pc_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null RNG accepted.");
			}
			else if (qsc_mceliece_6688128pc_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6688128pc_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128pc_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null private key accepted.");
			}
			else if (qsc_mceliece_6688128pc_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6688128pc_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128pc_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null public key accepted.");
			}
			else if (qsc_mceliece_6688128pc_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6688128pc_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6688128pc_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6688128pc_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: failing RNG accepted.");
			}
			else if (qsc_mceliece_6688128pc_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 6960119pc roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6960119pc_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6960119PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6960119pc: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6960119pc_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pc: key generation.");
		}
		else if (qsc_mceliece_6960119pc_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pc: encapsulation.");
		}
		else if (qsc_mceliece_6960119pc_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pc: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pc: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6960119pc_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_6960119pc_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null RNG accepted.");
			}
			else if (qsc_mceliece_6960119pc_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6960119pc_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119pc_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null private key accepted.");
			}
			else if (qsc_mceliece_6960119pc_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6960119pc_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119pc_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null public key accepted.");
			}
			else if (qsc_mceliece_6960119pc_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6960119pc_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6960119pc_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6960119pc_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: failing RNG accepted.");
			}
			else if (qsc_mceliece_6960119pc_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc: key generation accepted failing RNG.");
			}
			else
			{
				ct[QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE - 33U] |= 0x80U;

				if (qsc_mceliece_6960119pc_decapsulate(ssc, ct, sk) != false)
				{
					qsctest_print_line("FAIL McEliece 6960119pc: nonzero syndrome padding accepted.");
				}
				else
				{
					res = true;
				}
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 8192128pc roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_8192128pc_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_8192128PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_8192128PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 8192128pc: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_8192128pc_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pc: key generation.");
		}
		else if (qsc_mceliece_8192128pc_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pc: encapsulation.");
		}
		else if (qsc_mceliece_8192128pc_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pc: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pc: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_8192128pc_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_8192128pc_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null RNG accepted.");
			}
			else if (qsc_mceliece_8192128pc_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_8192128pc_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128pc_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null private key accepted.");
			}
			else if (qsc_mceliece_8192128pc_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_8192128pc_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128pc_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null public key accepted.");
			}
			else if (qsc_mceliece_8192128pc_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null keygen public key accepted.");
			}
			else if (qsc_mceliece_8192128pc_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null keygen private key accepted.");
			}
			else if (qsc_mceliece_8192128pc_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_8192128pc_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: failing RNG accepted.");
			}
			else if (qsc_mceliece_8192128pc_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 460896 roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_460896_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_460896_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_460896_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_460896_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_460896_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_460896_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 460896: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_460896_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896: key generation.");
		}
		else if (qsc_mceliece_460896_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896: encapsulation.");
		}
		else if (qsc_mceliece_460896_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 460896: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 460896: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_460896_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 460896: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 460896: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_460896_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null RNG accepted.");
			}
			else if (qsc_mceliece_460896_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_460896_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null ciphertext accepted.");
			}
			else if (qsc_mceliece_460896_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null private key accepted.");
			}
			else if (qsc_mceliece_460896_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_460896_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_460896_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null public key accepted.");
			}
			else if (qsc_mceliece_460896_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null keygen public key accepted.");
			}
			else if (qsc_mceliece_460896_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null keygen private key accepted.");
			}
			else if (qsc_mceliece_460896_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_460896_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: failing RNG accepted.");
			}
			else if (qsc_mceliece_460896_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_460896_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 6688128 roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6688128_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6688128_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6688128_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6688128_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6688128_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6688128_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6688128: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6688128_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128: key generation.");
		}
		else if (qsc_mceliece_6688128_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128: encapsulation.");
		}
		else if (qsc_mceliece_6688128_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6688128_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6688128: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6688128: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_6688128_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null RNG accepted.");
			}
			else if (qsc_mceliece_6688128_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6688128_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null private key accepted.");
			}
			else if (qsc_mceliece_6688128_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6688128_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null public key accepted.");
			}
			else if (qsc_mceliece_6688128_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6688128_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6688128_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6688128_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: failing RNG accepted.");
			}
			else if (qsc_mceliece_6688128_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6688128_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 6960119 roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6960119_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6960119_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6960119_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6960119_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6960119_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6960119_SHAREDSECRET_SIZE] = { 0U };
	uint8_t guarded[QSC_MCELIECE_6960119_CIPHERTEXT_SIZE + 32U] = { 0U };
	size_t i;
	bool intact;
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6960119: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6960119_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119: key generation.");
		}
		else if (qsc_mceliece_6960119_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119: encapsulation.");
		}
		else if (qsc_mceliece_6960119_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6960119_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6960119: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6960119: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_6960119_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null RNG accepted.");
			}
			else if (qsc_mceliece_6960119_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6960119_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null private key accepted.");
			}
			else if (qsc_mceliece_6960119_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6960119_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null public key accepted.");
			}
			else if (qsc_mceliece_6960119_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6960119_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6960119_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6960119_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: failing RNG accepted.");
			}
			else if (qsc_mceliece_6960119_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119: key generation accepted failing RNG.");
			}
			else
			{
				ct[QSC_MCELIECE_6960119_CIPHERTEXT_SIZE - 1U] |= 0x80U;

				if (qsc_mceliece_6960119_decapsulate(ssc, ct, sk) != false)
				{
					qsctest_print_line("FAIL McEliece 6960119: nonzero syndrome padding accepted.");
				}
				else
				{
					for (i = QSC_MCELIECE_6960119_CIPHERTEXT_SIZE; i < sizeof(guarded); ++i)
					{
						guarded[i] = 0xA5U;
					}

					pk[QSC_MCELIECE_6960119_PUBLICKEY_SIZE - 1U] |= 0x80U;

					if (qsc_mceliece_6960119_encapsulate(ssb, guarded, pk, qsc_csp_generate) != false)
					{
						qsctest_print_line("FAIL McEliece 6960119: invalid public-key padding accepted.");
					}
					else
					{
						intact = true;

						for (i = QSC_MCELIECE_6960119_CIPHERTEXT_SIZE; i < sizeof(guarded); ++i)
						{
							if (guarded[i] != 0xA5U)
							{
								intact = false;
							}
						}

						if (intact == false)
						{
							qsctest_print_line("FAIL McEliece 6960119: ciphertext buffer overrun.");
						}
						else
						{
							res = true;
						}
					}
				}
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6960119_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));
	qsc_memutils_secure_erase(guarded, sizeof(guarded));

	return res;
}

/**
 * \brief Independently qualifies 8192128 roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_8192128_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_8192128_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_8192128_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_8192128_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_8192128_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_8192128_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 8192128: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_8192128_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128: key generation.");
		}
		else if (qsc_mceliece_8192128_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128: encapsulation.");
		}
		else if (qsc_mceliece_8192128_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_8192128_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 8192128: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 8192128: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_8192128_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null RNG accepted.");
			}
			else if (qsc_mceliece_8192128_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_8192128_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null private key accepted.");
			}
			else if (qsc_mceliece_8192128_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_8192128_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null public key accepted.");
			}
			else if (qsc_mceliece_8192128_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null keygen public key accepted.");
			}
			else if (qsc_mceliece_8192128_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null keygen private key accepted.");
			}
			else if (qsc_mceliece_8192128_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_8192128_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: failing RNG accepted.");
			}
			else if (qsc_mceliece_8192128_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_8192128_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 460896f roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_460896f_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_460896F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_460896F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_460896F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_460896F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_460896F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896F_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 460896f: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_460896f_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896f: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 460896f: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_460896f_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896f: encapsulation.");
		}
		else if (qsc_mceliece_460896f_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 460896f: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 460896f: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_460896f_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 460896f: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 460896f: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_460896f_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null RNG accepted.");
			}
			else if (qsc_mceliece_460896f_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_460896f_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null ciphertext accepted.");
			}
			else if (qsc_mceliece_460896f_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null private key accepted.");
			}
			else if (qsc_mceliece_460896f_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_460896f_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_460896f_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null public key accepted.");
			}
			else if (qsc_mceliece_460896f_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null keygen public key accepted.");
			}
			else if (qsc_mceliece_460896f_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null keygen private key accepted.");
			}
			else if (qsc_mceliece_460896f_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_460896f_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: failing RNG accepted.");
			}
			else if (qsc_mceliece_460896f_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896f: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_460896F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 460896pcf roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_460896pcf_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_460896PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_460896PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 460896pcf: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_460896pcf_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pcf: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pcf: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_460896pcf_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pcf: encapsulation.");
		}
		else if (qsc_mceliece_460896pcf_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pcf: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 460896pcf: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_460896pcf_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_460896pcf_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null RNG accepted.");
			}
			else if (qsc_mceliece_460896pcf_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_460896pcf_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null ciphertext accepted.");
			}
			else if (qsc_mceliece_460896pcf_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null private key accepted.");
			}
			else if (qsc_mceliece_460896pcf_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_460896pcf_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_460896pcf_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null public key accepted.");
			}
			else if (qsc_mceliece_460896pcf_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null keygen public key accepted.");
			}
			else if (qsc_mceliece_460896pcf_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null keygen private key accepted.");
			}
			else if (qsc_mceliece_460896pcf_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_460896pcf_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: failing RNG accepted.");
			}
			else if (qsc_mceliece_460896pcf_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 460896pcf: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 6688128f roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6688128f_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6688128F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6688128F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128F_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6688128f: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6688128f_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128f: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128f: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_6688128f_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128f: encapsulation.");
		}
		else if (qsc_mceliece_6688128f_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128f: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128f: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6688128f_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6688128f: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6688128f: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_6688128f_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null RNG accepted.");
			}
			else if (qsc_mceliece_6688128f_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6688128f_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128f_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null private key accepted.");
			}
			else if (qsc_mceliece_6688128f_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6688128f_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128f_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null public key accepted.");
			}
			else if (qsc_mceliece_6688128f_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6688128f_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6688128f_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6688128f_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: failing RNG accepted.");
			}
			else if (qsc_mceliece_6688128f_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128f: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6688128F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 6688128pcf roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6688128pcf_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6688128PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6688128PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6688128pcf: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6688128pcf_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pcf: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pcf: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_6688128pcf_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pcf: encapsulation.");
		}
		else if (qsc_mceliece_6688128pcf_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pcf: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6688128pcf: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6688128pcf_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_6688128pcf_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null RNG accepted.");
			}
			else if (qsc_mceliece_6688128pcf_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6688128pcf_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128pcf_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null private key accepted.");
			}
			else if (qsc_mceliece_6688128pcf_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6688128pcf_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6688128pcf_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null public key accepted.");
			}
			else if (qsc_mceliece_6688128pcf_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6688128pcf_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6688128pcf_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6688128pcf_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: failing RNG accepted.");
			}
			else if (qsc_mceliece_6688128pcf_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6688128pcf: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 6960119f roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6960119f_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6960119F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t guarded[QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE + 32U] = { 0U };
	size_t i;
	bool intact;
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119F_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6960119f: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6960119f_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119f: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119f: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_6960119f_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119f: encapsulation.");
		}
		else if (qsc_mceliece_6960119f_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119f: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119f: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6960119f_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6960119f: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6960119f: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_6960119f_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null RNG accepted.");
			}
			else if (qsc_mceliece_6960119f_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6960119f_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119f_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null private key accepted.");
			}
			else if (qsc_mceliece_6960119f_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6960119f_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119f_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null public key accepted.");
			}
			else if (qsc_mceliece_6960119f_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6960119f_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6960119f_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6960119f_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: failing RNG accepted.");
			}
			else if (qsc_mceliece_6960119f_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119f: key generation accepted failing RNG.");
			}
			else
			{
				ct[QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE - 1U] |= 0x80U;

				if (qsc_mceliece_6960119f_decapsulate(ssc, ct, sk) != false)
				{
					qsctest_print_line("FAIL McEliece 6960119f: nonzero syndrome padding accepted.");
				}
				else
				{
					for (i = QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE; i < sizeof(guarded); ++i)
					{
						guarded[i] = 0xA5U;
					}

					pk[QSC_MCELIECE_6960119F_PUBLICKEY_SIZE - 1U] |= 0x80U;

					if (qsc_mceliece_6960119f_encapsulate(ssb, guarded, pk, qsc_csp_generate) != false)
					{
						qsctest_print_line("FAIL McEliece 6960119f: invalid public-key padding accepted.");
					}
					else
					{
						intact = true;

						for (i = QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE; i < sizeof(guarded); ++i)
						{
							if (guarded[i] != 0xA5U)
							{
								intact = false;
							}
						}

						if (intact == false)
						{
							qsctest_print_line("FAIL McEliece 6960119f: ciphertext buffer overrun.");
						}
						else
						{
							res = true;
						}
					}
				}
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6960119F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));
	qsc_memutils_secure_erase(guarded, sizeof(guarded));

	return res;
}

/**
 * \brief Independently qualifies 6960119pcf roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_6960119pcf_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_6960119PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6960119PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6960119pcf: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_6960119pcf_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pcf: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pcf: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_6960119pcf_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pcf: encapsulation.");
		}
		else if (qsc_mceliece_6960119pcf_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pcf: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 6960119pcf: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_6960119pcf_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_6960119pcf_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null RNG accepted.");
			}
			else if (qsc_mceliece_6960119pcf_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_6960119pcf_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119pcf_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null private key accepted.");
			}
			else if (qsc_mceliece_6960119pcf_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_6960119pcf_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_6960119pcf_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null public key accepted.");
			}
			else if (qsc_mceliece_6960119pcf_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null keygen public key accepted.");
			}
			else if (qsc_mceliece_6960119pcf_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null keygen private key accepted.");
			}
			else if (qsc_mceliece_6960119pcf_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_6960119pcf_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: failing RNG accepted.");
			}
			else if (qsc_mceliece_6960119pcf_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 6960119pcf: key generation accepted failing RNG.");
			}
			else
			{
				ct[QSC_MCELIECE_6960119PCF_CIPHERTEXT_SIZE - 33U] |= 0x80U;

				if (qsc_mceliece_6960119pcf_decapsulate(ssc, ct, sk) != false)
				{
					qsctest_print_line("FAIL McEliece 6960119pcf: nonzero syndrome padding accepted.");
				}
				else
				{
					res = true;
				}
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 8192128f roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_8192128f_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_8192128F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_8192128F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128F_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 8192128f: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_8192128f_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128f: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128f: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_8192128f_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128f: encapsulation.");
		}
		else if (qsc_mceliece_8192128f_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128f: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128f: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_8192128f_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 8192128f: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 8192128f: tampered ciphertext retained the session key.");
			}
			else if (qsc_mceliece_8192128f_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null RNG accepted.");
			}
			else if (qsc_mceliece_8192128f_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_8192128f_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128f_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null private key accepted.");
			}
			else if (qsc_mceliece_8192128f_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_8192128f_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128f_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null public key accepted.");
			}
			else if (qsc_mceliece_8192128f_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null keygen public key accepted.");
			}
			else if (qsc_mceliece_8192128f_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null keygen private key accepted.");
			}
			else if (qsc_mceliece_8192128f_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_8192128f_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: failing RNG accepted.");
			}
			else if (qsc_mceliece_8192128f_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128f: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_8192128F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Independently qualifies 8192128pcf roundtrip and tamper semantics.
 * \return True on success, otherwise false with a distinct diagnostic.
 * \note Allocations are local and released before returning. Serial invocation.
 */
bool qsctest_mceliece_8192128pcf_roundtrip(void)
{
	uint8_t ct[QSC_MCELIECE_8192128PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_8192128PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ssa[QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssb[QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ssc[QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE);

	if (pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 8192128pcf: public key allocation.");
	}
	else
	{
		if (qsc_mceliece_8192128pcf_generate_keypair(pk, sk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pcf: key generation.");
		}
		else if (qsctest_mceliece_pivots_valid(sk) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pcf: invalid semi-systematic pivot mask.");
		}
		else if (qsc_mceliece_8192128pcf_encapsulate(ssa, ct, pk, qsc_csp_generate) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pcf: encapsulation.");
		}
		else if (qsc_mceliece_8192128pcf_decapsulate(ssb, ct, sk) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pcf: decapsulation.");
		}
		else if (qsc_intutils_are_equal8(ssa, ssb, sizeof(ssa)) != true)
		{
			qsctest_print_line("FAIL McEliece 8192128pcf: shared secrets differ.");
		}
		else
		{
			ct[sizeof(ct) - 1U] ^= 1U;

			if (qsc_mceliece_8192128pcf_decapsulate(ssc, ct, sk) != true)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: rejection decapsulation.");
			}
			else if (qsc_intutils_are_equal8(ssa, ssc, sizeof(ssa)) == true)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: confirmation tampering accepted.");
			}
			else if (qsc_mceliece_8192128pcf_encapsulate(ssb, ct, pk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null RNG accepted.");
			}
			else if (qsc_mceliece_8192128pcf_decapsulate(NULL, ct, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null decapsulation output accepted.");
			}
			else if (qsc_mceliece_8192128pcf_decapsulate(ssc, NULL, sk) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128pcf_decapsulate(ssc, ct, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null private key accepted.");
			}
			else if (qsc_mceliece_8192128pcf_encapsulate(NULL, ct, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null encapsulation secret accepted.");
			}
			else if (qsc_mceliece_8192128pcf_encapsulate(ssb, NULL, pk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null encapsulation ciphertext accepted.");
			}
			else if (qsc_mceliece_8192128pcf_encapsulate(ssb, ct, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null public key accepted.");
			}
			else if (qsc_mceliece_8192128pcf_generate_keypair(NULL, sk, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null keygen public key accepted.");
			}
			else if (qsc_mceliece_8192128pcf_generate_keypair(pk, NULL, qsc_csp_generate) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null keygen private key accepted.");
			}
			else if (qsc_mceliece_8192128pcf_generate_keypair(pk, sk, NULL) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: null keygen RNG accepted.");
			}
			else if (qsc_mceliece_8192128pcf_encapsulate(ssb, ct, pk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: failing RNG accepted.");
			}
			else if (qsc_mceliece_8192128pcf_generate_keypair(pk, sk, qsctest_mceliece_rng_failure) != false)
			{
				qsctest_print_line("FAIL McEliece 8192128pcf: key generation accepted failing RNG.");
			}
			else
			{
				res = true;
			}
		}

		qsc_memutils_secure_erase(pk, QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(ssa, sizeof(ssa));
	qsc_memutils_secure_erase(ssb, sizeof(ssb));
	qsc_memutils_secure_erase(ssc, sizeof(ssc));

	return res;
}

/**
 * \brief Tests deterministic ISO 460896f/460896pcf key generation and KEM framing.
 * \return True if keypairs, syndromes and both decapsulated secrets are correct.
 * \note Uses global NIST test RNG sequentially. Caller owns all buffers.
 */
bool qsctest_mceliece_460896_framing(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_460896F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ctpc[QSC_MCELIECE_460896PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_460896F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skpc[QSC_MCELIECE_460896PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_460896F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t sspc[QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_460896F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recoveredpc[QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* pkpc;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896F_PUBLICKEY_SIZE);
	pkpc = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE);

	if (pk == NULL || pkpc == NULL)
	{
		qsctest_print_line("FAIL McEliece 460896f/pcf: allocation.");
	}
	else
	{
		qsctest_nistrng_prng_initialize(seed, NULL, 0U);

		if (qsc_mceliece_460896f_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
		{
			qsctest_print_line("FAIL McEliece 460896f/pcf: f key generation.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_460896pcf_generate_keypair(pkpc, skpc, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 460896f/pcf: pcf key generation.");
			}
			else if (qsc_intutils_are_equal8(pk, pkpc, QSC_MCELIECE_460896F_PUBLICKEY_SIZE) == false)
			{
				qsctest_print_line("FAIL McEliece 460896f/pcf: public keys differ.");
			}
			else if (qsc_intutils_are_equal8(sk, skpc, sizeof(sk)) == false)
			{
				qsctest_print_line("FAIL McEliece 460896f/pcf: secret keys differ.");
			}
			else
			{
				qsctest_nistrng_prng_initialize(seed, NULL, 0U);

				if (qsc_mceliece_460896f_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
				{
					qsctest_print_line("FAIL McEliece 460896f/pcf: f encapsulation.");
				}
				else
				{
					qsctest_nistrng_prng_initialize(seed, NULL, 0U);

					if (qsc_mceliece_460896pcf_encapsulate(sspc, ctpc, pkpc, qsctest_nistrng_prng_generate) == false)
					{
						qsctest_print_line("FAIL McEliece 460896f/pcf: pcf encapsulation.");
					}
					else if (qsc_intutils_are_equal8(ct, ctpc, sizeof(ct)) == false)
					{
						qsctest_print_line("FAIL McEliece 460896f/pcf: ciphertext syndromes differ.");
					}
					else if (qsc_intutils_are_equal8(ss, sspc, sizeof(ss)) == true)
					{
						qsctest_print_line("FAIL McEliece 460896f/pcf: keys lack domain separation.");
					}
					else if (qsc_mceliece_460896f_decapsulate(recovered, ct, sk) == false)
					{
						qsctest_print_line("FAIL McEliece 460896f/pcf: f decapsulation.");
					}
					else if (qsc_mceliece_460896pcf_decapsulate(recoveredpc, ctpc, skpc) == false)
					{
						qsctest_print_line("FAIL McEliece 460896f/pcf: pcf decapsulation.");
					}
					else if (qsc_intutils_are_equal8(ss, recovered, sizeof(ss)) == false)
					{
						qsctest_print_line("FAIL McEliece 460896f/pcf: f secret mismatch.");
					}
					else if (qsc_intutils_are_equal8(sspc, recoveredpc, sizeof(sspc)) == false)
					{
						qsctest_print_line("FAIL McEliece 460896f/pcf: pcf secret mismatch.");
					}
					else
					{
						res = true;
					}
				}
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_460896F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (pkpc != NULL)
	{
		qsc_memutils_secure_erase(pkpc, QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pkpc);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(skpc, sizeof(skpc));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(sspc, sizeof(sspc));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));
	qsc_memutils_secure_erase(recoveredpc, sizeof(recoveredpc));

	return res;
}

/**
 * \brief Tests deterministic ISO 6688128f/6688128pcf key generation and KEM framing.
 * \return True if keypairs, syndromes and both decapsulated secrets are correct.
 * \note Uses global NIST test RNG sequentially. Caller owns all buffers.
 */
bool qsctest_mceliece_6688128_framing(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_6688128F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ctpc[QSC_MCELIECE_6688128PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6688128F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skpc[QSC_MCELIECE_6688128PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t sspc[QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recoveredpc[QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* pkpc;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128F_PUBLICKEY_SIZE);
	pkpc = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE);

	if (pk == NULL || pkpc == NULL)
	{
		qsctest_print_line("FAIL McEliece 6688128f/pcf: allocation.");
	}
	else
	{
		qsctest_nistrng_prng_initialize(seed, NULL, 0U);

		if (qsc_mceliece_6688128f_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
		{
			qsctest_print_line("FAIL McEliece 6688128f/pcf: f key generation.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_6688128pcf_generate_keypair(pkpc, skpc, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128f/pcf: pcf key generation.");
			}
			else if (qsc_intutils_are_equal8(pk, pkpc, QSC_MCELIECE_6688128F_PUBLICKEY_SIZE) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128f/pcf: public keys differ.");
			}
			else if (qsc_intutils_are_equal8(sk, skpc, sizeof(sk)) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128f/pcf: secret keys differ.");
			}
			else
			{
				qsctest_nistrng_prng_initialize(seed, NULL, 0U);

				if (qsc_mceliece_6688128f_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
				{
					qsctest_print_line("FAIL McEliece 6688128f/pcf: f encapsulation.");
				}
				else
				{
					qsctest_nistrng_prng_initialize(seed, NULL, 0U);

					if (qsc_mceliece_6688128pcf_encapsulate(sspc, ctpc, pkpc, qsctest_nistrng_prng_generate) == false)
					{
						qsctest_print_line("FAIL McEliece 6688128f/pcf: pcf encapsulation.");
					}
					else if (qsc_intutils_are_equal8(ct, ctpc, sizeof(ct)) == false)
					{
						qsctest_print_line("FAIL McEliece 6688128f/pcf: ciphertext syndromes differ.");
					}
					else if (qsc_intutils_are_equal8(ss, sspc, sizeof(ss)) == true)
					{
						qsctest_print_line("FAIL McEliece 6688128f/pcf: keys lack domain separation.");
					}
					else if (qsc_mceliece_6688128f_decapsulate(recovered, ct, sk) == false)
					{
						qsctest_print_line("FAIL McEliece 6688128f/pcf: f decapsulation.");
					}
					else if (qsc_mceliece_6688128pcf_decapsulate(recoveredpc, ctpc, skpc) == false)
					{
						qsctest_print_line("FAIL McEliece 6688128f/pcf: pcf decapsulation.");
					}
					else if (qsc_intutils_are_equal8(ss, recovered, sizeof(ss)) == false)
					{
						qsctest_print_line("FAIL McEliece 6688128f/pcf: f secret mismatch.");
					}
					else if (qsc_intutils_are_equal8(sspc, recoveredpc, sizeof(sspc)) == false)
					{
						qsctest_print_line("FAIL McEliece 6688128f/pcf: pcf secret mismatch.");
					}
					else
					{
						res = true;
					}
				}
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6688128F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (pkpc != NULL)
	{
		qsc_memutils_secure_erase(pkpc, QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pkpc);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(skpc, sizeof(skpc));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(sspc, sizeof(sspc));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));
	qsc_memutils_secure_erase(recoveredpc, sizeof(recoveredpc));

	return res;
}

/**
 * \brief Tests deterministic ISO 6960119f/6960119pcf key generation and KEM framing.
 * \return True if keypairs, syndromes and both decapsulated secrets are correct.
 * \note Uses global NIST test RNG sequentially. Caller owns all buffers.
 */
bool qsctest_mceliece_6960119_framing(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ctpc[QSC_MCELIECE_6960119PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6960119F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skpc[QSC_MCELIECE_6960119PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t sspc[QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recoveredpc[QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* pkpc;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119F_PUBLICKEY_SIZE);
	pkpc = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE);

	if (pk == NULL || pkpc == NULL)
	{
		qsctest_print_line("FAIL McEliece 6960119f/pcf: allocation.");
	}
	else
	{
		qsctest_nistrng_prng_initialize(seed, NULL, 0U);

		if (qsc_mceliece_6960119f_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
		{
			qsctest_print_line("FAIL McEliece 6960119f/pcf: f key generation.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_6960119pcf_generate_keypair(pkpc, skpc, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119f/pcf: pcf key generation.");
			}
			else if (qsc_intutils_are_equal8(pk, pkpc, QSC_MCELIECE_6960119F_PUBLICKEY_SIZE) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119f/pcf: public keys differ.");
			}
			else if (qsc_intutils_are_equal8(sk, skpc, sizeof(sk)) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119f/pcf: secret keys differ.");
			}
			else
			{
				qsctest_nistrng_prng_initialize(seed, NULL, 0U);

				if (qsc_mceliece_6960119f_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
				{
					qsctest_print_line("FAIL McEliece 6960119f/pcf: f encapsulation.");
				}
				else
				{
					qsctest_nistrng_prng_initialize(seed, NULL, 0U);

					if (qsc_mceliece_6960119pcf_encapsulate(sspc, ctpc, pkpc, qsctest_nistrng_prng_generate) == false)
					{
						qsctest_print_line("FAIL McEliece 6960119f/pcf: pcf encapsulation.");
					}
					else if (qsc_intutils_are_equal8(ct, ctpc, sizeof(ct)) == false)
					{
						qsctest_print_line("FAIL McEliece 6960119f/pcf: ciphertext syndromes differ.");
					}
					else if (qsc_intutils_are_equal8(ss, sspc, sizeof(ss)) == true)
					{
						qsctest_print_line("FAIL McEliece 6960119f/pcf: keys lack domain separation.");
					}
					else if (qsc_mceliece_6960119f_decapsulate(recovered, ct, sk) == false)
					{
						qsctest_print_line("FAIL McEliece 6960119f/pcf: f decapsulation.");
					}
					else if (qsc_mceliece_6960119pcf_decapsulate(recoveredpc, ctpc, skpc) == false)
					{
						qsctest_print_line("FAIL McEliece 6960119f/pcf: pcf decapsulation.");
					}
					else if (qsc_intutils_are_equal8(ss, recovered, sizeof(ss)) == false)
					{
						qsctest_print_line("FAIL McEliece 6960119f/pcf: f secret mismatch.");
					}
					else if (qsc_intutils_are_equal8(sspc, recoveredpc, sizeof(sspc)) == false)
					{
						qsctest_print_line("FAIL McEliece 6960119f/pcf: pcf secret mismatch.");
					}
					else
					{
						res = true;
					}
				}
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6960119F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (pkpc != NULL)
	{
		qsc_memutils_secure_erase(pkpc, QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pkpc);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(skpc, sizeof(skpc));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(sspc, sizeof(sspc));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));
	qsc_memutils_secure_erase(recoveredpc, sizeof(recoveredpc));

	return res;
}

/**
 * \brief Tests deterministic ISO 8192128f/8192128pcf key generation and KEM framing.
 * \return True if keypairs, syndromes and both decapsulated secrets are correct.
 * \note Uses global NIST test RNG sequentially. Caller owns all buffers.
 */
bool qsctest_mceliece_8192128_framing(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_8192128F_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ctpc[QSC_MCELIECE_8192128PCF_CIPHERTEXT_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_8192128F_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skpc[QSC_MCELIECE_8192128PCF_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t sspc[QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recoveredpc[QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* pkpc;
	bool res;

	res = false;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128F_PUBLICKEY_SIZE);
	pkpc = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE);

	if (pk == NULL || pkpc == NULL)
	{
		qsctest_print_line("FAIL McEliece 8192128f/pcf: allocation.");
	}
	else
	{
		qsctest_nistrng_prng_initialize(seed, NULL, 0U);

		if (qsc_mceliece_8192128f_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
		{
			qsctest_print_line("FAIL McEliece 8192128f/pcf: f key generation.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_8192128pcf_generate_keypair(pkpc, skpc, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128f/pcf: pcf key generation.");
			}
			else if (qsc_intutils_are_equal8(pk, pkpc, QSC_MCELIECE_8192128F_PUBLICKEY_SIZE) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128f/pcf: public keys differ.");
			}
			else if (qsc_intutils_are_equal8(sk, skpc, sizeof(sk)) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128f/pcf: secret keys differ.");
			}
			else
			{
				qsctest_nistrng_prng_initialize(seed, NULL, 0U);

				if (qsc_mceliece_8192128f_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
				{
					qsctest_print_line("FAIL McEliece 8192128f/pcf: f encapsulation.");
				}
				else
				{
					qsctest_nistrng_prng_initialize(seed, NULL, 0U);

					if (qsc_mceliece_8192128pcf_encapsulate(sspc, ctpc, pkpc, qsctest_nistrng_prng_generate) == false)
					{
						qsctest_print_line("FAIL McEliece 8192128f/pcf: pcf encapsulation.");
					}
					else if (qsc_intutils_are_equal8(ct, ctpc, sizeof(ct)) == false)
					{
						qsctest_print_line("FAIL McEliece 8192128f/pcf: ciphertext syndromes differ.");
					}
					else if (qsc_intutils_are_equal8(ss, sspc, sizeof(ss)) == true)
					{
						qsctest_print_line("FAIL McEliece 8192128f/pcf: keys lack domain separation.");
					}
					else if (qsc_mceliece_8192128f_decapsulate(recovered, ct, sk) == false)
					{
						qsctest_print_line("FAIL McEliece 8192128f/pcf: f decapsulation.");
					}
					else if (qsc_mceliece_8192128pcf_decapsulate(recoveredpc, ctpc, skpc) == false)
					{
						qsctest_print_line("FAIL McEliece 8192128f/pcf: pcf decapsulation.");
					}
					else if (qsc_intutils_are_equal8(ss, recovered, sizeof(ss)) == false)
					{
						qsctest_print_line("FAIL McEliece 8192128f/pcf: f secret mismatch.");
					}
					else if (qsc_intutils_are_equal8(sspc, recoveredpc, sizeof(sspc)) == false)
					{
						qsctest_print_line("FAIL McEliece 8192128f/pcf: pcf secret mismatch.");
					}
					else
					{
						res = true;
					}
				}
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_8192128F_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (pkpc != NULL)
	{
		qsc_memutils_secure_erase(pkpc, QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pkpc);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(skpc, sizeof(skpc));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(sspc, sizeof(sspc));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));
	qsc_memutils_secure_erase(recoveredpc, sizeof(recoveredpc));

	return res;
}

/**
 * \brief Checks the ISO 460896pc implementation against the pinned repository KAT.
 * \return True only when keypair, ciphertext, encapsulated and recovered
 *         session keys match the reference fixture.
 * \note The reference fixture is the initial NIST PQC candidate KAT vector.
 *       Buffers are securely erased and freed. Uses a process-global test RNG;
 *       this function must be invoked serially.
 */
bool qsctest_mceliece_460896pc_kat(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_460896PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t expected_sk[QSC_MCELIECE_460896PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_460896PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t expected_ct[QSC_MCELIECE_460896PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t expected_ss[QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* expected_pk;
	size_t seedlen;
	size_t pklen;
	size_t sklen;
	size_t ctlen;
	size_t sslen;
	bool res;

	res = false;
	seedlen = 0U;
	pklen = 0U;
	sklen = 0U;
	ctlen = 0U;
	sslen = 0U;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE);
	expected_pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE);

	if (pk == NULL || expected_pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 460896pc KAT: public key allocation.");
	}
	else
	{
		parse_nist_cipher_kat("NPQC/mceliece-460896.rsp", seed, &seedlen, expected_pk, &pklen, expected_sk, &sklen, expected_ct, &ctlen, expected_ss, &sslen, 0U);

		if (seedlen != QSCTEST_NIST_RNG_SEED_SIZE || pklen != QSC_MCELIECE_460896PC_PUBLICKEY_SIZE || sklen != sizeof(sk) || ctlen != sizeof(ct) || sslen != sizeof(ss))
		{
			qsctest_print_line("FAIL McEliece 460896pc KAT: invalid reference vector dimensions.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_460896pc_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: key generation failed.");
			}
			else if (qsc_intutils_are_equal8(pk, expected_pk, pklen) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: public key mismatch.");
			}
			else if (qsc_intutils_are_equal8(sk, expected_sk, sklen) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: private key mismatch.");
			}
			else if (qsc_mceliece_460896pc_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: encapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(ct, expected_ct, ctlen) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: ciphertext mismatch.");
			}
			else if (qsc_intutils_are_equal8(ss, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: shared secret mismatch.");
			}
			else if (qsc_mceliece_460896pc_decapsulate(recovered, ct, sk) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: decapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(recovered, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 460896pc KAT: recovered key mismatch.");
			}
			else
			{
				res = true;
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (expected_pk != NULL)
	{
		qsc_memutils_secure_erase(expected_pk, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(expected_pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(expected_sk, sizeof(expected_sk));
	qsc_memutils_secure_erase(ct, sizeof(ct));
	qsc_memutils_secure_erase(expected_ct, sizeof(expected_ct));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(expected_ss, sizeof(expected_ss));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));

	return res;
}


/**
 * \brief Checks the ISO 6688128pc implementation against the pinned repository KAT.
 * \return True only when keypair, ciphertext, encapsulated and recovered
 *         session keys match the reference fixture.
 * \note The reference fixture is the initial NIST PQC candidate KAT vector.
 *       Buffers are securely erased and freed. Uses a process-global test RNG;
 *       this function must be invoked serially.
 */
bool qsctest_mceliece_6688128pc_kat(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6688128PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t expected_sk[QSC_MCELIECE_6688128PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_6688128PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t expected_ct[QSC_MCELIECE_6688128PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t expected_ss[QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* expected_pk;
	size_t seedlen;
	size_t pklen;
	size_t sklen;
	size_t ctlen;
	size_t sslen;
	bool res;

	res = false;
	seedlen = 0U;
	pklen = 0U;
	sklen = 0U;
	ctlen = 0U;
	sslen = 0U;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE);
	expected_pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE);

	if (pk == NULL || expected_pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6688128pc KAT: public key allocation.");
	}
	else
	{
		parse_nist_cipher_kat("NPQC/mceliece-6688128.rsp", seed, &seedlen, expected_pk, &pklen, expected_sk, &sklen, expected_ct, &ctlen, expected_ss, &sslen, 0U);

		if (seedlen != QSCTEST_NIST_RNG_SEED_SIZE || pklen != QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE || sklen != sizeof(sk) || ctlen != sizeof(ct) || sslen != sizeof(ss))
		{
			qsctest_print_line("FAIL McEliece 6688128pc KAT: invalid reference vector dimensions.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_6688128pc_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: key generation failed.");
			}
			else if (qsc_intutils_are_equal8(pk, expected_pk, pklen) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: public key mismatch.");
			}
			else if (qsc_intutils_are_equal8(sk, expected_sk, sklen) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: private key mismatch.");
			}
			else if (qsc_mceliece_6688128pc_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: encapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(ct, expected_ct, ctlen) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: ciphertext mismatch.");
			}
			else if (qsc_intutils_are_equal8(ss, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: shared secret mismatch.");
			}
			else if (qsc_mceliece_6688128pc_decapsulate(recovered, ct, sk) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: decapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(recovered, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 6688128pc KAT: recovered key mismatch.");
			}
			else
			{
				res = true;
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (expected_pk != NULL)
	{
		qsc_memutils_secure_erase(expected_pk, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(expected_pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(expected_sk, sizeof(expected_sk));
	qsc_memutils_secure_erase(ct, sizeof(ct));
	qsc_memutils_secure_erase(expected_ct, sizeof(expected_ct));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(expected_ss, sizeof(expected_ss));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));

	return res;
}


/**
 * \brief Checks the ISO 6960119pc implementation against the pinned repository KAT.
 * \return True only when keypair, ciphertext, encapsulated and recovered
 *         session keys match the reference fixture.
 * \note The reference fixture is the initial NIST PQC candidate KAT vector.
 *       Buffers are securely erased and freed. Uses a process-global test RNG;
 *       this function must be invoked serially.
 */
bool qsctest_mceliece_6960119pc_kat(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_6960119PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t expected_sk[QSC_MCELIECE_6960119PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t expected_ct[QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t expected_ss[QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* expected_pk;
	size_t seedlen;
	size_t pklen;
	size_t sklen;
	size_t ctlen;
	size_t sslen;
	bool res;

	res = false;
	seedlen = 0U;
	pklen = 0U;
	sklen = 0U;
	ctlen = 0U;
	sslen = 0U;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE);
	expected_pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE);

	if (pk == NULL || expected_pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 6960119pc KAT: public key allocation.");
	}
	else
	{
		parse_nist_cipher_kat("NPQC/mceliece-6960119.rsp", seed, &seedlen, expected_pk, &pklen, expected_sk, &sklen, expected_ct, &ctlen, expected_ss, &sslen, 0U);

		if (seedlen != QSCTEST_NIST_RNG_SEED_SIZE || pklen != QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE || sklen != sizeof(sk) || ctlen != sizeof(ct) || sslen != sizeof(ss))
		{
			qsctest_print_line("FAIL McEliece 6960119pc KAT: invalid reference vector dimensions.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_6960119pc_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: key generation failed.");
			}
			else if (qsc_intutils_are_equal8(pk, expected_pk, pklen) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: public key mismatch.");
			}
			else if (qsc_intutils_are_equal8(sk, expected_sk, sklen) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: private key mismatch.");
			}
			else if (qsc_mceliece_6960119pc_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: encapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(ct, expected_ct, ctlen) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: ciphertext mismatch.");
			}
			else if (qsc_intutils_are_equal8(ss, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: shared secret mismatch.");
			}
			else if (qsc_mceliece_6960119pc_decapsulate(recovered, ct, sk) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: decapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(recovered, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 6960119pc KAT: recovered key mismatch.");
			}
			else
			{
				res = true;
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (expected_pk != NULL)
	{
		qsc_memutils_secure_erase(expected_pk, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(expected_pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(expected_sk, sizeof(expected_sk));
	qsc_memutils_secure_erase(ct, sizeof(ct));
	qsc_memutils_secure_erase(expected_ct, sizeof(expected_ct));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(expected_ss, sizeof(expected_ss));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));

	return res;
}


/**
 * \brief Checks the ISO 8192128pc implementation against the pinned repository KAT.
 * \return True only when keypair, ciphertext, encapsulated and recovered
 *         session keys match the reference fixture.
 * \note The reference fixture is the initial NIST PQC candidate KAT vector.
 *       Buffers are securely erased and freed. Uses a process-global test RNG;
 *       this function must be invoked serially.
 */
bool qsctest_mceliece_8192128pc_kat(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sk[QSC_MCELIECE_8192128PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t expected_sk[QSC_MCELIECE_8192128PC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_MCELIECE_8192128PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t expected_ct[QSC_MCELIECE_8192128PC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t expected_ss[QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t recovered[QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t* pk;
	uint8_t* expected_pk;
	size_t seedlen;
	size_t pklen;
	size_t sklen;
	size_t ctlen;
	size_t sslen;
	bool res;

	res = false;
	seedlen = 0U;
	pklen = 0U;
	sklen = 0U;
	ctlen = 0U;
	sslen = 0U;
	pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE);
	expected_pk = qsc_memutils_aligned_alloc(QSC_SIMD_ALIGNMENT, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE);

	if (pk == NULL || expected_pk == NULL)
	{
		qsctest_print_line("FAIL McEliece 8192128pc KAT: public key allocation.");
	}
	else
	{
		parse_nist_cipher_kat("NPQC/mceliece-8192128.rsp", seed, &seedlen, expected_pk, &pklen, expected_sk, &sklen, expected_ct, &ctlen, expected_ss, &sslen, 0U);

		if (seedlen != QSCTEST_NIST_RNG_SEED_SIZE || pklen != QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE || sklen != sizeof(sk) || ctlen != sizeof(ct) || sslen != sizeof(ss))
		{
			qsctest_print_line("FAIL McEliece 8192128pc KAT: invalid reference vector dimensions.");
		}
		else
		{
			qsctest_nistrng_prng_initialize(seed, NULL, 0U);

			if (qsc_mceliece_8192128pc_generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: key generation failed.");
			}
			else if (qsc_intutils_are_equal8(pk, expected_pk, pklen) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: public key mismatch.");
			}
			else if (qsc_intutils_are_equal8(sk, expected_sk, sklen) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: private key mismatch.");
			}
			else if (qsc_mceliece_8192128pc_encapsulate(ss, ct, pk, qsctest_nistrng_prng_generate) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: encapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(ct, expected_ct, ctlen) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: ciphertext mismatch.");
			}
			else if (qsc_intutils_are_equal8(ss, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: shared secret mismatch.");
			}
			else if (qsc_mceliece_8192128pc_decapsulate(recovered, ct, sk) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: decapsulation failed.");
			}
			else if (qsc_intutils_are_equal8(recovered, expected_ss, sslen) == false)
			{
				qsctest_print_line("FAIL McEliece 8192128pc KAT: recovered key mismatch.");
			}
			else
			{
				res = true;
			}
		}
	}

	if (pk != NULL)
	{
		qsc_memutils_secure_erase(pk, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(pk);
	}

	if (expected_pk != NULL)
	{
		qsc_memutils_secure_erase(expected_pk, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE);
		qsc_memutils_aligned_free(expected_pk);
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	qsc_memutils_secure_erase(expected_sk, sizeof(expected_sk));
	qsc_memutils_secure_erase(ct, sizeof(ct));
	qsc_memutils_secure_erase(expected_ct, sizeof(expected_ct));
	qsc_memutils_secure_erase(ss, sizeof(ss));
	qsc_memutils_secure_erase(expected_ss, sizeof(expected_ss));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));

	return res;
}

void qsctest_mceliece_run(void)
{
	if (qsctest_mceliece_kat_test() == true)
	{
		qsctest_print_line("Success! Passed the McEliece encryption, and decryption known answer test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the McEliece encryption, and decryption known answer test.");
	}

	if (qsctest_mceliece_operations_test() == true)
	{
		qsctest_print_line("Success! Passed the McEliece key generation, encryption, and decryption stress test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the McEliece key generation, encryption, and decryption stress test.");
	}

	if (qsctest_mceliece_publickey_integrity() == true)
	{
		qsctest_print_line("Success! Passed the McEliece public-key tamper test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the McEliece public-key tamper test.");
	}

	if (qsctest_mceliece_ciphertext_integrity() == true)
	{
		qsctest_print_line("Success! Passed the McEliece cipher-text tamper test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the McEliece cipher-text tamper test.");
	}
	if (qsctest_mceliece_460896pc_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 460896pc: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 460896pc: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6688128pc_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6688128pc: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6688128pc: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6960119pc_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6960119pc: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6960119pc: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_8192128pc_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 8192128pc: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 8192128pc: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_460896_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 460896: ordinary roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 460896: ordinary roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6688128_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6688128: ordinary roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6688128: ordinary roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6960119_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6960119: ordinary roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6960119: ordinary roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_8192128_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 8192128: ordinary roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 8192128: ordinary roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_460896f_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 460896f: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 460896f: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_460896pcf_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 460896pcf: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 460896pcf: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6688128f_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6688128f: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6688128f: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6688128pcf_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6688128pcf: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6688128pcf: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6960119f_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6960119f: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6960119f: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_6960119pcf_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 6960119pcf: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6960119pcf: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_8192128f_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 8192128f: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 8192128f: roundtrip, tamper or null RNG.");
	}

	if (qsctest_mceliece_8192128pcf_roundtrip() == true)
	{
		qsctest_print_line("PASS McEliece 8192128pcf: roundtrip, tamper and null RNG.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 8192128pcf: roundtrip, tamper or null RNG.");
	}


	if (qsctest_mceliece_460896_framing() == true)
	{
		qsctest_print_line("PASS McEliece 460896f/pcf: keypair and framing equivalence.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 460896f/pcf: keypair or framing equivalence.");
	}

	if (qsctest_mceliece_6688128_framing() == true)
	{
		qsctest_print_line("PASS McEliece 6688128f/pcf: keypair and framing equivalence.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6688128f/pcf: keypair or framing equivalence.");
	}

	if (qsctest_mceliece_6960119_framing() == true)
	{
		qsctest_print_line("PASS McEliece 6960119f/pcf: keypair and framing equivalence.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6960119f/pcf: keypair or framing equivalence.");
	}

	if (qsctest_mceliece_8192128_framing() == true)
	{
		qsctest_print_line("PASS McEliece 8192128f/pcf: keypair and framing equivalence.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 8192128f/pcf: keypair or framing equivalence.");
	}

	if (qsctest_mceliece_460896pc_kat() == true)
	{
		qsctest_print_line("PASS McEliece 460896pc KAT: reference fixture.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 460896pc KAT: reference fixture.");
	}

	if (qsctest_mceliece_6688128pc_kat() == true)
	{
		qsctest_print_line("PASS McEliece 6688128pc KAT: reference fixture.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6688128pc KAT: reference fixture.");
	}

	if (qsctest_mceliece_6960119pc_kat() == true)
	{
		qsctest_print_line("PASS McEliece 6960119pc KAT: reference fixture.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 6960119pc KAT: reference fixture.");
	}

	if (qsctest_mceliece_8192128pc_kat() == true)
	{
		qsctest_print_line("PASS McEliece 8192128pc KAT: reference fixture.");
	}
	else
	{
		qsctest_print_line("FAIL McEliece 8192128pc KAT: reference fixture.");
	}
}
