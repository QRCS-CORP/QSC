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

#include "hqc_test.h"
#include "nistrng.h"
#include "testutils.h"
#include "consoleutils.h"
#include "csp.h"
#include "intutils.h"
#include "hqc.h"
#include "hqc_multi.h"
#include "memutils.h"
#include "sha3.h"

/*
 * The digest fixtures below are QSC-local deterministic regression values
 * for the 2026-10-12 algorithm revision. They are NOT the official HQC KATs.
 * Independent upstream vectors are required before conformance is claimed.
 */
#if defined(QSC_HQC_S1N2321)
/** \brief SHA3-256 QSC-local HQC-2026 publickey regression digest. */
static const uint8_t hqc_regression_publickey[32U] =
{
	0x2FU, 0xF5U, 0x38U, 0xD0U, 0x52U, 0x53U, 0xD3U, 0x96U,
	0x1EU, 0x15U, 0xB5U, 0x55U, 0x47U, 0xA5U, 0xE8U, 0x16U,
	0x07U, 0xE6U, 0x48U, 0x42U, 0x0AU, 0x97U, 0x1BU, 0xFDU,
	0xB3U, 0x9DU, 0x3DU, 0xB4U, 0xC6U, 0x05U, 0x86U, 0xCFU

};
/** \brief SHA3-256 QSC-local HQC-2026 ciphertext regression digest. */
static const uint8_t hqc_regression_ciphertext[32U] =
{
	0x04U, 0x52U, 0x6AU, 0x97U, 0x71U, 0xF6U, 0x25U, 0x21U,
	0x64U, 0xB5U, 0x16U, 0xA3U, 0x48U, 0x5CU, 0x6AU, 0x11U,
	0x7CU, 0xCDU, 0x78U, 0xF9U, 0x61U, 0xCFU, 0x45U, 0xEDU,
	0x2BU, 0xBBU, 0xD8U, 0x72U, 0xE3U, 0xD9U, 0x3EU, 0xA3U

};
/** \brief SHA3-256 QSC-local HQC-2026 secret regression digest. */
static const uint8_t hqc_regression_secret[32U] =
{
	0xF0U, 0xCAU, 0xDCU, 0xEBU, 0x35U, 0xAAU, 0x98U, 0xAFU,
	0x5CU, 0xAFU, 0xE9U, 0xD6U, 0xF3U, 0x9CU, 0x67U, 0xD4U,
	0x21U, 0xD4U, 0xE7U, 0xCDU, 0xCBU, 0x6BU, 0x33U, 0x88U,
	0xEBU, 0xE5U, 0x18U, 0x03U, 0x87U, 0x07U, 0x9EU, 0xCDU

};
#elif defined(QSC_HQC_S3N4602)
/** \brief SHA3-256 QSC-local HQC-2026 publickey regression digest. */
static const uint8_t hqc_regression_publickey[32U] =
{
	0x1EU, 0x84U, 0x6FU, 0x5BU, 0x3DU, 0xF3U, 0x17U, 0x0EU,
	0xF3U, 0x47U, 0xC6U, 0x62U, 0x33U, 0x25U, 0x6CU, 0x2BU,
	0xE9U, 0x98U, 0x21U, 0xA8U, 0x01U, 0x75U, 0x52U, 0x16U,
	0x2DU, 0xDAU, 0xCBU, 0x83U, 0x5BU, 0x8EU, 0xF1U, 0xBAU

};
/** \brief SHA3-256 QSC-local HQC-2026 ciphertext regression digest. */
static const uint8_t hqc_regression_ciphertext[32U] =
{
	0x64U, 0xEDU, 0x22U, 0x36U, 0xC7U, 0xF2U, 0xEDU, 0xF1U,
	0xF8U, 0x59U, 0x83U, 0x55U, 0x9BU, 0xEBU, 0xC7U, 0xC8U,
	0xCAU, 0x37U, 0xA3U, 0x7DU, 0x16U, 0x2CU, 0x44U, 0xC1U,
	0x64U, 0x1DU, 0x11U, 0x5DU, 0xA1U, 0xB2U, 0x05U, 0xD2U

};
/** \brief SHA3-256 QSC-local HQC-2026 secret regression digest. */
static const uint8_t hqc_regression_secret[32U] =
{
	0xE0U, 0xE4U, 0x0CU, 0xCAU, 0x49U, 0x42U, 0x19U, 0xB1U,
	0xD3U, 0x45U, 0x81U, 0x0EU, 0x84U, 0x5BU, 0x35U, 0xCBU,
	0x60U, 0xCEU, 0x0AU, 0xDDU, 0x2AU, 0xA0U, 0xE7U, 0x2FU,
	0x91U, 0x3FU, 0x33U, 0x2BU, 0x17U, 0x40U, 0x5EU, 0x36U

};
#elif defined(QSC_HQC_S5N7333)
/** \brief SHA3-256 QSC-local HQC-2026 publickey regression digest. */
static const uint8_t hqc_regression_publickey[32U] =
{
	0xADU, 0x15U, 0x91U, 0x64U, 0xE1U, 0x64U, 0x63U, 0x6EU,
	0xADU, 0xB9U, 0x44U, 0x28U, 0x61U, 0x71U, 0xC0U, 0xC7U,
	0xD8U, 0xCDU, 0xA0U, 0xADU, 0xC7U, 0xD4U, 0x15U, 0xABU,
	0x07U, 0x8DU, 0x46U, 0x41U, 0x42U, 0x38U, 0x2EU, 0xFEU

};
/** \brief SHA3-256 QSC-local HQC-2026 ciphertext regression digest. */
static const uint8_t hqc_regression_ciphertext[32U] =
{
	0x18U, 0xD1U, 0x59U, 0xF3U, 0x2CU, 0x2CU, 0xCBU, 0x6DU,
	0x18U, 0x12U, 0xB4U, 0xCCU, 0xCBU, 0x2DU, 0x3DU, 0xFFU,
	0xF6U, 0x5FU, 0xAEU, 0x42U, 0x8AU, 0x70U, 0x11U, 0x2BU,
	0x2CU, 0x4CU, 0xA8U, 0xE9U, 0x7FU, 0x23U, 0xF6U, 0x39U

};
/** \brief SHA3-256 QSC-local HQC-2026 secret regression digest. */
static const uint8_t hqc_regression_secret[32U] =
{
	0x2FU, 0x08U, 0xFFU, 0x2DU, 0xDAU, 0x21U, 0xC3U, 0x2EU,
	0x8BU, 0x71U, 0x00U, 0xC1U, 0x74U, 0xF8U, 0x7CU, 0xFFU,
	0xE6U, 0x2AU, 0xBFU, 0x1DU, 0x7BU, 0x52U, 0x79U, 0x52U,
	0x69U, 0xA1U, 0xE3U, 0x8AU, 0x70U, 0x2AU, 0x7AU, 0xEAU

};
#else
#error A valid HQC parameter set must be selected.
#endif

/**
 * \brief Checks a SHA3-256 digest against a QSC-local regression vector.
 * \param[in] value Source bytes; caller owns the buffer of size bytes.
 * \param[in] size Length of the source in bytes.
 * \param[in] expected Expected SHA3-256 digest, 32 bytes.
 * \return True if the computed digest matches the fixture.
 * \note No shared mutable state; inputs are unchanged.
 */
static bool qsctest_hqc_check_digest(const uint8_t* value, size_t size, const uint8_t expected[32U])
{
	uint8_t digest[32U] = { 0U };
	bool res;

	qsc_sha3_compute256(digest, value, size);
	res = qsc_intutils_are_equal8(digest, expected, sizeof(digest));
	qsc_memutils_secure_erase(digest, sizeof(digest));

	return res;
}

bool qsctest_hqc_kat_test(void)
{
	uint8_t pk[QSC_HQC_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ds[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t keyseed[QSC_HQC_SEED_SIZE] = { 0U };
	uint8_t encseed[QSC_HQC_SEED_SIZE] = { 0U };
	size_t i;
	bool res;

	res = true;

	for (i = 0U; i < QSC_HQC_SEED_SIZE; ++i)
	{
		keyseed[i] = (uint8_t)i;
		encseed[i] = (uint8_t)(0xA0U + i);
	}

	qsc_hqc_generate_seeded_keypair(pk, sk, keyseed);
	qsc_hqc_seeded_encapsulate(ss, ct, pk, encseed);

	if (qsc_intutils_are_equal8(sk, keyseed, sizeof(sk)) != true)
	{
		qsctest_print_line("Failure! HQC-2026 compressed secret-key seed mismatch -HQC26K1");
		res = false;
	}

	if (qsctest_hqc_check_digest(pk, sizeof(pk), hqc_regression_publickey) != true)
	{
		qsctest_print_line("Failure! HQC-2026 public-key regression -HQC26K2");
		res = false;
	}

	if (qsctest_hqc_check_digest(ct, sizeof(ct), hqc_regression_ciphertext) != true)
	{
		qsctest_print_line("Failure! HQC-2026 ciphertext regression -HQC26K3");
		res = false;
	}

	if (qsctest_hqc_check_digest(ss, sizeof(ss), hqc_regression_secret) != true)
	{
		qsctest_print_line("Failure! HQC-2026 shared-secret regression -HQC26K4");
		res = false;
	}

	if (qsc_hqc_decapsulate(ds, ct, sk) != true || qsc_intutils_are_equal8(ss, ds, sizeof(ss)) != true)
	{
		qsctest_print_line("Failure! HQC-2026 deterministic decapsulation -HQC26K5");
		res = false;
	}

	return res;
}

bool qsctest_hqc_operations_test(void)
{
	uint8_t pk[QSC_HQC_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ds[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng2_prng_initialize(seed, NULL, 0U);

	for (size_t i = 0U; i < QSCTEST_HQC_TEST_COUNT; ++i)
	{
		if (qsc_hqc_generate_keypair(pk, sk, qsctest_nistrng2_prng_generate) != true)
		{
			qsctest_print_line("Failure! HQC-2026 key generation -HQC26O1");
			res = false;
			break;
		}

		if (qsc_hqc_encapsulate(ss, ct, pk, qsctest_nistrng2_prng_generate) != true)
		{
			qsctest_print_line("Failure! HQC-2026 encapsulation -HQC26O2");
			res = false;
			break;
		}

		if (qsc_hqc_decapsulate(ds, ct, sk) != true)
		{
			qsctest_print_line("Failure! HQC-2026 decapsulation -HQC26O3");
			res = false;
			break;
		}

		if (qsc_intutils_are_equal8(ds, ss, QSC_HQC_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_line("Failure! HQC-2026 encapsulated secrets disagree -HQC26O4");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_hqc_privatekey_integrity(void)
{
	uint8_t pk[QSC_HQC_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ds[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	bool res;

	res = false;

	if (qsc_hqc_generate_keypair(pk, sk, qsc_csp_generate) == true)
	{
		if (qsc_hqc_encapsulate(ss, ct, pk, qsc_csp_generate) == true)
		{
			sk[0U] ^= 0x01U;

			if (qsc_hqc_decapsulate(ds, ct, sk) == true)
			{
				res = (qsc_intutils_are_equal8(ds, ss, sizeof(ss)) != true);
			}
		}
	}

	if (res != true)
	{
		qsctest_print_line("Failure! HQC-2026 compressed private-key tamper -HQC26S1");
	}

	return res;
}

bool qsctest_hqc_publickey_integrity(void)
{
	uint8_t pk[QSC_HQC_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ds[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	bool res;

	res = false;

	if (qsc_hqc_generate_keypair(pk, sk, qsc_csp_generate) == true)
	{
		pk[QSC_HQC_PUBLICKEY_SIZE - 1U] ^= 0x01U;

		if (qsc_hqc_encapsulate(ss, ct, pk, qsc_csp_generate) == true)
		{
			if (qsc_hqc_decapsulate(ds, ct, sk) == true)
			{
				res = (qsc_intutils_are_equal8(ds, ss, sizeof(ss)) != true);
			}
		}
	}

	if (res != true)
	{
		qsctest_print_line("Failure! HQC-2026 public-key tamper -HQC26P1");
	}

	return res;
}

bool qsctest_hqc_ciphertext_integrity(void)
{
	uint8_t pk[QSC_HQC_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE] = { 0U };
	uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE] = { 0U };
	uint8_t ss[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	uint8_t ds[QSC_HQC_SHAREDSECRET_SIZE] = { 0U };
	bool res;

	res = false;

	if (qsc_hqc_generate_keypair(pk, sk, qsc_csp_generate) == true)
	{
		if (qsc_hqc_encapsulate(ss, ct, pk, qsc_csp_generate) == true)
		{
			ct[0U] ^= 0x01U;

			if (qsc_hqc_decapsulate(ds, ct, sk) == true)
			{
				res = (qsc_intutils_are_equal8(ds, ss, sizeof(ss)) != true);
			}
		}
	}

	if (res != true)
	{
		qsctest_print_line("Failure! HQC-2026 ciphertext implicit rejection -HQC26C1");
	}

	return res;
}

void qsctest_hqc_run(void)
{
    if (qsctest_hqc1_parameter_test() == true)
    {
        qsctest_print_line("Success! HQC-1 independent compact-key and implicit-rejection test");
    }
    else
    {
        qsctest_print_line("Failure! HQC-1 independent compact-key and implicit-rejection test");
    }

    if (qsctest_hqc3_parameter_test() == true)
    {
        qsctest_print_line("Success! HQC-3 independent compact-key and implicit-rejection test");
    }
    else
    {
        qsctest_print_line("Failure! HQC-3 independent compact-key and implicit-rejection test");
    }

    if (qsctest_hqc5_parameter_test() == true)
    {
        qsctest_print_line("Success! HQC-5 independent compact-key and implicit-rejection test");
    }
    else
    {
        qsctest_print_line("Failure! HQC-5 independent compact-key and implicit-rejection test");
    }

	if (qsctest_hqc_kat_test() == true)
	{
		qsctest_print_line("Success! HQC-2026 QSC-local deterministic regression test (NOT official KAT).");
	}
	else
	{
		qsctest_print_line("Failure! HQC-2026 QSC-local deterministic regression test.");
	}

	if (qsctest_hqc_operations_test() == true)
	{
		qsctest_print_line("Success! HQC-2026 100-iteration (10 debug) operations test.");
	}
	else
	{
		qsctest_print_line("Failure! HQC-2026 operations test.");
	}

	if (qsctest_hqc_privatekey_integrity() == true)
	{
		qsctest_print_line("Success! HQC-2026 compressed private-key integrity test.");
	}
	else
	{
		qsctest_print_line("Failure! HQC-2026 compressed private-key integrity test.");
	}

	if (qsctest_hqc_publickey_integrity() == true)
	{
		qsctest_print_line("Success! HQC-2026 public-key integrity test.");
	}
	else
	{
		qsctest_print_line("Failure! HQC-2026 public-key integrity test.");
	}

	if (qsctest_hqc_ciphertext_integrity() == true)
	{
		qsctest_print_line("Success! HQC-2026 ciphertext implicit-rejection test.");
	}
	else
	{
		qsctest_print_line("Failure! HQC-2026 ciphertext implicit-rejection test.");
	}
}

/** \brief Reproducible test-only entropy for independent HQC parameter regressions.
 * \param output Caller-owned output buffer.
 * \param length Number of bytes to populate.
 * \return True after generating all requested bytes.
 * \note Not cryptographically secure; no shared state.
 */
static bool qsctest_hqc_multi_rng(uint8_t* output, size_t length)
{
    size_t i;

    for (i = 0U; i < length; ++i)
    {
        output[i] = (uint8_t)((i * 17U + 0x53U) & 0xFFU);
    }

    return true;
}

/** \brief Exercise seeded HQC-2026 operations and implicit rejection for one profile.
 * \param pkbytes Public-key size for this profile.
 * \param ctbytes Ciphertext size for this profile.
 * \param keygen Profile-specific key-generation callback.
 * \param seededkeygen Profile-specific seeded key-generation callback.
 * \param encapsulate Profile-specific encapsulation callback.
 * \param seededencap Profile-specific seeded encapsulation callback.
 * \param decapsulate Profile-specific decapsulation callback.
 * \return True on valid deterministic operations and invalid input rejection.
 * \note Maintains the QSC 32-byte compact private key, not upstream expanded encoding.
 */
static bool qsctest_hqc_multi_verify(size_t pkbytes, size_t ctbytes, bool (*keygen)(uint8_t*, uint8_t*, bool (*)(uint8_t*, size_t)), void (*seededkeygen)(uint8_t*, uint8_t*, uint8_t*), bool (*encapsulate)(uint8_t*, uint8_t*, const uint8_t*, bool (*)(uint8_t*, size_t)), void (*seededencap)(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*), bool (*decapsulate)(uint8_t*, const uint8_t*, const uint8_t*))
{
    uint8_t pk[QSC_HQC5_PUBLICKEY_SIZE] = { 0U };
    uint8_t sk[QSC_HQC_PRIVATEKEY_SEED_SIZE] = { 0U };
    uint8_t ct[QSC_HQC5_CIPHERTEXT_SIZE] = { 0U };
    uint8_t ss[QSC_HQC_SHAREDSECRET_BYTES] = { 0U };
    uint8_t ds[QSC_HQC_SHAREDSECRET_BYTES] = { 0U };
    uint8_t skseed[QSC_HQC_SEED_BYTES] = { 0U };
    uint8_t encseed[QSC_HQC_SEED_BYTES] = { 0U };
    size_t i;
    bool res;

    res = true;
    for (i = 0U; i < QSC_HQC_SEED_BYTES; ++i)
    {
        skseed[i] = (uint8_t)i;
        encseed[i] = (uint8_t)(i + 0xA0U);
    }

    seededkeygen(pk, sk, skseed);
    res = (qsc_memutils_are_equal(sk, skseed, sizeof(skseed)) == true) && res;
    seededencap(ss, ct, pk, encseed);
    res = (decapsulate(ds, ct, sk) == true && qsc_memutils_are_equal(ds, ss, sizeof(ss)) == true) && res;
    ct[0U] ^= 0x01U;
    res = (decapsulate(ds, ct, sk) == true && qsc_memutils_are_equal(ds, ss, sizeof(ss)) == false) && res;
    ct[0U] ^= 0x01U;
    sk[0U] ^= 0x01U;
    res = (decapsulate(ds, ct, sk) == true && qsc_memutils_are_equal(ds, ss, sizeof(ss)) == false) && res;
    sk[0U] ^= 0x01U;
    res = (keygen(NULL, sk, qsctest_hqc_multi_rng) == false) && res;
    res = (encapsulate(ss, ct, NULL, qsctest_hqc_multi_rng) == false) && res;
    res = (decapsulate(NULL, ct, sk) == false) && res;
    res = (pkbytes <= sizeof(pk) && ctbytes <= sizeof(ct)) && res;
    qsc_memutils_secure_erase(sk, sizeof(sk));

    return res;
}
/** \brief Test QSC HQC-1 compact-key seeded correctness and rejection behavior.
 * \return True when all per-profile operations and negative checks succeed.
 */
bool qsctest_hqc1_parameter_test(void)
{
    bool res;

    res = qsctest_hqc_multi_verify(QSC_HQC1_PUBLICKEY_SIZE, QSC_HQC1_CIPHERTEXT_SIZE, qsc_hqc1_generate_keypair, qsc_hqc1_generate_seeded_keypair, qsc_hqc1_encapsulate, qsc_hqc1_seeded_encapsulate, qsc_hqc1_decapsulate);
    return res;
}

/** \brief Test QSC HQC-3 compact-key seeded correctness and rejection behavior.
 * \return True when all per-profile operations and negative checks succeed.
 */
bool qsctest_hqc3_parameter_test(void)
{
    bool res;

    res = qsctest_hqc_multi_verify(QSC_HQC3_PUBLICKEY_SIZE, QSC_HQC3_CIPHERTEXT_SIZE, qsc_hqc3_generate_keypair, qsc_hqc3_generate_seeded_keypair, qsc_hqc3_encapsulate, qsc_hqc3_seeded_encapsulate, qsc_hqc3_decapsulate);
    return res;
}

/** \brief Test QSC HQC-5 compact-key seeded correctness and rejection behavior.
 * \return True when all per-profile operations and negative checks succeed.
 */
bool qsctest_hqc5_parameter_test(void)
{
    bool res;

    res = qsctest_hqc_multi_verify(QSC_HQC5_PUBLICKEY_SIZE, QSC_HQC5_CIPHERTEXT_SIZE, qsc_hqc5_generate_keypair, qsc_hqc5_generate_seeded_keypair, qsc_hqc5_encapsulate, qsc_hqc5_seeded_encapsulate, qsc_hqc5_decapsulate);
    return res;
}

