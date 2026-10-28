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

#include "kyber_test.h"
#include "katparser.h"
#include "nistrng.h"
#include "testutils.h"
#include "consoleutils.h"
#include "csp.h"
#include "intutils.h"
#include "kyber.h"
#include "kyber512.h"
#include "kyber768.h"
#include "kyber1024.h"
#include "kyber1280.h"
#include "memutils.h"

bool qsctest_kyber_ciphertext_integrity()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk3[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* change some bytes in the ciphertext */
	if (qsc_csp_generate(ct, 32) != true)
	{
		qsctest_print_line("Failure! kyber cipher-text: the random generator has failed -KCT0");
		res = false;
	}

	/* FIPS 203 uses implicit rejection; invalid ciphertexts still return a shared secret. */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) != true)
	{
		qsctest_print_line("Failure! kyber cipher-text: implicit rejection returned an error -KCT1");
		res = false;
	}

	/* the rejection shared secret must differ from the valid encapsulated secret */
	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
	{
		qsctest_print_line("Failure! kyber cipher-text: invalid shared secret -KCT2");
		res = false;
	}

	/* decapsulation of the same invalid ciphertext must produce the same implicit-rejection secret */
	if (qsc_kyber_decapsulate(ssk3, ct, sk) != true || qsc_intutils_are_equal8(ssk1, ssk3, QSC_KYBER_SHAREDSECRET_SIZE) != true)
	{
		qsctest_print_line("Failure! kyber cipher-text: implicit rejection is not deterministic -KCT3");
		res = false;
	}

	return res;
}

/**
 * \brief Verify a single parameter-qualified Kyber KAT against its stored response vector.
 * \param path Path to the parameter-specific NIST competition-format response file.
 * \param publickey_size Expected number of public-key bytes.
 * \param privatekey_size Expected number of private-key bytes.
 * \param ciphertext_size Expected number of ciphertext bytes.
 * \param generate_keypair Qualified keypair generation routine.
 * \param encapsulate Qualified encapsulation routine.
 * \param decapsulate Qualified decapsulation routine.
 * \return True when vector lengths and all five generated outputs match.
 * \note Runs synchronously and modifies the QSCTest NIST PRNG state; not thread safe.
 *       Input files are trusted project test vectors, not untrusted external data.
 *       All temporary buffers are allocated on the stack and owned by this function.
 */
static bool qsctest_kyber_kat_verify(const char* path, size_t publickey_size,
    size_t privatekey_size, size_t ciphertext_size,
    bool (*generate_keypair)(uint8_t*, uint8_t*, bool (*)(uint8_t*, size_t)),
    bool (*encapsulate)(uint8_t*, uint8_t*, const uint8_t*, bool (*)(uint8_t*, size_t)),
    bool (*decapsulate)(uint8_t*, const uint8_t*, const uint8_t*))
{
    uint8_t ct[QSC_KYBER1280_CIPHERTEXT_SIZE] = { 0U };
    uint8_t kct[QSC_KYBER1280_CIPHERTEXT_SIZE] = { 0U };
    uint8_t kpk[QSC_KYBER1280_PUBLICKEY_SIZE] = { 0U };
    uint8_t ksk[QSC_KYBER1280_PRIVATEKEY_SIZE] = { 0U };
    uint8_t kss[QSC_KYBER1280_SHAREDSECRET_SIZE] = { 0U };
    uint8_t pk[QSC_KYBER1280_PUBLICKEY_SIZE] = { 0U };
    uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
    uint8_t sk[QSC_KYBER1280_PRIVATEKEY_SIZE] = { 0U };
    uint8_t ss1[QSC_KYBER1280_SHAREDSECRET_SIZE] = { 0U };
    uint8_t ss2[QSC_KYBER1280_SHAREDSECRET_SIZE] = { 0U };
    size_t ctlen;
    size_t pklen;
    size_t seedlen;
    size_t sklen;
    size_t sslen;
    bool res;

    ctlen = 0U;
    pklen = 0U;
    seedlen = 0U;
    sklen = 0U;
    sslen = 0U;
    res = false;

    /* These files use the NIST PQC competition response format, not ACVP. */
    parse_nist_cipher_kat(path, seed, &seedlen, kpk, &pklen,
        ksk, &sklen, kct, &ctlen, kss, &sslen, 0U);

    if (seedlen == sizeof(seed) && pklen == publickey_size &&
        sklen == privatekey_size && ctlen == ciphertext_size &&
        sslen == sizeof(kss))
    {
        qsctest_nistrng_prng_initialize(seed, NULL, 0U);

        if (generate_keypair(pk, sk, qsctest_nistrng_prng_generate) == true)
        {
            if (encapsulate(ss2, ct, pk, qsctest_nistrng_prng_generate) == true)
            {
                if (decapsulate(ss1, ct, sk) == true)
                {
                    res = qsc_intutils_are_equal8(pk, kpk, publickey_size);
                    res = qsc_intutils_are_equal8(sk, ksk, privatekey_size) && res;
                    res = qsc_intutils_are_equal8(ct, kct, ciphertext_size) && res;
                    res = qsc_intutils_are_equal8(ss1, ss2, sizeof(ss1)) && res;
                    res = qsc_intutils_are_equal8(ss1, kss, sizeof(ss1)) && res;
                }
            }
        }
    }

    return res;
}

/** \brief Test Kyber-512 using NPQC/kyber-1632.rsp and the 512 API.
 * \return True when all response-vector fields match.
 * \note Calls the shared KAT verifier serially; modifies QSCTest PRNG state.
 */
bool qsctest_kyber512_kat_test(void)
{
    bool res;

    res = qsctest_kyber_kat_verify("NPQC/kyber-1632.rsp",
        QSC_KYBER512_PUBLICKEY_SIZE, QSC_KYBER512_PRIVATEKEY_SIZE,
        QSC_KYBER512_CIPHERTEXT_SIZE, qsc_kyber512_generate_keypair,
        qsc_kyber512_encapsulate, qsc_kyber512_decapsulate);

    return res;
}

/** \brief Test Kyber-768 using NPQC/kyber-2400.rsp and the 768 API.
 * \return True when all response-vector fields match.
 * \note Calls the shared KAT verifier serially; modifies QSCTest PRNG state.
 */
bool qsctest_kyber768_kat_test(void)
{
    bool res;

    res = qsctest_kyber_kat_verify("NPQC/kyber-2400.rsp",
        QSC_KYBER768_PUBLICKEY_SIZE, QSC_KYBER768_PRIVATEKEY_SIZE,
        QSC_KYBER768_CIPHERTEXT_SIZE, qsc_kyber768_generate_keypair,
        qsc_kyber768_encapsulate, qsc_kyber768_decapsulate);

    return res;
}

/** \brief Test Kyber-1024 using NPQC/kyber-3168.rsp and the 1024 API.
 * \return True when all response-vector fields match.
 * \note Calls the shared KAT verifier serially; modifies QSCTest PRNG state.
 */
bool qsctest_kyber1024_kat_test(void)
{
    bool res;

    res = qsctest_kyber_kat_verify("NPQC/kyber-3168.rsp",
        QSC_KYBER1024_PUBLICKEY_SIZE, QSC_KYBER1024_PRIVATEKEY_SIZE,
        QSC_KYBER1024_CIPHERTEXT_SIZE, qsc_kyber1024_generate_keypair,
        qsc_kyber1024_encapsulate, qsc_kyber1024_decapsulate);

    return res;
}

/** \brief Test QSC Kyber-1280 using NPQC/kyber-3936.rsp and the 1280 API.
 * \return True when all response-vector fields match.
 * \note QSC-specific nonstandard parameter set; modifies QSCTest PRNG state.
 */
bool qsctest_kyber1280_kat_test(void)
{
    bool res;

    res = qsctest_kyber_kat_verify("NPQC/kyber-3936.rsp",
        QSC_KYBER1280_PUBLICKEY_SIZE, QSC_KYBER1280_PRIVATEKEY_SIZE,
        QSC_KYBER1280_CIPHERTEXT_SIZE, qsc_kyber1280_generate_keypair,
        qsc_kyber1280_encapsulate, qsc_kyber1280_decapsulate);

    return res;
}

bool qsctest_kyber_privatekey_integrity()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
	qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate);

	/* corrupt the stored H(ek) value in the expanded decapsulation key */
	sk[QSC_KYBER_PRIVATEKEY_SIZE - (2U * QSC_KYBER_SHAREDSECRET_SIZE)] ^= 0x01U;

	/* FIPS 203 decapsulation-key input checking must reject the inconsistent key. */
	if (qsc_kyber_decapsulate(ssk1, ct, sk) == true)
	{
		qsctest_print_line("Failure! kyber private-key: invalid key was accepted -INTEG0");
		res = false;
	}

	if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
	{
		qsctest_print_line("Failure! kyber private-key: invalid key retained the valid shared secret -INTEG1");
		res = false;
	}

	return res;
}

bool qsctest_kyber_publickey_integrity()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ssk[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* encode the first 12-bit coefficient as q = 3329; FIPS 203 requires the modulus check to reject it */
	pk[0U] = 0x01U;
	pk[1U] = (uint8_t)((pk[1U] & 0xF0U) | 0x0DU);

	if (qsc_kyber_encapsulate(ssk, ct, pk, qsctest_nistrng_prng_generate) == true)
	{
		qsctest_print_line("Failure! kyber public-key: invalid encapsulation key was accepted -INTEG0");
		res = false;
	}

	return res;
}

bool qsctest_kyber_operations_test()
{
	uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ssk1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ssk2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0 };
	uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	bool res;

	res = false;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate public and secret keys */
	if (qsc_kyber_generate_keypair(pk, sk, qsctest_nistrng_prng_generate))
	{
		/* derive a shared-secret key and creates a response (in: pk | out: ct and ss2) */
		if (qsc_kyber_encapsulate(ssk2, ct, pk, qsctest_nistrng_prng_generate))
		{
			/* decapsulate the cipher-text and extract the shared secret */
			if (qsc_kyber_decapsulate(ssk1, ct, sk))
			{
				if (qsc_intutils_are_equal8(ssk1, ssk2, QSC_KYBER_SHAREDSECRET_SIZE) == true)
				{
					res = true;
				}
				else
				{
					qsctest_print_line("Failure! kyber operations: the shared secrets are not equal -KOT4");
				}
			}
			else
			{
				qsctest_print_line("Failure! kyber operations: decapsulation failure -KOT3");
			}
		}
		else
		{
			qsctest_print_line("Failure! kyber operations: encasulation failure -KOT2");
		}
	}
	else
	{
		qsctest_print_line("Failure! kyber operations: key generation failure -KOT1");
	}

	return res;
}

void qsctest_kyber_run()
{
	if (qsctest_kyber512_kat_test() == true)
	{
		qsctest_print_line("Success! Passed the Kyber-512 known-answer test");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber-512 known-answer test");
	}

	if (qsctest_kyber768_kat_test() == true)
	{
		qsctest_print_line("Success! Passed the Kyber-768 known-answer test");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber-768 known-answer test");
	}

	if (qsctest_kyber1024_kat_test() == true)
	{
		qsctest_print_line("Success! Passed the Kyber-1024 known-answer test");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber-1024 known-answer test");
	}

	if (qsctest_kyber1280_kat_test() == true)
	{
		qsctest_print_line("Success! Passed the Kyber-1280 known-answer test");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber-1280 known-answer test");
	}

	if (qsctest_kyber_operations_test() == true)
	{
		qsctest_print_line("Success! Passed the Kyber key generation, encryption, and decryption stress test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber key generation, encryption, and decryption stress test.");
	}

	if (qsctest_kyber_privatekey_integrity() == true)
	{
		qsctest_print_line("Success! Passed the Kyber private-key tamper test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber private-key tamper test.");
	}

	if (qsctest_kyber_publickey_integrity() == true)
	{
		qsctest_print_line("Success! Passed the Kyber public-key tamper test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber public-key tamper test.");
	}

	if (qsctest_kyber_ciphertext_integrity() == true)
	{
		qsctest_print_line("Success! Passed the Kyber cipher-text tamper test.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the Kyber cipher-text tamper test.");
	}

}
