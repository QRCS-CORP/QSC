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

#include "eddh_test.h"
#include "nistrng.h"
#include "testutils.h"
#include "csp.h"
#include "eddh.h"
#include "eddh25519.h"
#include "eddh448.h"
#include "ed448.h"
#include "memutils.h"

bool qsctest_eddh_kat_test(void)
{
	uint8_t kpka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t kpkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksec[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t kska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kskb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t seeda[QSC_EDDH_SEED_SIZE] = { 0 };
	uint8_t seedb[QSC_EDDH_SEED_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	bool ret;

#if defined(QSC_EDDH_S1EC25519)
	/* RFC 7748 X25519 official KAT */
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", seeda, sizeof(seeda));
	qsctest_hex_to_bin("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", seedb, sizeof(seedb));
	qsctest_hex_to_bin("9663AA1DA97E848A914A436D04163DFBB89178F107F1B5B77ED3854203382854", ksec, sizeof(ksec));
	qsctest_hex_to_bin("8F40C5ADB68F25624AE5B214EA767A6EC94D829D3D7B5E1AD1BA6F3E2138285F", kpka, sizeof(kpka));
	qsctest_hex_to_bin("358072D6365880D1AEEA329ADF9121383851ED21A28E3B75E965D0D2CD166254", kpkb, sizeof(kpkb));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", kska, sizeof(kska));
	qsctest_hex_to_bin("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", kskb, sizeof(kskb));
#elif defined(QSC_EDDH_S3EC448)
	/* RFC 7748 X448 official KAT */
	qsctest_hex_to_bin("9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BAF5"
		"74A9419744897391006382A6F127AB1D9AC2D8C0A598726B", seeda, sizeof(seeda));
	qsctest_hex_to_bin("1C306A7AC2A0E2E0990B294470CBA339E6453772B075811D8FAD0D1D6927C120"
		"BB5EE8972B0D3E21374C9C921B09D1B0366F10B65173992D", seedb, sizeof(seedb));
	qsctest_hex_to_bin("07FFF4181AC6CC95EC1C16A94A0F74D12DA232CE40A77552281D282BB60C0B56"
		"FD2464C335543936521C24403085D59A449A5037514A879D", ksec, sizeof(ksec));
	qsctest_hex_to_bin("9B08F7CC31B7E3E67D22D5AEA121074A273BD2B83DE09C63FAA73D2C22C5D9BB"
		"C836647241D953D40C5B12DA88120D53177F80E532C41FA0", kpka, sizeof(kpka));
	qsctest_hex_to_bin("3EB7A829B0CD20F5BCFC0B599B6FECCF6DA4627107BDB0D4F345B43027D8B972"
		"FC3E34FB4232A13CA706DCB57AEC3DAE07BDC1C67BF33609", kpkb, sizeof(kpkb));
	qsctest_hex_to_bin("9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BAF5"
		"74A9419744897391006382A6F127AB1D9AC2D8C0A598726B", kska, sizeof(kska));
	qsctest_hex_to_bin("1C306A7AC2A0E2E0990B294470CBA339E6453772B075811D8FAD0D1D6927C120"
		"BB5EE8972B0D3E21374C9C921B09D1B0366F10B65173992D", kskb, sizeof(kskb));
#else
#	error "No ECDH parameter has been selected!"
#endif
	ret = true;

	/* alice generates a key-pair */
	qsc_eddh_generate_seeded_keypair(pka, ska, seeda);
	/* bob generates a key-pair */
	qsc_eddh_generate_seeded_keypair(pkb, skb, seedb);

	/* test key generation */
	if (qsc_memutils_are_equal(pka, kpka, sizeof(pka)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: public key a does not match expected -EK1 \n");
		ret = false;
	}

	if (qsc_memutils_are_equal(pkb, kpkb, sizeof(pkb)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: public key b does not match expected -EK2 \n");
		ret = false;
	}

	if (qsc_memutils_are_equal(ska, kska, sizeof(ska)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: private key a does not match expected -EK3 \n");
		ret = false;
	}
	
	if (qsc_memutils_are_equal(skb, kskb, sizeof(skb)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: private key b does not match expected -EK4 \n");
		ret = false;
	}

	/* compare the secret key to the expected output */

	/* alice derives the secret key */
	if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: key exchange a has failed -EK5 \n");
		ret = false;
	}

	/* bob derives the secret key */
	if (qsc_eddh_key_exchange(secb, skb, pka) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: key exchange b has failed -EK6 \n");
		ret = false;
	}

	/* fail if alice and bobs secret are not equal */
	if (qsc_memutils_are_equal(seca, secb, sizeof(seca)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: secrets for a and b do not match -EK7 \n");
		ret = false;
	}

	/* fail if secret does not match known answer */
	if (qsc_memutils_are_equal(seca, ksec, sizeof(seca)) != true)
	{
		qsctest_print_safe("Failure! eddh_kat: secret does not match known answer -EK8 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_eddh_operations_test(void)
{
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	bool res;

	res = true;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (size_t i = 0; i < QSCTEST_EDDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_eddh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_eddh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* alice derives the secret key */
		if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! eddh_test_operations: key exchange failure -EO1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_eddh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! eddh_test_operations: key exchange failure -EO2 \n");
			res = false;
			break;
		}

		/* compare them for equality*/
		if (qsc_memutils_are_equal(seca, secb, QSC_EDDH_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! eddh_test_operations: secret keys do not match -EO3 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_eddh_privatekey_integrity(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (size_t i = 0; i < QSCTEST_EDDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_eddh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_eddh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* flip a bit in alices private key */
		ska[1] ^= 1U;

		/* alice derives the secret key */
		if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! eddh_test_privatekey: key exchange failure -ES1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_eddh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! eddh_test_privatekey: key exchange failure -ES2 \n");
			res = false;
			break;
		}

		/* fail if equal */
		if (qsc_memutils_are_equal(seca, secb, QSC_EDDH_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! eddh_test_privatekey: altered private key did not change secret -ES3 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_eddh_publickey_integrity(void)
{
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t pka[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t pkb[QSC_EDDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ska[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t skb[QSC_EDDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seca[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t secb[QSC_EDDH_SHAREDSECRET_SIZE] = { 0 };
	bool res;

	res = true;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	for (size_t i = 0; i < QSCTEST_EDDH_ITERATIONS; i++)
	{
		/* alice generates a key-pair */
		qsc_eddh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		/* bob generates a key-pair */
		qsc_eddh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		/* flip a bit in alices public key */
		pka[0] ^= 1U;

		/* alice derives the secret key */
		if (qsc_eddh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! eddh_test_publickey: key exchange failure -EP1 \n");
			res = false;
			break;
		}

		/* bob derives the secret key */
		if (qsc_eddh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! eddh_test_publickey: key exchange failure -EP2 \n");
			res = false;
			break;
		}

		/* fail if equal */
		if (qsc_memutils_are_equal(seca, secb, QSC_EDDH_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! eddh_test_publickey: altered public key did not change secret -EP3 \n");
			res = false;
			break;
		}
	}

	return res;
}


/* Independent RFC 7748 parameter validation. Both parameter sets run in every build. */

/**
 * \brief Validate X25519 existing deterministic key agreement vectors using its direct public API.
 * \return True if seeded keys, derived public keys and shared secrets match the vector.
 * \details Buffers are local and independent of the selected EDDH facade.
 */
bool qsctest_eddh_x25519_kat_test(void)
{
	uint8_t seeda[QSC_X25519_SEED_SIZE] = { 0U };
	uint8_t seedb[QSC_X25519_SEED_SIZE] = { 0U };
	uint8_t kpka[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t kpkb[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t ksecret[QSC_X25519_SECRET_SIZE] = { 0U };
	uint8_t pka[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t pkb[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t derived[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t ska[QSC_X25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skb[QSC_X25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seca[QSC_X25519_SECRET_SIZE] = { 0U };
	uint8_t secb[QSC_X25519_SECRET_SIZE] = { 0U };
	bool res;

	res = true;
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", seeda, sizeof(seeda));
	qsctest_hex_to_bin("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", seedb, sizeof(seedb));
	qsctest_hex_to_bin("8F40C5ADB68F25624AE5B214EA767A6EC94D829D3D7B5E1AD1BA6F3E2138285F", kpka, sizeof(kpka));
	qsctest_hex_to_bin("358072D6365880D1AEEA329ADF9121383851ED21A28E3B75E965D0D2CD166254", kpkb, sizeof(kpkb));
	qsctest_hex_to_bin("9663AA1DA97E848A914A436D04163DFBB89178F107F1B5B77ED3854203382854", ksecret, sizeof(ksecret));

	qsc_x25519_generate_seeded_keypair(pka, ska, seeda);
	qsc_x25519_generate_seeded_keypair(pkb, skb, seedb);
	qsc_x25519_public_from_private(derived, ska);

	if (qsc_memutils_are_equal(pka, kpka, sizeof(pka)) == false || qsc_memutils_are_equal(pkb, kpkb, sizeof(pkb)) == false)
	{
		qsctest_print_safe("Failure! X25519 direct KAT: public key does not match fixed test vector.\n");
		res = false;
	}

	if (qsc_memutils_are_equal(derived, pka, sizeof(derived)) == false)
	{
		qsctest_print_safe("Failure! X25519 direct KAT: private-to-public derivation differs.\n");
		res = false;
	}

	if (qsc_x25519_key_exchange(seca, pkb, ska) == false || qsc_x25519_key_exchange(secb, pka, skb) == false)
	{
		qsctest_print_safe("Failure! X25519 direct KAT: key agreement rejected valid peer.\n");
		res = false;
	}
	else if (qsc_memutils_are_equal(seca, secb, sizeof(seca)) == false || qsc_memutils_are_equal(seca, ksecret, sizeof(seca)) == false)
	{
		qsctest_print_safe("Failure! X25519 direct KAT: shared secret mismatch.\n");
		res = false;
	}

	qsc_memutils_secure_erase(ska, sizeof(ska));
	qsc_memutils_secure_erase(skb, sizeof(skb));
	qsc_memutils_secure_erase(seca, sizeof(seca));
	qsc_memutils_secure_erase(secb, sizeof(secb));

	return res;
}

/**
 * \brief Exercise independent X25519 random key agreement and invalid peer rejection.
 * \return True if both endpoints agree and all-zero peer public keys are rejected.
 * \details Uses caller-independent local buffers; RNG is the thread-safe CSP provider.
 */
bool qsctest_eddh_x25519_operations_test(void)
{
	uint8_t pka[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t pkb[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t bad[QSC_X25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t ska[QSC_X25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skb[QSC_X25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seca[QSC_X25519_SECRET_SIZE] = { 0U };
	uint8_t secb[QSC_X25519_SECRET_SIZE] = { 0U };
	bool res;

	res = true;
	qsc_x25519_generate_keypair(pka, ska, qsc_csp_generate);
	qsc_x25519_generate_keypair(pkb, skb, qsc_csp_generate);

	if (qsc_memutils_zeroed(ska, sizeof(ska)) == true || qsc_memutils_zeroed(skb, sizeof(skb)) == true ||
		qsc_memutils_zeroed(pka, sizeof(pka)) == true || qsc_memutils_zeroed(pkb, sizeof(pkb)) == true)
	{
		qsctest_print_safe("Failure! X25519 direct operations: random key generation failed.\n");
		res = false;
	}
	else if (qsc_x25519_key_exchange(seca, pkb, ska) == false || qsc_x25519_key_exchange(secb, pka, skb) == false ||
		qsc_memutils_are_equal(seca, secb, sizeof(seca)) == false)
	{
		qsctest_print_safe("Failure! X25519 direct operations: bilateral agreement failed.\n");
		res = false;
	}

	if (qsc_x25519_key_exchange(seca, bad, ska) == true)
	{
		qsctest_print_safe("Failure! X25519 direct operations: invalid all-zero public key accepted.\n");
		res = false;
	}

	qsc_memutils_secure_erase(ska, sizeof(ska));
	qsc_memutils_secure_erase(skb, sizeof(skb));
	qsc_memutils_secure_erase(seca, sizeof(seca));
	qsc_memutils_secure_erase(secb, sizeof(secb));

	return res;
}

/**
 * \brief Validate X448 existing deterministic key agreement vectors using its direct public API.
 * \return True if seeded keys, derived public keys and shared secrets match the vector.
 * \details Buffers are local and independent of the selected EDDH facade.
 */
bool qsctest_eddh_x448_kat_test(void)
{
	uint8_t seeda[QSC_X448_SEED_SIZE] = { 0U };
	uint8_t seedb[QSC_X448_SEED_SIZE] = { 0U };
	uint8_t kpka[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t kpkb[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t ksecret[QSC_X448_SECRET_SIZE] = { 0U };
	uint8_t pka[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t pkb[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t derived[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t ska[QSC_X448_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skb[QSC_X448_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seca[QSC_X448_SECRET_SIZE] = { 0U };
	uint8_t secb[QSC_X448_SECRET_SIZE] = { 0U };
	bool res;

	res = true;
	qsctest_hex_to_bin("9A8F4925D1519F5775CF46B04B5800D4EE9EE8BAE8BC5565D498C28DD9C9BAF574A9419744897391006382A6F127AB1D9AC2D8C0A598726B", seeda, sizeof(seeda));
	qsctest_hex_to_bin("1C306A7AC2A0E2E0990B294470CBA339E6453772B075811D8FAD0D1D6927C120BB5EE8972B0D3E21374C9C921B09D1B0366F10B65173992D", seedb, sizeof(seedb));
	qsctest_hex_to_bin("9B08F7CC31B7E3E67D22D5AEA121074A273BD2B83DE09C63FAA73D2C22C5D9BBC836647241D953D40C5B12DA88120D53177F80E532C41FA0", kpka, sizeof(kpka));
	qsctest_hex_to_bin("3EB7A829B0CD20F5BCFC0B599B6FECCF6DA4627107BDB0D4F345B43027D8B972FC3E34FB4232A13CA706DCB57AEC3DAE07BDC1C67BF33609", kpkb, sizeof(kpkb));
	qsctest_hex_to_bin("07FFF4181AC6CC95EC1C16A94A0F74D12DA232CE40A77552281D282BB60C0B56FD2464C335543936521C24403085D59A449A5037514A879D", ksecret, sizeof(ksecret));

	qsc_x448_generate_seeded_keypair(pka, ska, seeda);
	qsc_x448_generate_seeded_keypair(pkb, skb, seedb);
	qsc_x448_public_from_private(derived, ska);

	if (qsc_memutils_are_equal(pka, kpka, sizeof(pka)) == false || qsc_memutils_are_equal(pkb, kpkb, sizeof(pkb)) == false)
	{
		qsctest_print_safe("Failure! X448 direct KAT: public key does not match fixed test vector.\n");
		res = false;
	}

	if (qsc_memutils_are_equal(derived, pka, sizeof(derived)) == false)
	{
		qsctest_print_safe("Failure! X448 direct KAT: private-to-public derivation differs.\n");
		res = false;
	}

	if (qsc_x448_key_exchange(seca, pkb, ska) == false || qsc_x448_key_exchange(secb, pka, skb) == false)
	{
		qsctest_print_safe("Failure! X448 direct KAT: key agreement rejected valid peer.\n");
		res = false;
	}
	else if (qsc_memutils_are_equal(seca, secb, sizeof(seca)) == false || qsc_memutils_are_equal(seca, ksecret, sizeof(seca)) == false)
	{
		qsctest_print_safe("Failure! X448 direct KAT: shared secret mismatch.\n");
		res = false;
	}

	qsc_memutils_secure_erase(ska, sizeof(ska));
	qsc_memutils_secure_erase(skb, sizeof(skb));
	qsc_memutils_secure_erase(seca, sizeof(seca));
	qsc_memutils_secure_erase(secb, sizeof(secb));

	return res;
}

/**
 * \brief Exercise independent X448 random key agreement and invalid peer rejection.
 * \return True if both endpoints agree and all-zero peer public keys are rejected.
 * \details Uses caller-independent local buffers; RNG is the thread-safe CSP provider.
 */
bool qsctest_eddh_x448_operations_test(void)
{
	uint8_t pka[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t pkb[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t bad[QSC_X448_PUBLICKEY_SIZE] = { 0U };
	uint8_t ska[QSC_X448_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skb[QSC_X448_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seca[QSC_X448_SECRET_SIZE] = { 0U };
	uint8_t secb[QSC_X448_SECRET_SIZE] = { 0U };
	bool res;

	res = true;
	qsc_x448_generate_keypair(pka, ska, qsc_csp_generate);
	qsc_x448_generate_keypair(pkb, skb, qsc_csp_generate);

	if (qsc_memutils_zeroed(ska, sizeof(ska)) == true || qsc_memutils_zeroed(skb, sizeof(skb)) == true ||
		qsc_memutils_zeroed(pka, sizeof(pka)) == true || qsc_memutils_zeroed(pkb, sizeof(pkb)) == true)
	{
		qsctest_print_safe("Failure! X448 direct operations: random key generation failed.\n");
		res = false;
	}
	else if (qsc_x448_key_exchange(seca, pkb, ska) == false || qsc_x448_key_exchange(secb, pka, skb) == false ||
		qsc_memutils_are_equal(seca, secb, sizeof(seca)) == false)
	{
		qsctest_print_safe("Failure! X448 direct operations: bilateral agreement failed.\n");
		res = false;
	}

	if (qsc_x448_key_exchange(seca, bad, ska) == true)
	{
		qsctest_print_safe("Failure! X448 direct operations: invalid all-zero public key accepted.\n");
		res = false;
	}

	qsc_memutils_secure_erase(ska, sizeof(ska));
	qsc_memutils_secure_erase(skb, sizeof(skb));
	qsc_memutils_secure_erase(seca, sizeof(seca));
	qsc_memutils_secure_erase(secb, sizeof(secb));

	return res;
}

/**
 * \brief Regression test for maximal positive lazy limbs in Ed448 multiplication.
 * \return True when the independent modular reference matches both ordinary and aliased multiplication.
 * \details Validates a fixed 448-bit expected residue; inputs are intentionally not normalized.
 * Fixed local state makes the test thread-independent.
 */
bool qsctest_eddh_field_mul_positive_bounds_test(void)
{
	qsc_fe448 f = { 0 };
	qsc_fe448 g = { 0 };
	qsc_fe448 h = { 0 };
	uint8_t actual[ED448_CURVE_SIZE] = { 0U };
	uint8_t expected[ED448_CURVE_SIZE] = { 0U };
	bool res;

	res = true;
	qsctest_hex_to_bin("170500604A000075040040440000130400203E0000B1030000380000660800407C0000620700007000009E0600C0630000DA050080570000", expected, sizeof(expected));

	for (size_t i = 0U; i < 16U; ++i)
	{
		f[i] = INT32_MAX;
		g[i] = INT32_MAX;
	}

	qsc_fe448_mul(h, f, g);
	qsc_fe448_to_bytes(actual, h);

	if (qsc_memutils_are_equal(actual, expected, sizeof(expected)) == false)
	{
		qsctest_print_safe("Failure! Ed448 field multiplication positive-limb overflow regression -FMP1.\n");
		res = false;
	}

	qsc_fe448_mul(f, f, g);
	qsc_fe448_to_bytes(actual, f);

	if (qsc_memutils_are_equal(actual, expected, sizeof(expected)) == false)
	{
		qsctest_print_safe("Failure! Ed448 field multiplication aliased destination -FMP2.\n");
		res = false;
	}

	return res;
}

/**
 * \brief Regression test for maximal negative lazy limbs in Ed448 multiplication.
 * \return True when the computed residue equals the independent modular reference.
 * \details Tests complete signed 32-bit limb input ranges, without global state.
 */
bool qsctest_eddh_field_mul_negative_bounds_test(void)
{
	qsc_fe448 f = { 0 };
	qsc_fe448 g = { 0 };
	qsc_fe448 h = { 0 };
	uint8_t actual[ED448_CURVE_SIZE] = { 0U };
	uint8_t expected[ED448_CURVE_SIZE] = { 0U };

	qsctest_hex_to_bin("80060000600000C005000058000040050000500000C0040000480000C00A0000A00000800900009000008008000080000080070000700000", expected, sizeof(expected));

	for (size_t i = 0U; i < 16U; ++i)
	{
		f[i] = INT32_MIN;
		g[i] = INT32_MIN;
	}

	qsc_fe448_mul(h, f, g);
	qsc_fe448_to_bytes(actual, h);

	if (qsc_memutils_are_equal(actual, expected, sizeof(expected)) == false)
	{
		qsctest_print_safe("Failure! Ed448 field multiplication negative-limb overflow regression -FMN1.\n");
		return false;
	}

	return true;
}

/**
 * \brief Check negative-carry field serialization and reduction.
 * \return True when both paths produce canonical p-1 bytes.
 * \details Prevents the undefined left-shift of a negative carry, without shared state.
 */
bool qsctest_eddh_field_negative_carry_test(void)
{
	qsc_fe448 f = { 0 };
	qsc_fe448 h = { 0 };
	uint8_t actual[ED448_CURVE_SIZE] = { 0U };
	uint8_t expected[ED448_CURVE_SIZE] = { 0U };
	bool res;

	res = true;
	f[0U] = -1;
	qsctest_hex_to_bin("FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", expected, sizeof(expected));
	qsc_fe448_to_bytes(actual, f);

	if (qsc_memutils_are_equal(actual, expected, sizeof(expected)) == false)
	{
		qsctest_print_safe("Failure! Ed448 field serialization of negative carry -FC1.\n");
		res = false;
	}

	qsc_fe448_reduce(h, f);
	qsc_fe448_to_bytes(actual, h);

	if (qsc_memutils_are_equal(actual, expected, sizeof(expected)) == false)
	{
		qsctest_print_safe("Failure! Ed448 field reduction of negative carry -FC2.\n");
		res = false;
	}

	return res;
}

void qsctest_eddh_run(void)
{
	if (qsctest_eddh_field_mul_positive_bounds_test() == true)
	{
		qsctest_print_safe("Success! Passed Ed448 positive-limb overflow regression.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed Ed448 positive-limb overflow regression.\n");
	}

	if (qsctest_eddh_field_mul_negative_bounds_test() == true)
	{
		qsctest_print_safe("Success! Passed Ed448 negative-limb overflow regression.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed Ed448 negative-limb overflow regression.\n");
	}

	if (qsctest_eddh_field_negative_carry_test() == true)
	{
		qsctest_print_safe("Success! Passed Ed448 negative-carry normalization regression.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed Ed448 negative-carry normalization regression.\n");
	}


	if (qsctest_eddh_x25519_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed direct X25519 fixed-vector KAT.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed direct X25519 fixed-vector KAT.\n");
	}

	if (qsctest_eddh_x25519_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed direct X25519 random agreement and invalid-key test.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed direct X25519 random agreement and invalid-key test.\n");
	}

	if (qsctest_eddh_x448_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed direct X448 RFC 7748 KAT.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed direct X448 RFC 7748 KAT.\n");
	}

	if (qsctest_eddh_x448_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed direct X448 random agreement and invalid-key test.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed direct X448 random agreement and invalid-key test.\n");
	}

	if (qsctest_eddh_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed EDDH known answer test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH known answer test. \n");
	}

	if (qsctest_eddh_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed EDDH key generation, encryption, and decryption stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH the encryption stress tests. \n");
	}

	if (qsctest_eddh_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed EDDH secret-key tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH secret-key tamper test. \n");
	}

	if (qsctest_eddh_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed EDDH public-key tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDH public-key tamper test. \n");
	}
}
