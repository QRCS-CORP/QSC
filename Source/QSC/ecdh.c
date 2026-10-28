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

#include "ecdh.h"
#include "memutils.h"
#if defined(QSC_ECDH_S1P256)
#	include "ecdhp256.h"
#elif defined(QSC_ECDH_S3P384)
#	include "ecdhp384.h"
#elif defined(QSC_ECDH_S5P521)
#	include "ecdhp521.h"
#else
#   error "No ECDH parameter set defined. Define QSC_ECDH_S1P256, QSC_ECDH_S3P384, or QSC_ECDH_S5P521."
#endif

bool qsc_ecdh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;

	res = false;

	if (privatekey != NULL && publickey != NULL && rng_generate != NULL)
	{
#if defined(QSC_ECDH_S1P256)
		qsc_p256_generate_keypair(publickey, privatekey, rng_generate);
#elif defined(QSC_ECDH_S3P384)
		qsc_p384_generate_keypair(publickey, privatekey, rng_generate);
#else
		qsc_p521_generate_keypair(publickey, privatekey, rng_generate);
#endif

		if (qsc_memutils_zeroed(publickey, QSC_ECDH_PUBLICKEY_SIZE) == false && 
			qsc_memutils_zeroed(privatekey, QSC_ECDH_PRIVATEKEY_SIZE) == false)
		{
			res = true;
		}
	}

	return res;
}

bool qsc_ecdh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(seed != NULL);

	bool res;

	res = false;

	if (privatekey != NULL && publickey != NULL && seed != NULL)
	{
#if defined(QSC_ECDH_S1P256)
		qsc_p256_generate_seeded_keypair(publickey, privatekey, seed);
#elif defined(QSC_ECDH_S3P384)
		qsc_p384_generate_seeded_keypair(publickey, privatekey, seed);
#else
		qsc_p521_generate_seeded_keypair(publickey, privatekey, seed);
#endif

		if (qsc_memutils_zeroed(publickey, QSC_ECDH_PUBLICKEY_SIZE) == false && 
			qsc_memutils_zeroed(privatekey, QSC_ECDH_PRIVATEKEY_SIZE) == false)
		{
			res = true;
		}
	}

	return res;
}

bool qsc_ecdh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

	bool res;

	res = false;

	if (secret != NULL && privatekey != NULL && publickey != NULL)
	{
#if defined(QSC_ECDH_S1P256)
		res = qsc_p256_key_exchange(secret, publickey, privatekey);
#elif defined(QSC_ECDH_S3P384)
		res = qsc_p384_key_exchange(secret, publickey, privatekey);
#else
		res = qsc_p521_key_exchange(secret, publickey, privatekey);
#endif
	}

	return res;
}

void qsc_ecdh_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	if (publickey != NULL && privatekey != NULL)
	{
#if defined(QSC_ECDH_S1P256)
		qsc_p256_public_from_private(publickey, privatekey);
#elif defined(QSC_ECDH_S3P384)
		qsc_p384_public_from_private(publickey, privatekey);
#else
		qsc_p521_public_from_private(publickey, privatekey);
#endif
	}
}
