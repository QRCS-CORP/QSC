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

/**
 * \file mceliece.c
 * \brief Backward-compatible ISO Classic McEliece plaintext-confirmation facade.
 * \details This facade selects the parameter family using qsccommon.h.
 *          Callers own all buffers. Operations are reentrant for disjoint
 *          input/output arrays and a concurrency-safe RNG callback.
 */

#include "mceliece.h"
#include "mceliecebase.h"

/**
 * \brief Recovers a session key from a plaintext-confirmation ciphertext.
 * \param secret: Caller-owned output, QSC_MCELIECE_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false for invalid
 *         arguments or rejected public padding where applicable.
 * \note Reentrant for disjoint buffers; all memory remains caller-owned.
 */
bool qsc_mceliece_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(privatekey != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = qsc_mceliece_ref_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

/**
 * \brief Encapsulates a plaintext-confirmation session key.
 * \param secret: Caller-owned output, QSC_MCELIECE_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Caller-owned output, QSC_MCELIECE_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Cryptographically secure RNG callback.
 * \return True on success; false for invalid inputs, RNG failure, or invalid padding.
 * \note Reentrant with separate buffers and thread-safe RNG state.
 */
bool qsc_mceliece_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(ciphertext != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
	}

	return res;
}

/**
 * \brief Creates a compatibility-facade plaintext-confirmation keypair.
 * \param publickey: Caller-owned output, QSC_MCELIECE_PUBLICKEY_SIZE bytes.
 * \param privatekey: Caller-owned output, QSC_MCELIECE_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Cryptographically secure RNG callback.
 * \return True on successful key generation; false on invalid arguments or RNG failure.
 * \note Key generation requires a sufficiently large caller thread stack.
 *       Reentrant with independent buffers and thread-safe RNG state.
 */
bool qsc_mceliece_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);
	
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_ref_generate_keypair(publickey, privatekey, rng_generate);
	}

	return res;
}
