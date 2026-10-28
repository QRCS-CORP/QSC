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

/*
 * Compile-time instantiation of the shared Classic McEliece implementation.
 * Only the literal parameter selector and exported names differ.
 */
#if defined(QSC_MCELIECE_S3N4608T96)
#	undef QSC_MCELIECE_S3N4608T96
#endif
#if defined(QSC_MCELIECE_S6N6960T119)
#	undef QSC_MCELIECE_S6N6960T119
#endif
#if defined(QSC_MCELIECE_S7N8192T128)
#	undef QSC_MCELIECE_S7N8192T128
#endif
#define QSC_MCELIECE_S5N6688T128
#include "mceliece_multi.h"

#define qsc_mceliece_ref_decapsulate qsc_mceliece_6688128_ref_decapsulate
#define qsc_mceliece_ref_encapsulate qsc_mceliece_6688128_ref_encapsulate
#define qsc_mceliece_ref_generate_keypair qsc_mceliece_6688128_ref_generate_keypair

/**
 * \def QSC_MCELIECE_NO_PLAINTEXT_CONFIRMATION
 * \brief Selects the ordinary ISO ciphertext and session-key derivation.
 * \note Defined only while instantiating this translation unit.
 */
#define QSC_MCELIECE_NO_PLAINTEXT_CONFIRMATION
#include "mceliecebase.c"
#undef QSC_MCELIECE_NO_PLAINTEXT_CONFIRMATION

#undef qsc_mceliece_ref_decapsulate
#undef qsc_mceliece_ref_encapsulate
#undef qsc_mceliece_ref_generate_keypair

/**
 * \brief Decapsulates 6688128 via its independently compiled core.
 * \param secret: Caller-owned 32-byte output.
 * \param ciphertext: Caller-owned 208-byte input.
 * \param privatekey: Caller-owned 13932-byte input.
 * \return True when processed; false for null inputs or rejected padding.
 * \note Reentrant with distinct buffers.
 */
bool qsc_mceliece_6688128_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey)
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && privatekey != NULL)
	{
		res = qsc_mceliece_6688128_ref_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

/**
 * \brief Encapsulates 6688128 using the provided RNG.
 * \param secret: Caller-owned 32-byte output.
 * \param ciphertext: Caller-owned 208-byte output.
 * \param publickey: Caller-owned 1044992-byte input.
 * \param rng_generate: Secure RNG callback; must synchronize shared state.
 * \return True on success, otherwise false.
 * \note Reentrant for distinct buffers and RNG state.
 */
bool qsc_mceliece_6688128_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && publickey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_6688128_ref_encapsulate(ciphertext, secret, publickey, rng_generate);
	}

	return res;
}

/**
 * \brief Generates a 6688128 key pair.
 * \param publickey: Caller-owned 1044992-byte output.
 * \param privatekey: Caller-owned 13932-byte output.
 * \param rng_generate: Secure RNG callback; must synchronize shared state.
 * \return True on success, otherwise false.
 * \note Requires a large stack; reentrant with independent RNG and buffers.
 */
bool qsc_mceliece_6688128_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		res = qsc_mceliece_6688128_ref_generate_keypair(publickey, privatekey, rng_generate);
	}

	return res;
}
