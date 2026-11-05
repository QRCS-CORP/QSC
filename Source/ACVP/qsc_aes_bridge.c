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

#include "aes.h"
#include "memutils.h"

/**
 * \brief Execute a single AES-GCM-128 or AES-GCM-256 ACVP AFT case.
 *
 * The IV is externally supplied, 96 bits long, and the tag is always 128 bits.
 * Encryption writes inputlen bytes of ciphertext followed by a 16-byte tag.
 * Decryption expects inputlen bytes of ciphertext followed by a 16-byte tag;
 * it writes inputlen plaintext bytes only on successful authentication.
 * This adapter owns all temporary states and does not retain input pointers.
 * This function is stateless and safe for concurrent independent calls.
 *
 * \param key Input 16- or 32-byte AES key; borrowed, never retained.
 * \param keylen Key length in bytes; must be 16 or 32.
 * \param iv Input 12-byte nonce; borrowed, never retained.
 * \param ivlen IV length in bytes; must be 12.
 * \param aad Optional associated data, required if aadlen is nonzero.
 * \param aadlen Length of AAD in bytes; maximum QSC_GCM_MAXAAD_SIZE.
 * \param input Input plaintext (encrypt) or ciphertext + tag (decrypt).
 * \param inputlen Number of plaintext or ciphertext bytes, excluding tag.
 * \param output Output capacity inputlen + 16 (encrypt) or inputlen (decrypt).
 * \param encryption True to encrypt, false to authenticate and decrypt.
 * \return 1 on success, 0 on invalid arguments or authentication failure.
 * \warning Output must not overlap input or any other supplied buffer.
 */
QSC_EXPORT_API int qsc_acvp_aes_gcm_execute(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen,
	const uint8_t* aad, size_t aadlen, const uint8_t* input, size_t inputlen, uint8_t* output, bool encryption)
{
	qsc_aes_keyparams kp = { 0U };
	uint8_t nonce[QSC_GCM_NONCE_SIZE] = { 0U };
	int result;

	result = 0;

	if (key != NULL && iv != NULL && input != NULL && output != NULL &&
		(keylen == QSC_AES128_KEY_SIZE || keylen == QSC_AES256_KEY_SIZE) &&
		ivlen == QSC_GCM_NONCE_SIZE && aadlen <= QSC_GCM_MAXAAD_SIZE &&
		(aad != NULL || aadlen == 0U) && inputlen <= 8192U)
	{
		qsc_memutils_copy(nonce, iv, sizeof(nonce));
		kp.key = key;
		kp.keylen = keylen;
		kp.nonce = nonce;
		kp.noncelen = sizeof(nonce);

		if (keylen == QSC_AES128_KEY_SIZE)
		{
			qsc_aes_gcm128_state ctx = { 0U };

			qsc_aes_gcm128_initialize(&ctx, &kp, encryption);
			qsc_aes_gcm128_set_associated(&ctx, aad, aadlen);
			result = qsc_aes_gcm128_transform(&ctx, output, input, inputlen) ? 1 : 0;
			qsc_aes_gcm128_dispose(&ctx);
		}
		else
		{
			qsc_aes_gcm256_state ctx = { 0U };

			qsc_aes_gcm256_initialize(&ctx, &kp, encryption);
			qsc_aes_gcm256_set_associated(&ctx, aad, aadlen);
			result = qsc_aes_gcm256_transform(&ctx, output, input, inputlen) ? 1 : 0;
			qsc_aes_gcm256_dispose(&ctx);
		}
	}

	qsc_memutils_secure_erase(nonce, sizeof(nonce));
	return result;
}

/**
 * \brief Execute one raw AES-ECB block for ACVP AFT or MCT testing.
 * \param key Borrowed 16- or 32-byte AES key.
 * \param keylen Key length, 16 or 32 bytes.
 * \param input Borrowed 16-byte block, not overlapping output.
 * \param output Caller-owned writable 16-byte block.
 * \param encryption True for encrypt, false for decrypt.
 * \return 1 on success, 0 for invalid arguments.
 * \note Stateless, thread safe, and never retains caller buffers.
 */
QSC_EXPORT_API int qsc_acvp_aes_ecb_block(const uint8_t* key, size_t keylen,
	const uint8_t* input, uint8_t* output, bool encryption)
{
	qsc_aes_keyparams kp = { 0U };
	qsc_aes_state ctx = { 0U };
	int result;

	result = 0;

	if (key != NULL && input != NULL && output != NULL &&
		(keylen == QSC_AES128_KEY_SIZE || keylen == QSC_AES256_KEY_SIZE))
	{
		kp.key = key;
		kp.keylen = keylen;
		qsc_aes_initialize(&ctx, &kp, encryption,
			keylen == QSC_AES128_KEY_SIZE ? qsc_aes_cipher_128 : qsc_aes_cipher_256);

		if (encryption)
		{
			qsc_aes_ecb_encrypt_block(&ctx, output, input);
		}
		else
		{
			qsc_aes_ecb_decrypt_block(&ctx, output, input);
		}

		result = 1;
	}

	qsc_aes_dispose(&ctx);
	return result;
}

/**
 * \brief Execute unpadded AES-CBC encryption or decryption for an ACVP vector.
 * \param key Borrowed 16- or 32-byte key, not retained.
 * \param keylen Key length in bytes.
 * \param iv Borrowed 16-byte IV, not modified.
 * \param input Borrowed block-aligned data, disjoint from output.
 * \param inputlen Input length in bytes, between 16 and 8192 inclusive.
 * \param output Caller-owned buffer of at least inputlen bytes.
 * \param encryption True for encryption, false for decryption.
 * \return 1 for a completed transform, otherwise 0; output untouched on rejection.
 * \note Stateless across calls and safe for independent concurrent invocations.
 */
QSC_EXPORT_API int qsc_acvp_aes_cbc_execute(const uint8_t* key, size_t keylen,
	const uint8_t* iv, const uint8_t* input, size_t inputlen,
	uint8_t* output, bool encryption)
{
	qsc_aes_keyparams kp = { 0U };
	qsc_aes_state ctx = { 0U };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0U };
	size_t i;
	int result;

	result = 0;

	if (key != NULL && iv != NULL && input != NULL && output != NULL &&
		(keylen == QSC_AES128_KEY_SIZE || keylen == QSC_AES256_KEY_SIZE) &&
		inputlen >= QSC_AES_BLOCK_SIZE && inputlen <= 8192U &&
		(inputlen % QSC_AES_BLOCK_SIZE) == 0U)
	{
		qsc_memutils_copy(nonce, iv, sizeof(nonce));
		kp.key = key;
		kp.keylen = keylen;
		kp.nonce = nonce;
		kp.noncelen = sizeof(nonce);
		qsc_aes_initialize(&ctx, &kp, encryption,
			keylen == QSC_AES128_KEY_SIZE ? qsc_aes_cipher_128 : qsc_aes_cipher_256);

		for (i = 0U; i < inputlen; i += QSC_AES_BLOCK_SIZE)
		{
			if (encryption)
			{
				qsc_aes_cbc_encrypt_block(&ctx, output + i, input + i);
			}
			else
			{
				qsc_aes_cbc_decrypt_block(&ctx, output + i, input + i);
			}
		}

		result = 1;
	}

	qsc_aes_dispose(&ctx);
	qsc_memutils_secure_erase(nonce, sizeof(nonce));

	return result;
}

/**
 * \brief Execute byte-aligned AES-CTR with a supplied 128-bit big-endian counter.
 * \param key Borrowed 16- or 32-byte AES key, not retained.
 * \param keylen Key length in bytes.
 * \param iv Borrowed 16-byte initial counter value, not modified.
 * \param input Borrowed input of inputlen bytes, disjoint from output.
 * \param inputlen Length in bytes, between 1 and 1048576 inclusive.
 * \param output Caller-owned buffer of at least inputlen bytes.
 * \return 1 on completed transform; 0 for invalid parameters.
 * \note Stateless, no allocation, thread-safe for independent calls. Caller
 * must ensure the counter sequence does not repeat under a given key.
 */
QSC_EXPORT_API int qsc_acvp_aes_ctrbe_execute(const uint8_t* key, size_t keylen,
	const uint8_t* iv, const uint8_t* input, size_t inputlen, uint8_t* output)
{
	qsc_aes_keyparams kp = { 0U };
	qsc_aes_state ctx = { 0U };
	uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0U };
	int result;

	result = 0;

	if (key != NULL && iv != NULL && input != NULL && output != NULL &&
		(keylen == QSC_AES128_KEY_SIZE || keylen == QSC_AES256_KEY_SIZE) &&
		inputlen > 0U && inputlen <= 1048576U)
	{
		qsc_memutils_copy(nonce, iv, sizeof(nonce));
		kp.key = key;
		kp.keylen = keylen;
		kp.nonce = nonce;
		kp.noncelen = sizeof(nonce);
		qsc_aes_initialize(&ctx, &kp, true,
			keylen == QSC_AES128_KEY_SIZE ? qsc_aes_cipher_128 : qsc_aes_cipher_256);
		qsc_aes_ctrbe_transform(&ctx, output, input, inputlen);
		result = 1;
	}

	qsc_aes_dispose(&ctx);
	qsc_memutils_secure_erase(nonce, sizeof(nonce));

	return result;
}
