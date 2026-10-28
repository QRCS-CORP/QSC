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

/* Include only in one parameter-specific SLH-DSA translation unit.
 * The following five public-name selectors are object-like macros, never
 * function-like macros or generated identifiers.
 */

/** \brief Validate the common pure SLH-DSA input contract.
 * \param message Message pointer, NULL for empty only.
 * \param msglen Message length in bytes.
 * \param context Context pointer, NULL for empty only.
 * \param ctxlen Context length, 0..255.
 * \return True when pointers and lengths describe valid input.
 * \note No ownership transfer; thread-safe.
 */
static bool slhdsa_validate_message(const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen)
{
	return (ctxlen <= 255U && (message != NULL || msglen == 0U) && (context != NULL || ctxlen == 0U));
}

/** \brief Assemble FIPS 205 pure-domain prefix 0x00 || ctxlen || ctx.
 * \param pre Output buffer, exactly 257 bytes.
 * \param context Caller-owned context, NULL if ctxlen zero.
 * \param ctxlen Context length, at most 255 bytes.
 * \note Reentrant; no heap allocation.
 */
static void slhdsa_make_pure_prefix(uint8_t pre[257U], const uint8_t* context, size_t ctxlen)
{
	pre[0U] = 0U;
	pre[1U] = (uint8_t)ctxlen;

	if (ctxlen != 0U)
	{
		qsc_memutils_copy(pre + 2U, context, ctxlen);
	}
}

/** \brief Generate a FIPS 205 SLH-DSA key pair.
 * \param publickey Output 2*n bytes.
 * \param privatekey Output 4*n bytes; secret.
 * \param rng_generate Caller-supplied approved random generator.
 * \return True on success; false on invalid pointers or RNG failure.
 * \note Reentrant and caller-owned buffers.
 */
bool SLH_DSA_KEYGEN(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	if (publickey == NULL || privatekey == NULL || rng_generate == NULL)
	{
		return false;
	}

	return sphincsplus_ref_generate_keypair(publickey, privatekey, rng_generate);
}

/** \brief Generate a repeatable FIPS 205 SLH-DSA key pair from 3*n seed bytes.
 * \param publickey Output 2*n bytes.
 * \param privatekey Output 4*n bytes; secret.
 * \param seed Input 3*n bytes, remains caller-owned.
 * \return True on success, false for invalid input.
 * \note Reentrant; does not erase caller input.
 */
bool SLH_DSA_SEEDED_KEYGEN(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[SPHINCSPLUS_CRYPTO_SEEDBYTES])
{
	if (publickey == NULL || privatekey == NULL || seed == NULL)
	{
		return false;
	}

	return sphincsplus_ref_generate_seeded_keypair(publickey, privatekey, seed);
}

/** \brief Generate a hedged pure FIPS 205 detached signature.
 * \param signature Output SPX_BYTES bytes.
 * \param siglen Receives signature length on success, zero otherwise.
 * \param message Caller-owned message, optional for zero msglen.
 * \param msglen Message length.
 * \param context Optional caller-owned context.
 * \param ctxlen Context length, at most 255.
 * \param privatekey Caller-owned 4*n-byte private key.
 * \param rng_generate Generator of an additional n random bytes.
 * \return True on success; false on invalid parameters or randomizer failure.
 * \note Reentrant; wipes randomizer after signing.
 */
bool SLH_DSA_SIGN(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t pre[257U] = { 0U };
	uint8_t optrand[SPX_N] = { 0U };
	const uint8_t empty = 0U;
	bool result;

	if (siglen != NULL)
	{
		*siglen = 0U;
	}

	if (signature == NULL || siglen == NULL || privatekey == NULL || rng_generate == NULL || !slhdsa_validate_message(message, msglen, context, ctxlen))
	{
		return false;
	}

	result = rng_generate(optrand, sizeof(optrand));

	if (result == true)
	{
		slhdsa_make_pure_prefix(pre, context, ctxlen);
		result = sphincsplus_ref_sign_signature(signature, siglen, (message != NULL) ? message : &empty, msglen, pre, ctxlen + 2U, privatekey, optrand);
	}

	qsc_memutils_secure_erase(optrand, sizeof(optrand));

	return result;
}

/** \brief Generate a pure FIPS 205 deterministic detached signature.
 * \param signature Output SPX_BYTES bytes.
 * \param siglen Receives signature length, or zero on failure.
 * \param message Caller-owned message; NULL permitted for empty input.
 * \param msglen Message length.
 * \param context Caller-owned context; NULL permitted for empty context.
 * \param ctxlen Context length, maximum 255 bytes.
 * \param privatekey Caller-owned secret key, 4*n bytes.
 * \return True on success.
 * \note Reentrant; FIPS 205 deterministic opt_rand equals PK.seed in private key.
 */
bool SLH_DSA_SIGN_DETERMINISTIC(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey)
{
	uint8_t pre[257U] = { 0U };
	const uint8_t empty = 0U;

	if (siglen != NULL)
	{
		*siglen = 0U;
	}

	if (signature == NULL || siglen == NULL || privatekey == NULL || !slhdsa_validate_message(message, msglen, context, ctxlen))
	{
		return false;
	}

	slhdsa_make_pure_prefix(pre, context, ctxlen);

	return sphincsplus_ref_sign_signature(signature, siglen, (message != NULL) ? message : &empty, msglen, pre, ctxlen + 2U, privatekey, privatekey + (2U * SPX_N));
}

/** \brief Verify exactly one pure FIPS 205 detached signature.
 * \param signature Caller-owned SPX_BYTES-byte signature.
 * \param siglen Signature length, must be SPX_BYTES.
 * \param message Caller-owned message or NULL for empty.
 * \param msglen Message length.
 * \param context Caller-owned context or NULL for empty.
 * \param ctxlen Context length, 0..255.
 * \param publickey Caller-owned 2*n-byte public key.
 * \return True only if the cryptographic signature verifies.
 * \note Reentrant; no heap or ownership transfer.
 */
bool SLH_DSA_VERIFY(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* publickey)
{
	uint8_t pre[257U] = { 0U };
	const uint8_t empty = 0U;

	if (signature == NULL || publickey == NULL || siglen != SPX_BYTES || !slhdsa_validate_message(message, msglen, context, ctxlen))
	{
		return false;
	}

	slhdsa_make_pure_prefix(pre, context, ctxlen);

	return sphincsplus_ref_verify(signature, siglen, (message != NULL) ? message : &empty, msglen, pre, ctxlen + 2U, publickey);
}

/** \brief Build HashSLH-DSA prehash domain prefix and message digest.
 * \param prefix Output 268-byte scratch area, containing 1 || ctxlen || ctx || OID.
 * \param digest Output at least 64 bytes, caller-owned temporary.
 * \param digestlen Receives 32 or 64 bytes.
 * \param message Non-null caller-owned message (possibly zero-length).
 * \param msglen Message length.
 * \param context Context pointer, NULL only if ctxlen zero.
 * \param ctxlen Context length, 0..255.
 * \param algorithm One of the supported FIPS 205 prehash identifiers.
 * \return True for a supported algorithm with valid input.
 * \note Reentrant; caller securely wipes the output digest after use.
 */
static bool slhdsa_prepare_prehash(uint8_t prefix[268U], uint8_t digest[64U], size_t* digestlen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm)
{
	uint8_t oid[11U] = { 0x06U, 0x09U, 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0U };

	if (prefix == NULL || digest == NULL || digestlen == NULL || !slhdsa_validate_message(message, msglen, context, ctxlen))
	{
		return false;
	}

	prefix[0U] = 1U;
	prefix[1U] = (uint8_t)ctxlen;

	if (ctxlen != 0U)
	{
		qsc_memutils_copy(prefix + 2U, context, ctxlen);
	}

	*digestlen = 0U;

#if SPX_N > 16U
	/* FIPS 205: a 128-bit strength prehash cannot serve a Level 3/5 variant. */
	if (algorithm == qsc_slhdsa_prehash_sha256 || algorithm == qsc_slhdsa_prehash_shake128)
	{
		return false;
	}
#endif

	switch (algorithm)
	{
		case qsc_slhdsa_prehash_sha256:
		{
			oid[10U] = 1U;
			*digestlen = 32U;
			qsc_sha256_compute(digest, message, msglen);
			break;
		}
		case qsc_slhdsa_prehash_sha512:
		{
			oid[10U] = 3U;
			*digestlen = 64U;
			qsc_sha512_compute(digest, message, msglen);
			break;
		}
		case qsc_slhdsa_prehash_shake128:
		{
			oid[10U] = 11U;
			*digestlen = 32U;
			qsc_shake128_compute(digest, *digestlen, message, msglen);
			break;
		}
		case qsc_slhdsa_prehash_shake256:
		{
			oid[10U] = 12U;
			*digestlen = 64U;
			qsc_shake256_compute(digest, *digestlen, message, msglen);
			break;
		}
		default:
		{
			return false;
		}
	}

	qsc_memutils_copy(prefix + 2U + ctxlen, oid, sizeof(oid));

	return true;
}

/** \brief Internally sign a prehashed message using a supplied randomizer.
 * \param signature Caller-owned output SPX_BYTES bytes.
 * \param siglen Receives signature size on success or zero on failure.
 * \param message Input message; NULL if zero length.
 * \param msglen Message length.
 * \param context Optional context, max 255 bytes.
 * \param ctxlen Context length.
 * \param algorithm FIPS-approved prehash selector.
 * \param privatekey Caller-owned private key, 4*n bytes.
 * \param randomizer Caller-owned n-byte randomizer.
 * \return True on success.
 * \note Reentrant; securely erases its 64-byte prehash digest.
 */
static bool slhdsa_sign_prehash_internal(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, const uint8_t* randomizer)
{
	uint8_t prefix[268U] = { 0U };
	uint8_t digest[64U] = { 0U };
	const uint8_t empty = 0U;
	size_t digestlen;
	bool result;

	if (siglen != NULL)
	{
		*siglen = 0U;
	}

	if (signature == NULL || siglen == NULL || privatekey == NULL || randomizer == NULL || !slhdsa_validate_message(message, msglen, context, ctxlen))
	{
		return false;
	}

	result = slhdsa_prepare_prehash(prefix, digest, &digestlen, (message != NULL) ? message : &empty, msglen, context, ctxlen, algorithm);

	if (result == true)
	{
		result = sphincsplus_ref_sign_signature(signature, siglen, digest, digestlen, prefix, ctxlen + 13U, privatekey, randomizer);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return result;
}

/** \brief Generate hedged HashSLH-DSA detached signature.
 * \param signature Output SPX_BYTES bytes.
 * \param siglen Output signature length.
 * \param message Input plaintext, NULL permitted for empty.
 * \param msglen Message length.
 * \param context Optional context, max 255 bytes.
 * \param ctxlen Context length.
 * \param algorithm Supported prehash algorithm.
 * \param privatekey Input secret key, 4*n bytes.
 * \param rng_generate Randomizer callback, must be cryptographically secure.
 * \return True on success.
 * \note Reentrant; wipes randomizer and digest.
 */
bool SLH_DSA_SIGN_PREHASH(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t optrand[SPX_N] = { 0U };
	bool result;

	if (siglen != NULL)
	{
		*siglen = 0U;
	}

	if (signature == NULL || siglen == NULL || privatekey == NULL || rng_generate == NULL || !slhdsa_validate_message(message, msglen, context, ctxlen))
	{
		return false;
	}

	/* Reject unsupported hash identifiers without consuming caller randomness. */
	if (algorithm != qsc_slhdsa_prehash_sha256 && algorithm != qsc_slhdsa_prehash_sha512 &&
		algorithm != qsc_slhdsa_prehash_shake128 && algorithm != qsc_slhdsa_prehash_shake256)
	{
		return false;
	}

#if SPX_N > 16U
	if (algorithm == qsc_slhdsa_prehash_sha256 || algorithm == qsc_slhdsa_prehash_shake128)
	{
		return false;
	}
#endif

	result = rng_generate(optrand, sizeof(optrand));

	if (result == true)
	{
		result = slhdsa_sign_prehash_internal(signature, siglen, message, msglen, context, ctxlen, algorithm, privatekey, optrand);
	}

	qsc_memutils_secure_erase(optrand, sizeof(optrand));

	return result;
}

/** \brief Generate deterministic HashSLH-DSA detached signature.
 * \param signature Output SPX_BYTES bytes.
 * \param siglen Output signature length.
 * \param message Input plaintext, NULL permitted for empty.
 * \param msglen Message length.
 * \param context Optional context, max 255 bytes.
 * \param ctxlen Context length.
 * \param algorithm Supported prehash function.
 * \param privatekey Input secret key, 4*n bytes.
 * \return True on success.
 * \note Reentrant; FIPS deterministic randomizer equals PK.seed.
 */
bool SLH_DSA_SIGN_PREHASH_DETERMINISTIC(uint8_t* signature, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* privatekey)
{
	if (siglen != NULL)
	{
		*siglen = 0U;
	}

	if (privatekey == NULL)
	{
		return false;
	}

	return slhdsa_sign_prehash_internal(signature, siglen, message, msglen, context, ctxlen, algorithm, privatekey, privatekey + (2U * SPX_N));
}

/** \brief Verify a HashSLH-DSA signature using FIPS 205 prehash domain.
 * \param signature Fixed-size caller-owned detached signature.
 * \param siglen Must match SPX_BYTES.
 * \param message Caller-owned plaintext, NULL for zero length only.
 * \param msglen Message length.
 * \param context Optional context pointer, max 255 bytes.
 * \param ctxlen Context length.
 * \param algorithm Supported prehash algorithm.
 * \param publickey Input public key, 2*n bytes.
 * \return True only if signature verifies.
 * \note Reentrant; erases temporary prehash digest.
 */
bool SLH_DSA_VERIFY_PREHASH(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, qsc_slhdsa_prehash_algorithm algorithm, const uint8_t* publickey)
{
	uint8_t prefix[268U] = { 0U };
	uint8_t digest[64U] = { 0U };
	const uint8_t empty = 0U;
	size_t digestlen;
	bool result;

	if (signature == NULL || publickey == NULL || siglen != SPX_BYTES || !slhdsa_validate_message(message, msglen, context, ctxlen))
	{
		return false;
	}

	result = slhdsa_prepare_prehash(prefix, digest, &digestlen, (message != NULL) ? message : &empty, msglen, context, ctxlen, algorithm);

	if (result == true)
	{
		result = sphincsplus_ref_verify(signature, siglen, digest, digestlen, prefix, ctxlen + 13U, publickey);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return result;
}
