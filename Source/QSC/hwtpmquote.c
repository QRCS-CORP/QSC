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

#include "hwtpmquote.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_TPM_ENABLED)

#include "ecdsap256.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"

/** \def HWTPM_GENERATED_VALUE
 * \brief TPM_GENERATED_VALUE magic for TPMS_ATTEST, in network byte order.
 */
#define HWTPM_GENERATED_VALUE UINT32_C(0xFF544347)

/** \def HWTPM_ST_ATTEST_QUOTE
 * \brief TPM_ST_ATTEST_QUOTE attestation discriminator.
 */
#define HWTPM_ST_ATTEST_QUOTE 0x8018U

/** \def HWTPM_ALG_SHA256
 * \brief TPM2_ALG_SHA256 mechanism value.
 */
#define HWTPM_ALG_SHA256 0x000BU

/** \def HWTPM_ALG_ECDSA
 * \brief TPM2_ALG_ECDSA mechanism value.
 */
#define HWTPM_ALG_ECDSA 0x0018U

/** \struct hwtpm_cursor
 * \brief Bounded read-only TPM wire cursor.
 */
typedef struct hwtpm_cursor
{
	const uint8_t* bytes; /**< Borrowed read-only serialized bytes. */
	size_t length; /**< Total number of available bytes. */
	size_t offset; /**< Current validated read position. */
} hwtpm_cursor;

/** \brief Consume a bounded number of bytes from a wire cursor.
 * \param cursor Mutable cursor with valid byte span.
 * \param length Requested byte count.
 * \param output Receives the borrowed subspan, or NULL on exhaustion.
 * \return true only if the complete requested subspan is present; no overflow.
 */
static bool hwtpm_take(hwtpm_cursor* cursor, size_t length, const uint8_t** output)
{
	bool valid;

	valid = false;

	if (cursor != NULL && output != NULL && cursor->offset <= cursor->length &&
		length <= cursor->length - cursor->offset)
	{
		*output = cursor->bytes + cursor->offset;
		cursor->offset += length;
		valid = true;
	}

	return valid;
}

/** \brief Read one unsigned big-endian 16-bit TPM wire integer.
 * \param cursor Cursor to advance on success only.
 * \param output Receives integer on success.
 * \return true when at least two bytes are available.
 */
static bool hwtpm_u16(hwtpm_cursor* cursor, uint16_t* output)
{
	const uint8_t* bytes;
	bool valid;

	valid = false;

	if (output != NULL && hwtpm_take(cursor, 2U, &bytes) == true)
	{
		*output = (uint16_t)(((uint16_t)bytes[0U] << 8U) | bytes[1U]);
		valid = true;
	}

	return valid;
}

/** \brief Read one unsigned big-endian 32-bit TPM wire integer.
 * \param cursor Cursor to advance on success only.
 * \param output Receives integer on success.
 * \return true when at least four bytes are available.
 */
static bool hwtpm_u32(hwtpm_cursor* cursor, uint32_t* output)
{
	const uint8_t* bytes;
	bool valid;

	valid = false;

	if (output != NULL && hwtpm_take(cursor, 4U, &bytes) == true)
	{
		*output = qsc_intutils_be8to32(bytes);
		valid = true;
	}

	return valid;
}

/** \brief Consume a TPM2B-sized byte sequence without allocating memory.
 * \param cursor Cursor at a TPM2B length field.
 * \param output Receives borrowed byte span.
 * \param length Receives validated byte length.
 * \return true only if size and data both fit inside the cursor.
 */
static bool hwtpm_2b(hwtpm_cursor* cursor, const uint8_t** output, uint16_t* length)
{
	bool valid;

	valid = false;

	if (hwtpm_u16(cursor, length) == true)
	{
		valid = hwtpm_take(cursor, (size_t)*length, output);
	}

	return valid;
}

/** \brief Decode an ECDSA P-256 TPMT_SIGNATURE into fixed-width r||s.
 * \param source Serialized TPM signature.
 * \param length Exact signature length in bytes.
 * \param output Caller-owned 64-byte signature buffer, erased on failure.
 * \return success for valid SHA-256 ECDSA structure; unsupported for other schemes.
 */
static qsc_hw_status hwtpm_signature(const uint8_t* source, size_t length, uint8_t* output)
{
	hwtpm_cursor cursor;
	const uint8_t* component;
	uint16_t componentlen;
	uint16_t algorithm;
	uint16_t hash;
	qsc_hw_status status;

	cursor.bytes = source;
	cursor.length = length;
	cursor.offset = 0U;
	status = qsc_hw_status_invalid_parameter;
	qsc_memutils_clear(output, 64U);

	if (hwtpm_u16(&cursor, &algorithm) == true && hwtpm_u16(&cursor, &hash) == true)
	{
		if (algorithm != HWTPM_ALG_ECDSA || hash != HWTPM_ALG_SHA256)
		{
			status = qsc_hw_status_unsupported;
		}
		else if (hwtpm_2b(&cursor, &component, &componentlen) == true && componentlen != 0U && componentlen <= 32U)
		{
			qsc_memutils_copy(output + 32U - componentlen, component, componentlen);

			if (hwtpm_2b(&cursor, &component, &componentlen) == true && componentlen != 0U && componentlen <= 32U && cursor.offset == cursor.length)
			{
				qsc_memutils_copy(output + 64U - componentlen, component, componentlen);
				status = qsc_hw_status_success;
			}
		}
	}

	if (status != qsc_hw_status_success)
	{
		qsc_memutils_secure_erase(output, 64U);
	}

	return status;
}

/** \brief Parse and validate an exact SHA-256 TPM quote policy and its claims.
 * \param quote Raw TPMS_ATTEST bytes.
 * \param quotelen Size of the supplied quote.
 * \param policy Trusted caller policy.
 * \return success only for matching canonical signed claims; malformed claims fail closed.
 */
static qsc_hw_status hwtpm_claims(const uint8_t* quote, size_t quotelen, const qsc_hw_tpm_quote_policy* policy)
{
	hwtpm_cursor cursor;
	const uint8_t* bytes;
	uint32_t magic;
	uint32_t count;
	uint16_t type;
	uint16_t length;
	uint16_t algorithm;
	bool valid;
	qsc_hw_status status;

	cursor.bytes = quote;
	cursor.length = quotelen;
	cursor.offset = 0U;
	status = qsc_hw_status_invalid_parameter;

	if (hwtpm_u32(&cursor, &magic) == true && hwtpm_u16(&cursor, &type) == true &&
		magic == HWTPM_GENERATED_VALUE && type == HWTPM_ST_ATTEST_QUOTE &&
		hwtpm_2b(&cursor, &bytes, &length) == true)
	{
		if (length == policy->aknamelen && qsc_memutils_are_equal(bytes, policy->akname, length) == true)
		{
			if (hwtpm_2b(&cursor, &bytes, &length) == true)
			{
				if (length == policy->noncelen && qsc_memutils_are_equal(bytes, policy->nonce, length) == true)
				{
					/* TPMS_CLOCK_INFO (17 bytes) and firmwareVersion (8 bytes). */
					if (hwtpm_take(&cursor, 25U, &bytes) == true)
					{
						valid = (policy->require_safe_clock == false || bytes[16U] == 1U);

						if (valid == true && hwtpm_u32(&cursor, &count) == true && count == 1U &&
							hwtpm_u16(&cursor, &algorithm) == true)
						{
							if (algorithm == HWTPM_ALG_SHA256)
							{
								if (hwtpm_take(&cursor, 1U, &bytes) == true && bytes[0U] == 3U &&
									hwtpm_take(&cursor, 3U, &bytes) == true &&
									qsc_memutils_are_equal(bytes, policy->pcrselect, 3U) == true &&
									hwtpm_2b(&cursor, &bytes, &length) == true && length == QSC_HW_TPM_PCR_DIGEST_SIZE &&
									cursor.offset == cursor.length &&
									qsc_memutils_are_equal(bytes, policy->pcrdigest, QSC_HW_TPM_PCR_DIGEST_SIZE) == true)
								{
									status = qsc_hw_status_success;
								}
								else
								{
									status = qsc_hw_status_policy;
								}
							}
							else
							{
								status = qsc_hw_status_unsupported;
							}
						}
						else
						{
							status = qsc_hw_status_policy;
						}
					}
				}
				else
				{
					status = qsc_hw_status_policy;
				}
			}
		}
		else
		{
			status = qsc_hw_status_policy;
		}
	}

	return status;
}

qsc_hw_status qsc_hw_tpm_quote_verify(const uint8_t* quote, size_t quotelen,
	const uint8_t* signature, size_t signaturelen, const qsc_hw_tpm_quote_policy* policy)
{
	uint8_t signedmsg[64U + QSC_HW_TPM_QUOTE_MAX_SIZE] = { 0U };
	uint8_t recovered[QSC_HW_TPM_QUOTE_MAX_SIZE] = { 0U };
	uint8_t digest[32U] = { 0U };
	size_t recoveredlen;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;
	recoveredlen = 0U;

	if (quote != NULL && signature != NULL && policy != NULL && policy->nonce != NULL &&
		policy->akname != NULL && policy->akpublic != NULL && policy->pcrdigest != NULL &&
		policy->noncelen >= 16U && policy->noncelen <= 64U && policy->aknamelen == 34U &&
		policy->akname[0U] == 0U && policy->akname[1U] == HWTPM_ALG_SHA256 &&
		quotelen != 0U && quotelen <= QSC_HW_TPM_QUOTE_MAX_SIZE &&
		signaturelen >= 10U && signaturelen <= 76U &&
		(policy->pcrselect[0U] | policy->pcrselect[1U] | policy->pcrselect[2U]) != 0U)
	{
		status = hwtpm_claims(quote, quotelen, policy);

		if (status == qsc_hw_status_success)
		{
			status = hwtpm_signature(signature, signaturelen, signedmsg);

			if (status == qsc_hw_status_success)
			{
				qsc_sha256_compute(digest, quote, quotelen);
				qsc_memutils_copy(signedmsg + 64U, quote, quotelen);

				if (qsc_ecdsap256_verify_prehashed(recovered, &recoveredlen, signedmsg,
					64U + quotelen, policy->akpublic, digest, sizeof(digest)) != true ||
					recoveredlen != quotelen || qsc_memutils_are_equal(recovered, quote, quotelen) != true)
				{
					status = qsc_hw_status_policy;
				}
			}
		}
	}

	qsc_memutils_secure_erase(signedmsg, sizeof(signedmsg));
	qsc_memutils_secure_erase(recovered, sizeof(recovered));
	qsc_memutils_secure_erase(digest, sizeof(digest));

	return status;
}

/** \brief Validate the bounded QSC TPM attestation envelope framing.
 * \param envelope Caller-owned envelope bytes.
 * \param envelopelen Exact envelope length.
 * \param policy Trusted attestation verification policy.
 * \return success only when both envelope and its cryptographic quote are verified.
 */
qsc_hw_status qsc_hw_tpm_quote_envelope_verify(const uint8_t* envelope,
	size_t envelopelen, const qsc_hw_tpm_quote_policy* policy)
{
	hwtpm_cursor cursor;
	const uint8_t* quote;
	const uint8_t* signature;
	uint16_t quotelen;
	uint16_t signaturelen;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (envelope != NULL && policy != NULL && envelopelen >= 4U &&
		envelopelen <= 4U + QSC_HW_TPM_QUOTE_MAX_SIZE + 76U)
	{
		cursor.bytes = envelope;
		cursor.length = envelopelen;
		cursor.offset = 0U;

		if (hwtpm_2b(&cursor, &quote, &quotelen) == true &&
			hwtpm_2b(&cursor, &signature, &signaturelen) == true && cursor.offset == cursor.length)
		{
			status = qsc_hw_tpm_quote_verify(quote, quotelen, signature, signaturelen, policy);
		}
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_TPM_ENABLED */
