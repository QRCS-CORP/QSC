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

#include "hwtpm.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_TPM_ENABLED)

#include "memutils.h"

/** \brief Check a TPM 2.0 persistent object-handle range.
 * \param handle Expected TPM persistent handle.
 * \return true only for persistent-object handle class 0x81xxxxxx.
 */
static bool hwtpm_handle_valid(uint32_t handle)
{
	return (handle >= UINT32_C(0x81000000) && handle <= UINT32_C(0x81FFFFFF));
}

#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

/** \struct hwtpm_native
 * \brief Owned native TCTI, ESAPI and public metadata for a persistent TPM signing key.
 */
typedef struct hwtpm_native
{
	TSS2_TCTI_CONTEXT* tcti; /**< External loader-owned TCTI, released on close. */
	ESYS_CONTEXT* esys; /**< ESAPI object and session manager for this provider. */
	ESYS_TR signingkey; /**< Loaded reference to persistent signing identity. */
	ESYS_TR attestationkey; /**< Loaded reference to persistent AK, or ESYS_TR_NONE. */
	uint32_t persistenthandle; /**< TPM persistent signing identity handle. */
	bool physical_device_confirmed; /**< OEM-confirmed physical TPM, not a quote-derived claim. */
	uint8_t publickey[65U]; /**< SEC1 uncompressed public key bytes. */
	uint8_t akpublic[64U]; /**< TPM AK public Qx||Qy bytes, or zeros. */
	uint8_t akname[34U]; /**< TPM AK Name bytes, or zeros. */
	uint8_t pcrselect[3U]; /**< SHA-256 PCR bank selection for quote. */
} hwtpm_native;

/** \struct hwtpm_key
 * \brief Short-lived non-exportable TPM identity reference, not raw key material.
 */
typedef struct hwtpm_key
{
	uint32_t persistenthandle; /**< Verified handle identity for this provider instance. */
} hwtpm_key;

/** \brief Classify an ESAPI device failure conservatively.
 * \param result TPM2-TSS result code.
 * \return typed failure, with no secrets in diagnostics.
 */
static qsc_hw_status hwtpm_tss_status(TSS2_RC result)
{
	qsc_hw_status status;

	status = qsc_hw_status_internal;

	if (result == TSS2_RC_SUCCESS)
	{
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Validate a TPM-resident P-256 signing public object, without private extraction.
 * \param publicarea Vendor TPM public object.
 * \param require_restricted True for quote-capable restricted AK, false for digest signer.
 * \param output Writable 65-byte SEC1 public key.
 * \return true only when object and attributes match non-migratable hardware custody.
 */
static bool hwtpm_public_valid(const TPM2B_PUBLIC* publicarea, bool require_restricted, uint8_t* output)
{
	TPMA_OBJECT attributes;
	bool valid;

	valid = false;

	if (publicarea != NULL && output != NULL && publicarea->publicArea.type == TPM2_ALG_ECC &&
		publicarea->publicArea.parameters.eccDetail.curveID == TPM2_ECC_NIST_P256 &&
		publicarea->publicArea.unique.ecc.x.size == 32U && publicarea->publicArea.unique.ecc.y.size == 32U)
	{
		attributes = publicarea->publicArea.objectAttributes;
		valid = ((attributes & (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
			TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_SIGN_ENCRYPT)) ==
			(TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
			TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_SIGN_ENCRYPT));
		valid = valid && ((attributes & TPMA_OBJECT_RESTRICTED) != 0U) == require_restricted;

		if (valid == true)
		{
			output[0U] = 0x04U;
			qsc_memutils_copy(output + 1U, publicarea->publicArea.unique.ecc.x.buffer, 32U);
			qsc_memutils_copy(output + 33U, publicarea->publicArea.unique.ecc.y.buffer, 32U);
		}
	}

	return valid;
}

/** \brief Close ESAPI and TCTI handles without deleting persistent TPM objects.
 * \param native Owned native backend state; always clears/releases it.
 */
static void hwtpm_native_free(hwtpm_native* native)
{
	if (native != NULL)
	{
		if (native->esys != NULL)
		{
			if (native->attestationkey != ESYS_TR_NONE)
			{
				(void)Esys_TR_Close(native->esys, &native->attestationkey);
			}

			if (native->signingkey != ESYS_TR_NONE)
			{
				(void)Esys_TR_Close(native->esys, &native->signingkey);
			}

			Esys_Finalize(&native->esys);
		}

		if (native->tcti != NULL)
		{
			Tss2_TctiLdr_Finalize(&native->tcti);
		}

		qsc_memutils_secure_erase(native, sizeof(hwtpm_native));
		qsc_memutils_alloc_free(native);
	}
}

/** \brief Report exact initialized TPM backend capabilities, never FIPS status.
 * \param context Opened TPM provider context.
 * \param capabilities Caller-owned versioned capability structure.
 * \return success only for an initialized backend.
 */
static qsc_hw_status hwtpm_capabilities(void* context, qsc_hw_capabilities* capabilities)
{
	qsc_hw_tpm_context* state;
	qsc_hw_status status;

	state = (qsc_hw_tpm_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->native_state != NULL && capabilities != NULL)
	{
		capabilities->flags = qsc_hw_capability_key_open | qsc_hw_capability_sign |
			qsc_hw_capability_public_key;

		if (((hwtpm_native*)state->native_state)->attestationkey != ESYS_TR_NONE)
		{
			capabilities->flags |= qsc_hw_capability_attest;
		}

		capabilities->max_sessions = 1U;
		capabilities->thread_safe = false;
		capabilities->requires_serialization = true;
		capabilities->operation_can_block = true;
		capabilities->supports_cancel = false;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Match exact 8-digit persistent TPM key locator, no variable-length parsing.
 * \param locator NUL-terminated `tpm2:XXXXXXXX` hexadecimal key handle.
 * \param expected Persistent handle already opened in the native context.
 * \return true only when all eight digits match expected and string ends.
 */
static bool hwtpm_locator_matches(const char* locator, uint32_t expected)
{
	uint32_t decoded;
	uint32_t digit;
	size_t i;
	char ch;
	bool valid;

	decoded = 0U;
	valid = false;

	if (locator != NULL && locator[0U] == 't' && locator[1U] == 'p' &&
		locator[2U] == 'm' && locator[3U] == '2' && locator[4U] == ':')
	{
		valid = true;

		for (i = 5U; i < 13U; ++i)
		{
			ch = locator[i];
			digit = 16U;

			if (ch >= '0' && ch <= '9')
			{
				digit = (uint32_t)(ch - '0');
			}
			else if (ch >= 'A' && ch <= 'F')
			{
				digit = 10U + (uint32_t)(ch - 'A');
			}

			if (digit > 15U)
			{
				valid = false;
				break;
			}

			decoded = (decoded << 4U) | digit;
		}

		valid = valid && (locator[13U] == '\0') && (decoded == expected);
	}

	return valid;
}

/** \brief Resolve one already-attached non-exportable TPM key without re-provisioning.
 * \param context Opened TPM context.
 * \param locator Exact persistent handle locator.
 * \param key Receives allocated transient reference.
 * \param info Receives key metadata with no private bytes.
 * \return success, stale_key, memory, or invalid_parameter.
 */
static qsc_hw_status hwtpm_open_key(void* context, const char* locator, void** key, qsc_hw_key_info* info)
{
	qsc_hw_tpm_context* state;
	hwtpm_native* native;
	hwtpm_key* ref;
	qsc_hw_status status;

	state = (qsc_hw_tpm_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (state != NULL && state->native_state != NULL && locator != NULL && key != NULL && info != NULL)
	{
		native = (hwtpm_native*)state->native_state;
		status = qsc_hw_status_stale_key;

		if (hwtpm_locator_matches(locator, native->persistenthandle) == true)
		{
			ref = (hwtpm_key*)qsc_memutils_malloc(sizeof(hwtpm_key));
			status = qsc_hw_status_memory;

			if (ref != NULL)
			{
				ref->persistenthandle = native->persistenthandle;
				*key = ref;
				info->size = sizeof(qsc_hw_key_info);
				info->version = QSC_HW_ABI_VERSION;
				info->algorithm = qsc_hw_algorithm_ecdsa_p256;
				info->usage = qsc_hw_usage_sign;

				if (native->attestationkey != ESYS_TR_NONE)
				{
					info->usage |= qsc_hw_usage_attest;
				}

				info->custody = native->physical_device_confirmed ?
					qsc_hw_custody_hardware_nonexportable : qsc_hw_custody_software;
				info->extractable = false;
				status = qsc_hw_status_success;
			}
		}
	}

	return status;
}

/** \brief Release a transient key reference; persistent TPM key is untouched.
 * \param context Caller-owned TPM context, unused.
 * \param key Owned transient key reference to erase and free.
 */
static void hwtpm_release_key(void* context, void* key)
{
	(void)context;

	if (key != NULL)
	{
		qsc_memutils_secure_erase(key, sizeof(hwtpm_key));
		qsc_memutils_alloc_free(key);
	}
}

/** \brief Return the opened TPM signing key's SEC1 public point.
 * \param context Opened TPM context.
 * \param key Live matching key reference.
 * \param output Writable 65-byte SEC1 public buffer or NULL for size query.
 * \param outputlen In/out output capacity/required length.
 * \return success, buffer_too_small, or typed failure.
 */
static qsc_hw_status hwtpm_public_key(void* context, void* key, uint8_t* output, size_t* outputlen)
{
	qsc_hw_tpm_context* state;
	hwtpm_native* native;
	qsc_hw_status status;

	state = (qsc_hw_tpm_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->native_state != NULL && key != NULL && outputlen != NULL)
	{
		native = (hwtpm_native*)state->native_state;
		status = qsc_hw_status_stale_key;

		if (((hwtpm_key*)key)->persistenthandle == native->persistenthandle)
		{
			status = qsc_hw_status_buffer_too_small;

			if (output != NULL && *outputlen >= sizeof(native->publickey))
			{
				qsc_memutils_copy(output, native->publickey, sizeof(native->publickey));
				status = qsc_hw_status_success;
			}

			*outputlen = sizeof(native->publickey);
		}
	}

	return status;
}

/** \brief Produce one prehashed ECDSA P-256 signature inside the TPM.
 * \param context Opened TPM context.
 * \param key Verified transient identity reference.
 * \param algorithm Exactly qsc_hw_algorithm_ecdsa_p256.
 * \param message SHA-256 digest of the externally supplied message.
 * \param msglen Exactly 32 digest bytes, never a raw un-hashed message.
 * \param signature Writable 64-byte r||s output, or NULL for size query.
 * \param signaturelen In/out signature capacity/required length.
 * \return success or typed failure; no software signing fallback.
 */
static qsc_hw_status hwtpm_sign(void* context, void* key, qsc_hw_algorithm algorithm,
	const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	qsc_hw_tpm_context* state;
	hwtpm_native* native;
	TPM2B_DIGEST digest;
	TPMT_SIG_SCHEME scheme;
	TPMT_TK_HASHCHECK ticket;
	TPMT_SIGNATURE* result;
	qsc_hw_status status;
	TSS2_RC rc;

	state = (qsc_hw_tpm_context*)context;
	status = qsc_hw_status_invalid_parameter;
	result = NULL;

	if (state != NULL && state->native_state != NULL && key != NULL && signaturelen != NULL &&
		message != NULL && msglen == 32U && algorithm == qsc_hw_algorithm_ecdsa_p256)
	{
		native = (hwtpm_native*)state->native_state;
		status = qsc_hw_status_stale_key;

		if (((hwtpm_key*)key)->persistenthandle == native->persistenthandle)
		{
			status = qsc_hw_status_buffer_too_small;

			if (signature != NULL && *signaturelen >= 64U)
			{
				qsc_memutils_clear(&digest, sizeof(digest));
				qsc_memutils_clear(&scheme, sizeof(scheme));
				qsc_memutils_clear(&ticket, sizeof(ticket));
				digest.size = 32U;
				qsc_memutils_copy(digest.buffer, message, 32U);
				scheme.scheme = TPM2_ALG_ECDSA;
				scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
				ticket.tag = TPM2_ST_HASHCHECK;
				ticket.hierarchy = TPM2_RH_NULL;
				rc = Esys_Sign(native->esys, native->signingkey, ESYS_TR_PASSWORD,
					ESYS_TR_NONE, ESYS_TR_NONE, &digest, &scheme, &ticket, &result);
				status = hwtpm_tss_status(rc);

				if (status == qsc_hw_status_success && result != NULL &&
					result->sigAlg == TPM2_ALG_ECDSA &&
					result->signature.ecdsa.hash == TPM2_ALG_SHA256 &&
					result->signature.ecdsa.signatureR.size > 0U &&
					result->signature.ecdsa.signatureR.size <= 32U &&
					result->signature.ecdsa.signatureS.size > 0U &&
					result->signature.ecdsa.signatureS.size <= 32U)
				{
					qsc_memutils_clear(signature, 64U);
					qsc_memutils_copy(signature + 32U - result->signature.ecdsa.signatureR.size,
						result->signature.ecdsa.signatureR.buffer, result->signature.ecdsa.signatureR.size);
					qsc_memutils_copy(signature + 64U - result->signature.ecdsa.signatureS.size,
						result->signature.ecdsa.signatureS.buffer, result->signature.ecdsa.signatureS.size);
				}
				else
				{
					status = qsc_hw_status_internal;
					qsc_memutils_secure_erase(signature, 64U);
				}

				if (result != NULL)
				{
					Esys_Free(result);
				}

				qsc_memutils_secure_erase(&digest, sizeof(digest));
			}

			*signaturelen = 64U;
		}
	}

	return status;
}

/** \brief Produce a bounded SHA-256 PCR0..23 TPM quote with an AK and fresh challenge.
 * \param context Opened TPM provider context with attestation key.
 * \param key Live identity key reference.
 * \param challenge Fresh caller-supplied nonce of 16..64 bytes.
 * \param challengelen Exact nonce size.
 * \param evidence Caller-owned envelope buffer, or NULL for size query.
 * \param evidencelen In/out envelope buffer length.
 * \return success or typed error; evidence is unverified and must be checked separately.
 * \note Envelope wire format: u16 quote-size, TPMS_ATTEST, u16 signature-size,
 * TPMT_SIGNATURE. Does not include an AK chain or trust-anchor assertion.
 */
static qsc_hw_status hwtpm_attest(void* context, void* key, const uint8_t* challenge,
	size_t challengelen, uint8_t* evidence, size_t* evidencelen)
{
	qsc_hw_tpm_context* state;
	hwtpm_native* native;
	TPM2B_DATA nonce;
	TPMT_SIG_SCHEME scheme;
	TPML_PCR_SELECTION selection;
	TPM2B_ATTEST* quote;
	TPMT_SIGNATURE* signature;
	uint16_t rlen;
	uint16_t slen;
	size_t total;
	size_t offset;
	qsc_hw_status status;

	state = (qsc_hw_tpm_context*)context;
	status = qsc_hw_status_invalid_parameter;
	quote = NULL;
	signature = NULL;

	if (state != NULL && state->native_state != NULL && key != NULL && challenge != NULL &&
		challengelen >= 16U && challengelen <= 64U && evidencelen != NULL)
	{
		native = (hwtpm_native*)state->native_state;
		status = qsc_hw_status_unsupported;

		if (native->attestationkey != ESYS_TR_NONE &&
			((hwtpm_key*)key)->persistenthandle == native->persistenthandle)
		{
			/* Bound = two u16 prefixes + maximum quote + maximum TPMT_SIGNATURE. */
			status = qsc_hw_status_buffer_too_small;
			total = 4U + 1024U + 72U;

			if (evidence != NULL && *evidencelen >= total)
			{
				qsc_memutils_clear(&nonce, sizeof(nonce));
				qsc_memutils_clear(&scheme, sizeof(scheme));
				qsc_memutils_clear(&selection, sizeof(selection));
				nonce.size = (UINT16)challengelen;
				qsc_memutils_copy(nonce.buffer, challenge, challengelen);
				scheme.scheme = TPM2_ALG_ECDSA;
				scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
				selection.count = 1U;
				selection.pcrSelections[0U].hash = TPM2_ALG_SHA256;
				selection.pcrSelections[0U].sizeofSelect = 3U;
				qsc_memutils_copy(selection.pcrSelections[0U].pcrSelect, native->pcrselect, 3U);

				status = hwtpm_tss_status(Esys_Quote(native->esys, native->attestationkey,
					ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &nonce, &scheme, &selection,
					&quote, &signature));

				if (status == qsc_hw_status_success && quote != NULL && signature != NULL &&
					quote->size <= 1024U && signature->sigAlg == TPM2_ALG_ECDSA &&
					signature->signature.ecdsa.hash == TPM2_ALG_SHA256 &&
					signature->signature.ecdsa.signatureR.size > 0U &&
					signature->signature.ecdsa.signatureS.size > 0U &&
					signature->signature.ecdsa.signatureR.size <= 32U &&
					signature->signature.ecdsa.signatureS.size <= 32U)
				{
					rlen = signature->signature.ecdsa.signatureR.size;
					slen = signature->signature.ecdsa.signatureS.size;
					offset = 0U;
					evidence[offset++] = (uint8_t)(quote->size >> 8U);
					evidence[offset++] = (uint8_t)quote->size;
					qsc_memutils_copy(evidence + offset, quote->attestationData, quote->size);
					offset += quote->size;
					/* signature-size accounts for two TPM_ALG_ID and two TPM2B components. */
					total = 8U + rlen + slen;
					evidence[offset++] = (uint8_t)(total >> 8U);
					evidence[offset++] = (uint8_t)total;
					evidence[offset++] = 0U;
					evidence[offset++] = 0x18U;
					evidence[offset++] = 0U;
					evidence[offset++] = 0x0BU;
					evidence[offset++] = (uint8_t)(rlen >> 8U);
					evidence[offset++] = (uint8_t)rlen;
					qsc_memutils_copy(evidence + offset, signature->signature.ecdsa.signatureR.buffer, rlen);
					offset += rlen;
					evidence[offset++] = (uint8_t)(slen >> 8U);
					evidence[offset++] = (uint8_t)slen;
					qsc_memutils_copy(evidence + offset, signature->signature.ecdsa.signatureS.buffer, slen);
					offset += slen;
					*evidencelen = offset;
				}
				else
				{
					status = qsc_hw_status_internal;
				}

				if (quote != NULL)
				{
					Esys_Free(quote);
				}

				if (signature != NULL)
				{
					Esys_Free(signature);
				}

				if (status != qsc_hw_status_success)
				{
					qsc_memutils_secure_erase(evidence, *evidencelen);
				}
			}
			else
			{
				*evidencelen = total;
			}
		}
	}

	return status;
}

/** \brief Release backend resources when the generic provider wrapper closes.
 * \param context Caller-owned context to dispose after all key references close.
 */
static void hwtpm_dispose_callback(void* context)
{
	qsc_hw_tpm_dispose((qsc_hw_tpm_context*)context);
}

#endif /* QSC_SYSTEM_OS_LINUX && QSC_TPM2_TSS_ENABLED */

qsc_hw_status qsc_hw_tpm_initialize(qsc_hw_tpm_context* context,
	const char* tcti, uint32_t identityhandle, uint32_t akhandle, const uint8_t* pcrselect,
	bool physical_device_confirmed)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && context->native_state == NULL &&
		hwtpm_handle_valid(identityhandle) == true &&
		(akhandle == 0U || hwtpm_handle_valid(akhandle) == true) &&
		identityhandle != akhandle)
	{
#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)
		hwtpm_native* native;
		TPM2B_PUBLIC* keypublic;
		TPM2B_NAME* name;
		TPM2B_NAME* qualifiedname;
		uint8_t temporary[65U] = { 0U };

		keypublic = NULL;
		name = NULL;
		qualifiedname = NULL;
		native = (hwtpm_native*)qsc_memutils_malloc(sizeof(hwtpm_native));
		status = qsc_hw_status_memory;

		if (native != NULL)
		{
			qsc_memutils_clear(native, sizeof(*native));
			native->signingkey = ESYS_TR_NONE;
			native->attestationkey = ESYS_TR_NONE;
			status = hwtpm_tss_status(Tss2_TctiLdr_Initialize(tcti, &native->tcti));

			if (status == qsc_hw_status_success)
			{
				status = hwtpm_tss_status(Esys_Initialize(&native->esys, native->tcti, NULL));
			}

			if (status == qsc_hw_status_success)
			{
				status = hwtpm_tss_status(Esys_TR_FromTPMPublic(native->esys, identityhandle,
					ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &native->signingkey));
			}

			if (status == qsc_hw_status_success)
			{
				status = hwtpm_tss_status(Esys_ReadPublic(native->esys, native->signingkey,
					ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keypublic, &name, &qualifiedname));
			}

			if (status == qsc_hw_status_success)
			{
				if (hwtpm_public_valid(keypublic, false, native->publickey) != true)
				{
					status = qsc_hw_status_policy;
				}
			}

			if (keypublic != NULL)
			{
				Esys_Free(keypublic);
				keypublic = NULL;
			}
			if (name != NULL)
			{
				Esys_Free(name);
				name = NULL;
			}
			if (qualifiedname != NULL)
			{
				Esys_Free(qualifiedname);
				qualifiedname = NULL;
			}

			if (status == qsc_hw_status_success && akhandle != 0U)
			{
				status = hwtpm_tss_status(Esys_TR_FromTPMPublic(native->esys, akhandle,
					ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &native->attestationkey));

				if (status == qsc_hw_status_success)
				{
					status = hwtpm_tss_status(Esys_ReadPublic(native->esys, native->attestationkey,
						ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keypublic, &name, &qualifiedname));
				}

				if (status == qsc_hw_status_success)
				{
					if (hwtpm_public_valid(keypublic, true, temporary) == true &&
						name != NULL && name->size == sizeof(native->akname) &&
						name->name[0U] == 0U && name->name[1U] == 0x0BU)
					{
						qsc_memutils_copy(native->akpublic, temporary + 1U, sizeof(native->akpublic));
						qsc_memutils_copy(native->akname, name->name, sizeof(native->akname));
					}
					else
					{
						status = qsc_hw_status_policy;
					}
				}
			}

			if (keypublic != NULL)
			{
				Esys_Free(keypublic);
			}
			if (name != NULL)
			{
				Esys_Free(name);
			}
			if (qualifiedname != NULL)
			{
				Esys_Free(qualifiedname);
			}

			if (status == qsc_hw_status_success)
			{
				native->persistenthandle = identityhandle;
				native->physical_device_confirmed = physical_device_confirmed;
				native->pcrselect[0U] = 1U;

				if (pcrselect != NULL)
				{
					qsc_memutils_copy(native->pcrselect, pcrselect, 3U);
				}

				if ((native->pcrselect[0U] | native->pcrselect[1U] |
					native->pcrselect[2U]) == 0U)
				{
					status = qsc_hw_status_policy;
				}
			}

			if (status == qsc_hw_status_success)
			{
				context->native_state = native;
			}
			else
			{
				hwtpm_native_free(native);
			}

			qsc_memutils_secure_erase(temporary, sizeof(temporary));
		}
#else
		(void)tcti;
		(void)pcrselect;
		(void)physical_device_confirmed;
		status = qsc_hw_status_unsupported;
#endif
	}

	return status;
}

qsc_hw_status qsc_hw_tpm_get_operations(qsc_hw_provider_ops* operations)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (operations != NULL)
	{
		qsc_memutils_clear(operations, sizeof(*operations));
#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)
		operations->size = sizeof(*operations);
		operations->version = QSC_HW_ABI_VERSION;
		operations->get_capabilities = hwtpm_capabilities;
		operations->release_key = hwtpm_release_key;
		operations->dispose = hwtpm_dispose_callback;
		operations->open_key = hwtpm_open_key;
		operations->sign = hwtpm_sign;
		operations->attest = hwtpm_attest;
		operations->public_key = hwtpm_public_key;
		status = qsc_hw_status_success;
#else
		status = qsc_hw_status_unsupported;
#endif
	}

	return status;
}

qsc_hw_status qsc_hw_tpm_get_ak_identity(const qsc_hw_tpm_context* context,
	uint8_t* publickey, uint8_t* akname)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && publickey != NULL && akname != NULL)
	{
		status = qsc_hw_status_unsupported;

#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)
		if (context->native_state != NULL)
		{
			const hwtpm_native* native;

			native = (const hwtpm_native*)context->native_state;

			if (native->attestationkey != ESYS_TR_NONE)
			{
				qsc_memutils_copy(publickey, native->akpublic, 64U);
				qsc_memutils_copy(akname, native->akname, 34U);
				status = qsc_hw_status_success;
			}
		}
#endif
	}

	return status;
}

void qsc_hw_tpm_dispose(qsc_hw_tpm_context* context)
{
	if (context != NULL)
	{
#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)
		hwtpm_native_free((hwtpm_native*)context->native_state);
#endif
		context->native_state = NULL;
	}
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_TPM_ENABLED */
