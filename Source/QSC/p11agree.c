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

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "p11internal.h"
#include "memutils.h"

/** \file p11agree.c
 * \brief Token-backed ECDH derivation with deliberate, explicitly permitted raw-secret export.
 * \details A derived CKO_SECRET_KEY is transient and destroyed before returning. Private key bytes are never accessed.
 */

qsc_hw_status qsc_hw_pkcs11_key_agree(qsc_hw_pkcs11_key* key, const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen, bool allow_export)
{
	CK_ECDH1_DERIVE_PARAMS params;
	CK_MECHANISM mechanism;
	CK_MECHANISM_INFO mechanism_info;
	CK_OBJECT_CLASS object_class;
	CK_KEY_TYPE key_type;
	CK_BBOOL no;
	CK_BBOOL yes;
	CK_ATTRIBUTE attributes[5U];
	CK_ATTRIBUTE value;
	CK_OBJECT_HANDLE derived;
	const uint8_t* oid;
	size_t oidlen;
	size_t pointlen;
	size_t expected;
	size_t capacity;
	bool sign;
	CK_RV rv;
	CK_RV cleanup_rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && peer != NULL && secretlen != NULL && p11_module_current(key->session->module) == true &&
		p11_key_curve(key->algorithm, &oid, &oidlen, &pointlen, &sign) == true)
	{
		if (sign == true)
		{
			status = qsc_hw_status_unsupported;
		}
		else if (allow_export == false)
		{
			status = qsc_hw_status_policy;
		}
		else if (peerlen != pointlen || peer[0U] != 0x04U)
		{
			status = qsc_hw_status_invalid_parameter;
		}
		else
		{
			expected = (pointlen - 1U) / 2U;
			capacity = *secretlen;
			*secretlen = expected;

			if (secret != NULL && capacity < expected)
			{
				status = qsc_hw_status_buffer_too_small;
			}
			else
			{
				p11_module_lock(key->session->module);
				status = p11_key_validate_locked(key);

				if (status == qsc_hw_status_success)
				{
					if (key->session->module->functions->C_DeriveKey == NULL_PTR ||
						key->session->module->functions->C_DestroyObject == NULL_PTR ||
						key->session->module->functions->C_GetMechanismInfo == NULL_PTR)
					{
						status = qsc_hw_status_unsupported;
					}
					else
					{
						rv = key->session->module->functions->C_GetMechanismInfo(key->session->slot, CKM_ECDH1_DERIVE, &mechanism_info);
						status = p11_status_from_rv(rv);

						if (rv == CKR_OK && (mechanism_info.flags & CKF_DERIVE) == 0UL)
						{
							status = qsc_hw_status_unsupported;
						}
					}
				}

				if (status == qsc_hw_status_success && secret != NULL)
				{
					params.kdf = CKD_NULL;
					params.pSharedData = NULL_PTR;
					params.ulSharedDataLen = 0UL;
					params.pPublicData = (CK_BYTE_PTR)peer;
					params.ulPublicDataLen = (CK_ULONG)peerlen;
					mechanism.mechanism = CKM_ECDH1_DERIVE;
					mechanism.pParameter = &params;
					mechanism.ulParameterLen = sizeof(params);
					object_class = CKO_SECRET_KEY;
					key_type = CKK_GENERIC_SECRET;
					no = CK_FALSE;
					yes = CK_TRUE;
					attributes[0U].type = CKA_CLASS;
					attributes[0U].pValue = &object_class;
					attributes[0U].ulValueLen = sizeof(object_class);
					attributes[1U].type = CKA_KEY_TYPE;
					attributes[1U].pValue = &key_type;
					attributes[1U].ulValueLen = sizeof(key_type);
					attributes[2U].type = CKA_TOKEN;
					attributes[2U].pValue = &no;
					attributes[2U].ulValueLen = sizeof(no);
					attributes[3U].type = CKA_SENSITIVE;
					attributes[3U].pValue = &no;
					attributes[3U].ulValueLen = sizeof(no);
					attributes[4U].type = CKA_EXTRACTABLE;
					attributes[4U].pValue = &yes;
					attributes[4U].ulValueLen = sizeof(yes);
					derived = CK_INVALID_HANDLE;
					rv = key->session->module->functions->C_DeriveKey(key->session->handle, &mechanism, key->handle, attributes, 5UL, &derived);
					status = p11_status_from_rv(rv);

					if (rv == CKR_OK)
					{
						value.type = CKA_VALUE;
						value.pValue = secret;
						value.ulValueLen = (CK_ULONG)expected;
						rv = key->session->module->functions->C_GetAttributeValue(key->session->handle, derived, &value, 1UL);
						status = p11_status_from_rv(rv);

						if (rv == CKR_OK && value.ulValueLen != (CK_ULONG)expected)
						{
							status = qsc_hw_status_policy;
						}

						cleanup_rv = key->session->module->functions->C_DestroyObject(key->session->handle, derived);

						if (cleanup_rv != CKR_OK)
						{
							status = qsc_hw_status_internal;
						}
					}
				}
				p11_module_unlock(key->session->module);
			}

			if (status != qsc_hw_status_success && secret != NULL && capacity >= expected)
			{
				qsc_memutils_secure_erase(secret, capacity);
			}
		}
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
