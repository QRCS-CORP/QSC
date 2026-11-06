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

/** \file p11sign.c
 * \brief CKM_ECDSA prehashed signing using a verified sensitive, nonextractable private token key.
 */

qsc_hw_status qsc_hw_pkcs11_key_sign(qsc_hw_pkcs11_key* key, const uint8_t* digest, size_t digestlen, uint8_t* signature, size_t* signaturelen)
{
	CK_MECHANISM mechanism;
	CK_ULONG native_length;
	size_t expected;
	size_t capacity;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && signaturelen != NULL && digest != NULL && p11_module_current(key->session->module) == true)
	{
		expected = 0U;

		switch (key->algorithm)
		{
			case qsc_hw_algorithm_ecdsa_p256:
				expected = 64U;
				break;
			case qsc_hw_algorithm_ecdsa_p384:
				expected = 96U;
				break;
			case qsc_hw_algorithm_ecdsa_p521:
				expected = 132U;
				break;
			default:
				status = qsc_hw_status_unsupported;
				break;
		}

		if (expected != 0U)
		{
			/* The token receives a caller-prehashed digest. P-521 uses SHA-512 (64 bytes). */
			if (digestlen == (expected == 132U ? 64U : expected / 2U))
			{
				capacity = *signaturelen;
				*signaturelen = expected;

				if (signature == NULL || capacity >= expected)
				{
					p11_module_lock(key->session->module);
					status = p11_key_validate_locked(key);

					if (status == qsc_hw_status_success && signature != NULL)
					{
						if (key->session->module->functions->C_SignInit == NULL_PTR ||
							key->session->module->functions->C_Sign == NULL_PTR)
						{
							status = qsc_hw_status_unsupported;
						}
						else
						{
						mechanism.mechanism = CKM_ECDSA;
						mechanism.pParameter = NULL_PTR;
						mechanism.ulParameterLen = 0UL;
						rv = key->session->module->functions->C_SignInit(key->session->handle, &mechanism, key->handle);
						status = p11_status_from_rv(rv);

						if (rv == CKR_OK)
						{
							native_length = (CK_ULONG)expected;
							rv = key->session->module->functions->C_Sign(key->session->handle, (CK_BYTE_PTR)digest,
								(CK_ULONG)digestlen, (CK_BYTE_PTR)signature, &native_length);
							status = p11_status_from_rv(rv);

							if (rv == CKR_OK && native_length != (CK_ULONG)expected)
							{
								status = qsc_hw_status_policy;
							}
						}
						}
					}
					p11_module_unlock(key->session->module);
				}
				else
				{
					status = qsc_hw_status_buffer_too_small;
				}

				if (status != qsc_hw_status_success && signature != NULL && capacity >= expected)
				{
					qsc_memutils_secure_erase(signature, capacity);
				}
			}
		}
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
