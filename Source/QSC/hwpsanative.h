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

#ifndef QSC_HWPSANATIVE_H
#define QSC_HWPSANATIVE_H

#include "hwpsa.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PSA_ENABLED) && defined(QSC_HARDWARE_PSA_NATIVE_ENABLED)

/** \file hwpsanative.h
 * \brief Optional direct Arm PSA Crypto v1.x binding for supported TF-M clients.
 * \details Requires OEM-installed <psa/crypto.h> and PSA library only when enabled.
 * Uses the official application API rather than an unstable internal driver ABI.
 */

/** \def QSC_HARDWARE_PSA_NATIVE_ENABLED
 * \brief Opt into PSA native calls; external PSA headers and runtime required.
 */

/** \struct qsc_hw_psa_native_service
 * \brief Caller-owned native PSA service configuration with no private-key bytes.
 * \note The location is a PSA key location constant. QSC does not select a
 * location automatically or infer physical attestation from the location field.
 */
typedef struct qsc_hw_psa_native_service
{
	uint32_t size;			/**< sizeof(qsc_hw_psa_native_service). */
	uint32_t version;		/**< QSC_HW_ABI_VERSION. */
	uint32_t location;		/**< Required PSA_KEY_LIFETIME_GET_LOCATION result for this key. */
	bool hardware_verified;	/**< OEM hardware-operation verification, not attestation. */
	bool initialized;		/**< PSA Crypto init succeeded; no global finalize is performed. */
} qsc_hw_psa_native_service;

/** \brief Initialize a native PSA client and bind a fixed persistent ID to QSC.
 * \param context Zero-initialized caller-owned PSA bridge state.
 * \param service Zero-initialized caller-owned native PSA service state.
 * \param key_id Nonzero persistent PSA key identifier.
 * \param location Expected PSA storage location returned by platform key attributes.
 * \param hardware_verified Independently qualified physical key-operation path.
 * \return Typed status. Does not take device ownership or delete keys.
 * \note A local-storage PSA key can never be claimed as hardware-backed here.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_psa_native_initialize(qsc_hw_psa_context* context, qsc_hw_psa_native_service* service, uint32_t key_id, uint32_t location, bool hardware_verified);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
