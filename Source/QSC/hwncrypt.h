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

#ifndef QSC_HWNCRYPT_H
#define QSC_HWNCRYPT_H

#include "hwprovider.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_NCRYPT_ENABLED)

/** \file hwncrypt.h
 * \brief Optional Windows TPM key provider using Microsoft Platform Crypto Provider.
 * \details No software-KSP fallback and no private-key export. The Windows adapter
 * never claims remote attestation and requires physical TPM qualification.
 * Calls, context disposal and qsc_hw_provider_close must be serialized by the caller.
 */

/** \def QSC_HARDWARE_NCRYPT_ENABLED
 * \brief Enable the NCrypt adapter when QSC_HARDWARE_ENABLED is also defined.
 * \note Enabled only by explicit compiler configuration; on non-Windows targets
 * the API reports unsupported without introducing OS or vendor dependencies.
 */

/** \struct qsc_hw_ncrypt_context
 * \brief Caller-owned context for one Microsoft Platform Crypto Provider instance.
 * \note Zero-initialize before first use; the backend owns native_state until
 * qsc_hw_ncrypt_dispose or the registered provider's close callback releases it.
 */
typedef struct qsc_hw_ncrypt_context
{
	void* native_state; /**< Internal Windows provider object; never access or release directly. */
} qsc_hw_ncrypt_context;

/** \brief Open the TPM-only Windows key storage provider for one persistent identity name.
 * \param context Caller-owned zeroed context; initialized on success.
 * \param name UTF-8 NUL-terminated persistent key name, 1..127 bytes, no embedded NUL.
 * \param machine_key True for machine-wide storage, false for current-user scope.
 * \return Success or typed error. Unsupported on non-Windows systems or without TPM KSP.
 * \note Caller must close any qsc_hw_provider using this context before disposal.
 * Never invoke from a Windows service StartService callback.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_ncrypt_initialize(qsc_hw_ncrypt_context* context, const char* name, bool machine_key);

/** \brief Populate a versioned hardware-provider operations descriptor.
 * \param operations Caller-owned output; initialized only on success.
 * \return Success, invalid parameter, or unsupported on non-Windows platforms.
 * \note The caller passes the returned descriptor and initialized context to
 * qsc_hw_provider_open; closing that provider disposes the native context.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_ncrypt_get_operations(qsc_hw_provider_ops* operations);

/** \brief Check a specific signature curve against the opened TPM KSP.
 * \param context Initialized provider context.
 * \param algorithm ECDSA P-256, P-384 or P-521; other algorithms return false.
 * \return True only when the platform provider explicitly supports the algorithm.
 * \note This is mechanism availability, not physical-operation or FIPS qualification.
 */
QSC_EXPORT_API bool qsc_hw_ncrypt_algorithm_available(const qsc_hw_ncrypt_context* context, qsc_hw_algorithm algorithm);

/** \brief Dispose native provider storage after all key references have been released.
 * \param context Initialized context, or a zeroed context for idempotent cleanup.
 * \note qsc_hw_provider_close performs this automatically when registered.
 * Do not call while a provider wrapper or key reference is still active.
 */
QSC_EXPORT_API void qsc_hw_ncrypt_dispose(qsc_hw_ncrypt_context* context);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
