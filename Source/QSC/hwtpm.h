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

#ifndef QSC_HWTPM_H
#define QSC_HWTPM_H

#include "hwprovider.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_TPM_ENABLED)

/** \file hwtpm.h
 * \brief Optional Linux TPM2-TSS ESAPI identity and quote backend.
 * \details Build-time QSC_TPM2_TSS_ENABLED requires vendor-installed tss2-esys and
 * tss2-tctildr. Without it, the API fails unsupported with no TPM dependency.
 * The backend opens pre-provisioned persistent TPM P-256 signing/AK handles only.
 * It never takes ownership, initializes a hierarchy, clears a TPM, or persists keys.
 * The caller serializes operations and is responsible for provisioning/recovery.
 */

/** \def QSC_HARDWARE_TPM_ENABLED
 * \brief Include the optional portable TPM provider API.
 */

/** \def QSC_TPM2_TSS_ENABLED
 * \brief Compile the Linux TPM2-TSS ESAPI backend using externally installed headers and libraries.
 */

/** \struct qsc_hw_tpm_context
 * \brief Caller-owned backend context; zero-initialize before use.
 */
typedef struct qsc_hw_tpm_context
{
	void* native_state; /**< Internal ESAPI state; do not access directly. */
} qsc_hw_tpm_context;

/** \brief Open a pre-provisioned non-exportable P-256 signing identity on a Linux TPM.
 * \param context Caller-owned zeroed context initialized only on success.
 * \param tcti Optional installed TCTI configuration, or NULL for system default.
 * \param identityhandle TPM persistent identity handle in 0x81000000..0x81FFFFFF.
 * \param akhandle TPM persistent P-256 attestation-key handle, or zero to disable quotes.
 * \param pcrselect Optional SHA-256 bank 3-byte PCR bitset, or NULL for PCR 0.
 * \param physical_device_confirmed Explicit OEM-confirmed physical TPM classification.
 * False labels key custody as software for simulators, subject to caller fallback policy.
 * True requires external evidence of real TPM transport, not inferred from key flags.
 * \return success only for a verified TPM-resident sign-capable key, unsupported when
 * TSS is not compiled or the TPM/handle cannot be accessed; typed failures otherwise.
 * \note Handles must have empty authorization and be provisioned by authorized tooling.
 * Never clears, reassigns or changes TPM ownership. Does not attest platform origin.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_tpm_initialize(qsc_hw_tpm_context* context, const char* tcti, uint32_t identityhandle, 
	uint32_t akhandle, const uint8_t* pcrselect, bool physical_device_confirmed);

/** \brief Populate the generic QSC hardware provider callback descriptor.
 * \param operations Caller-owned output descriptor.
 * \return success only when compiled for Linux with TPM2-TSS ESAPI support;
 * otherwise unsupported, with a cleared descriptor.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_tpm_get_operations(qsc_hw_provider_ops* operations);

/** \brief Retrieve the opened AK's public key and TPM Name for out-of-band trust enrollment.
 * \param context Initialized context with a persistent AK handle.
 * \param publickey Caller-owned 64-byte P-256 Qx||Qy output.
 * \param akname Caller-owned 34-byte TPM Name (SHA-256 name algorithm and digest).
 * \return success, unsupported when no AK configured, or typed failure.
 * \note Outputs are untrusted metadata until checked against OEM trust anchors.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_tpm_get_ak_identity(const qsc_hw_tpm_context* context, uint8_t* publickey, uint8_t* akname);

/** \brief Release only local ESAPI/TCTI state without deleting persistent TPM objects.
 * \param context Backend context; may be NULL or already disposed.
 * \note Must be called only after the generic provider wrapper and keys close.
 */
QSC_EXPORT_API void qsc_hw_tpm_dispose(qsc_hw_tpm_context* context);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
