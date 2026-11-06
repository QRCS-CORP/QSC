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

#ifndef QSC_HWSE050_H
#define QSC_HWSE050_H

#include "hwpkcs11.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED) && defined(QSC_HARDWARE_SE050_ENABLED)

/** \file hwse050.h
 * \brief SE050/SE05x profile validation for an OEM-installed NXP Plug & Trust PKCS#11 module.
 * \details Reuses the common QSC PKCS#11 adapter; never links NXP SDK into QSC.
 * Token label and serial are configuration selectors, NOT cryptographic attestation.
 * SCP03 and applet authentication must be independently established by vendor middleware.
 */

/** \def QSC_HARDWARE_SE050_ENABLED
 * \brief Enable NXP PKCS#11 profile preflight; requires hardware and PKCS#11 features.
 */

/** \struct qsc_hw_se050_policy
 * \brief Caller-supplied minimum requirements for the OEM's SE05x Cryptoki token.
 * \note Serial must be pinned to avoid slot-renumbering ambiguity. Vendor SCP03 assurance
 * cannot be inferred from the PKCS#11 token flags and remains OEM responsibility.
 */
typedef struct qsc_hw_se050_policy
{
	uint32_t size;							/**< sizeof(qsc_hw_se050_policy), in bytes. */
	uint32_t version;						/**< QSC_HW_ABI_VERSION. */
	char expected_serial[17U];				/**< Explicit 1..16-byte NUL-terminated token serial. */
	bool require_protected_authentication;	/**< Reject token lacking protected-PIN-path advertisement. */
	bool require_ec_key_generation;			/**< Require EC key-pair generation as well as ECDSA signing. */
	bool require_scp03;						/**< Caller requires vendor-confirmed secure channel. */
	bool scp03_confirmed;					/**< OEM-provided status, not independently verified by QSC. */
} qsc_hw_se050_policy;

/** \brief Preflight the NXP middleware token before opening QSC PKCS#11 keys.
 * \param module Loaded vendor Cryptoki module, managed by existing QSC PKCS#11 API.
 * \param slot Current slot enumerated from that module; not a persistent identity.
 * \param policy Versioned caller requirements including exact expected serial.
 * \return Success only for initialized token with exact serial and requested mechanisms.
 * \note Does not certify device make, applet, SCP03, residency, secure boot or FIPS.
 * Key custody is checked later by QSC's existing PKCS#11 protected-key functions.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_se050_preflight(qsc_hw_pkcs11_module* module, uint64_t slot, const qsc_hw_se050_policy* policy);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
