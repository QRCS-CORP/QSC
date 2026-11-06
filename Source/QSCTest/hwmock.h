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

#ifndef QSCTEST_HWMOCK_H
#define QSCTEST_HWMOCK_H

#include "hwprovider.h"

#if defined(QSC_HARDWARE_ENABLED)

/** \file hwmock.h
 * \brief Deterministic, noncryptographic hardware-token simulator for isolated QSC tests.
 * \details Test-only provider; it cannot produce authentic signatures, entropy or attestation.
 * State is caller-owned and single-threaded. Tests can simulate session contention.
 */

/** \def QSCTEST_HWMOCK_KEY_CAPACITY
 * \brief Maximum number of deterministic mock key objects.
 */
#define QSCTEST_HWMOCK_KEY_CAPACITY 4U

/** \def QSCTEST_HWMOCK_SESSION_LIMIT
 * \brief Maximum simultaneously opened mock key handles.
 */
#define QSCTEST_HWMOCK_SESSION_LIMIT 2U

/** \def QSCTEST_HWMOCK_SIGNATURE_SIZE
 * \brief Fixed number of noncryptographic signature test bytes.
 */
#define QSCTEST_HWMOCK_SIGNATURE_SIZE 8U

/** \def QSCTEST_HWMOCK_PUBLIC_SIZE
 * \brief Fixed number of mock public key bytes.
 */
#define QSCTEST_HWMOCK_PUBLIC_SIZE 4U

/** \def QSCTEST_HWMOCK_SECRET_SIZE
 * \brief Fixed number of noncryptographic derived-secret test bytes.
 */
#define QSCTEST_HWMOCK_SECRET_SIZE 8U

/** \def QSCTEST_HWMOCK_EVIDENCE_SIZE
 * \brief Fixed length of synthetic attestation evidence.
 */
#define QSCTEST_HWMOCK_EVIDENCE_SIZE 8U

/** \enum qsctest_hwmock_action
 * \brief One-shot injectable backend operation selector.
 */
typedef enum qsctest_hwmock_action
{
	qsctest_hwmock_action_none = 0, /**< No injected error. */
	qsctest_hwmock_action_capabilities = 1, /**< Capability-query fault. */
	qsctest_hwmock_action_open = 2, /**< Persistent key open fault. */
	qsctest_hwmock_action_generate = 3, /**< Key generation fault. */
	qsctest_hwmock_action_sign = 4, /**< Signing fault. */
	qsctest_hwmock_action_agree = 5, /**< Key agreement fault. */
	qsctest_hwmock_action_random = 6, /**< Random output fault. */
	qsctest_hwmock_action_attest = 7, /**< Attestation fault. */
	qsctest_hwmock_action_public = 8 /**< Public key output fault. */
} qsctest_hwmock_action;

/** \struct qsctest_hwmock_key
 * \brief One mock object; no real private cryptographic bytes.
 */
typedef struct qsctest_hwmock_key
{
	uint32_t object_id; /**< Persistent synthetic object identifier. */
	uint32_t serial; /**< Token serial at object creation. */
	uint32_t usage; /**< Requested/available qsc_hw_usage flags. */
	size_t references; /**< Transient opens not yet released. */
	qsc_hw_algorithm algorithm; /**< Simulated key algorithm. */
	qsc_hw_custody custody; /**< Simulated reported custody. */
	bool exists; /**< Persistent object is present. */
	bool extractable; /**< Simulated extractability attribute. */
} qsctest_hwmock_key;

/** \struct qsctest_hwmock_context
 * \brief Caller-owned simulator state, requiring external serialization.
 */
typedef struct qsctest_hwmock_context
{
	qsctest_hwmock_key keys[QSCTEST_HWMOCK_KEY_CAPACITY]; /**< Fixed synthetic object table. */
	uint32_t serial; /**< Active token serial for identity matching. */
	uint32_t slot; /**< Renumberable local slot ID. */
	uint32_t pin_failures; /**< Invalid PIN attempts since last correct login. */
	size_t sessions; /**< Open transient mock key handles. */
	size_t opens; /**< Successful open callback count. */
	size_t generations; /**< Successful key generation callback count. */
	size_t signatures; /**< Signing callback count. */
	size_t releases; /**< Transient release callback count. */
	size_t closes; /**< Provider disposal notification count. */
	qsctest_hwmock_action fault_action; /**< Selected callback fault operation. */
	qsc_hw_status fault_status; /**< Injected typed error result. */
	bool fault_partial_output; /**< Poison first output byte before injected failure. */
	bool fault_issued; /**< Selected fault triggered in callback. */
	bool present; /**< Simulated token inserted. */
	bool authenticated; /**< Mock user PIN authenticated. */
	bool pin_locked; /**< Three consecutive failures lock mock token. */
	bool operation_active; /**< Simulate in-progress token operation or queue saturation. */
	bool bad_metadata; /**< Emit incorrect versioned key metadata on open. */
	bool bad_capabilities; /**< Advertise an invalid capability bit. */
	bool software_custody; /**< Report software custody for negative-policy tests. */
	bool extractable; /**< Report extractable key for negative-policy tests. */
} qsctest_hwmock_context;

/** \brief Initialize deterministic token, persistent objects and counters.
 * \param context Caller-owned writable context, required to be non-NULL.
 * \note Clears previous state; do not call while provider references are live.
 */
void qsctest_hwmock_initialize(qsctest_hwmock_context* context);

/** \brief Populate the QSC hardware ops table with test-only callbacks.
 * \param operations Caller-owned output, not retained by simulator.
 * \note Requires the caller to compile with QSC_HARDWARE_ENABLED.
 */
void qsctest_hwmock_make_ops(qsc_hw_provider_ops* operations);

/** \brief Simulate user PIN login, failure-counting and lockout.
 * \param context Caller-owned token context.
 * \param pin PIN bytes, treated as ephemeral read-only input.
 * \param length Length of pin in bytes.
 * \return success, auth_failed, locked, device_removed or invalid_parameter.
 * \note Valid test PIN is the 4 ASCII bytes 1234; this is not secure authentication.
 */
qsc_hw_status qsctest_hwmock_login(qsctest_hwmock_context* context, const uint8_t* pin, size_t length);

/** \brief Simulate logout; does not invalidate existing transient key references.
 * \param context Caller-owned mock state.
 */
void qsctest_hwmock_logout(qsctest_hwmock_context* context);

/** \brief Mark the device as removed and unauthenticated.
 * \param context Caller-owned mock state.
 * \note Caller must explicitly call qsc_hw_provider_invalidate to stale wrapper handles.
 */
void qsctest_hwmock_remove(qsctest_hwmock_context* context);

/** \brief Reinsert test device, optionally changing the token serial/key identity.
 * \param context Caller-owned mock state.
 * \param replace_token True changes serial, invalidating persistent object identity.
 * \note Caller must explicitly invalidate existing QSC provider key references.
 */
void qsctest_hwmock_insert(qsctest_hwmock_context* context, bool replace_token);

/** \brief Install or clear a one-operation fault injection.
 * \param context Caller-owned simulator context.
 * \param action Callback to fail; none clears the fault.
 * \param status Typed error to return from callback.
 * \param partial_output When true, write one synthetic output byte before returning an error.
 * \note Fault remains active until reset; no timers or physical devices are used.
 */
void qsctest_hwmock_set_fault(qsctest_hwmock_context* context, qsctest_hwmock_action action, qsc_hw_status status, bool partial_output);

#endif /* QSC_HARDWARE_ENABLED */

#endif
