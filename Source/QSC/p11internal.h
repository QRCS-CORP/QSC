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

#ifndef QSC_P11INTERNAL_H
#define QSC_P11INTERNAL_H

#include "hwpkcs11.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "async.h"
/* Cryptoki ABI definitions come from the bundled or an external compatible header. */
#if defined(__has_include)
#   if __has_include("pkcs11.h")
#       include "pkcs11.h"
#   elif __has_include(<p11-kit/pkcs11.h>)
#       include <p11-kit/pkcs11.h>
#   else
#       error The optional PKCS11 adapter requires a compatible external pkcs11.h
#   endif
#else
#   include "pkcs11.h"
#endif

/** \file p11internal.h
 * \brief Internal-only Cryptoki module/session state; not part of the QSC public ABI.
 */

/** \struct qsc_hw_pkcs11_module
 * \brief Loaded module shared by clients using the identical dynamic library handle.
 */
struct qsc_hw_pkcs11_module
{
	struct qsc_hw_pkcs11_module* next; /**< Process registry chain, guarded by registry mutex. */
	void* library; /**< dlopen or Windows HMODULE; released at final close. */
	CK_FUNCTION_LIST_PTR functions; /**< Validated Cryptoki function dispatch table. */
	qsc_mutex mutex; /**< Serializes all adapter calls into this module. */
	size_t clients; /**< Outstanding module-open references. */
	size_t sessions; /**< Active session reference count. */
	uint64_t process_id; /**< PID of original loader, prevents use after fork. */
	bool owns_initialization; /**< True only if this adapter received CKR_OK from Initialize. */
};

/** \struct qsc_hw_pkcs11_session
 * \brief Transient session wrapper; user login never persists a copied PIN.
 */
struct qsc_hw_pkcs11_session
{
	qsc_hw_pkcs11_module* module; /**< Referenced module; cannot close while sessions exist. */
	CK_SESSION_HANDLE handle; /**< Module-scoped Cryptoki session handle. */
	CK_SLOT_ID slot; /**< Fixed token slot associated with this session. */
	bool read_write; /**< Session was opened with CKF_RW_SESSION. */
	size_t keys; /**< Outstanding key references blocking session close. */
	bool authenticated; /**< Login outcome for caller diagnostics only, not trusted token state. */
};

/** \struct qsc_hw_pkcs11_key
 * \brief Session-bound protected object handle and immutable identity snapshot.
 */
struct qsc_hw_pkcs11_key
{
	qsc_hw_pkcs11_session* session; /**< Owning live session. */
	CK_OBJECT_HANDLE handle; /**< Transient vendor private-key handle. */
	qsc_hw_algorithm algorithm; /**< Validated curve and permitted key operation. */
	uint8_t id[QSC_HW_PKCS11_MAX_KEY_ID]; /**< Persistent object identifier, not secret. */
	size_t idlen; /**< Stored identifier byte count. */
	uint8_t serial[16U]; /**< Fixed-width token serial at open time. */
};

/** \brief Check key identity and nonextractable private attributes under module lock.
 * \param key Live referenced private token key.
 * \return Success or typed stale-key/device/policy failure.
 * \note Caller holds the module mutex; never export CKA_VALUE.
 */
qsc_hw_status p11_key_validate_locked(const qsc_hw_pkcs11_key* key);

/** \brief Map a QSC ECDSA/ECDH curve to DER OID and public point dimensions.
 * \param algorithm Requested EC algorithm.
 * \param oid Receives static DER OID bytes on success.
 * \param oidlen Receives byte length.
 * \param pointlen Receives uncompressed SEC1 point size.
 * \param sign Receives true for ECDSA; false for ECDH.
 * \return True for supported EC algorithms.
 */
bool p11_key_curve(qsc_hw_algorithm algorithm, const uint8_t** oid, size_t* oidlen, size_t* pointlen, bool* sign);

/** \brief Classify a module status without exposing vendor data to the public ABI.
 * \param result Cryptoki CK_RV from the backend.
 * \return Nearest QSC hardware status, fail-closed for unknown errors.
 */
qsc_hw_status p11_status_from_rv(CK_RV result);

/** \brief Check that module belongs to the current process, not a forked child.
 * \param module Loaded module.
 * \return True only when module's process ID matches the current process.
 */
bool p11_module_current(const qsc_hw_pkcs11_module* module);

/** \brief Enter a module's serialized Cryptoki-call critical section.
 * \param module Live module, originally loaded in this process.
 */
void p11_module_lock(qsc_hw_pkcs11_module* module);

/** \brief Release the module critical section.
 * \param module Live module whose lock is held by caller.
 */
void p11_module_unlock(qsc_hw_pkcs11_module* module);

#endif

#endif
