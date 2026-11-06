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

#ifndef QSC_HWPLATFORM_H
#define QSC_HWPLATFORM_H

#include "hwprovider.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PLATFORM_ENABLED)

/** \file hwplatform.h
 * \brief Optional Apple Secure Enclave and Android Keystore provider adapter.
 * \details The platform bridge signs precomputed SHA-256 digests with P-256 keys.
 * Native backends must return raw 64-byte ECDSA signatures. No automatic software
 * fallback, platform key deletion, attestation verification or private-key export occurs.
 * Caller must serialize provider operations and retain native service state until close.
 */

/** \def QSC_HARDWARE_PLATFORM_ENABLED
 * \brief Include the optional OS Keystore provider facade in QSC build and consumers.
 * \note Without this macro, hwplatform.c introduces no platform SDK dependency or symbols.
 */

/** \def QSC_HW_PLATFORM_ALIAS_MAX
 * \brief Maximum number of bytes including NUL in a persistent key alias.
 */
#define QSC_HW_PLATFORM_ALIAS_MAX 80U

/** \def QSC_HW_PLATFORM_LOCATOR_MAX
 * \brief Maximum number of bytes including NUL in a platform key locator.
 */
#define QSC_HW_PLATFORM_LOCATOR_MAX 91U

/** \def QSC_HW_PLATFORM_PUBLIC_SIZE
 * \brief Uncompressed SEC1 P-256 point size in bytes.
 */
#define QSC_HW_PLATFORM_PUBLIC_SIZE 65U

/** \def QSC_HW_PLATFORM_SIGNATURE_SIZE
 * \brief Raw P-256 ECDSA r||s size in bytes.
 */
#define QSC_HW_PLATFORM_SIGNATURE_SIZE 64U

/** \enum qsc_hw_platform_family
 * \brief Selected OS-specific bridge with fixed API and namespace.
 */
typedef enum qsc_hw_platform_family
{
	qsc_hw_platform_family_none = 0, /**< Invalid or unselected platform. */
	qsc_hw_platform_family_apple = 1, /**< Apple Keychain/Secure Enclave. */
	qsc_hw_platform_family_android = 2 /**< Android Keystore/StrongBox. */
} qsc_hw_platform_family;

/** \enum qsc_hw_platform_security
 * \brief Reported platform security level, not remote attestation evidence.
 */
typedef enum qsc_hw_platform_security
{
	qsc_hw_platform_security_unknown = 0, /**< Security level could not be determined. */
	qsc_hw_platform_security_software = 1, /**< Key operation takes place in software. */
	qsc_hw_platform_security_tee = 2, /**< Android trusted execution environment. */
	qsc_hw_platform_security_strongbox = 3, /**< Android StrongBox hardware. */
	qsc_hw_platform_security_enclave = 4 /**< Apple Secure Enclave hardware. */
} qsc_hw_platform_security;

/** \struct qsc_hw_platform_key_attributes
 * \brief Nonsecret persistent P-256 identity snapshot returned by native bridge.
 */
typedef struct qsc_hw_platform_key_attributes
{
	uint32_t size; /**< Total structure bytes, must be sizeof this structure. */
	uint32_t version; /**< QSC_HW_ABI_VERSION. */
	qsc_hw_platform_security security; /**< Platform-reported key operation security level. */
	uint8_t public_key[QSC_HW_PLATFORM_PUBLIC_SIZE]; /**< SEC1 uncompressed P-256 public point. */
	bool persistent; /**< Key remains available after reopening the OS keystore. */
	bool private_exportable; /**< True if private bytes can be extracted by host code. */
	bool authentication_required; /**< Key signing may require user presence/authorization. */
} qsc_hw_platform_key_attributes;

/** \typedef qsc_hw_platform_query_callback
 * \brief Read live platform key attributes by exact persistent alias.
 * \param service Caller-owned native bridge state.
 * \param alias Validated NUL-terminated alias, valid for callback duration.
 * \param attributes Versioned caller-owned output including public point.
 * \return Success, stale_key if absent, or another typed platform error.
 */
typedef qsc_hw_status (*qsc_hw_platform_query_callback)(void* service, const char* alias, qsc_hw_platform_key_attributes* attributes);

/** \typedef qsc_hw_platform_create_callback
 * \brief Create a new persistent non-exportable P-256 key, never overwrite an alias.
 * \param service Caller-owned platform state.
 * \param alias Exact persistent alias; backend MUST fail if it exists.
 * \param require_strongbox True to demand Android StrongBox specifically.
 * \param attributes Output actual metadata on successful creation.
 * \return Typed status; never silently choose a software provider.
 */
typedef qsc_hw_status (*qsc_hw_platform_create_callback)(void* service, const char* alias, bool require_strongbox, qsc_hw_platform_key_attributes* attributes);

/** \typedef qsc_hw_platform_rollback_callback
 * \brief Destroy exclusively a freshly created key after failed policy verification.
 * \param service Caller-owned native service.
 * \param alias Alias created during the current generation attempt.
 * \return Success if fresh key removed, otherwise typed failure for manual recovery.
 */
typedef qsc_hw_status (*qsc_hw_platform_rollback_callback)(void* service, const char* alias);

/** \typedef qsc_hw_platform_sign_callback
 * \brief Sign SHA-256 digest using the native protected private key.
 * \param service Caller-owned native service.
 * \param alias Exact persistent alias.
 * \param digest Precomputed SHA-256 digest of 32 bytes.
 * \param digestlen Digest length, exactly 32 bytes.
 * \param signature Caller output raw P-256 ECDSA r||s of 64 bytes.
 * \param signaturelen In/out output capacity/actual length.
 * \return Typed error; no signed-data prehashing a second time.
 * \note Authentication prompting may be blocking; never invoke from an unsuitable UI thread.
 */
typedef qsc_hw_status (*qsc_hw_platform_sign_callback)(void* service, const char* alias, const uint8_t* digest, size_t digestlen, uint8_t* signature, size_t* signaturelen);

/** \struct qsc_hw_platform_callbacks
 * \brief Versioned native callback functions, without mandatory OS headers.
 */
typedef struct qsc_hw_platform_callbacks
{
	uint32_t size;								/**< sizeof(qsc_hw_platform_callbacks). */
	uint32_t version;							/**< QSC_HW_ABI_VERSION. */
	qsc_hw_platform_query_callback query;		/**< Required fresh key metadata lookup. */
	qsc_hw_platform_create_callback create;		/**< Optional protected key creation. */
	qsc_hw_platform_rollback_callback rollback; /**< Required if create is available. */
	qsc_hw_platform_sign_callback sign_digest;	/**< Optional raw prehashed ECDSA operation. */
} qsc_hw_platform_callbacks;

/** \struct qsc_hw_platform_context
 * \brief Caller-owned fixed identity scope; no private key bytes or hidden registry.
 * \note Not thread-safe. The caller owns service and retains it through provider close.
 */
typedef struct qsc_hw_platform_context
{
	qsc_hw_platform_callbacks callbacks;	/**< Validated copied native callback table. */
	void* service;							/**< Caller-owned active native platform bridge. */
	char alias[QSC_HW_PLATFORM_ALIAS_MAX];	/**< Validated persistent, nonsecret key alias. */
	qsc_hw_platform_family family;			/**< Apple or Android namespace and policy. */
	bool require_strongbox;					/**< Refuse TEE downgrade on Android. */
	bool hardware_verified;					/**< True only after independent target hardware qualification. */
	bool initialized;						/**< True until dispose, caller synchronizes lifecycle. */
} qsc_hw_platform_context;

/** \brief Initialize one portable platform signing context without creating keys.
 * \param context Zero-initialized caller-owned context.
 * \param callbacks Native bridge callback table; copied and validated.
 * \param service Non-NULL caller-owned native service instance.
 * \param family Apple or Android, never none.
 * \param alias Nonempty ASCII alias with only letters, digits, '.', '_' or '-'.
 * \param require_strongbox Valid only for Android, forces StrongBox custody.
 * \param hardware_verified Device-specific qualification decision, not inferred from API.
 * \return Typed status. No key/device operation occurs during initialization.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_platform_initialize(qsc_hw_platform_context* context, const qsc_hw_platform_callbacks* callbacks, 
	void* service, qsc_hw_platform_family family, const char* alias, bool require_strongbox, bool hardware_verified);

/** \brief Return generic provider operations wrapping this OS-backed P-256 identity.
 * \param operations Caller-owned descriptor populated on success.
 * \return Success, or invalid_parameter when NULL.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_platform_get_operations(qsc_hw_provider_ops* operations);

/** \brief Format canonical apple:// or android:// persistent key locator.
 * \param context Initialized platform identity scope.
 * \param output Output bytes or NULL for size query.
 * \param outputlen In/out capacity and required count including NUL.
 * \return Success or buffer_too_small; no writes outside supplied capacity.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_platform_locator(const qsc_hw_platform_context* context, char* output, size_t* outputlen);

/** \brief Clear adapter metadata without deleting persistent platform key.
 * \param context Caller-owned object with no outstanding provider/key references.
 * \note Native service remains caller-owned; do not use this before provider_close.
 */
QSC_EXPORT_API void qsc_hw_platform_dispose(qsc_hw_platform_context* context);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
