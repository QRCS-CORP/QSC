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

#ifndef QSC_HWPSA_H
#define QSC_HWPSA_H

#include "hwprovider.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PSA_ENABLED)

/** \file hwpsa.h
 * \brief Optional Arm PSA Crypto-compatible key service bridge.
 * \details No PSA or TF-M header is needed for this interface. An OEM supplies
 * callbacks backed by the platform PSA Crypto service, not a parallel crypto engine.
 * This bridge does not claim physical hardware custody without platform evidence.
 * All operations are synchronous, non-reentrant, and caller-serialized.
 */

/** \def QSC_HARDWARE_PSA_ENABLED
 * \brief Compile the independent Arm PSA Crypto key-service adapter.
 */

/** \def QSC_HW_PSA_LOCATOR_SIZE
 * \brief Storage including NUL for canonical "psa://" plus eight hex digits.
 */
#define QSC_HW_PSA_LOCATOR_SIZE 15U

/** \def QSC_HW_PSA_PUBLIC_MAX_SIZE
 * \brief Maximum SEC1 uncompressed point length for supported NIST curves.
 */
#define QSC_HW_PSA_PUBLIC_MAX_SIZE 133U

/** \def QSC_HW_PSA_SIGNATURE_MAX_SIZE
 * \brief Maximum raw ECDSA signature length for supported curves.
 */
#define QSC_HW_PSA_SIGNATURE_MAX_SIZE 132U

/** \struct qsc_hw_psa_key_attributes
 * \brief Nonsecret PSA persistent-key metadata returned by OEM PSA callbacks.
 * \note persistent, key id and export policy must be confirmed by the secure service.
 * hardware_protected is a platform qualification assertion, not a PSA API attestation.
 */
typedef struct qsc_hw_psa_key_attributes
{
	uint32_t size;					/**< sizeof(qsc_hw_psa_key_attributes), required on input and output. */
	uint32_t version;				/**< QSC_HW_ABI_VERSION. */
	uint32_t key_id;				/**< PSA persistent key identifier, not a raw private key. */
	qsc_hw_algorithm algorithm;		/**< Exact NIST curve/operation profile. */
	uint32_t usage;					/**< qsc_hw_usage_sign or qsc_hw_usage_agree. */
	bool persistent;				/**< Key remains usable after application/PSA-session close. */
	bool private_exportable;		/**< True if PSA key usage/policy permits private export. */
	bool hardware_protected;		/**< OEM-confirmed true hardware key-operation boundary. */
} qsc_hw_psa_key_attributes;

/** \typedef qsc_hw_psa_query_callback
 * \brief Query actual PSA attributes for the named key, not cached declarations.
 * \param service Caller-owned initialized secure-service context.
 * \param key_id Persistent PSA key identifier.
 * \param attributes Caller sets size/version; callee returns complete metadata.
 * \return Typed result. Deny inaccessible/missing keys and forbidden usage.
 */
typedef qsc_hw_status (*qsc_hw_psa_query_callback)(void* service, uint32_t key_id, qsc_hw_psa_key_attributes* attributes);

/** \typedef qsc_hw_psa_create_callback
 * \brief Create a new protected persistent PSA key at a requested unused key id.
 * \param service OEM-owned service context.
 * \param key_id Requested unused persistent ID; never overwrite existing keys.
 * \param policy Requested algorithm, usage and private export policy.
 * \param attributes Full actual key attributes on success.
 * \return Typed status. On error callee must roll back any newly created key.
 */
typedef qsc_hw_status (*qsc_hw_psa_create_callback)(void* service, uint32_t key_id, const qsc_hw_key_policy* policy, qsc_hw_psa_key_attributes* attributes);

/** \typedef qsc_hw_psa_rollback_callback
 * \brief Destroy only a newly generated object if post-creation validation fails.
 * \param service OEM service context.
 * \param key_id The newly created persistent ID, never an arbitrary existing key.
 * \return Typed result. Failure must be reported for manual secure cleanup.
 */
typedef qsc_hw_status (*qsc_hw_psa_rollback_callback)(void* service, uint32_t key_id);

/** \typedef qsc_hw_psa_public_callback
 * \brief Export public SEC1 uncompressed EC point; never private bytes.
 * \param service OEM service context.
 * \param key_id Persistent key ID.
 * \param output Caller buffer sized for a full point, never NULL.
 * \param outputlen In/out capacity and actual length.
 * \return Typed result. Never expose partial output on failure.
 */
typedef qsc_hw_status (*qsc_hw_psa_public_callback)(void* service, uint32_t key_id, uint8_t* output, size_t* outputlen);

/** \typedef qsc_hw_psa_sign_hash_callback
 * \brief Execute PSA-style ECDSA prehashed signing, returning raw r||s.
 * \param service OEM service context.
 * \param key_id Persistent key ID.
 * \param algorithm Selected curve and digest profile.
 * \param digest Precomputed hash bytes; digest length must match profile.
 * \param digestlen Digest length in bytes.
 * \param signature Caller output buffer; never NULL.
 * \param signaturelen In/out output length; exactly raw signature size on success.
 * \return Typed error or success. No signature bytes on error.
 */
typedef qsc_hw_status (*qsc_hw_psa_sign_hash_callback)(void* service, uint32_t key_id, qsc_hw_algorithm algorithm, const uint8_t* digest, 
	size_t digestlen, uint8_t* signature, size_t* signaturelen);

/** \typedef qsc_hw_psa_agreement_callback
 * \brief Perform PSA ECDH with explicit raw-secret export permission.
 * \param service OEM service context.
 * \param key_id Persistent key ID.
 * \param algorithm Requested NIST ECDH curve.
 * \param peer SEC1 uncompressed peer key bytes.
 * \param peerlen Input length, in bytes.
 * \param secret Host-side destination for raw ECDH output; never NULL.
 * \param secretlen In/out capacity/actual size; must match curve field size.
 * \return Typed result. Backend clears partial raw secrets on error.
 */
typedef qsc_hw_status (*qsc_hw_psa_agreement_callback)(void* service, uint32_t key_id, qsc_hw_algorithm algorithm, const uint8_t* peer, 
	size_t peerlen, uint8_t* secret, size_t* secretlen);

/** \typedef qsc_hw_psa_random_callback
 * \brief Request bytes from platform PSA RNG, without claiming entropy approval.
 * \param service OEM-owned PSA service context.
 * \param output Caller-owned output buffer.
 * \param length Requested byte count.
 * \return Typed result; output is erased on failure by the QSC provider.
 */
typedef qsc_hw_status (*qsc_hw_psa_random_callback)(void* service, uint8_t* output, size_t length);

/** \struct qsc_hw_psa_callbacks
 * \brief Versioned OEM platform binding, e.g. to TF-M PSA Crypto service.
 * \note No callback may implement a private-key operation in QSC application memory.
 */
typedef struct qsc_hw_psa_callbacks
{
	uint32_t size;								/**< sizeof(qsc_hw_psa_callbacks). */
	uint32_t version;							/**< QSC_HW_ABI_VERSION. */
	qsc_hw_psa_query_callback query;			/**< Mandatory live key attributes lookup. */
	qsc_hw_psa_create_callback create;			/**< Optional persistent key creation. */
	qsc_hw_psa_rollback_callback rollback;		/**< Required when create is provided. */
	qsc_hw_psa_public_callback public_key;		/**< Optional SEC1 point export. */
	qsc_hw_psa_sign_hash_callback sign_hash;	/**< Optional ECDSA hash signing. */
	qsc_hw_psa_agreement_callback agree;		/**< Optional raw ECDH key agreement. */
	qsc_hw_psa_random_callback random;			/**< Optional PSA entropy source. */
} qsc_hw_psa_callbacks;

/** \struct qsc_hw_psa_context
 * \brief Caller-owned, pinned single-key-id PSA provider scope.
 * \note Initialize to all zero before use; service lifetime extends to provider close.
 * Caller serializes operations; hardware_verified must not be set for a software PSA backend.
 */
typedef struct qsc_hw_psa_context
{
	qsc_hw_psa_callbacks callbacks;	/**< Copied OEM callback descriptor. */
	void* service;					/**< OEM-owned TF-M/PSA client context; never freed by QSC. */
	uint32_t key_id;				/**< Fixed PSA persistent key ID for this provider scope. */
	bool hardware_verified;			/**< OEM independently qualified hardware key operations. */
	bool initialized;				/**< True after successful initialization until dispose. */
} qsc_hw_psa_context;

/** \brief Initialize a caller-owned PSA provider scope without creating/destroying keys.
 * \param context Zero-initialized caller-owned context.
 * \param callbacks Versioned OEM PSA service operations.
 * \param service Non-NULL OEM-owned initialized PSA service context.
 * \param key_id Nonzero persistent PSA ID; pin one identity per provider instance.
 * \param hardware_verified True only after device-specific independent custody proof.
 * \return Typed error or success; no authorization prompts or vendor calls.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_psa_initialize(qsc_hw_psa_context* context, const qsc_hw_psa_callbacks* callbacks, void* service, uint32_t key_id, bool hardware_verified);

/** \brief Construct versioned callback operations for the generic QSC provider.
 * \param operations Caller-owned versioned descriptor, cleared before population.
 * \return Success or invalid parameter.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_psa_get_operations(qsc_hw_provider_ops* operations);

/** \brief Format a canonical persistent PSA ID locator, no secret material.
 * \param context Initialized PSA context.
 * \param output Caller output or NULL for size query.
 * \param outputlen In/out byte capacity, including final NUL.
 * \return Success or buffer-too-small; outputs exactly QSC_HW_PSA_LOCATOR_SIZE bytes.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_psa_locator(qsc_hw_psa_context* context, char* output, size_t* outputlen);

/** \brief Erase bridge state only, never remove PSA persistent keys or close OEM service.
 * \param context Caller-owned context with no outstanding provider/key handles.
 */
QSC_EXPORT_API void qsc_hw_psa_dispose(qsc_hw_psa_context* context);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
