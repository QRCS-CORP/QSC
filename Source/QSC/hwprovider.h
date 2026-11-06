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

#ifndef QSC_HWPROVIDER_H
#define QSC_HWPROVIDER_H

#include "hwtypes.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED)

/** \file hwprovider.h
 * \brief Optional, backend-independent hardware-key provider facade.
 * \details The provider owns its wrapper allocation, but backend_context remains caller-owned.
 * Backend callbacks must not expose private key bytes unless permitted by explicit policy.
 * Caller must serialize provider-close and key-release against concurrent operations.
 * There is no global provider registry, runtime ISA dispatch or mandatory vendor library.
 */

/** \struct qsc_hw_provider
 * \brief Opaque provider handle owned by qsc_hw_provider_close.
 */
typedef struct qsc_hw_provider qsc_hw_provider;

/** \struct qsc_hw_keyref
 * \brief Opaque transient key reference owned by qsc_hw_key_release.
 * \note Do not persist or reuse this pointer across device reconnection.
 */
typedef struct qsc_hw_keyref qsc_hw_keyref;

/** \typedef qsc_hw_dispose_callback
 * \brief Optional notification when a provider wrapper closes.
 * \param context Caller-owned backend context; callback does not release this memory unless arranged by caller.
 * \note Called only when there are no outstanding key references.
 */
typedef void (*qsc_hw_dispose_callback)(void* context);

/** \typedef qsc_hw_capabilities_callback
 * \brief Report the current backend capabilities.
 * \param context Caller-owned backend state.
 * \param capabilities In/out size/version-qualified caller-owned structure.
 * \return Typed status; no FIPS or hardware attestation implied by flags.
 */
typedef qsc_hw_status (*qsc_hw_capabilities_callback)(void* context, qsc_hw_capabilities* capabilities);

/** \typedef qsc_hw_key_open_callback
 * \brief Open an existing key by persistent locator.
 * \param context Caller-owned backend state.
 * \param locator NUL-terminated locator valid only during the callback; backend validates it.
 * \param key On success receives a non-NULL backend-private key handle.
 * \param info On success receives versioned key metadata, no private bytes.
 * \return Typed status. On failure backend must not retain or return a key reference.
 */
typedef qsc_hw_status (*qsc_hw_key_open_callback)(void* context, const char* locator, void** key, qsc_hw_key_info* info);

/** \typedef qsc_hw_key_generate_callback
 * \brief Generate a key using device-enforced requested policy.
 * \param context Caller-owned backend state.
 * \param policy Validated caller policy; backend must enforce it before irreversible key creation.
 * \param key On success receives backend-private key reference.
 * \param info On success receives metadata to verify actual custody and usage.
 * \return Typed status; backend owns cleanup of any partially created persistent object.
 */
typedef qsc_hw_status (*qsc_hw_key_generate_callback)(void* context, const qsc_hw_key_policy* policy, void** key, qsc_hw_key_info* info);

/** \typedef qsc_hw_key_release_callback
 * \brief Release one transient backend-private key handle (not persistent key deletion).
 * \param context Caller-owned backend state.
 * \param key Non-NULL key returned from open or generation.
 * \note Must release all transient resources; caller serializes with active operations.
 */
typedef void (*qsc_hw_key_release_callback)(void* context, void* key);

/** \typedef qsc_hw_sign_callback
 * \brief Sign bytes under an existing backend key handle.
 * \param context Caller-owned backend state.
 * \param key Backend-private key reference.
 * \param algorithm Exact requested signing algorithm.
 * \param message Message bytes, or NULL only for zero length.
 * \param msglen Message byte count.
 * \param signature Caller-owned output, or NULL for size query.
 * \param signaturelen In/out byte capacity; reports size on success or buffer-too-small.
 * \return Typed status; must not expose partial signatures on other failures.
 * \note Signature encoding is backend-specified; TLS conversion belongs to a later adapter.
 */
typedef qsc_hw_status (*qsc_hw_sign_callback)(void* context, void* key, qsc_hw_algorithm algorithm, const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen);

/** \typedef qsc_hw_agree_callback
 * \brief Perform key agreement with an explicitly exportable derived secret.
 * \param context Caller-owned backend state.
 * \param key Backend-private key reference.
 * \param peer Public peer key bytes.
 * \param peerlen Public peer key byte count.
 * \param secret Caller-owned secret bytes; NULL permitted for size query.
 * \param secretlen In/out secret capacity/actual byte count.
 * \return Typed status. Backend must enforce the derived-secret export policy.
 * \note This interface does NOT claim an opaque derived key remains hardware-resident.
 */
typedef qsc_hw_status (*qsc_hw_agree_callback)(void* context, void* key, const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen);

/** \typedef qsc_hw_random_callback
 * \brief Generate backend RNG bytes without implying approved entropy status.
 * \param context Caller-owned backend state.
 * \param output Caller-owned writable buffer of length bytes.
 * \param length Required number of output bytes.
 * \return Typed status. Partial output must be cleared by backend on failure.
 */
typedef qsc_hw_status (*qsc_hw_random_callback)(void* context, uint8_t* output, size_t length);

/** \typedef qsc_hw_attest_callback
 * \brief Retrieve a device-specific evidence envelope for an existing key.
 * \param context Caller-owned backend state.
 * \param key Backend-private key reference.
 * \param challenge Nonce/challenge bytes.
 * \param challengelen Challenge length in bytes.
 * \param evidence Caller-owned evidence output, or NULL for size query.
 * \param evidencelen In/out byte length.
 * \return Typed status. Evidence requires separate validation before making an attestation claim.
 */
typedef qsc_hw_status (*qsc_hw_attest_callback)(void* context, void* key, const uint8_t* challenge, size_t challengelen, uint8_t* evidence, size_t* evidencelen);

/** \typedef qsc_hw_public_key_callback
 * \brief Obtain an opened key's public component without extracting private material.
 * \param context Caller-owned backend state.
 * \param key Backend-private transient key reference.
 * \param output Caller-owned public-key output, or NULL for size query.
 * \param outputlen In/out byte capacity and actual/required public-key length.
 * \return Success, buffer-too-small or typed backend failure.
 * \note Encoding must be documented by the backend for each algorithm.
 */
typedef qsc_hw_status (*qsc_hw_public_key_callback)(void* context, void* key, uint8_t* output, size_t* outputlen);

/** \struct qsc_hw_provider_ops
 * \brief Versioned callback descriptor supplied by a backend adapter.
 * \details Append-only layout. Core copies at most its known descriptor size.
 * Mandatory fields: size, version, get_capabilities and release_key.
 */
typedef struct qsc_hw_provider_ops
{
	uint32_t size;									/**< sizeof(qsc_hw_provider_ops), in bytes. */
	uint32_t version;								/**< QSC_HW_ABI_VERSION. */
	qsc_hw_capabilities_callback get_capabilities;	/**< Required capability callback. */
	qsc_hw_key_release_callback release_key;		/**< Required transient key handle release. */
	qsc_hw_dispose_callback dispose;				/**< Optional close notification; backend_context remains caller-owned. */
	qsc_hw_key_open_callback open_key;				/**< Optional persistent key lookup. */
	qsc_hw_key_generate_callback generate_key;		/**< Optional key creation. */
	qsc_hw_sign_callback sign;						/**< Optional signing. */
	qsc_hw_agree_callback agree;					/**< Optional exported-secret ECDH. */
	qsc_hw_random_callback random;					/**< Optional RNG. */
	qsc_hw_attest_callback attest;					/**< Optional attestation evidence. */
	qsc_hw_public_key_callback public_key;          /**< Optional public-key extraction, never private bytes. */
} qsc_hw_provider_ops;

/** \brief Construct an isolated provider wrapper around an externally managed backend context.
 * \param provider Output receives allocated handle; set to NULL before validation when non-NULL.
 * \param operations Descriptor with recognized ABI version, minimum mandatory callbacks and size.
 * \param context Backend context; caller guarantees lifetime through successful close.
 * \return Success or typed failure. Failure transfers no ownership and does not invoke dispose.
 * \note Caller must synchronize close against concurrent operations.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_provider_open(qsc_hw_provider** provider, const qsc_hw_provider_ops* operations, void* context);

/** \brief Obtain a current capability snapshot.
 * \param provider Live provider handle.
 * \param capabilities Caller initializes size/version; output available on success.
 * \return Typed error or success; no device attestation implied.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_provider_capabilities(qsc_hw_provider* provider, qsc_hw_capabilities* capabilities);

/** \brief Open a key with explicit custody and usage requirements.
 * \param key Output receives allocated transient reference; no private bytes.
 * \param provider Live provider.
 * \param locator NUL-terminated persistent key locator, not a session handle.
 * \param policy Requested immutable policy with size/version.
 * \return Typed error or success; backend object released on policy mismatch.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_open(qsc_hw_keyref** key, qsc_hw_provider* provider, const char* locator, const qsc_hw_key_policy* policy);

/** \brief Generate and reference a device-protected key under explicit policy.
 * \param key Output receives transient key reference.
 * \param provider Live provider.
 * \param policy Requested algorithm, usage and custody; backend must enforce before generation.
 * \return Typed error or success; persistent key rollback is backend responsibility on failure.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_generate(qsc_hw_keyref** key, qsc_hw_provider* provider, const qsc_hw_key_policy* policy);

/** \brief Retrieve public key metadata, not private key material.
 * \param key Live key reference.
 * \param info Caller-owned versioned output (size/version set before calling).
 * \return Success or typed error.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_get_info(const qsc_hw_keyref* key, qsc_hw_key_info* info);

/** \brief Retrieve public key bytes from an opened protected key.
 * \param key Live key reference, including a current generation.
 * \param output Writable public bytes or NULL for a size query.
 * \param outputlen In/out capacity and actual/required byte length.
 * \return Success, unsupported, stale-key or backend error.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_public(qsc_hw_keyref* key, uint8_t* output, size_t* outputlen);

/** \brief Sign using an opened key, with enforced usage and custody policy.
 * \param key Live key reference.
 * \param message Input bytes or NULL when msglen is zero.
 * \param msglen Input byte length.
 * \param signature Output or NULL for length query.
 * \param signaturelen In/out capacity and actual/required bytes.
 * \return Success or typed failure; unsupported operations never invoke the backend.
 * \note Backend error (except buffer_too_small) clears the supplied signature capacity.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_sign(qsc_hw_keyref* key, const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen);

/** \brief Derive an explicitly exportable shared secret using a protected key.
 * \param key Live key reference.
 * \param peer Public peer key bytes.
 * \param peerlen Peer public key bytes.
 * \param secret Caller-owned output or NULL for length query.
 * \param secretlen In/out capacity/required bytes.
 * \return Success or typed error; never claim the resulting exported bytes are hardware-resident.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_agree(qsc_hw_keyref* key, const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen);

/** \brief Request key-bound attestation evidence without verifying its trust chain.
 * \param key Live key reference.
 * \param challenge Required nonempty fresh challenge bytes.
 * \param challengelen Challenge length in bytes.
 * \param evidence Caller-owned output or NULL for length query.
 * \param evidencelen In/out capacity/required length.
 * \return Success or typed failure. Caller must independently verify freshness and trust.
 * \note Backend error (except buffer_too_small) clears the supplied evidence capacity.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_attest(qsc_hw_keyref* key, const uint8_t* challenge, size_t challengelen, uint8_t* evidence, size_t* evidencelen);

/** \brief Request random data from a provider's optional RNG.
 * \param provider Live provider.
 * \param output Writable buffer, required for nonzero length.
 * \param length Requested output bytes; zero is permitted.
 * \return Typed status; not an entropy quality or FIPS approval claim.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_provider_random(qsc_hw_provider* provider, uint8_t* output, size_t length);

/** \brief Invalidate all previously opened keys on device reconnect or replacement.
 * \param provider Live provider; caller serializes against concurrent key operations.
 * \return Success or typed error. Invalidated keys must still be released.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_provider_invalidate(qsc_hw_provider* provider);

/** \brief Release one transient key handle without deleting persistent hardware objects.
 * \param key Address of live key; set to NULL on successful release.
 * \return Typed status; caller synchronizes release with in-flight calls.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_key_release(qsc_hw_keyref** key);

/** \brief Close a provider without invalidating outstanding handles.
 * \param provider Address of live provider; set to NULL on success.
 * \return busy while any key references remain, otherwise success.
 * \note Caller synchronizes close with all active operations. Backend context remains caller-owned.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_provider_close(qsc_hw_provider** provider);


#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
