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

#ifndef QSC_HWPKCS11_H
#define QSC_HWPKCS11_H

#include "hwtypes.h"

QSC_CPLUSPLUS_ENABLED_START

/** \file hwpkcs11.h
 * \brief Optional PKCS#11 Cryptoki module/session integration for the QSC hardware interface.
 * \details No vendor SDK is required by this public header. Compile adapter sources with
 * QSC_HARDWARE_ENABLED and QSC_HARDWARE_PKCS11_ENABLED and an externally installed
 * standards-compatible pkcs11.h. Load modules only from an application-trusted absolute path.
 * The caller synchronizes concurrent use and close of the same session handle.
 */

/** \def QSC_HARDWARE_PKCS11_ENABLED
 * \brief Opt in to the Cryptoki adapter; requires QSC_HARDWARE_ENABLED.
 * \note Disabled by default. The adapter requires an external PKCS#11 development header.
 */

/** \def QSC_HW_PKCS11_MAX_ITEMS
 * \brief Maximum slot or mechanism entries accepted from a potentially untrusted module.
 */
#define QSC_HW_PKCS11_MAX_ITEMS 4096U

/** \def QSC_HW_PKCS11_MAX_PATH
 * \brief Maximum accepted path length excluding the terminating NUL, in bytes.
 */
#define QSC_HW_PKCS11_MAX_PATH 4096U

/** \def QSC_HW_PKCS11_MAX_PIN_LENGTH
 * \brief Maximum PIN length accepted before creating a transient private copy, in bytes.
 */
#define QSC_HW_PKCS11_MAX_PIN_LENGTH 1024U

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

/** \struct qsc_hw_pkcs11_module
 * \brief Opaque process-local, reference-counted loaded Cryptoki module.
 */
typedef struct qsc_hw_pkcs11_module qsc_hw_pkcs11_module;

/** \struct qsc_hw_pkcs11_session
 * \brief Opaque session; may become invalid on token removal/reconnection.
 */
typedef struct qsc_hw_pkcs11_session qsc_hw_pkcs11_session;

/** \struct qsc_hw_pkcs11_token_info
 * \brief Trimmed public token metadata; neither object nor private key material.
 */
typedef struct qsc_hw_pkcs11_token_info
{
	char label[33U];				/**< NUL-terminated token label; max 32 printable bytes. */
	char serial[17U];				/**< NUL-terminated token serial; max 16 bytes. */
	bool protected_authentication;	/**< Token advertises protected PIN entry path. */
	bool token_initialized;			/**< Token has been initialized by its owner. */
} qsc_hw_pkcs11_token_info;

/** \struct qsc_hw_pkcs11_mechanism_info
 * \brief Native Cryptoki mechanism properties, converted to bounded portable integers.
 */
typedef struct qsc_hw_pkcs11_mechanism_info
{
	uint64_t min_key_bits;	/**< Module-reported minimum key length/size. */
	uint64_t max_key_bits;	/**< Module-reported maximum key length/size. */
	uint64_t flags;			/**< Native CKF_* mechanism flags; vendor-specific semantics unchanged. */
} qsc_hw_pkcs11_mechanism_info;

/** \def QSC_HW_PKCS11_MAX_KEY_ID
 * \brief Maximum accepted CKA_ID size for protected-key discovery and generation, in bytes.
 */
#define QSC_HW_PKCS11_MAX_KEY_ID 64U

/** \struct qsc_hw_pkcs11_key
 * \brief Opaque session-bound non-exportable token private-key reference.
 * \note Must be released before closing the owning session. Never persisted across reconnects.
 */
typedef struct qsc_hw_pkcs11_key qsc_hw_pkcs11_key;

/** \brief Resolve one protected private key by exact CKA_ID and elliptic-curve algorithm.
 * \param key Output reference, NULL on error.
 * \param session Active Cryptoki session, including token authorization where required.
 * \param id Nonempty binary CKA_ID bytes, at most QSC_HW_PKCS11_MAX_KEY_ID bytes.
 * \param idlen Length of id in bytes.
 * \param algorithm Exact ECDSA curve (P-256/P-384/P-521), or supported ECDH curve.
 * \return Success only for exactly one sensitive, nonextractable, token-resident matching key.
 * \note This interface reports token attributes, not independent hardware attestation.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_key_find(qsc_hw_pkcs11_key** key, qsc_hw_pkcs11_session* session, const uint8_t* id, size_t idlen, qsc_hw_algorithm algorithm);

/** \brief Generate one token-resident nonextractable EC keypair with unique CKA_ID.
 * \param key Receives live private key reference, NULL on failure.
 * \param session Active read-write token session.
 * \param id Unique nonempty caller-selected CKA_ID; never a secret.
 * \param idlen Identifier length in bytes.
 * \param algorithm ECDSA P-256/P-384/P-521 or ECDH P-256/P-384/P-521.
 * \return Typed generation, policy, or rollback failure. Generated objects persist until explicitly destroyed by provisioning software.
 * \note Token must enforce CKA_SENSITIVE=true and CKA_EXTRACTABLE=false. Creation failure attempts rollback; treat failed rollback as provisioning incident.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_key_generate(qsc_hw_pkcs11_key** key, qsc_hw_pkcs11_session* session, const uint8_t* id, size_t idlen, qsc_hw_algorithm algorithm);

/** \brief Retrieve a token private-key reference's matched public EC point.
 * \param key Live protected key reference.
 * \param output Caller buffer for SEC1 uncompressed point (0x04 || X || Y), or NULL for size query.
 * \param outputlen In/out buffer capacity and exact point length, in bytes.
 * \return Success, buffer-too-small, stale-key or typed backend failure; no private data is exported.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_key_public(qsc_hw_pkcs11_key* key, uint8_t* output, size_t* outputlen);

/** \brief Sign a precomputed digest using CKM_ECDSA, returning raw fixed-width r||s.
 * \param key Live ECDSA private-key reference; ECDH-only keys are rejected.
 * \param digest Precomputed digest bytes, exactly 32, 48 or 64 bytes for P-256/P-384/P-521 respectively.
 * \param digestlen Digest length in bytes.
 * \param signature Writable raw r||s buffer, or NULL for required-length query.
 * \param signaturelen In/out capacity and raw signature length (64, 96, 132 bytes).
 * \return Typed status; signature buffer is erased on failed backend execution.
 * \note Digest construction and TLS DER conversion are caller responsibilities.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_key_sign(qsc_hw_pkcs11_key* key, const uint8_t* digest, size_t digestlen, uint8_t* signature, size_t* signaturelen);

/** \brief Perform token-backed ECDH with an explicitly authorized export of the derived secret.
 * \param key Live ECDH-only protected private key reference.
 * \param peer Uncompressed SEC1 peer public EC point; caller must authenticate the peer.
 * \param peerlen Exact peer point length for this key's curve, in bytes.
 * \param secret Caller-owned raw output buffer, or NULL to query supported length.
 * \param secretlen In/out output size; 32, 48 or 66 bytes for P-256/P-384/P-521.
 * \param allow_export Explicit authorization to export derived secret into application memory.
 * \return Typed result; a temporary token-derived object is always destroyed before success.
 * \note Only the private key remains non-exportable; output bytes are NOT hardware-resident.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_key_agree(qsc_hw_pkcs11_key* key, const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen, bool allow_export);

/** \brief Release an ephemeral key reference without deleting token objects.
 * \param key Address of reference; set NULL on release.
 * \return Typed status. Owning session must remain live; caller synchronizes concurrent calls.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_key_release(qsc_hw_pkcs11_key** key);

/** \brief Open or share one initialized module in the current process.
 * \param module Output receives one shared module reference, NULL on failure.
 * \param absolute_path NUL-terminated absolute filesystem path; no relative or traversal paths.
 * \return Typed status. When CKR_CRYPTOKI_ALREADY_INITIALIZED is returned, QSC does not own Finalize.
 * \note Thread-safe module registry; application must trust the path and protect module integrity.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_module_open(qsc_hw_pkcs11_module** module, const char* absolute_path);

/** \brief Close one client reference, finalizing/unloading only when owned and unused.
 * \param module In/out live module reference; set NULL on successful release.
 * \return Busy if any open session exists, otherwise typed status.
 * \note Module references are process-local; do not inherit them across fork.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_module_close(qsc_hw_pkcs11_module** module);

/** \brief Enumerate slot identifiers without exposing Cryptoki-dependent public types.
 * \param module Loaded module.
 * \param token_present Filter for slots reporting inserted tokens.
 * \param slots Caller buffer of capacity *count entries, or NULL for count-only query.
 * \param count In/out capacity and reported count in entries; zeroed on errors except insufficient capacity.
 * \return Success or typed failure, including buffer-too-small and malicious oversized enumeration.
 * \note Query and copy are serialized with this module's other QSC adapter operations.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_slot_list(qsc_hw_pkcs11_module* module, bool token_present, uint64_t* slots, size_t* count);

/** \brief Query public metadata of a physical/logical token.
 * \param module Loaded module.
 * \param slot Numeric slot identifier returned from slot_list.
 * \param info Caller-owned output; zeroed before querying.
 * \return Typed status; token absence reported distinctly.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_token_info_get(qsc_hw_pkcs11_module* module, uint64_t slot, qsc_hw_pkcs11_token_info* info);

/** \brief Enumerate actual available Cryptoki mechanisms for a slot.
 * \param module Loaded module.
 * \param slot Slot identifier obtained from enumeration.
 * \param mechanisms Caller buffer or NULL for size query.
 * \param count In/out entry capacity and reported count.
 * \return Success, buffer-too-small, or typed failure.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_mechanism_list(qsc_hw_pkcs11_module* module, uint64_t slot, uint64_t* mechanisms, size_t* count);

/** \brief Obtain mechanism limits and attributes from the token.
 * \param module Loaded module.
 * \param slot Slot identifier.
 * \param mechanism Cryptoki mechanism identifier.
 * \param info Caller-owned output.
 * \return Typed status; unsupported mechanism is explicit.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_mechanism_info_get(qsc_hw_pkcs11_module* module, uint64_t slot, uint64_t mechanism, qsc_hw_pkcs11_mechanism_info* info);

/** \brief Open one isolated serial Cryptoki session.
 * \param session Output handle, NULL on failure.
 * \param module Loaded module; cannot be closed while any session is live.
 * \param slot Slot identifier from enumeration.
 * \param read_write Request read-write access; false opens a read-only session.
 * \return Success or a typed module/session/authorization failure.
 * \note Shared token-wide login state may affect other sessions; caller coordinates access.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_session_open(qsc_hw_pkcs11_session** session, qsc_hw_pkcs11_module* module, uint64_t slot, bool read_write);

/** \brief Log in as CKU_USER, with a transient copy of PIN bytes securely erased.
 * \param session Open session.
 * \param pin PIN bytes; NULL with zero length requests a token protected-authentication path.
 * \param pinlen PIN byte count, bounded by QSC_HW_PKCS11_MAX_PIN_LENGTH.
 * \return Typed authentication, lockout or token status. No retry is performed.
 * \note Does not cache credentials; QSC never performs Security Officer login.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_session_login(qsc_hw_pkcs11_session* session, const uint8_t* pin, size_t pinlen);

/** \brief Explicitly log out the USER token login state.
 * \param session Open session.
 * \return Typed status; logout may affect other sessions to the same token.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_session_logout(qsc_hw_pkcs11_session* session);

/** \brief Close a session without implicitly logging out other consumers.
 * \param session In/out open handle, set NULL on successful close or device loss.
 * \return Typed result. A lost session is discarded; other module sessions remain live.
 * \note Caller serializes close against calls using the same session.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_pkcs11_session_close(qsc_hw_pkcs11_session** session);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
