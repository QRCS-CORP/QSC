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

#ifndef QSC_HWATECC_H
#define QSC_HWATECC_H

#include "hwprovider.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_ATECC_ENABLED)

/** \file hwatecc.h
 * \brief Optional ATECC608 P-256 identity adapter for an OEM-supplied CryptoAuthLib bridge.
 * \details No vendor SDK is included or linked by QSC. The application supplies verified
 * device-specific callbacks, normally backed by CryptoAuthLib atcab_*_ext functions.
 * No slot locking, key generation, administrative commands or software substitution occurs.
 * Callers serialize all operations and dispose only after closing the provider.
 */

/** \def QSC_HARDWARE_ATECC_ENABLED
 * \brief Enables ATECC-specific functions when QSC_HARDWARE_ENABLED is also defined.
 */
/** \def QSC_HW_ATECC_SERIAL_SIZE
 * \brief Fixed ATECC serial number size in bytes.
 */
#define QSC_HW_ATECC_SERIAL_SIZE 9U
/** \def QSC_HW_ATECC_PUBLIC_SIZE
 * \brief SEC1 uncompressed P-256 public-key size in bytes.
 */
#define QSC_HW_ATECC_PUBLIC_SIZE 65U
/** \def QSC_HW_ATECC_SIGNATURE_SIZE
 * \brief Raw P-256 ECDSA r||s signature size in bytes.
 */
#define QSC_HW_ATECC_SIGNATURE_SIZE 64U
/** \def QSC_HW_ATECC_LOCATOR_SIZE
 * \brief Required locator buffer capacity including final NUL.
 */
#define QSC_HW_ATECC_LOCATOR_SIZE 30U
/** \def QSC_HW_ATECC_MAX_SLOT
 * \brief Highest supported ATECC slot index (0 through 15).
 */
#define QSC_HW_ATECC_MAX_SLOT 15U

/** \struct qsc_hw_atecc_slot_policy
 * \brief Verified read-only slot configuration returned by the OEM device bridge.
 * \note These are assertions from the trusted vendor middleware, not remote attestation.
 */
typedef struct qsc_hw_atecc_slot_policy
{
	bool configuration_locked;	/**< Device configuration zone is locked. */
	bool data_locked;			/**< Device data zone is locked for intended configuration. */
	bool private_key;			/**< Selected slot holds a private P-256 key. */
	bool signing_enabled;		/**< Slot permits external digest signing. */
	bool private_exportable;	/**< Must be false for all accepted keys. */
} qsc_hw_atecc_slot_policy;

/** \typedef qsc_hw_atecc_serial_callback
 * \brief Query a device's 9-byte serial number each time identity is needed.
 * \param device OEM-owned active CryptoAuthLib device context.
 * \param serial Writable array of exactly QSC_HW_ATECC_SERIAL_SIZE bytes.
 * \return Typed failure or success; never expose secret values.
 */
typedef qsc_hw_status (*qsc_hw_atecc_serial_callback)(void* device, uint8_t* serial);

/** \typedef qsc_hw_atecc_policy_callback
 * \brief Retrieve trusted slot configuration and lock information.
 * \param device OEM-owned device context.
 * \param slot Selected slot index (0..15).
 * \param policy Writable public slot policy.
 * \return Typed status; fail closed if device policy cannot be verified.
 */
typedef qsc_hw_status (*qsc_hw_atecc_policy_callback)(void* device, uint8_t slot, qsc_hw_atecc_slot_policy* policy);

/** \typedef qsc_hw_atecc_public_callback
 * \brief Read the existing private slot's associated public P-256 point.
 * \param device OEM-owned device context.
 * \param slot Selected slot index.
 * \param publickey Writable Qx||Qy output of exactly 64 bytes.
 * \return Typed status; implementation must provide a genuine hardware-derived point.
 */
typedef qsc_hw_status (*qsc_hw_atecc_public_callback)(void* device, uint8_t slot, uint8_t* publickey);

/** \typedef qsc_hw_atecc_sign_callback
 * \brief Sign a prehashed SHA-256 digest with a protected ATECC P-256 slot.
 * \param device OEM-owned device context.
 * \param slot Selected slot index.
 * \param digest Exactly 32-byte SHA-256 digest, not a raw TLS transcript.
 * \param signature Writable 64-byte raw r||s signature.
 * \return Typed status. On errors the QSC adapter erases the signature output.
 */
typedef qsc_hw_status (*qsc_hw_atecc_sign_callback)(void* device, uint8_t slot, const uint8_t* digest, uint8_t* signature);

/** \struct qsc_hw_atecc_callbacks
 * \brief Versioned OEM-supplied adapter to CryptoAuthLib or a native device HAL.
 * \note No callback may silently execute a software private-key operation.
 */
typedef struct qsc_hw_atecc_callbacks
{
	uint32_t size;									/**< sizeof(qsc_hw_atecc_callbacks). */
	uint32_t version;								/**< QSC_HW_ABI_VERSION. */
	qsc_hw_atecc_serial_callback read_serial;		/**< Required device identity callback. */
	qsc_hw_atecc_policy_callback read_slot_policy;	/**< Required protected slot check. */
	qsc_hw_atecc_public_callback read_public;		/**< Required public-key lookup. */
	qsc_hw_atecc_sign_callback sign_digest;			/**< Required hardware digest signing. */
} qsc_hw_atecc_callbacks;

/** \struct qsc_hw_atecc_context
 * \brief Caller-owned ATECC adapter context, with no private-key bytes.
 * \note Must be zero-initialized. Caller owns device and must keep it open until
 * the provider and all key references are closed; no concurrent operations.
 */
typedef struct qsc_hw_atecc_context
{
	qsc_hw_atecc_callbacks callbacks;			/**< Copied callback table; caller retains vendor device. */
	void* device;								/**< OEM-owned CryptoAuthLib or HAL device context. */
	uint8_t serial[QSC_HW_ATECC_SERIAL_SIZE];	/**< Pinned device serial number. */
	uint8_t slot;								/**< Pinned pre-provisioned identity slot. */
	bool hardware_confirmed;					/**< OEM verified physical device rather than simulator. */
	bool initialized;							/**< Context is active until provider closes/disposes. */
} qsc_hw_atecc_context;

/** \brief Initialize one pre-provisioned ATECC slot without changing device configuration.
 * \param context Caller-owned zero-initialized context.
 * \param callbacks Complete versioned OEM backend callbacks; copied on success.
 * \param device Non-NULL OEM-owned initialized device handle.
 * \param slot Pre-provisioned P-256 signing slot (0..15).
 * \param physical_confirmed True only after out-of-band physical-device qualification.
 * \return Success or typed failure. Invalid or unlocked slots fail closed.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_atecc_initialize(qsc_hw_atecc_context* context, const qsc_hw_atecc_callbacks* callbacks, void* device, uint8_t slot, bool physical_confirmed);

/** \brief Return the common versioned provider callback table for this ATECC adapter.
 * \param operations Caller-owned output descriptor, cleared on failure.
 * \return Success or invalid parameter; no vendor initialization is performed.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_atecc_get_operations(qsc_hw_provider_ops* operations);

/** \brief Encode a persistent device-bound locator for the configured slot.
 * \param context Initialized caller-owned context.
 * \param output Caller buffer, or NULL to query required size.
 * \param outputlen In/out byte capacity and required size, including NUL.
 * \return Success or buffer-too-small; no secrets in the locator.
 */
QSC_EXPORT_API qsc_hw_status qsc_hw_atecc_locator(qsc_hw_atecc_context* context, char* output, size_t* outputlen);

/** \brief Dispose callback state without modifying or clearing any hardware slot.
 * \param context Caller-owned context; must have no live provider/key references.
 * \note Does not call atcab_release; the OEM retains vendor-device ownership.
 */
QSC_EXPORT_API void qsc_hw_atecc_dispose(qsc_hw_atecc_context* context);

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
