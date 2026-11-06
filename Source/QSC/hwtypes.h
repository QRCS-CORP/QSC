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

#ifndef QSC_HWTYPES_H
#define QSC_HWTYPES_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/** \file hwtypes.h
 * \brief Versioned hardware key policy, capability and error types.
 * \details Hardware custody is separate from software cryptographic operations.
 * No device or vendor runtime is required by this header.
 */

/** \def QSC_HARDWARE_ENABLED
 * \brief Define this compile-time option in both QSC and its consumer to enable hardware provider APIs.
 * \note Undefined by default; no backend is linked without explicit selection.
 */

/** \def QSC_HW_ABI_VERSION
 * \brief Public hardware-provider contract revision, not the QSC library ABI epoch.
 */
#define QSC_HW_ABI_VERSION 1U

/** \enum qsc_hw_status
 * \brief Portable operation outcome; vendor error codes remain backend-specific.
 */
typedef enum qsc_hw_status
{
	qsc_hw_status_success = 0,				/**< Operation completed. */
	qsc_hw_status_invalid_parameter = 1,	/**< Argument or structure size is invalid. */
	qsc_hw_status_version = 2,				/**< Unsupported provider ABI version. */
	qsc_hw_status_memory = 3,				/**< Allocation failed. */
	qsc_hw_status_unsupported = 4,			/**< Capability or operation is unavailable. */
	qsc_hw_status_policy = 5,				/**< Requested key custody, usage or export policy denied. */
	qsc_hw_status_auth_required = 6,		/**< Caller must provide authorized authentication. */
	qsc_hw_status_auth_failed = 7,			/**< Authentication failed. */
	qsc_hw_status_locked = 8,				/**< Token or key is locked. */
	qsc_hw_status_stale_key = 9,			/**< Provider generation/key identity is no longer current. */
	qsc_hw_status_device_removed = 10,		/**< Hardware device is unavailable after opening. */
	qsc_hw_status_timeout = 11,				/**< Backend timed out. */
	qsc_hw_status_busy = 12,				/**< Active key references or operations prevent closure. */
	qsc_hw_status_buffer_too_small = 13,	/**< Output capacity insufficient; required size may be reported. */
	qsc_hw_status_internal = 14				/**< Unclassified backend failure. */
} qsc_hw_status;

/** \enum qsc_hw_algorithm
 * \brief Explicit algorithm identities; support must be queried per backend.
 */
typedef enum qsc_hw_algorithm
{
	qsc_hw_algorithm_none = 0,			/**< No selected algorithm. */
	qsc_hw_algorithm_ecdsa_p256 = 1,	/**< ECDSA over NIST P-256. */
	qsc_hw_algorithm_ecdsa_p384 = 2,	/**< ECDSA over NIST P-384. */
	qsc_hw_algorithm_ecdsa_p521 = 3,	/**< ECDSA over NIST P-521. */
	qsc_hw_algorithm_eddsa_25519 = 4,	/**< Ed25519. */
	qsc_hw_algorithm_eddsa_448 = 5,		/**< Ed448. */
	qsc_hw_algorithm_ml_dsa_44 = 6,		/**< ML-DSA-44. */
	qsc_hw_algorithm_ml_dsa_65 = 7,		/**< ML-DSA-65. */
	qsc_hw_algorithm_ml_dsa_87 = 8,		/**< ML-DSA-87. */
	qsc_hw_algorithm_ecdh_p256 = 9,		/**< ECDH over NIST P-256. */
	qsc_hw_algorithm_ecdh_p384 = 10,	/**< ECDH over NIST P-384. */
	qsc_hw_algorithm_ecdh_p521 = 11,	/**< ECDH over NIST P-521. */
	qsc_hw_algorithm_ml_kem_512 = 12,	/**< ML-KEM-512. */
	qsc_hw_algorithm_ml_kem_768 = 13,	/**< ML-KEM-768. */
	qsc_hw_algorithm_ml_kem_1024 = 14	/**< ML-KEM-1024. */
} qsc_hw_algorithm;

/** \enum qsc_hw_custody
 * \brief Actual private-key custody, not an attestation claim.
 */
typedef enum qsc_hw_custody
{
	qsc_hw_custody_unknown = 0,					/**< Backend has not established custody. */
	qsc_hw_custody_software = 1,				/**< Software-managed private key. */
	qsc_hw_custody_hardware_wrapped = 2,		/**< Software key protected at rest by hardware wrapping. */
	qsc_hw_custody_hardware_nonexportable = 3	/**< Private-key operation remains inside selected hardware. */
} qsc_hw_custody;

/** \enum qsc_hw_usage
 * \brief Bit flags describing authorized key operations.
 */
typedef enum qsc_hw_usage
{
	qsc_hw_usage_none = 0,		/**< No permitted operations. */
	qsc_hw_usage_sign = 1U,		/**< Key may produce signatures. */
	qsc_hw_usage_agree = 2U,	/**< Key may perform key agreement. */
	qsc_hw_usage_attest = 4U	/**< Key may produce attestation evidence. */
} qsc_hw_usage;

/** \enum qsc_hw_capability_flag
 * \brief Bit flags for provider-level optional functionality.
 */
typedef enum qsc_hw_capability_flag
{
	qsc_hw_capability_none = 0,			/**< No advertised service. */
	qsc_hw_capability_key_open = 1U,	/**< Persistent key lookup supported. */
	qsc_hw_capability_generate = 2U,	/**< Hardware/provider key generation supported. */
	qsc_hw_capability_sign = 4U,		/**< Signing supported. */
	qsc_hw_capability_agree = 8U,		/**< Key agreement supported. */
	qsc_hw_capability_random = 16U,		/**< Provider random generation supported. */
	qsc_hw_capability_attest = 32U,		/**< Provider attestation supported. */
	qsc_hw_capability_public_key = 64U	/**< Public key retrieval supported. */
} qsc_hw_capability_flag;

/** \struct qsc_hw_key_policy
 * \brief Caller-required policy for opening or creating a key.
 * \note Immutable for each returned key reference; no secret material is stored.
 */
typedef struct qsc_hw_key_policy
{
	uint32_t size;						/**< Set to sizeof(qsc_hw_key_policy), in bytes. */
	uint32_t version;					/**< Set to QSC_HW_ABI_VERSION. */
	qsc_hw_algorithm algorithm;			/**< Required key algorithm. */
	uint32_t usage;						/**< Required qsc_hw_usage bit flags. */
	bool require_hardware;				/**< Only non-exportable hardware custody is accepted. */
	bool allow_software_fallback;		/**< Explicitly permit software custody when hardware is not required. */
	bool allow_export;					/**< Permit keys whose private material is extractable. */
	bool allow_derived_secret_export;	/**< Permit raw ECDH secret output to host memory. */
} qsc_hw_key_policy;

/** \struct qsc_hw_key_info
 * \brief Backend-supplied metadata for one opened/generated key.
 * \note Contains no private key bytes. The provider verifies metadata against requested policy.
 */
typedef struct qsc_hw_key_info
{
	uint32_t size;				/**< Structure size in bytes. */
	uint32_t version;			/**< QSC_HW_ABI_VERSION. */
	qsc_hw_algorithm algorithm;	/**< Actual algorithm. */
	uint32_t usage;				/**< Actual authorized qsc_hw_usage bits. */
	qsc_hw_custody custody;		/**< Actual reported private-key custody. */
	bool extractable;			/**< Private key can be extracted under backend policy. */
} qsc_hw_key_info;

/** \struct qsc_hw_capabilities
 * \brief Backend capability snapshot, not evidence of attestation or FIPS validation.
 */
typedef struct qsc_hw_capabilities
{
	uint32_t size;					/**< Set by the caller to sizeof(qsc_hw_capabilities). */
	uint32_t version;				/**< Set by the caller to QSC_HW_ABI_VERSION. */
	uint32_t flags;					/**< Available qsc_hw_capability_flag values. */
	uint32_t max_sessions;			/**< Maximum supported sessions; zero means not reported. */
	bool thread_safe;				/**< Backend permits concurrent calls by independent threads. */
	bool requires_serialization;	/**< Caller must serialize operations. */
	bool operation_can_block;		/**< Operations may await device or user interaction. */
	bool supports_cancel;			/**< Backend supports an explicit cancellation mechanism. */
} qsc_hw_capabilities;

QSC_CPLUSPLUS_ENABLED_END

#endif
