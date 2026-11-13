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

#ifndef QSC_CSG_H
#define QSC_CSG_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file csg.h
 * \brief CSG candidate XDRBG-256 based on FIPS 202 SHAKE-256.
 * \details Implements the Kelsey-Lucks-Mueller XDRBG construction (ToSC 2024,
 * Algorithm 2 and Appendix B). This is a provisional candidate for SP 800-90A
 * Revision 2: NIST has not yet published normative xofDRBG requirements.
 * Deterministic APIs accept caller-owned seed material, without acquiring entropy.
 * Optional ACP-backed APIs acquire entropy automatically. This implementation
 * does not certify an entropy source under SP 800-90B.
 * \note State layout and behavior differ from the legacy cSHAKE-based CSG (ABI break).
 * \note Not thread safe; callers synchronize each mutable state.
 */

/** \def QSC_CSG_256_SEED_SIZE
 * \brief Legacy 32-byte seed length; accepted only by the nonconformant compatibility wrapper.
 * \note Not sufficient to satisfy the proposed XDRBG-256 instantiation entropy.
 */
#define QSC_CSG_256_SEED_SIZE 32UL

/** \def QSC_CSG_512_SEED_SIZE
 * \brief Legacy 64-byte seed length, accepted by the SHAKE-256 candidate.
 */
#define QSC_CSG_512_SEED_SIZE 64UL

/** \def QSC_CSG_STATE_SIZE
 * \brief XDRBG-256 state V in bytes (512 bits).
 */
#define QSC_CSG_STATE_SIZE 64UL

/** \def QSC_CSG_MIN_INSTANTIATE_SIZE
 * \brief Minimum caller-asserted instantiation seed entropy in bytes (384 bits).
 * \note Byte count alone does not establish entropy quality.
 */
#define QSC_CSG_MIN_INSTANTIATE_SIZE 48UL

/** \def QSC_CSG_MIN_RESEED_SIZE
 * \brief Minimum caller-asserted reseed entropy in bytes (256 bits).
 * \note Byte count alone does not establish entropy quality.
 */
#define QSC_CSG_MIN_RESEED_SIZE 32UL

/** \def QSC_CSG_MAX_SEED_SIZE
 * \brief Maximum seed byte count supported by this bounded implementation.
 */
#define QSC_CSG_MAX_SEED_SIZE 64UL

/** \def QSC_CSG_MAX_ADDITIONAL_SIZE
 * \brief Maximum additional-data length for the proposed one-byte encoding.
 */
#define QSC_CSG_MAX_ADDITIONAL_SIZE 84UL

/** \def QSC_CSG_MAX_REQUEST_SIZE
 * \brief Proposed conservative maximum per Generate operation in bytes.
 * \note This 344-byte limit is from the 2024 candidate paper, not NIST Rev. 2.
 */
#define QSC_CSG_MAX_REQUEST_SIZE 344UL

/** \def QSC_CSG_RESEED_THRESHOLD
 * \brief Optional automatic reseed threshold in generated bytes.
 */
#define QSC_CSG_RESEED_THRESHOLD 1024000UL

/** \def QSC_CSG_RESEED_THRESHHOLD
 * \brief Deprecated spelling retained for existing source compatibility.
 */
#define QSC_CSG_RESEED_THRESHHOLD QSC_CSG_RESEED_THRESHOLD

/** \def QSC_CSG_RESEED_INTERVAL
 * \brief Local maximum Generate operations per reseed; not a normative XDRBG limit.
 */
#define QSC_CSG_RESEED_INTERVAL 281474976710656ULL

/**
 * \struct qsc_csg_state
 * \brief Mutable, non-thread-safe XDRBG-SHAKE-256 state.
 * \note State and layout are secret and must be erased when no longer needed.
 */
QSC_EXPORT_API typedef struct
{
	uint8_t value[QSC_CSG_STATE_SIZE]; /*!< Secret 64-byte state V. */
	uint64_t reseed_counter; /*!< Successful Generate operations since reseeding, starting at 1. */
	uint64_t generated_bytes; /*!< Generated bytes since the last reseed. */
	bool initialized; /*!< True only after successful instantiation. */
	bool auto_reseed; /*!< Permit ACP entropy acquisition at the local threshold. */
	bool pres; /*!< Require fresh ACP entropy before each Generate operation. */
	bool legacy_seed; /*!< True when legacy 32-byte initialization lacks proposed entropy minimum. */
} qsc_csg_state;

/**
 * \brief Securely erase a CSG state, whether initialized or not.
 * \param ctx State to clear; NULL is ignored.
 * \note Does not allocate, and is not thread safe.
 */
QSC_EXPORT_API void qsc_csg_dispose(qsc_csg_state* ctx);

/**
 * \brief Deterministically instantiate XDRBG-256 using the provided seed.
 * \param ctx Caller-owned state; reset on entry and cleared on failure.
 * \param seed Input seed with at least 384 bits of externally assessed entropy.
 * \param seedlen Seed length, from 48 through 64 bytes.
 * \param info Optional personalization bytes; may be NULL when infolen is zero.
 * \param infolen Personalization length, zero through 84 bytes.
 * \return True on success; false on invalid input or unsupported length.
 * \note Deterministic; does not call ACP. Seed min-entropy is the caller's responsibility.
 */
QSC_EXPORT_API bool qsc_csg_instantiate(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen);

/**
 * \brief Instantiate using the platform's automatic ACP entropy provider.
 * \param ctx Caller-owned state; cleared on failure.
 * \param info Optional personalization, NULL allowed for zero infolen.
 * \param infolen Personalization bytes, maximum 84.
 * \param predres Request fresh ACP entropy before every generation operation.
 * \return True if ACP acquisition and instantiation succeeded; false otherwise.
 * \note ACP entropy certification is independent of this DRBG mechanism.
 */
QSC_EXPORT_API bool qsc_csg_initialize_auto(qsc_csg_state* ctx, const uint8_t* info, size_t infolen, bool predres);

/**
 * \brief Legacy void initialization wrapper; accepts 32-byte seeds as a nonconformant mode.
 * \param ctx Caller-owned mutable state; cleared on invalid input or failure.
 * \param seed Externally provisioned seed with sufficient assessed entropy.
 * \param seedlen Seed byte count, 32 or 48 through 64.
 * \param info Optional personalization, NULL permitted for zero infolen.
 * \param infolen Additional personalization length, at most 84 bytes.
 * \param predres Enable ACP prediction resistance before each generation.
 * \note A 32-byte seed is supported ONLY for legacy callers and is explicitly
 * not a candidate XDRBG-256 instantiation. Check ctx->legacy_seed. Prefer
 * qsc_csg_instantiate for a strict deterministic and status-reporting interface.
 */
QSC_EXPORT_API void qsc_csg_initialize(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predres);

/**
 * \brief Deterministically reseed with externally supplied entropy.
 * \param ctx Initialized mutable state.
 * \param seed Reseed input with at least 256 bits of externally assessed entropy.
 * \param seedlen Seed byte count, 32 through 64.
 * \param additional Optional additional bytes, NULL allowed for zero length.
 * \param addlen Additional-input length, at most 84 bytes.
 * \return True on successful reseed; false otherwise, leaving state unchanged.
 * \note Caller retains ownership of seed and additional; no ACP is called.
 */
QSC_EXPORT_API bool qsc_csg_reseed(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* additional, size_t addlen);

/**
 * \brief Generate one XDRBG operation with optional additional input.
 * \param ctx Initialized mutable state; may reseed automatically if configured.
 * \param output Caller-owned buffer, at least otplen bytes.
 * \param otplen Required output, 1 through 344 bytes.
 * \param additional Optional input, NULL allowed for zero addlen.
 * \param addlen Additional input length, at most 84 bytes.
 * \return True on success; false on invalid request, reseed failure or exhausted interval.
 * \note Invalid requests do not advance state; automatic entropy failures zero output
 * and invalidate state. This function performs a single candidate Generate operation.
 */
QSC_EXPORT_API bool qsc_csg_generate_ex(qsc_csg_state* ctx, uint8_t* output, size_t otplen, const uint8_t* additional, size_t addlen);

/**
 * \brief Legacy large-buffer generation API, split into 344-byte XDRBG requests.
 * \param ctx Initialized mutable state.
 * \param output Caller-owned buffer of at least otplen bytes.
 * \param otplen Number of requested bytes; must be nonzero.
 * \return True on success; false on invalid state or ACP failure (output erased).
 * \note Chunk boundaries advance state; not equivalent to one unbounded XOF call.
 * Not thread safe. An optional automatic reseed may occur between chunks.
 */
QSC_EXPORT_API bool qsc_csg_generate(qsc_csg_state* ctx, uint8_t* output, size_t otplen);

/**
 * \brief Compatibility wrapper for explicitly entropy-qualified reseeding.
 * \param ctx Initialized mutable state.
 * \param seed Entropy-qualified reseed material, at least 32 bytes.
 * \param seedlen Reseed input length in bytes (32 through 64).
 * \note Deprecated; use qsc_csg_reseed to detect failures. This is not an
 * additional-input API; arbitrary data must not be represented as entropy.
 */
QSC_EXPORT_API void qsc_csg_update(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
