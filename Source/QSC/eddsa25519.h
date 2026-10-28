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

#ifndef QSC_EDDSA25519_H
#define QSC_EDDSA25519_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file eddsa25519.h
 * \brief Independent RFC 8032 Ed25519 signature API.
 *
 * \details These functions remain callable regardless of the default
 * QSC_EDDSA_S1EC25519 / QSC_EDDSA_S3EC448 facade configuration.
 * Private keys are stored as seed concatenated with public key.
 * Signatures are returned in signed-message format: signature || message.
 * Caller owns all buffers; distinct calls use no shared mutable state in this wrapper.
 */

/** \def QSC_ED25519_SEED_SIZE
 * \brief Seed length in bytes. */
#define QSC_ED25519_SEED_SIZE 32U

/** \def QSC_ED25519_PUBLICKEY_SIZE
 * \brief Encoded public-key length in bytes. */
#define QSC_ED25519_PUBLICKEY_SIZE 32U

/** \def QSC_ED25519_PRIVATEKEY_SIZE
 * \brief Private-key length in bytes (seed || public key). */
#define QSC_ED25519_PRIVATEKEY_SIZE 64U

/** \def QSC_ED25519_SIGNATURE_SIZE
 * \brief Detached signature length in bytes. */
#define QSC_ED25519_SIGNATURE_SIZE 64U

/**
 * \brief Generate an Ed25519 key pair from a caller-supplied RNG.
 * \param publickey Output array, QSC_ED25519_PUBLICKEY_SIZE bytes.
 * \param privatekey Output array, QSC_ED25519_PRIVATEKEY_SIZE bytes.
 * \param rng_generate Non-NULL callback writing the requested number of bytes; returns true on success.
 * \details Key buffers must not overlap. RNG failure clears both output buffers.
 * No dynamic ownership is transferred. The callback's thread safety is the caller's responsibility.
 */
QSC_EXPORT_API void qsc_ed25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generate an Ed25519 key pair deterministically from a seed.
 * \param publickey Output array, QSC_ED25519_PUBLICKEY_SIZE bytes.
 * \param privatekey Output array, QSC_ED25519_PRIVATEKEY_SIZE bytes.
 * \param seed Input array, QSC_ED25519_SEED_SIZE bytes.
 * \details Caller retains ownership. Inputs and outputs must not overlap.
 */
QSC_EXPORT_API void qsc_ed25519_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Sign a message and prepend its Ed25519 signature.
 * \param signedmsg Output array, at least msglen + QSC_ED25519_SIGNATURE_SIZE bytes.
 * \param smsglen Output length of signed message in bytes; set on success.
 * \param message Input message, msglen bytes.
 * \param msglen Message length in bytes.
 * \param privatekey Input array, QSC_ED25519_PRIVATEKEY_SIZE bytes.
 * \return true on successful signing; false on failure.
 * \details Buffers are caller-owned; use disjoint signedmsg and message buffers.
 */
QSC_EXPORT_API bool qsc_ed25519_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verify a signature-prefixed message and recover its plaintext.
 * \param message Output array, at least smsglen - QSC_ED25519_SIGNATURE_SIZE bytes on valid input.
 * \param msglen Output recovered-message length in bytes.
 * \param signedmsg Input signature-prefixed message of smsglen bytes.
 * \param smsglen Signed-message length including QSC_ED25519_SIGNATURE_SIZE bytes of signature.
 * \param publickey Input array, QSC_ED25519_PUBLICKEY_SIZE bytes.
 * \return true when signature is valid; false when invalid or malformed.
 * \details Caller owns all buffers; recovery output must not overlap signedmsg.
 */
QSC_EXPORT_API bool qsc_ed25519_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
