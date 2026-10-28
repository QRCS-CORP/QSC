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

#ifndef QSC_KYBER1024_H
#define QSC_KYBER1024_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file kyber1024.h
 * \brief Independent standardized ML-KEM-1024 profile API.
 * \details Buffers are caller-owned, sized by the constants in this header.
 * The selected-default QSC_KYBER_S*K*P* macro does not affect this API.
 * All functions are synchronous; separate caller buffers are required.
 * Standard algorithm conformance is not established by this wrapper alone.
 */
#define QSC_KYBER1024_PUBLICKEY_SIZE 1568U
#define QSC_KYBER1024_PRIVATEKEY_SIZE 3168U
#define QSC_KYBER1024_CIPHERTEXT_SIZE 1568U
#define QSC_KYBER1024_SHAREDSECRET_SIZE 32U
#define QSC_KYBER1024_SEED_SIZE 32U

/**
 * \brief Validate the private key and decapsulate a ciphertext.
 * \param secret Output shared secret (QSC_KYBER1024_SHAREDSECRET_SIZE bytes).
 * \param ciphertext Input ciphertext (QSC_KYBER1024_CIPHERTEXT_SIZE bytes).
 * \param privatekey Input private key (QSC_KYBER1024_PRIVATEKEY_SIZE bytes).
 * \return True for a valid private key and completed decapsulation. An
 * invalid ciphertext uses implicit rejection and still returns true.
 * \note Invalid secret key erases the output. Inputs must not overlap.
 */
QSC_EXPORT_API bool qsc_kyber1024_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulate a shared secret for a validated public key.
 * \param secret Output shared secret (QSC_KYBER1024_SHAREDSECRET_SIZE bytes).
 * \param ciphertext Output ciphertext (QSC_KYBER1024_CIPHERTEXT_SIZE bytes).
 * \param publickey Input public key (QSC_KYBER1024_PUBLICKEY_SIZE bytes).
 * \param rng_generate Caller-supplied CSPRNG callback; must fill requested bytes.
 * \return True on success; false if the key, callback or pointer is invalid.
 * \note An invalid public key clears the output buffers. Inputs must not overlap.
 */
QSC_EXPORT_API bool qsc_kyber1024_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Deterministically encapsulate for known-answer testing.
 * \param secret Output shared secret (QSC_KYBER1024_SHAREDSECRET_SIZE bytes).
 * \param ciphertext Output ciphertext (QSC_KYBER1024_CIPHERTEXT_SIZE bytes).
 * \param publickey Input public key (QSC_KYBER1024_PUBLICKEY_SIZE bytes).
 * \param m Input fixed 32-byte test coin.
 * \note For tests only; production callers must use encapsulate with a CSPRNG.
 */
QSC_EXPORT_API void qsc_kyber1024_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t* m);

/**
 * \brief Generate a keypair for the independent 1024 profile.
 * \param publickey Output public key (QSC_KYBER1024_PUBLICKEY_SIZE bytes).
 * \param privatekey Output private key (QSC_KYBER1024_PRIVATEKEY_SIZE bytes).
 * \param rng_generate Caller-supplied CSPRNG callback.
 * \return True on successful generation; false on invalid pointers or RNG failure.
 * \note Output buffers must not overlap.
 */
QSC_EXPORT_API bool qsc_kyber1024_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Deterministically generate a keypair for regression testing.
 * \param publickey Output public key (QSC_KYBER1024_PUBLICKEY_SIZE bytes).
 * \param privatekey Output private key (QSC_KYBER1024_PRIVATEKEY_SIZE bytes).
 * \param d Input fixed 32-byte key-generation seed (may be modified by backend).
 * \param z Input fixed 32-byte implicit-rejection seed.
 * \note For test vectors only; production callers must use generate_keypair.
 */
QSC_EXPORT_API void qsc_kyber1024_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* d, uint8_t* z);

QSC_CPLUSPLUS_ENABLED_END

#endif
