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

#ifndef QSC_HQC_MULTI_H
#define QSC_HQC_MULTI_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/** \def QSC_HQC1_PUBLICKEY_SIZE
 * \brief HQC-1 public key length in bytes.
 */
#define QSC_HQC1_PUBLICKEY_SIZE 2241U

/** \def QSC_HQC3_PUBLICKEY_SIZE
 * \brief HQC-3 public key length in bytes.
 */
#define QSC_HQC3_PUBLICKEY_SIZE 4514U

/** \def QSC_HQC5_PUBLICKEY_SIZE
 * \brief HQC-5 public key length in bytes.
 */
#define QSC_HQC5_PUBLICKEY_SIZE 7237U

/** \def QSC_HQC1_CIPHERTEXT_SIZE
 * \brief HQC-1 ciphertext length in bytes.
 */
#define QSC_HQC1_CIPHERTEXT_SIZE 4433U

/** \def QSC_HQC3_CIPHERTEXT_SIZE
 * \brief HQC-3 ciphertext length in bytes.
 */
#define QSC_HQC3_CIPHERTEXT_SIZE 8978U

/** \def QSC_HQC5_CIPHERTEXT_SIZE
 * \brief HQC-5 ciphertext length in bytes.
 */
#define QSC_HQC5_CIPHERTEXT_SIZE 14421U

/** \def QSC_HQC_PRIVATEKEY_SEED_SIZE
 * \brief QSC-specific HQC-2026 compact private seed length in bytes; this is not the expanded upstream key encoding.
 */
#define QSC_HQC_PRIVATEKEY_SEED_SIZE 32U

/** \def QSC_HQC_SHAREDSECRET_BYTES
 * \brief HQC-2026 shared-secret output length in bytes.
 */
#define QSC_HQC_SHAREDSECRET_BYTES 32U

/** \def QSC_HQC_SEED_BYTES
 * \brief HQC-2026 seed input length in bytes.
 */
#define QSC_HQC_SEED_BYTES 32U

/** \brief Generate a QSC HQC-1 compact-key pair using the supplied RNG.
 * \param publickey Caller-owned output of QSC_HQC1_PUBLICKEY_SIZE bytes.
 * \param privatekey Caller-owned secret seed output of 32 bytes; caller must erase it.
 * \param rng_generate RNG callback; thread safety depends on its implementation.
 * \return True on success; false for invalid arguments or RNG failure.
 */
QSC_EXPORT_API bool qsc_hqc1_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generate a QSC HQC-1 key pair from the supplied 32-byte seed.
 * \param publickey Caller-owned output of QSC_HQC1_PUBLICKEY_SIZE bytes.
 * \param privatekey Caller-owned 32-byte compact seed output; erase after use.
 * \param seed Caller-owned seed, at least QSC_HQC_SEED_BYTES bytes.
 * \note No output is produced for null pointers; caller owns all buffers.
 */
QSC_EXPORT_API void qsc_hqc1_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed);

/** \brief Encapsulate a 32-byte secret and HQC-1 ciphertext.
 * \param secret Caller-owned output of QSC_HQC_SHAREDSECRET_BYTES bytes.
 * \param ciphertext Caller-owned output of QSC_HQC1_CIPHERTEXT_SIZE bytes.
 * \param publickey Verification input of QSC_HQC1_PUBLICKEY_SIZE bytes.
 * \param rng_generate RNG callback, which must supply secure entropy; thread safety depends on it.
 * \return True on success; false on invalid pointers or random source failure.
 */
QSC_EXPORT_API bool qsc_hqc1_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Deterministically encapsulate a shared secret for HQC-1.
 * \param secret Caller-owned 32-byte secret output.
 * \param ciphertext Caller-owned ciphertext output of QSC_HQC1_CIPHERTEXT_SIZE bytes.
 * \param publickey Public key input, QSC_HQC1_PUBLICKEY_SIZE bytes.
 * \param seed Caller-provided 32-byte reproducibility seed.
 * \note For tests/controlled entropy only; no output if any pointer is null.
 */
QSC_EXPORT_API void qsc_hqc1_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_HQC_SEED_BYTES]);

/** \brief Decapsulate HQC-1 with the QSC compact 32-byte private seed.
 * \param secret Caller-owned shared secret output of 32 bytes.
 * \param ciphertext Ciphertext input of QSC_HQC1_CIPHERTEXT_SIZE bytes.
 * \param privatekey QSC compact private seed input of 32 bytes.
 * \return True when backend decapsulation completed; follow documented implicit rejection semantics.
 * \note All buffers are caller-owned. On invalid arguments, no backend call occurs.
 */
QSC_EXPORT_API bool qsc_hqc1_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/** \brief Generate a QSC HQC-3 compact-key pair using the supplied RNG.
 * \param publickey Caller-owned output of QSC_HQC3_PUBLICKEY_SIZE bytes.
 * \param privatekey Caller-owned secret seed output of 32 bytes; caller must erase it.
 * \param rng_generate RNG callback; thread safety depends on its implementation.
 * \return True on success; false for invalid arguments or RNG failure.
 */
QSC_EXPORT_API bool qsc_hqc3_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generate a QSC HQC-3 key pair from the supplied 32-byte seed.
 * \param publickey Caller-owned output of QSC_HQC3_PUBLICKEY_SIZE bytes.
 * \param privatekey Caller-owned 32-byte compact seed output; erase after use.
 * \param seed Caller-owned seed, at least QSC_HQC_SEED_BYTES bytes.
 * \note No output is produced for null pointers; caller owns all buffers.
 */
QSC_EXPORT_API void qsc_hqc3_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed);

/** \brief Encapsulate a 32-byte secret and HQC-3 ciphertext.
 * \param secret Caller-owned output of QSC_HQC_SHAREDSECRET_BYTES bytes.
 * \param ciphertext Caller-owned output of QSC_HQC3_CIPHERTEXT_SIZE bytes.
 * \param publickey Verification input of QSC_HQC3_PUBLICKEY_SIZE bytes.
 * \param rng_generate RNG callback, which must supply secure entropy; thread safety depends on it.
 * \return True on success; false on invalid pointers or random source failure.
 */
QSC_EXPORT_API bool qsc_hqc3_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Deterministically encapsulate a shared secret for HQC-3.
 * \param secret Caller-owned 32-byte secret output.
 * \param ciphertext Caller-owned ciphertext output of QSC_HQC3_CIPHERTEXT_SIZE bytes.
 * \param publickey Public key input, QSC_HQC3_PUBLICKEY_SIZE bytes.
 * \param seed Caller-provided 32-byte reproducibility seed.
 * \note For tests/controlled entropy only; no output if any pointer is null.
 */
QSC_EXPORT_API void qsc_hqc3_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_HQC_SEED_BYTES]);

/** \brief Decapsulate HQC-3 with the QSC compact 32-byte private seed.
 * \param secret Caller-owned shared secret output of 32 bytes.
 * \param ciphertext Ciphertext input of QSC_HQC3_CIPHERTEXT_SIZE bytes.
 * \param privatekey QSC compact private seed input of 32 bytes.
 * \return True when backend decapsulation completed; follow documented implicit rejection semantics.
 * \note All buffers are caller-owned. On invalid arguments, no backend call occurs.
 */
QSC_EXPORT_API bool qsc_hqc3_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/** \brief Generate a QSC HQC-5 compact-key pair using the supplied RNG.
 * \param publickey Caller-owned output of QSC_HQC5_PUBLICKEY_SIZE bytes.
 * \param privatekey Caller-owned secret seed output of 32 bytes; caller must erase it.
 * \param rng_generate RNG callback; thread safety depends on its implementation.
 * \return True on success; false for invalid arguments or RNG failure.
 */
QSC_EXPORT_API bool qsc_hqc5_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Generate a QSC HQC-5 key pair from the supplied 32-byte seed.
 * \param publickey Caller-owned output of QSC_HQC5_PUBLICKEY_SIZE bytes.
 * \param privatekey Caller-owned 32-byte compact seed output; erase after use.
 * \param seed Caller-owned seed, at least QSC_HQC_SEED_BYTES bytes.
 * \note No output is produced for null pointers; caller owns all buffers.
 */
QSC_EXPORT_API void qsc_hqc5_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed);

/** \brief Encapsulate a 32-byte secret and HQC-5 ciphertext.
 * \param secret Caller-owned output of QSC_HQC_SHAREDSECRET_BYTES bytes.
 * \param ciphertext Caller-owned output of QSC_HQC5_CIPHERTEXT_SIZE bytes.
 * \param publickey Verification input of QSC_HQC5_PUBLICKEY_SIZE bytes.
 * \param rng_generate RNG callback, which must supply secure entropy; thread safety depends on it.
 * \return True on success; false on invalid pointers or random source failure.
 */
QSC_EXPORT_API bool qsc_hqc5_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Deterministically encapsulate a shared secret for HQC-5.
 * \param secret Caller-owned 32-byte secret output.
 * \param ciphertext Caller-owned ciphertext output of QSC_HQC5_CIPHERTEXT_SIZE bytes.
 * \param publickey Public key input, QSC_HQC5_PUBLICKEY_SIZE bytes.
 * \param seed Caller-provided 32-byte reproducibility seed.
 * \note For tests/controlled entropy only; no output if any pointer is null.
 */
QSC_EXPORT_API void qsc_hqc5_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_HQC_SEED_BYTES]);

/** \brief Decapsulate HQC-5 with the QSC compact 32-byte private seed.
 * \param secret Caller-owned shared secret output of 32 bytes.
 * \param ciphertext Ciphertext input of QSC_HQC5_CIPHERTEXT_SIZE bytes.
 * \param privatekey QSC compact private seed input of 32 bytes.
 * \return True when backend decapsulation completed; follow documented implicit rejection semantics.
 * \note All buffers are caller-owned. On invalid arguments, no backend call occurs.
 */
QSC_EXPORT_API bool qsc_hqc5_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

QSC_CPLUSPLUS_ENABLED_END

#endif
