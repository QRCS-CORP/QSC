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

#ifndef QSC_MLDSA_H
#define QSC_MLDSA_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/** \def QSC_MLDSA_SEED_SIZE
 * brief Length of the seeded key-generation input in bytes.
 */
#define QSC_MLDSA_SEED_SIZE 32U

/** \def QSC_MLDSA44_PUBLICKEY_SIZE
 * \brief Byte count of the ML-DSA-44 verification key.
 */
#define QSC_MLDSA44_PUBLICKEY_SIZE 1312U

/** \def QSC_MLDSA44_PRIVATEKEY_SIZE
 * \brief Byte count of the ML-DSA-44 private signing key.
 */
#define QSC_MLDSA44_PRIVATEKEY_SIZE 2560U

/** \def QSC_MLDSA44_SIGNATURE_SIZE
 * \brief Byte count of the ML-DSA-44 detached signature.
 */
#define QSC_MLDSA44_SIGNATURE_SIZE 2420U

/** \brief Generate an ML-DSA-44 key pair with caller RNG.
 * \param pk Caller-owned output, QSC_MLDSA44_PUBLICKEY_SIZE bytes.
 * \param sk Caller-owned secret output, QSC_MLDSA44_PRIVATEKEY_SIZE bytes.
 * \param rng_generate Random-byte callback, true on success; must be thread safe if called concurrently.
 * \return True on successful generation; false on invalid argument or RNG failure.
 * \note Non-thread-safe if the supplied RNG is non-thread-safe; caller must erase the secret key.
 */
QSC_EXPORT_API bool qsc_mldsa44_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Deterministically derive an ML-DSA-44 key pair from a 32-byte seed.
 * \param pk Output, QSC_MLDSA44_PUBLICKEY_SIZE bytes.
 * \param sk Secret output, QSC_MLDSA44_PRIVATEKEY_SIZE bytes.
 * \param seed Input array of QSC_MLDSA_SEED_SIZE bytes.
 * \note Not thread-sensitive; caller owns and erases keys; invalid pointers perform no operation.
 */
QSC_EXPORT_API void qsc_mldsa44_seeded_generate_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

/** \brief Sign a message with ML-DSA-44; append message to signature.
 * \param sm Caller-owned output, at least QSC_MLDSA44_SIGNATURE_SIZE + msglen bytes.
 * \param smlen Receives output length.
 * \param msg Input message, msglen bytes.
 * \param msglen Message length in bytes.
 * \param sk Secret signing key, QSC_MLDSA44_PRIVATEKEY_SIZE bytes.
 * \param rng_generate RNG callback needed for hedged signing; ignored in deterministic mode.
 * \return True on signing success; false on invalid arguments, rejected length or RNG failure.
 * \note Use sign_ex for context binding. Caller owns buffers, protect secret and output aliasing.
 */
QSC_EXPORT_API bool qsc_mldsa44_sign(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Sign using explicit ML-DSA-44 context binding.
 * \param sm Output, QSC_MLDSA44_SIGNATURE_SIZE + msglen bytes.
 * \param smlen Receives signed output length.
 * \param msg Message input, msglen bytes.
 * \param msglen Message length.
 * \param ctx Optional context string, at most 255 bytes; non-null when ctxlen is nonzero.
 * \param ctxlen Context length (0 to 255 bytes).
 * \param sk Signing key, QSC_MLDSA44_PRIVATEKEY_SIZE bytes.
 * \param rng_generate RNG callback for randomized signing, or null in deterministic builds.
 * \return True on successful signing; false on invalid parameters, RNG or backend failure.
 * \note Caller owns outputs; thread safety depends on the supplied RNG.
 */
QSC_EXPORT_API bool qsc_mldsa44_sign_ex(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Verify an ML-DSA-44 signature and recover its attached message.
 * \param msg Caller-owned message output, at least smlen - signature-size bytes when valid.
 * \param msglen Receives verified message length, zero on failure.
 * \param sm Input signature followed by message.
 * \param smlen Total input length.
 * \param pk Public verification key, QSC_MLDSA44_PUBLICKEY_SIZE bytes.
 * \return True on a valid signature, otherwise false.
 * \note No output size is inferred from pointer; caller must allocate appropriately.
 */
QSC_EXPORT_API bool qsc_mldsa44_verify(uint8_t* msg, size_t* msglen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

/** \brief Verify an ML-DSA-44 signed message with context binding.
 * \param msg Caller-owned recovered message output.
 * \param msglen Receives output length; zero on failure.
 * \param ctx Context input, non-null when ctxlen is nonzero.
 * \param ctxlen Context length in the range 0 to 255 bytes.
 * \param sm Signed message input.
 * \param smlen Signed-message length.
 * \param pk Public verification key, QSC_MLDSA44_PUBLICKEY_SIZE bytes.
 * \return True if signature, message and context match; otherwise false.
 * \note No mutable shared state; output owned by caller.
 */
QSC_EXPORT_API bool qsc_mldsa44_verify_ex(uint8_t* msg, size_t* msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

/** \def QSC_MLDSA65_PUBLICKEY_SIZE
 * \brief Byte count of the ML-DSA-65 verification key.
 */
#define QSC_MLDSA65_PUBLICKEY_SIZE 1952U

/** \def QSC_MLDSA65_PRIVATEKEY_SIZE
 * \brief Byte count of the ML-DSA-65 private signing key.
 */
#define QSC_MLDSA65_PRIVATEKEY_SIZE 4032U

/** \def QSC_MLDSA65_SIGNATURE_SIZE
 * \brief Byte count of the ML-DSA-65 detached signature.
 */
#define QSC_MLDSA65_SIGNATURE_SIZE 3309U

/** \brief Generate an ML-DSA-65 key pair with caller RNG.
 * \param pk Caller-owned output, QSC_MLDSA65_PUBLICKEY_SIZE bytes.
 * \param sk Caller-owned secret output, QSC_MLDSA65_PRIVATEKEY_SIZE bytes.
 * \param rng_generate Random-byte callback, true on success; must be thread safe if called concurrently.
 * \return True on successful generation; false on invalid argument or RNG failure.
 * \note Non-thread-safe if the supplied RNG is non-thread-safe; caller must erase the secret key.
 */
QSC_EXPORT_API bool qsc_mldsa65_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Deterministically derive an ML-DSA-65 key pair from a 32-byte seed.
 * \param pk Output, QSC_MLDSA65_PUBLICKEY_SIZE bytes.
 * \param sk Secret output, QSC_MLDSA65_PRIVATEKEY_SIZE bytes.
 * \param seed Input array of QSC_MLDSA_SEED_SIZE bytes.
 * \note Not thread-sensitive; caller owns and erases keys; invalid pointers perform no operation.
 */
QSC_EXPORT_API void qsc_mldsa65_seeded_generate_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

/** \brief Sign a message with ML-DSA-65; append message to signature.
 * \param sm Caller-owned output, at least QSC_MLDSA65_SIGNATURE_SIZE + msglen bytes.
 * \param smlen Receives output length.
 * \param msg Input message, msglen bytes.
 * \param msglen Message length in bytes.
 * \param sk Secret signing key, QSC_MLDSA65_PRIVATEKEY_SIZE bytes.
 * \param rng_generate RNG callback needed for hedged signing; ignored in deterministic mode.
 * \return True on signing success; false on invalid arguments, rejected length or RNG failure.
 * \note Use sign_ex for context binding. Caller owns buffers, protect secret and output aliasing.
 */
QSC_EXPORT_API bool qsc_mldsa65_sign(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Sign using explicit ML-DSA-65 context binding.
 * \param sm Output, QSC_MLDSA65_SIGNATURE_SIZE + msglen bytes.
 * \param smlen Receives signed output length.
 * \param msg Message input, msglen bytes.
 * \param msglen Message length.
 * \param ctx Optional context string, at most 255 bytes; non-null when ctxlen is nonzero.
 * \param ctxlen Context length (0 to 255 bytes).
 * \param sk Signing key, QSC_MLDSA65_PRIVATEKEY_SIZE bytes.
 * \param rng_generate RNG callback for randomized signing, or null in deterministic builds.
 * \return True on successful signing; false on invalid parameters, RNG or backend failure.
 * \note Caller owns outputs; thread safety depends on the supplied RNG.
 */
QSC_EXPORT_API bool qsc_mldsa65_sign_ex(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Verify an ML-DSA-65 signature and recover its attached message.
 * \param msg Caller-owned message output, at least smlen - signature-size bytes when valid.
 * \param msglen Receives verified message length, zero on failure.
 * \param sm Input signature followed by message.
 * \param smlen Total input length.
 * \param pk Public verification key, QSC_MLDSA65_PUBLICKEY_SIZE bytes.
 * \return True on a valid signature, otherwise false.
 * \note No output size is inferred from pointer; caller must allocate appropriately.
 */
QSC_EXPORT_API bool qsc_mldsa65_verify(uint8_t* msg, size_t* msglen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

/** \brief Verify an ML-DSA-65 signed message with context binding.
 * \param msg Caller-owned recovered message output.
 * \param msglen Receives output length; zero on failure.
 * \param ctx Context input, non-null when ctxlen is nonzero.
 * \param ctxlen Context length in the range 0 to 255 bytes.
 * \param sm Signed message input.
 * \param smlen Signed-message length.
 * \param pk Public verification key, QSC_MLDSA65_PUBLICKEY_SIZE bytes.
 * \return True if signature, message and context match; otherwise false.
 * \note No mutable shared state; output owned by caller.
 */
QSC_EXPORT_API bool qsc_mldsa65_verify_ex(uint8_t* msg, size_t* msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

/** \def QSC_MLDSA87_PUBLICKEY_SIZE
 * \brief Byte count of the ML-DSA-87 verification key.
 */
#define QSC_MLDSA87_PUBLICKEY_SIZE 2592U

/** \def QSC_MLDSA87_PRIVATEKEY_SIZE
 * \brief Byte count of the ML-DSA-87 private signing key.
 */
#define QSC_MLDSA87_PRIVATEKEY_SIZE 4896U

/** \def QSC_MLDSA87_SIGNATURE_SIZE
 * \brief Byte count of the ML-DSA-87 detached signature.
 */
#define QSC_MLDSA87_SIGNATURE_SIZE 4627U

/** \brief Generate an ML-DSA-87 key pair with caller RNG.
 * \param pk Caller-owned output, QSC_MLDSA87_PUBLICKEY_SIZE bytes.
 * \param sk Caller-owned secret output, QSC_MLDSA87_PRIVATEKEY_SIZE bytes.
 * \param rng_generate Random-byte callback, true on success; must be thread safe if called concurrently.
 * \return True on successful generation; false on invalid argument or RNG failure.
 * \note Non-thread-safe if the supplied RNG is non-thread-safe; caller must erase the secret key.
 */
QSC_EXPORT_API bool qsc_mldsa87_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Deterministically derive an ML-DSA-87 key pair from a 32-byte seed.
 * \param pk Output, QSC_MLDSA87_PUBLICKEY_SIZE bytes.
 * \param sk Secret output, QSC_MLDSA87_PRIVATEKEY_SIZE bytes.
 * \param seed Input array of QSC_MLDSA_SEED_SIZE bytes.
 * \note Not thread-sensitive; caller owns and erases keys; invalid pointers perform no operation.
 */
QSC_EXPORT_API void qsc_mldsa87_seeded_generate_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

/** \brief Sign a message with ML-DSA-87; append message to signature.
 * \param sm Caller-owned output, at least QSC_MLDSA87_SIGNATURE_SIZE + msglen bytes.
 * \param smlen Receives output length.
 * \param msg Input message, msglen bytes.
 * \param msglen Message length in bytes.
 * \param sk Secret signing key, QSC_MLDSA87_PRIVATEKEY_SIZE bytes.
 * \param rng_generate RNG callback needed for hedged signing; ignored in deterministic mode.
 * \return True on signing success; false on invalid arguments, rejected length or RNG failure.
 * \note Use sign_ex for context binding. Caller owns buffers, protect secret and output aliasing.
 */
QSC_EXPORT_API bool qsc_mldsa87_sign(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Sign using explicit ML-DSA-87 context binding.
 * \param sm Output, QSC_MLDSA87_SIGNATURE_SIZE + msglen bytes.
 * \param smlen Receives signed output length.
 * \param msg Message input, msglen bytes.
 * \param msglen Message length.
 * \param ctx Optional context string, at most 255 bytes; non-null when ctxlen is nonzero.
 * \param ctxlen Context length (0 to 255 bytes).
 * \param sk Signing key, QSC_MLDSA87_PRIVATEKEY_SIZE bytes.
 * \param rng_generate RNG callback for randomized signing, or null in deterministic builds.
 * \return True on successful signing; false on invalid parameters, RNG or backend failure.
 * \note Caller owns outputs; thread safety depends on the supplied RNG.
 */
QSC_EXPORT_API bool qsc_mldsa87_sign_ex(uint8_t* sm, size_t* smlen, const uint8_t* msg, size_t msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/** \brief Verify an ML-DSA-87 signature and recover its attached message.
 * \param msg Caller-owned message output, at least smlen - signature-size bytes when valid.
 * \param msglen Receives verified message length, zero on failure.
 * \param sm Input signature followed by message.
 * \param smlen Total input length.
 * \param pk Public verification key, QSC_MLDSA87_PUBLICKEY_SIZE bytes.
 * \return True on a valid signature, otherwise false.
 * \note No output size is inferred from pointer; caller must allocate appropriately.
 */
QSC_EXPORT_API bool qsc_mldsa87_verify(uint8_t* msg, size_t* msglen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

/** \brief Verify an ML-DSA-87 signed message with context binding.
 * \param msg Caller-owned recovered message output.
 * \param msglen Receives output length; zero on failure.
 * \param ctx Context input, non-null when ctxlen is nonzero.
 * \param ctxlen Context length in the range 0 to 255 bytes.
 * \param sm Signed message input.
 * \param smlen Signed-message length.
 * \param pk Public verification key, QSC_MLDSA87_PUBLICKEY_SIZE bytes.
 * \return True if signature, message and context match; otherwise false.
 * \note No mutable shared state; output owned by caller.
 */
QSC_EXPORT_API bool qsc_mldsa87_verify_ex(uint8_t* msg, size_t* msglen, const uint8_t* ctx, size_t ctxlen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

QSC_CPLUSPLUS_ENABLED_END

#endif
