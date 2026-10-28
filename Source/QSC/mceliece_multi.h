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

#ifndef QSC_MCELIECE_MULTI_H
#define QSC_MCELIECE_MULTI_H
#include "qsccommon.h"
QSC_CPLUSPLUS_ENABLED_START

/**
 * \file mceliece_multi.h
 * \brief Independent ISO Classic McEliece ordinary and plaintext-confirmation APIs.
 * \details All sixteen ISO/IEC 18033-2:2006/Amd 2:2026 configurations.
 *          All arrays are caller-owned and must not overlap. The supplied RNG
 *          must be cryptographically secure and concurrency-safe if shared.
 *          The f and pcf configurations use semi-systematic (32,64) key generation.
 */

/** \def QSC_MCELIECE_460896PC_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 460896pc.
 */
#define QSC_MCELIECE_460896PC_CIPHERTEXT_SIZE 188U

/** \def QSC_MCELIECE_460896PC_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 460896pc.
 */
#define QSC_MCELIECE_460896PC_PRIVATEKEY_SIZE 13608U

/** \def QSC_MCELIECE_460896PC_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 460896pc.
 */
#define QSC_MCELIECE_460896PC_PUBLICKEY_SIZE 524160U

/** \def QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 460896pc.
 */
#define QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 460896pc construction.
 * \param secret: Output, QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_460896PC_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_460896PC_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_460896pc_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 460896pc.
 * \param secret: Output, QSC_MCELIECE_460896PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_460896PC_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896pc_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 460896pc.
 * \param publickey: Output, QSC_MCELIECE_460896PC_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_460896PC_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896pc_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6688128PC_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6688128pc.
 */
#define QSC_MCELIECE_6688128PC_CIPHERTEXT_SIZE 240U

/** \def QSC_MCELIECE_6688128PC_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6688128pc.
 */
#define QSC_MCELIECE_6688128PC_PRIVATEKEY_SIZE 13932U

/** \def QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6688128pc.
 */
#define QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE 1044992U

/** \def QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6688128pc.
 */
#define QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6688128pc construction.
 * \param secret: Output, QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6688128PC_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6688128PC_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128pc_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6688128pc.
 * \param secret: Output, QSC_MCELIECE_6688128PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6688128PC_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128pc_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6688128pc.
 * \param publickey: Output, QSC_MCELIECE_6688128PC_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6688128PC_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128pc_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6960119pc.
 */
#define QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE 226U

/** \def QSC_MCELIECE_6960119PC_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6960119pc.
 */
#define QSC_MCELIECE_6960119PC_PRIVATEKEY_SIZE 13948U

/** \def QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6960119pc.
 */
#define QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE 1047319U

/** \def QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6960119pc.
 */
#define QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6960119pc construction.
 * \param secret: Output, QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6960119PC_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119pc_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6960119pc.
 * \param secret: Output, QSC_MCELIECE_6960119PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6960119PC_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119pc_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6960119pc.
 * \param publickey: Output, QSC_MCELIECE_6960119PC_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6960119PC_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119pc_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_8192128PC_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 8192128pc.
 */
#define QSC_MCELIECE_8192128PC_CIPHERTEXT_SIZE 240U

/** \def QSC_MCELIECE_8192128PC_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 8192128pc.
 */
#define QSC_MCELIECE_8192128PC_PRIVATEKEY_SIZE 14120U

/** \def QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 8192128pc.
 */
#define QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE 1357824U

/** \def QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 8192128pc.
 */
#define QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 8192128pc construction.
 * \param secret: Output, QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_8192128PC_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_8192128PC_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128pc_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 8192128pc.
 * \param secret: Output, QSC_MCELIECE_8192128PC_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_8192128PC_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128pc_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 8192128pc.
 * \param publickey: Output, QSC_MCELIECE_8192128PC_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_8192128PC_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128pc_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_460896_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 460896.
 */
#define QSC_MCELIECE_460896_CIPHERTEXT_SIZE 156U

/** \def QSC_MCELIECE_460896_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 460896.
 */
#define QSC_MCELIECE_460896_PRIVATEKEY_SIZE 13608U

/** \def QSC_MCELIECE_460896_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 460896.
 */
#define QSC_MCELIECE_460896_PUBLICKEY_SIZE 524160U

/** \def QSC_MCELIECE_460896_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 460896.
 */
#define QSC_MCELIECE_460896_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 460896 construction.
 * \param secret: Output, QSC_MCELIECE_460896_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_460896_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_460896_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_460896_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 460896.
 * \param secret: Output, QSC_MCELIECE_460896_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_460896_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_460896_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 460896.
 * \param publickey: Output, QSC_MCELIECE_460896_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_460896_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6688128_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6688128.
 */
#define QSC_MCELIECE_6688128_CIPHERTEXT_SIZE 208U

/** \def QSC_MCELIECE_6688128_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6688128.
 */
#define QSC_MCELIECE_6688128_PRIVATEKEY_SIZE 13932U

/** \def QSC_MCELIECE_6688128_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6688128.
 */
#define QSC_MCELIECE_6688128_PUBLICKEY_SIZE 1044992U

/** \def QSC_MCELIECE_6688128_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6688128.
 */
#define QSC_MCELIECE_6688128_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6688128 construction.
 * \param secret: Output, QSC_MCELIECE_6688128_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6688128_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6688128_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6688128.
 * \param secret: Output, QSC_MCELIECE_6688128_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6688128_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6688128_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6688128.
 * \param publickey: Output, QSC_MCELIECE_6688128_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6688128_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6960119_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6960119.
 */
#define QSC_MCELIECE_6960119_CIPHERTEXT_SIZE 194U

/** \def QSC_MCELIECE_6960119_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6960119.
 */
#define QSC_MCELIECE_6960119_PRIVATEKEY_SIZE 13948U

/** \def QSC_MCELIECE_6960119_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6960119.
 */
#define QSC_MCELIECE_6960119_PUBLICKEY_SIZE 1047319U

/** \def QSC_MCELIECE_6960119_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6960119.
 */
#define QSC_MCELIECE_6960119_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6960119 construction.
 * \param secret: Output, QSC_MCELIECE_6960119_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6960119_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6960119_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6960119.
 * \param secret: Output, QSC_MCELIECE_6960119_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6960119_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6960119_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6960119.
 * \param publickey: Output, QSC_MCELIECE_6960119_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6960119_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_8192128_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 8192128.
 */
#define QSC_MCELIECE_8192128_CIPHERTEXT_SIZE 208U

/** \def QSC_MCELIECE_8192128_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 8192128.
 */
#define QSC_MCELIECE_8192128_PRIVATEKEY_SIZE 14120U

/** \def QSC_MCELIECE_8192128_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 8192128.
 */
#define QSC_MCELIECE_8192128_PUBLICKEY_SIZE 1357824U

/** \def QSC_MCELIECE_8192128_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 8192128.
 */
#define QSC_MCELIECE_8192128_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 8192128 construction.
 * \param secret: Output, QSC_MCELIECE_8192128_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_8192128_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_8192128_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 8192128.
 * \param secret: Output, QSC_MCELIECE_8192128_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_8192128_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_8192128_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 8192128.
 * \param publickey: Output, QSC_MCELIECE_8192128_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_8192128_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_460896F_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 460896f.
 */
#define QSC_MCELIECE_460896F_CIPHERTEXT_SIZE 156U

/** \def QSC_MCELIECE_460896F_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 460896f.
 */
#define QSC_MCELIECE_460896F_PRIVATEKEY_SIZE 13608U

/** \def QSC_MCELIECE_460896F_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 460896f.
 */
#define QSC_MCELIECE_460896F_PUBLICKEY_SIZE 524160U

/** \def QSC_MCELIECE_460896F_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 460896f.
 */
#define QSC_MCELIECE_460896F_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 460896f construction.
 * \param secret: Output, QSC_MCELIECE_460896F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_460896F_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_460896F_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_460896f_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 460896f.
 * \param secret: Output, QSC_MCELIECE_460896F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_460896F_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_460896F_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896f_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 460896f.
 * \param publickey: Output, QSC_MCELIECE_460896F_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_460896F_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896f_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_460896PCF_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 460896pcf.
 */
#define QSC_MCELIECE_460896PCF_CIPHERTEXT_SIZE 188U

/** \def QSC_MCELIECE_460896PCF_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 460896pcf.
 */
#define QSC_MCELIECE_460896PCF_PRIVATEKEY_SIZE 13608U

/** \def QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 460896pcf.
 */
#define QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE 524160U

/** \def QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 460896pcf.
 */
#define QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 460896pcf construction.
 * \param secret: Output, QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_460896PCF_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_460896PCF_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_460896pcf_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 460896pcf.
 * \param secret: Output, QSC_MCELIECE_460896PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_460896PCF_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896pcf_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 460896pcf.
 * \param publickey: Output, QSC_MCELIECE_460896PCF_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_460896PCF_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_460896pcf_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6688128F_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6688128f.
 */
#define QSC_MCELIECE_6688128F_CIPHERTEXT_SIZE 208U

/** \def QSC_MCELIECE_6688128F_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6688128f.
 */
#define QSC_MCELIECE_6688128F_PRIVATEKEY_SIZE 13932U

/** \def QSC_MCELIECE_6688128F_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6688128f.
 */
#define QSC_MCELIECE_6688128F_PUBLICKEY_SIZE 1044992U

/** \def QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6688128f.
 */
#define QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6688128f construction.
 * \param secret: Output, QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6688128F_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6688128F_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128f_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6688128f.
 * \param secret: Output, QSC_MCELIECE_6688128F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6688128F_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6688128F_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128f_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6688128f.
 * \param publickey: Output, QSC_MCELIECE_6688128F_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6688128F_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128f_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6688128PCF_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6688128pcf.
 */
#define QSC_MCELIECE_6688128PCF_CIPHERTEXT_SIZE 240U

/** \def QSC_MCELIECE_6688128PCF_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6688128pcf.
 */
#define QSC_MCELIECE_6688128PCF_PRIVATEKEY_SIZE 13932U

/** \def QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6688128pcf.
 */
#define QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE 1044992U

/** \def QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6688128pcf.
 */
#define QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6688128pcf construction.
 * \param secret: Output, QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6688128PCF_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6688128PCF_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128pcf_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6688128pcf.
 * \param secret: Output, QSC_MCELIECE_6688128PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6688128PCF_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128pcf_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6688128pcf.
 * \param publickey: Output, QSC_MCELIECE_6688128PCF_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6688128PCF_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6688128pcf_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6960119f.
 */
#define QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE 194U

/** \def QSC_MCELIECE_6960119F_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6960119f.
 */
#define QSC_MCELIECE_6960119F_PRIVATEKEY_SIZE 13948U

/** \def QSC_MCELIECE_6960119F_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6960119f.
 */
#define QSC_MCELIECE_6960119F_PUBLICKEY_SIZE 1047319U

/** \def QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6960119f.
 */
#define QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6960119f construction.
 * \param secret: Output, QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6960119F_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119f, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119f_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6960119f.
 * \param secret: Output, QSC_MCELIECE_6960119F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6960119F_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6960119F_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119f_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6960119f.
 * \param publickey: Output, QSC_MCELIECE_6960119F_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6960119F_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119f_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_6960119PCF_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 6960119pcf.
 */
#define QSC_MCELIECE_6960119PCF_CIPHERTEXT_SIZE 226U

/** \def QSC_MCELIECE_6960119PCF_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 6960119pcf.
 */
#define QSC_MCELIECE_6960119PCF_PRIVATEKEY_SIZE 13948U

/** \def QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 6960119pcf.
 */
#define QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE 1047319U

/** \def QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 6960119pcf.
 */
#define QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 6960119pcf construction.
 * \param secret: Output, QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_6960119PCF_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_6960119PCF_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119pcf_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 6960119pcf.
 * \param secret: Output, QSC_MCELIECE_6960119PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_6960119PCF_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119pcf_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 6960119pcf.
 * \param publickey: Output, QSC_MCELIECE_6960119PCF_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_6960119PCF_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_6960119pcf_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_8192128F_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 8192128f.
 */
#define QSC_MCELIECE_8192128F_CIPHERTEXT_SIZE 208U

/** \def QSC_MCELIECE_8192128F_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 8192128f.
 */
#define QSC_MCELIECE_8192128F_PRIVATEKEY_SIZE 14120U

/** \def QSC_MCELIECE_8192128F_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 8192128f.
 */
#define QSC_MCELIECE_8192128F_PUBLICKEY_SIZE 1357824U

/** \def QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 8192128f.
 */
#define QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 8192128f construction.
 * \param secret: Output, QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_8192128F_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_8192128F_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128f_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 8192128f.
 * \param secret: Output, QSC_MCELIECE_8192128F_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_8192128F_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_8192128F_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128f_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 8192128f.
 * \param publickey: Output, QSC_MCELIECE_8192128F_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_8192128F_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128f_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/** \def QSC_MCELIECE_8192128PCF_CIPHERTEXT_SIZE
 * \brief Required ciphertext size, in bytes, for 8192128pcf.
 */
#define QSC_MCELIECE_8192128PCF_CIPHERTEXT_SIZE 240U

/** \def QSC_MCELIECE_8192128PCF_PRIVATEKEY_SIZE
 * \brief Required secret key size, in bytes, for 8192128pcf.
 */
#define QSC_MCELIECE_8192128PCF_PRIVATEKEY_SIZE 14120U

/** \def QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE
 * \brief Required public key size, in bytes, for 8192128pcf.
 */
#define QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE 1357824U

/** \def QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE
 * \brief Required session key size, in bytes, for 8192128pcf.
 */
#define QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates using the ISO 8192128pcf construction.
 * \param secret: Output, QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Input, QSC_MCELIECE_8192128PCF_CIPHERTEXT_SIZE bytes.
 * \param privatekey: Input, QSC_MCELIECE_8192128PCF_PRIVATEKEY_SIZE bytes.
 * \return True after implicit-rejection processing; false on invalid inputs
 *         or, for 6960119, nonzero ciphertext padding.
 * \note Reentrant with disjoint input/output arrays; the caller owns memory.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128pcf_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates using ISO 8192128pcf.
 * \param secret: Output, QSC_MCELIECE_8192128PCF_SHAREDSECRET_SIZE bytes.
 * \param ciphertext: Output, QSC_MCELIECE_8192128PCF_CIPHERTEXT_SIZE bytes.
 * \param publickey: Input, QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false.
 * \note Caller owns all buffers; reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128pcf_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a public and secret key pair for ISO 8192128pcf.
 * \param publickey: Output, QSC_MCELIECE_8192128PCF_PUBLICKEY_SIZE bytes.
 * \param privatekey: Output, QSC_MCELIECE_8192128PCF_PRIVATEKEY_SIZE bytes.
 * \param rng_generate: Secure RNG callback; shared state must be synchronized.
 * \return True on success, otherwise false, including RNG failure.
 * \note Requires a sufficiently large stack; recommended minimum is 4 MiB.
 *       Caller owns key buffers. Reentrant for independent RNG and buffers.
 */
QSC_EXPORT_API bool qsc_mceliece_8192128pcf_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

QSC_CPLUSPLUS_ENABLED_END
#endif
