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

/**
 * \file hqcbase.h
 * \brief Defines the public AVX2 entry points, parameter constants, and data structures
 * for the QSC HQC implementation.
 *
 * \details
 * This header provides the configuration layer for the AVX2-enabled HQC implementation.
 * It selects one HQC parameter set at compile time, exposes the derived compile-time
 * constants used by the implementation, defines the internal ciphertext container types,
 * and declares the public AVX2 key generation, encapsulation, and decapsulation functions.
 *
 * The file is intended to mirror the scalar HQC base interface while binding the
 * implementation to AVX2-capable code paths contained in the companion source module.
 * Only one parameter guard may be enabled for a build. If no parameter set is selected,
 * HQC-3 is enabled by default.
 *
 * This header includes <immintrin.h> because the associated implementation uses Intel
 * AVX2 intrinsics. The caller is responsible for ensuring that the compilation target
 * and runtime environment support the required instruction set extensions.
 */

#ifndef QSC_HQCBASE_H
#define QSC_HQCBASE_H

/* \cond NO_DOCUMENT */

#include "qsccommon.h"
#include <immintrin.h>

/**
 * \brief Selects HQC-3 when no explicit HQC parameter guard has been defined.
 *
 * \details
 * Exactly one of QSC_HQC_S1N2321, QSC_HQC_S3N4602, or QSC_HQC_S5N7333 must be active.
 * This default keeps the module buildable without requiring an external parameter-set
 * define and makes HQC-3 the default target profile.
 */
#if !defined(QSC_HQC_S1N2321) && !defined(QSC_HQC_S3N4602) && !defined(QSC_HQC_S5N7333)
#   define QSC_HQC_S3N4602
#endif

/**
 * \brief Enforces single-parameter-set compilation.
 *
 * \details
 * The HQC implementation is parameterized entirely at compile time. Building with more
 * than one parameter-set guard would create conflicting constant definitions and invalid
 * object layouts, so the preprocessor rejects that configuration.
 */
#if (defined(QSC_HQC_S1N2321) + defined(QSC_HQC_S3N4602) + defined(QSC_HQC_S5N7333)) != 1
#   error "Define exactly one HQC parameter guard: QSC_HQC_S1N2321, QSC_HQC_S3N4602, or QSC_HQC_S5N7333."
#endif

#if defined(QSC_HQC_S1N2321)
/**
 * \def CEIL_DIVIDE(a, b)
 * \brief Computes the ceiling of a divided by b using integer arithmetic.
 */
#   define CEIL_DIVIDE(a, b) (((a) / (b)) + (((a) % (b)) == 0 ? 0 : 1))
/**
 * \def BITMASK(a, size)
 * \brief Creates a low-bit mask covering the remainder width of a modulo size.
 */
#   define BITMASK(a, size)  ((1UL << ((a) % (size))) - 1UL)
/**
 * \def CRYPTO_ALGNAME
 * \brief Formal algorithm name string for the selected HQC parameter set.
 */
#   define CRYPTO_ALGNAME "HQC-1"
/**
 * \def CRYPTO_SECRETKEYBYTES
 * \brief Encoded secret-key length in bytes.
 */
#   define CRYPTO_SECRETKEYBYTES 2321U
/**
 * \def CRYPTO_PUBLICKEYBYTES
 * \brief Encoded public-key length in bytes.
 */
#   define CRYPTO_PUBLICKEYBYTES 2241U
/**
 * \def CRYPTO_BYTES
 * \brief Shared-secret length in bytes.
 */
#   define CRYPTO_BYTES 32U
/**
 * \def CRYPTO_CIPHERTEXTBYTES
 * \brief Encoded ciphertext length in bytes.
 */
#   define CRYPTO_CIPHERTEXTBYTES 4433U
/**
 * \def PARAM_N
 * \brief Code length in bits.
 */
#   define PARAM_N 17669U
/**
 * \def PARAM_N1
 * \brief Reed-Muller message block length in bytes.
 */
#   define PARAM_N1 46U
/**
 * \def PARAM_N2
 * \brief Reed-Muller code expansion factor.
 */
#   define PARAM_N2 384U
/**
 * \def PARAM_N1N2
 * \brief Product of PARAM_N1 and PARAM_N2.
 */
#   define PARAM_N1N2 17664U
/**
 * \def PARAM_OMEGA
 * \brief Hamming weight of secret vectors.
 */
#   define PARAM_OMEGA 66U
/**
 * \def PARAM_OMEGA_E
 * \brief Hamming weight of the encryption error vectors.
 */
#   define PARAM_OMEGA_E 75U
/**
 * \def PARAM_OMEGA_R
 * \brief Hamming weight of the encryption randomness vectors.
 */
#   define PARAM_OMEGA_R 75U
/**
 * \def PARAM_SECURITY
 * \brief Target classical security level in bits.
 */
#   define PARAM_SECURITY 128U
/**
 * \def PARAM_SECURITY_BYTES
 * \brief Security level expressed in bytes.
 */
#   define PARAM_SECURITY_BYTES 16U
/**
 * \def PARAM_DFR_EXP
 * \brief Decryption-failure-rate exponent parameter.
 */
#   define PARAM_DFR_EXP 128U
#   define SECRET_KEY_BYTES CRYPTO_SECRETKEYBYTES
#   define PUBLIC_KEY_BYTES CRYPTO_PUBLICKEYBYTES
#   define SHARED_SECRET_BYTES CRYPTO_BYTES
#   define CIPHERTEXT_BYTES CRYPTO_CIPHERTEXTBYTES
/**
 * \def PARAM_DELTA
 * \brief Reed-Solomon correction capacity parameter.
 */
#   define PARAM_DELTA 15U
/**
 * \def PARAM_M
 * \brief Galois-field extension degree.
 */
#   define PARAM_M 8U
/**
 * \def PARAM_GF_POLY
 * \brief Reduction polynomial used for GF(2^m) multiplication.
 */
#   define PARAM_GF_POLY 0x11DU
/**
 * \def PARAM_GF_MUL_ORDER
 * \brief Multiplicative group order used by the finite-field arithmetic.
 */
#   define PARAM_GF_MUL_ORDER 255U
/**
 * \def PARAM_K
 * \brief Reed-Solomon message length in symbols.
 */
#   define PARAM_K 16U
/**
 * \def PARAM_G
 * \brief Reed-Solomon generator polynomial degree plus one.
 */
#   define PARAM_G 31U
/**
 * \def PARAM_FFT
 * \brief FFT recursion depth used by the decoder implementation.
 */
#   define PARAM_FFT 4U
/**
 * \def SEED_BYTES
 * \brief Seed length in bytes used by HQC key derivation and encapsulation paths.
 */
#   define SEED_BYTES 32U
/**
 * \def SALT_BYTES
 * \brief Ciphertext salt length in bytes.
 */
#   define SALT_BYTES 16U
/**
 * \def PARAM_N_MU
 * \brief Rejection-sampling constant derived from PARAM_N.
 */
#   define PARAM_N_MU 243079ULL
/**
 * \def UTILS_REJECTION_THRESHOLD
 * \brief Threshold used by constant-time rejection sampling.
 */
#   define UTILS_REJECTION_THRESHOLD 16767881U
#elif defined(QSC_HQC_S3N4602)
#   define CEIL_DIVIDE(a, b) (((a) / (b)) + (((a) % (b)) == 0 ? 0 : 1))
#   define BITMASK(a, size)  ((1UL << ((a) % (size))) - 1UL)
#   define CRYPTO_ALGNAME "HQC-3"
#   define CRYPTO_SECRETKEYBYTES 4602U
#   define CRYPTO_PUBLICKEYBYTES 4514U
#   define CRYPTO_BYTES 32U
#   define CRYPTO_CIPHERTEXTBYTES 8978U
#   define PARAM_N 35851U
#   define PARAM_N1 56U
#   define PARAM_N2 640U
#   define PARAM_N1N2 35840U
#   define PARAM_OMEGA 100U
#   define PARAM_OMEGA_E 114U
#   define PARAM_OMEGA_R 114U
#   define PARAM_SECURITY 192U
#   define PARAM_SECURITY_BYTES 24U
#   define PARAM_DFR_EXP 192U
#   define SECRET_KEY_BYTES CRYPTO_SECRETKEYBYTES
#   define PUBLIC_KEY_BYTES CRYPTO_PUBLICKEYBYTES
#   define SHARED_SECRET_BYTES CRYPTO_BYTES
#   define CIPHERTEXT_BYTES CRYPTO_CIPHERTEXTBYTES
#   define PARAM_DELTA 16U
#   define PARAM_M 8U
#   define PARAM_GF_POLY 0x11DU
#   define PARAM_GF_MUL_ORDER 255U
#   define PARAM_K 24U
#   define PARAM_G 33U
#   define PARAM_FFT 5U
#   define SEED_BYTES 32U
#   define SALT_BYTES 16U
#   define PARAM_N_MU 119800ULL
#   define UTILS_REJECTION_THRESHOLD 16742417U
#elif defined(QSC_HQC_S5N7333)
#   define CEIL_DIVIDE(a, b) (((a) / (b)) + (((a) % (b)) == 0 ? 0 : 1))
#   define BITMASK(a, size)  ((1ULL << ((a) % (size))) - 1ULL)
#   define CRYPTO_ALGNAME "HQC-5"
#   define CRYPTO_SECRETKEYBYTES 7333U
#   define CRYPTO_PUBLICKEYBYTES 7237U
#   define CRYPTO_BYTES 32U
#   define CRYPTO_CIPHERTEXTBYTES 14421U
#   define PARAM_N 57637U
#   define PARAM_N1 90U
#   define PARAM_N2 640U
#   define PARAM_N1N2 57600U
#   define PARAM_OMEGA 131U
#   define PARAM_OMEGA_E 149U
#   define PARAM_OMEGA_R 149U
#   define PARAM_SECURITY 256U
#   define PARAM_SECURITY_BYTES 32U
#   define PARAM_DFR_EXP 256U
#   define SECRET_KEY_BYTES CRYPTO_SECRETKEYBYTES
#   define PUBLIC_KEY_BYTES CRYPTO_PUBLICKEYBYTES
#   define SHARED_SECRET_BYTES CRYPTO_BYTES
#   define CIPHERTEXT_BYTES CRYPTO_CIPHERTEXTBYTES
#   define PARAM_DELTA 29U
#   define PARAM_M 8U
#   define PARAM_GF_POLY 0x11DU
#   define PARAM_GF_MUL_ORDER 255U
#   define PARAM_K 32U
#   define PARAM_G 59U
#   define PARAM_FFT 5U
#   define SEED_BYTES 32U
#   define SALT_BYTES 16U
#   define PARAM_N_MU 74517ULL
#   define UTILS_REJECTION_THRESHOLD 16772367U
#endif

#if defined(QSC_HQC_S1N2321)
/**
 * \def RS_POLY_COEFS
 * \brief Reed-Solomon generator polynomial coefficients for HQC-1.
 */
#define RS_POLY_COEFS 89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1
#elif defined(QSC_HQC_S3N4602)
/**
 * \def RS_POLY_COEFS
 * \brief Reed-Solomon generator polynomial coefficients for HQC-3.
 */
#define RS_POLY_COEFS 45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1
#elif defined(QSC_HQC_S5N7333)
/**
 * \def RS_POLY_COEFS
 * \brief Reed-Solomon generator polynomial coefficients for HQC-5.
 */
#define RS_POLY_COEFS 49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1
#endif

/**
 * \def VEC_N_SIZE_BYTES
 * \brief Byte length of a packed length-n binary vector.
 */
#define VEC_N_SIZE_BYTES CEIL_DIVIDE(PARAM_N, 8U)
/**
 * \def VEC_K_SIZE_BYTES
 * \brief Byte length of the Reed-Solomon message vector.
 */
#define VEC_K_SIZE_BYTES PARAM_K
/**
 * \def VEC_N1_SIZE_BYTES
 * \brief Byte length of the Reed-Muller input vector.
 */
#define VEC_N1_SIZE_BYTES PARAM_N1
/**
 * \def VEC_N1N2_SIZE_BYTES
 * \brief Byte length of the expanded Reed-Muller codeword vector.
 */
#define VEC_N1N2_SIZE_BYTES CEIL_DIVIDE(PARAM_N1N2, 8U)
/**
 * \def VEC_N_SIZE_64
 * \brief Number of 64-bit words required to store a packed length-n vector.
 */
#define VEC_N_SIZE_64 CEIL_DIVIDE(PARAM_N, 64U)
/**
 * \def VEC_N1_SIZE_64
 * \brief Number of 64-bit words required to store PARAM_N1 bytes.
 */
#define VEC_N1_SIZE_64 CEIL_DIVIDE(PARAM_N1, 8U)
/**
 * \def VEC_N1N2_SIZE_64
 * \brief Number of 64-bit words required to store the expanded codeword vector.
 */
#define VEC_N1N2_SIZE_64 CEIL_DIVIDE(PARAM_N1N2, 64U)
/**
 * \def QSC_HQC_SEED_SIZE
 * \brief Public constant defining the HQC seed size in bytes.
 */
#define QSC_HQC_SEED_SIZE 32U
/**
 * \def QSC_HQC_SHAREDSECRET_SIZE
 * \brief Public constant defining the HQC shared-secret size in bytes.
 */
#define QSC_HQC_SHAREDSECRET_SIZE 32U

/**
 * \struct qsc_hqc_ciphertext_pke
 * \brief Internal public-key-encryption ciphertext container.
 *
 * \details
 * The PKE ciphertext consists of two packed binary vectors. The member \c u holds the
 * first code-length vector, and \c v holds the second vector derived from the encoded
 * message domain. This type is used internally by the KEM conversion functions and by
 * the AVX2 implementation routines.
 */
typedef struct
{
    uint64_t u[VEC_N_SIZE_64];
    uint64_t v[VEC_N1N2_SIZE_64];
} qsc_hqc_ciphertext_pke;

/**
 * \struct qsc_hqc_ciphertext_kem
 * \brief Internal KEM ciphertext container.
 *
 * \details
 * HQC KEM ciphertexts augment the PKE ciphertext with a fixed-width salt value. The
 * encoded external ciphertext representation is constructed from this structure.
 */
typedef struct
{
    qsc_hqc_ciphertext_pke c_pke;
    uint8_t salt[SALT_BYTES];
} qsc_hqc_ciphertext_kem;

/**
 * \union rm_codeword_t
 * \brief Overlay type used by the Reed-Muller AVX2 code path.
 *
 * \details
 * The AVX2 Reed-Muller routines interpret a 128-bit codeword fragment through multiple
 * scalar views. The 8-bit, 16-bit, and 32-bit members provide layout-compatible access
 * for packing, accumulation, and Hadamard-domain processing.
 */
typedef union
{
    uint8_t u8[16];
    uint16_t u16[8];
    uint32_t u32[4];
} rm_codeword_t;

/**
 * \brief Decapsulates an HQC ciphertext using the AVX2 implementation.
 *
 * \param[out] secret A pointer to the output shared secret buffer.
 * The buffer must be at least QSC_HQC_SHAREDSECRET_SIZE bytes long.
 * \param[in] ciphertext A pointer to the encoded ciphertext.
 * The buffer must contain exactly CIPHERTEXT_BYTES bytes.
 * \param[in] privatekey A pointer to the encoded private key.
 * The buffer must contain exactly SECRET_KEY_BYTES bytes.
 *
 * \return Returns true if decapsulation succeeds and the shared secret is produced.
 * Returns false if the ciphertext fails verification or the operation otherwise rejects.
 */
bool qsc_hqc_ref_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates a shared secret using the AVX2 implementation and an external RNG.
 *
 * \param[out] secret A pointer to the output shared secret buffer.
 * The buffer must be at least QSC_HQC_SHAREDSECRET_SIZE bytes long.
 * \param[out] ciphertext A pointer to the output ciphertext buffer.
 * The buffer must be at least CIPHERTEXT_BYTES bytes long.
 * \param[in] publickey A pointer to the encoded public key.
 * The buffer must contain exactly PUBLIC_KEY_BYTES bytes.
 * \param[in] rng_generate The caller-supplied random generator callback.
 * The callback must return true on success and fill the requested number of bytes.
 *
 * \return Returns true on success. Returns false if random generation fails.
 */
bool qsc_hqc_ref_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Encapsulates deterministically from a caller-supplied seed.
 *
 * \param[out] secret A pointer to the output shared secret buffer.
 * The buffer must be at least QSC_HQC_SHAREDSECRET_SIZE bytes long.
 * \param[out] ciphertext A pointer to the output ciphertext buffer.
 * The buffer must be at least CIPHERTEXT_BYTES bytes long.
 * \param[in] publickey A pointer to the encoded public key.
 * The buffer must contain exactly PUBLIC_KEY_BYTES bytes.
 * \param[in] seed A pointer to a QSC_HQC_SEED_SIZE-byte seed.
 *
 * \remarks
 * This function is intended for deterministic testing, known-answer validation, and
 * other controlled uses where the encapsulation seed must be provided explicitly.
 */
void qsc_hqc_ref_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_HQC_SEED_SIZE]);

/**
 * \brief Generates an HQC key pair using the AVX2 implementation and an external RNG.
 *
 * \param[out] publickey A pointer to the output public-key buffer.
 * The buffer must be at least PUBLIC_KEY_BYTES bytes long.
 * \param[out] privatekey A pointer to the output private-key buffer.
 * The buffer must be at least SECRET_KEY_BYTES bytes long.
 * \param[in] rng_generate The caller-supplied random generator callback.
 * The callback must return true on success and fill the requested number of bytes.
 *
 * \return Returns true on success. Returns false if random generation fails.
 */
bool qsc_hqc_ref_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates an HQC key pair deterministically from a caller-supplied seed.
 *
 * \param[out] publickey A pointer to the output public-key buffer.
 * The buffer must be at least PUBLIC_KEY_BYTES bytes long.
 * \param[out] privatekey A pointer to the output private-key buffer.
 * The buffer must be at least SECRET_KEY_BYTES bytes long.
 * \param[in] seed A pointer to the seed material used to derive the key pair.
 * The caller must provide at least QSC_HQC_SEED_SIZE bytes.
 *
 * \remarks
 * This entry point is intended for deterministic tests and reproducible vector
 * generation. The caller is responsible for protecting the seed material.
 */
void qsc_hqc_ref_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed);

/* \cond NO_DOCUMENT */

#endif
