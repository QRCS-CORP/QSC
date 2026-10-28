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

#include "slhdsa.h"
#include "sha2.h"

/* FIPS 205 independent SLH-DSA-SHAKE-192s compilation unit.
 * Only object-like parameter and symbol selectors; no function macros.
 */

/** \def SPX_N
 * \brief Hash output/security parameter for SHAKE-192s.
 */
#define SPX_N 24U

/** \def SPX_FULL_HEIGHT
 * \brief Hypertree height for SHAKE-192s.
 */
#define SPX_FULL_HEIGHT 63U

/** \def SPX_D
 * \brief Hypertree layers for SHAKE-192s.
 */
#define SPX_D 7U

/** \def SPX_FORS_HEIGHT
 * \brief FORS tree height for SHAKE-192s.
 */
#define SPX_FORS_HEIGHT 14U

/** \def SPX_FORS_TREES
 * \brief Number of FORS trees for SHAKE-192s.
 */
#define SPX_FORS_TREES 17U

/** \def sphincsplus_ref_sign_secretkeybytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_secretkeybytes qsc_slhdsa_shake192s_internal_sign_secretkeybytes

/** \def sphincsplus_ref_sign_publickeybytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_publickeybytes qsc_slhdsa_shake192s_internal_sign_publickeybytes

/** \def sphincsplus_ref_sign_bytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_bytes qsc_slhdsa_shake192s_internal_sign_bytes

/** \def sphincsplus_ref_sign_seedbytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_seedbytes qsc_slhdsa_shake192s_internal_sign_seedbytes

/** \def sphincsplus_ref_generate_seeded_keypair
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_generate_seeded_keypair qsc_slhdsa_shake192s_internal_generate_seeded_keypair

/** \def sphincsplus_ref_generate_keypair
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_generate_keypair qsc_slhdsa_shake192s_internal_generate_keypair

/** \def sphincsplus_ref_sign_signature
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_signature qsc_slhdsa_shake192s_internal_sign_signature

/** \def sphincsplus_ref_sign
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign qsc_slhdsa_shake192s_internal_sign

/** \def sphincsplus_ref_verify
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_verify qsc_slhdsa_shake192s_internal_verify

/** \def sphincsplus_ref_open
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_open qsc_slhdsa_shake192s_internal_open

/** \def SLH_DSA_KEYGEN
 * \brief Exported SHAKE-192s symbol binding for common API implementation.
 */
#define SLH_DSA_KEYGEN qsc_slhdsa_shake192s_generate_keypair

/** \def SLH_DSA_SEEDED_KEYGEN
 * \brief Exported SHAKE-192s symbol binding for common API implementation.
 */
#define SLH_DSA_SEEDED_KEYGEN qsc_slhdsa_shake192s_generate_seeded_keypair

/** \def SLH_DSA_SIGN
 * \brief Exported SHAKE-192s symbol binding for common API implementation.
 */
#define SLH_DSA_SIGN qsc_slhdsa_shake192s_sign

/** \def SLH_DSA_SIGN_DETERMINISTIC
 * \brief Exported SHAKE-192s symbol binding for common API implementation.
 */
#define SLH_DSA_SIGN_DETERMINISTIC qsc_slhdsa_shake192s_sign_deterministic

/** \def SLH_DSA_VERIFY
 * \brief Exported SHAKE-192s symbol binding for common API implementation.
 */
#define SLH_DSA_VERIFY qsc_slhdsa_shake192s_verify

/** \def SLH_DSA_SIGN_PREHASH
 * \brief Bind SHAKE-192s HashSLH-DSA sign_prehash to its independent public symbol.
 */
#define SLH_DSA_SIGN_PREHASH qsc_slhdsa_shake192s_sign_prehash

/** \def SLH_DSA_SIGN_PREHASH_DETERMINISTIC
 * \brief Bind SHAKE-192s HashSLH-DSA sign_prehash_deterministic to its independent public symbol.
 */
#define SLH_DSA_SIGN_PREHASH_DETERMINISTIC qsc_slhdsa_shake192s_sign_prehash_deterministic

/** \def SLH_DSA_VERIFY_PREHASH
 * \brief Bind SHAKE-192s HashSLH-DSA verify_prehash to its independent public symbol.
 */
#define SLH_DSA_VERIFY_PREHASH qsc_slhdsa_shake192s_verify_prehash

#include "slhdsa_shake_core.inc"

#if SPX_BYTES != QSC_SLHDSA_SHAKE192S_SIGNATURE_SIZE
#	error "SLH-DSA FIPS 205 signature size mismatch for SHAKE-192s"
#endif

#include "slhdsa_shake_api.inc"
#undef SLH_DSA_KEYGEN
#undef SLH_DSA_SEEDED_KEYGEN
#undef SLH_DSA_SIGN
#undef SLH_DSA_SIGN_DETERMINISTIC
#undef SLH_DSA_VERIFY
#undef SLH_DSA_VERIFY_PREHASH
#undef SLH_DSA_SIGN_PREHASH_DETERMINISTIC
#undef SLH_DSA_SIGN_PREHASH
#undef sphincsplus_ref_sign_secretkeybytes
#undef sphincsplus_ref_sign_publickeybytes
#undef sphincsplus_ref_sign_bytes
#undef sphincsplus_ref_sign_seedbytes
#undef sphincsplus_ref_generate_seeded_keypair
#undef sphincsplus_ref_generate_keypair
#undef sphincsplus_ref_sign_signature
#undef sphincsplus_ref_sign
#undef sphincsplus_ref_verify
#undef sphincsplus_ref_open
#undef SPX_N
#undef SPX_FULL_HEIGHT
#undef SPX_D
#undef SPX_FORS_HEIGHT
#undef SPX_FORS_TREES
