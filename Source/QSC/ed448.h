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

#ifndef QSC_ED448_H
#define QSC_ED448_H

#include "qsccommon.h"

/* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file ed448.h
 * \brief Elliptic Curve (Ed448-Goldilocks) and Field Arithmetic Implementation.
 *
 * \details
 * This header defines the data structures and functions for performing operations on the
 * Ed448-Goldilocks elliptic curve, which provides approximately 224-bit security and is
 * standardized for digital signatures (RFC 8032) and key exchange (RFC 7748). It provides
 * several coordinate representations for curve points, including:
 *  - **P2:** Projective coordinates (X:Y:Z)
 *  - **P3:** Extended coordinates (X:Y:Z:T)
 *  - **P1P1:** Intermediate coordinates used in addition formulas
 *  - **Precomputed:** A structure for precomputed values to speed up base point operations
 *  - **Cached:** A structure for caching repeated computations
 *
 * In addition, this header defines functions for field arithmetic in the finite field defined
 * by the Goldilocks prime p = 2^448 - 2^224 - 1. Field elements are represented as arrays of
 * 16 int32_t values in a radix-2^28 format. The field arithmetic functions include:
 *  - Initialization routines to set field elements to zero or one.
 *  - Copy, addition, subtraction, and negation operations.
 *  - Constant-time conditional swap and conditional move operations.
 *  - Multiplication and squaring routines.
 *  - Conversion routines between a 56-byte little-endian representation and the field element.
 *  - Exponentiation and inversion routines.
 *
 * These operations form the foundation of the Ed448 digital signature scheme (RFC 8032) and
 * the X448 key exchange protocol (RFC 7748), and are implemented to be constant-time to
 * mitigate timing attacks.
 *
 * \section ed448_links Reference Links:
 *  - <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)</a>
 *  - <a href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748: Elliptic Curves for Diffie-Hellman Key Agreement</a>
 *  - <a href="https://eprint.iacr.org/2015/625.pdf">Hamburg: Ed448-Goldilocks, a new elliptic curve</a>
 */

/*!
 * \def ED448_SEED_SIZE
 * \brief The Ed448 seed size in bytes (RFC 8032).
 */
#define ED448_SEED_SIZE 57U

/*!
 * \def ED448_SIGNATURE_SIZE
 * \brief The Ed448 signature size in bytes (R || S, each 57 bytes).
 */
#define ED448_SIGNATURE_SIZE 114U

/*!
 * \def ED448_PUBLICKEY_SIZE
 * \brief The Ed448 public key size in bytes.
 */
#define ED448_PUBLICKEY_SIZE 57U

/*!
 * \def ED448_PRIVATEKEY_SIZE
 * \brief The Ed448 private key size in bytes (seed || public key).
 */
#define ED448_PRIVATEKEY_SIZE 114U

/*!
 * \def ED448_CURVE_SIZE
 * \brief The Ed448 field element byte size (u-coordinate for X448).
 */
#define ED448_CURVE_SIZE 56U

/*!
 * \typedef qsc_fe448
 * \brief A field element in GF(2^448 - 2^224 - 1), represented as 16 int32_t limbs in radix 2^28.
 */
typedef int32_t qsc_fe448[16U];

/*!
 * \struct qsc_ge448_p2
 * \brief Projective coordinate representation.
 *
 * Represents a point on the Ed448-Goldilocks curve in projective coordinates (X:Y:Z).
 */
typedef struct
{
    qsc_fe448 x; /*!< [qsc_fe448] The X-coordinate. */
    qsc_fe448 y; /*!< [qsc_fe448] The Y-coordinate. */
    qsc_fe448 z; /*!< [qsc_fe448] The Z-coordinate. */
} qsc_ge448_p2;

/*!
 * \struct qsc_ge448_p3
 * \brief Extended projective coordinate representation.
 *
 * Represents a point on the Ed448-Goldilocks curve in extended coordinates (X:Y:Z:T),
 * where T is an auxiliary coordinate satisfying T = XY/Z.
 */
typedef struct
{
    qsc_fe448 x; /*!< [qsc_fe448] The X-coordinate. */
    qsc_fe448 y; /*!< [qsc_fe448] The Y-coordinate. */
    qsc_fe448 z; /*!< [qsc_fe448] The Z-coordinate. */
    qsc_fe448 t; /*!< [qsc_fe448] The T-coordinate. */
} qsc_ge448_p3;

/*!
 * \struct qsc_ge448_p1p1
 * \brief Intermediate coordinate representation.
 *
 * Used as an intermediate format during point addition and doubling operations.
 */
typedef struct
{
    qsc_fe448 x; /*!< [qsc_fe448] The X-coordinate. */
    qsc_fe448 y; /*!< [qsc_fe448] The Y-coordinate. */
    qsc_fe448 z; /*!< [qsc_fe448] The Z-coordinate. */
    qsc_fe448 t; /*!< [qsc_fe448] The T-coordinate. */
} qsc_ge448_p1p1;

/*!
 * \struct qsc_ge448_precomp
 * \brief Precomputed point representation.
 *
 * Stores precomputed values (y+x, y-x, and xy*2d) to accelerate scalar multiplication.
 */
typedef struct
{
    qsc_fe448 yplusx;  /*!< [qsc_fe448] The sum of Y and X coordinates. */
    qsc_fe448 yminusx; /*!< [qsc_fe448] The difference of Y and X coordinates. */
    qsc_fe448 xy2d;    /*!< [qsc_fe448] The product of X and Y, multiplied by 2d. */
} qsc_ge448_precomp;

/*!
 * \struct qsc_ge448_cached
 * \brief Cached point representation.
 *
 * Used to cache computed values during point addition for efficiency.
 */
typedef struct
{
    qsc_fe448 yplusx;  /*!< [qsc_fe448] The sum of Y and X coordinates. */
    qsc_fe448 yminusx; /*!< [qsc_fe448] The difference of Y and X coordinates. */
    qsc_fe448 z;       /*!< [qsc_fe448] The Z-coordinate. */
    qsc_fe448 t2d;     /*!< [qsc_fe448] The T-coordinate multiplied by 2d. */
} qsc_ge448_cached;

/* ------------------------------------------------------------------ */
/* Field element arithmetic                                            */
/* ------------------------------------------------------------------ */

/**
 * \brief Set a field element to zero.
 *
 * \param h: [qsc_fe448] The field element to zero.
 */
void qsc_fe448_0(qsc_fe448 h);

/**
 * \brief Set a field element to one.
 *
 * \param h: [qsc_fe448] The field element to set to one.
 */
void qsc_fe448_1(qsc_fe448 h);

/**
 * \brief Copy a field element.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] Source field element.
 */
void qsc_fe448_copy(qsc_fe448 h, const qsc_fe448 f);

/**
 * \brief Add two field elements.
 *
 * Computes h = f + g.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] First addend.
 * \param g: [const qsc_fe448] Second addend.
 */
void qsc_fe448_add(qsc_fe448 h, const qsc_fe448 f, const qsc_fe448 g);

/**
 * \brief Subtract one field element from another.
 *
 * Computes h = f - g.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] Minuend.
 * \param g: [const qsc_fe448] Subtrahend.
 */
void qsc_fe448_sub(qsc_fe448 h, const qsc_fe448 f, const qsc_fe448 g);

/**
 * \brief Negate a field element.
 *
 * Computes h = -f.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] Field element to negate.
 */
void qsc_fe448_neg(qsc_fe448 h, const qsc_fe448 f);

/**
 * \brief Conditionally swap two field elements in constant time.
 *
 * \param f: [qsc_fe448] First field element; may be swapped.
 * \param g: [qsc_fe448] Second field element; may be swapped.
 * \param b: [uint32_t] Condition bit; if nonzero, f and g are swapped.
 */
void qsc_fe448_cswap(qsc_fe448 f, qsc_fe448 g, uint32_t b);

/**
 * \brief Conditionally move a field element in constant time.
 *
 * Conditionally moves g into f when b is set.
 *
 * \param f: [qsc_fe448] Destination field element; modified in place.
 * \param g: [const qsc_fe448] Source field element.
 * \param b: [uint32_t] Condition bit.
 */
void qsc_fe448_cmov(qsc_fe448 f, const qsc_fe448 g, uint32_t b);

/**
 * \brief Determine if a field element is negative.
 *
 * \param f: [const qsc_fe448] The field element to check.
 * \return [int32_t] Returns nonzero if f is negative; otherwise, zero.
 */
int32_t qsc_fe448_is_negative(const qsc_fe448 f);

/**
 * \brief Determine if a field element is zero.
 *
 * \param f: [const qsc_fe448] The field element to check.
 * \return [int32_t] Returns nonzero if f is zero; otherwise, zero.
 */
int32_t qsc_fe448_is_zero(const qsc_fe448 f);

/**
 * \brief Multiply two field elements.
 *
 * Computes h = f * g mod p where p = 2^448 - 2^224 - 1.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] First factor.
 * \param g: [const qsc_fe448] Second factor.
 */
void qsc_fe448_mul(qsc_fe448 h, const qsc_fe448 f, const qsc_fe448 g);

/**
 * \brief Multiply a field element by a 32-bit scalar.
 *
 * Computes h = f * n.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] Field element to be multiplied.
 * \param n: [uint32_t] Scalar multiplier.
 */
void qsc_fe448_mul32(qsc_fe448 h, const qsc_fe448 f, uint32_t n);

/**
 * \brief Square a field element.
 *
 * Computes h = f^2 mod p.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] Field element to square.
 */
void qsc_fe448_sq(qsc_fe448 h, const qsc_fe448 f);

/**
 * \brief Compute 2 * f^2.
 *
 * Computes h = 2 * f^2 mod p.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] Field element to square and double.
 */
void qsc_fe448_sq2(qsc_fe448 h, const qsc_fe448 f);

/**
 * \brief Convert a 56-byte little-endian array to a field element.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param s: [const uint8_t*] Source 56-byte array.
 */
void qsc_fe448_from_bytes(qsc_fe448 h, const uint8_t* s);

/**
 * \brief Reduce a field element modulo p = 2^448 - 2^224 - 1.
 *
 * \param h: [qsc_fe448] Destination field element.
 * \param f: [const qsc_fe448] Field element to reduce.
 */
void qsc_fe448_reduce(qsc_fe448 h, const qsc_fe448 f);

/**
 * \brief Convert a field element to a 56-byte little-endian array.
 *
 * \param s: [uint8_t*] Destination 56-byte array.
 * \param h: [const qsc_fe448] Field element to serialize.
 */
void qsc_fe448_to_bytes(uint8_t* s, const qsc_fe448 h);

/**
 * \brief Compute the multiplicative inverse of a field element.
 *
 * Computes out = z^(p-2) mod p using Fermat's little theorem.
 *
 * \param out: [qsc_fe448] Destination field element for the inverse.
 * \param z:   [const qsc_fe448] Field element to invert.
 */
void qsc_fe448_invert(qsc_fe448 out, const qsc_fe448 z);

/* ------------------------------------------------------------------ */
/* Group element operations                                            */
/* ------------------------------------------------------------------ */

/**
 * \brief Convert a point from P1P1 to P3 coordinates.
 *
 * \param r: [qsc_ge448_p3*] Output point in P3 coordinates.
 * \param p: [const qsc_ge448_p1p1*] Input point in P1P1 coordinates.
 */
void qsc_ge448_p1p1_to_p3(qsc_ge448_p3* r, const qsc_ge448_p1p1* p);

/**
 * \brief Convert a point from P1P1 to P2 coordinates.
 *
 * \param r: [qsc_ge448_p2*] Output point in P2 coordinates.
 * \param p: [const qsc_ge448_p1p1*] Input point in P1P1 coordinates.
 */
void qsc_ge448_p1p1_to_p2(qsc_ge448_p2* r, const qsc_ge448_p1p1* p);

/**
 * \brief Multiply the base point by a scalar.
 *
 * Computes h = a * B, where B is the Ed448-Goldilocks standard base point.
 *
 * \param h: [qsc_ge448_p3*] Output point in P3 coordinates.
 * \param a: [const uint8_t*] Pointer to a 57-byte scalar.
 */
void qsc_ge448_scalarmult_base(qsc_ge448_p3* h, const uint8_t* a);

/**
 * \brief Compress a point in P3 coordinates to a 57-byte representation.
 *
 * \param s: [uint8_t*] Output 57-byte array.
 * \param h: [const qsc_ge448_p3*] Input point in P3 coordinates.
 */
void qsc_ge448_p3_to_bytes(uint8_t* s, const qsc_ge448_p3* h);

/**
 * \brief Check if a compressed point is canonical.
 *
 * \param s: [const uint8_t*] Pointer to the 57-byte compressed representation.
 * \return [int32_t] Returns 1 if the point is canonical; 0 otherwise.
 */
int32_t qsc_ge448_is_canonical(const uint8_t* s);

/**
 * \brief Determine if a compressed point has small order.
 *
 * \param s: [const uint8_t[57]] The 57-byte compressed point.
 * \return [int32_t] Returns 1 if the point has small order; 0 otherwise.
 */
int32_t qsc_ge448_has_small_order(const uint8_t s[57U]);

/**
 * \brief Decode and conditionally negate a compressed point.
 *
 * Decodes a 57-byte compressed point into extended P3 coordinates and
 * conditionally negates the X-coordinate to enforce a canonical representation.
 *
 * \param h: [qsc_ge448_p3*] Output point in P3 coordinates.
 * \param s: [const uint8_t*] Input 57-byte compressed point.
 * \return [int32_t] Returns 0 on success, or -1 if decoding fails.
 */
int32_t qsc_ge448_from_bytes_negate_vartime(qsc_ge448_p3* h, const uint8_t* s);

/**
 * \brief Convert a point from P3 coordinates to a cached representation.
 *
 * \param r: [qsc_ge448_cached*] Output cached point.
 * \param p: [const qsc_ge448_p3*] Input point in P3 coordinates.
 */
void qsc_ge448_p3_to_cached(qsc_ge448_cached* r, const qsc_ge448_p3* p);

/**
 * \brief Add a cached point to a P3 point.
 *
 * Computes r = p + q, storing the result in P1P1 representation.
 *
 * \param r: [qsc_ge448_p1p1*] Output point in P1P1 coordinates.
 * \param p: [const qsc_ge448_p3*] Input point in P3 coordinates.
 * \param q: [const qsc_ge448_cached*] Cached point.
 */
void qsc_ge448_add_cached(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_cached* q);

/**
 * \brief Subtract a cached point from a P3 point.
 *
 * Computes r = p - q, storing the result in P1P1 representation.
 *
 * \param r: [qsc_ge448_p1p1*] Output point in P1P1 coordinates.
 * \param p: [const qsc_ge448_p3*] Input point in P3 coordinates.
 * \param q: [const qsc_ge448_cached*] Cached point.
 */
void qsc_ge448_sub_cached(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_cached* q);

/**
 * \brief Add a precomputed point to a P3 point.
 *
 * Computes r = p + q, storing the result in P1P1 representation.
 *
 * \param r: [qsc_ge448_p1p1*] Output point in P1P1 coordinates.
 * \param p: [const qsc_ge448_p3*] Input point in P3 coordinates.
 * \param q: [const qsc_ge448_precomp*] Precomputed point.
 */
void qsc_ge448_add_precomp(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_precomp* q);

/**
 * \brief Subtract a precomputed point from a P3 point.
 *
 * Computes r = p - q, storing the result in P1P1 representation.
 *
 * \param r: [qsc_ge448_p1p1*] Output point in P1P1 coordinates.
 * \param p: [const qsc_ge448_p3*] Input point in P3 coordinates.
 * \param q: [const qsc_ge448_precomp*] Precomputed point.
 */
void qsc_ge448_sub_precomp(qsc_ge448_p1p1* r, const qsc_ge448_p3* p, const qsc_ge448_precomp* q);

/**
 * \brief Compute a double scalar multiplication (variable-time).
 *
 * Computes r = a * A + b * B, where B is the base point and A is an arbitrary point.
 *
 * \param r: [qsc_ge448_p2*] Output point in P2 coordinates.
 * \param a: [const uint8_t*] Scalar for point A.
 * \param A: [const qsc_ge448_p3*] Point A in P3 coordinates.
 * \param b: [const uint8_t*] Scalar for the base point.
 */
void qsc_ge448_double_scalarmult_vartime(qsc_ge448_p2* r, const uint8_t* a,
    const qsc_ge448_p3* A, const uint8_t* b);

/**
 * \brief Compress a point in P2 coordinates to a 57-byte representation.
 *
 * \param s: [uint8_t*] Output 57-byte array.
 * \param h: [const qsc_ge448_p2*] Input point in P2 coordinates.
 */
void qsc_ge448_to_bytes(uint8_t* s, const qsc_ge448_p2* h);

/* ------------------------------------------------------------------ */
/* Scalar arithmetic                                                   */
/* ------------------------------------------------------------------ */

/**
 * \brief Clamp a secret scalar for X448/Ed448.
 *
 * Clears the two low-order bits and sets the high bit of byte 55,
 * per RFC 7748 / RFC 8032.
 *
 * \param k: [uint8_t*] Pointer to the 57-byte scalar to be clamped.
 */
void qsc_sc448_clamp(uint8_t* k);

/**
 * \brief Check if a compressed point has small order (Ed448).
 *
 * \param s: [const uint8_t[57]] The 57-byte compressed point.
 * \return [int32_t] Returns non-zero if the point has small order, 0 otherwise.
 */
int32_t qsc_ed448_small_order(const uint8_t s[57U]);

/**
 * \brief Check if a scalar is canonical (less than the group order l).
 *
 * \param s: [const uint8_t[57]] Pointer to the 57-byte scalar.
 * \return [int32_t] Returns non-zero if the scalar is canonical, 0 otherwise.
 */
int32_t qsc_sc448_is_canonical(const uint8_t s[57U]);

/**
 * \brief Compute s = (a * b + c) mod l for Ed448 scalars.
 *
 * \param s: [uint8_t[57]] Output scalar.
 * \param a: [const uint8_t[57]] First scalar operand.
 * \param b: [const uint8_t[57]] Second scalar operand.
 * \param c: [const uint8_t[57]] Scalar addend.
 */
void qsc_sc448_muladd(uint8_t s[57U], const uint8_t a[57U], const uint8_t b[57U],
    const uint8_t c[57U]);

/**
 * \brief Reduce a 114-byte scalar modulo the Ed448 group order l.
 *
 * \param s: [uint8_t*] A pointer to a 114-byte array representing the scalar.
 */
void qsc_sc448_reduce(uint8_t s[114U]);

/**
 * \brief Constant-time comparison of two byte arrays.
 *
 * \param x: [const uint8_t*] Pointer to the first byte array.
 * \param y: [const uint8_t*] Pointer to the second byte array.
 * \param n: [size_t]          Number of bytes to compare.
 * \return [int32_t] Returns 0 if equal; -1 if they differ.
 */
int32_t qsc_sc448_verify(const uint8_t* x, const uint8_t* y, size_t n);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond NO_DOCUMENT */

#endif
