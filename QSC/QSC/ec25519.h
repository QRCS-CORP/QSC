/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_EC25519_H
#define QSC_EC25519_H

#include "common.h"

/**
 * \file ec25519.h
 * \brief Elliptic Curve (Ed25519) and Field Arithmetic Implementation.
 *
 * \details
 * This header defines the data structures and functions for performing operations on the Ed25519 elliptic curve,
 * which is widely used for digital signatures and key exchange protocols. It provides several coordinate representations for 
 * curve points, including:
 *  - **P2:** Projective coordinates (X:Y:Z)
 *  - **P3:** Extended coordinates (X:Y:Z:T)
 *  - **P1P1:** Intermediate coordinates used in addition formulas
 *  - **Precomputed:** A structure for precomputed values to speed up base point operations
 *  - **Cached:** A structure for caching repeated computations
 *
 * In addition, this header defines functions for field arithmetic in the finite field defined by 2^255 - 19. Field elements 
 * are represented as arrays of 10 int32_t values in a radix-2^25.5 format. The field arithmetic functions include:
 *  - Initialization routines to set field elements to zero or one.
 *  - Copy, addition, subtraction, and negation operations.
 *  - Constant-time conditional swap and conditional move operations.
 *  - Multiplication and squaring routines.
 *  - Conversion routines between a 32-byte little-endian representation and the field element.
 *  - Exponentiation and inversion routines.
 *
 * These operations form the foundation of the Ed25519 digital signature scheme and key exchange protocols and are implemented
 * to be constant-time to mitigate timing attacks.
 *
 * \section ec25519_links Reference Links:
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Official Ed25519 Documentation</a>
 *  - <a href="https://cr.yp.to/ecdh.html">Curve25519 ECDH</a>
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Ed25519 Field Operations</a>
 */

/*!
\def EC25519_SEED_SIZE
* \brief The ecc seed cize
*/
#define EC25519_SEED_SIZE 32ULL

/*!
\def EC25519_SIGNATURE_SIZE
* \brief The ecc signature size
*/
#define EC25519_SIGNATURE_SIZE 64ULL

/*!
\def EC25519_PUBLICKEY_SIZE
* \brief The ecc public key size
*/
#define EC25519_PUBLICKEY_SIZE 32ULL

/*!
\def EC25519_PRIVATEKEY_SIZE
* \brief The ecc private key size
*/
#define EC25519_PRIVATEKEY_SIZE 64ULL

/*!
\def EC25519_CURVE_SIZE
* \brief The ecc curve size
*/
#define EC25519_CURVE_SIZE 32ULL

/*!
\typedef fe25519
* \brief The ecc fe25519 polynomial
*/
typedef QSC_SIMD_ALIGN int32_t fe25519[10];

/*! 
 * \struct ge25519_p2
 * \brief Projective coordinate representation.
 *
 * Represents a point on the Ed25519 curve in projective coordinates (X:Y:Z).
 */
typedef struct 
{
    fe25519 x; /*!< [fe25519] The X-coordinate. */
    fe25519 y; /*!< [fe25519] The Y-coordinate. */
    fe25519 z; /*!< [fe25519] The Z-coordinate. */
} ge25519_p2;

/*! 
 * \struct ge25519_p3
 * \brief Extended projective coordinate representation.
 *
 * Represents a point on the Ed25519 curve in extended coordinates (X:Y:Z:T),
 * where T is an auxiliary coordinate satisfying T = XY/Z.
 */
typedef struct 
{
    fe25519 x; /*!< [fe25519] The X-coordinate. */
    fe25519 y; /*!< [fe25519] The Y-coordinate. */
    fe25519 z; /*!< [fe25519] The Z-coordinate. */
    fe25519 t; /*!< [fe25519] The T-coordinate. */
} ge25519_p3;

/*! 
 * \struct ge25519_p1p1
 * \brief Intermediate coordinate representation.
 *
 * Used as an intermediate format during point addition and doubling operations.
 */
typedef struct 
{
    fe25519 x; /*!< [fe25519] The X-coordinate. */
    fe25519 y; /*!< [fe25519] The Y-coordinate. */
    fe25519 z; /*!< [fe25519] The Z-coordinate. */
    fe25519 t; /*!< [fe25519] The T-coordinate. */
} ge25519_p1p1;

/*! 
 * \struct ge25519_precomp
 * \brief Precomputed point representation.
 *
 * Stores precomputed values (y+x, y-x, and xy*2d) to accelerate scalar multiplication.
 */
typedef struct 
{
    fe25519 yplusx;  /*!< [fe25519] The sum of Y and X coordinates. */
    fe25519 yminusx; /*!< [fe25519] The difference of Y and X coordinates. */
    fe25519 xy2d;    /*!< [fe25519] The product of X and Y, multiplied by 2d. */
} ge25519_precomp;

/*! 
 * \struct ge25519_cached
 * \brief Cached point representation.
 *
 * Used to cache computed values during point addition for efficiency.
 */
typedef struct 
{
    fe25519 yplusx; /*!< [fe25519] The sum of Y and X coordinates. */
    fe25519 yminusx;/*!< [fe25519] The difference of Y and X coordinates. */
    fe25519 z;      /*!< [fe25519] The Z-coordinate. */
    fe25519 t2d;    /*!< [fe25519] The T-coordinate multiplied by 2d. */
} ge25519_cached;

/**
 * \brief Set a field element to zero.
 *
 * Sets all limbs of the field element \a h to 0.
 *
 * \param h: [fe25519] The field element to zero.
 */
void fe25519_0(fe25519 h);

/**
 * \brief Set a field element to one.
 *
 * Initializes the field element \a h to the multiplicative identity (1).
 *
 * \param h: [fe25519] The field element to set to one.
 */
void fe25519_1(fe25519 h);

/**
 * \brief Copy a field element.
 *
 * Copies the field element \a f into \a h.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] Source field element.
 */
void fe25519_copy(fe25519 h, const fe25519 f);

/**
 * \brief Add two field elements.
 *
 * Computes the sum \a h = \a f + \a g.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] First addend.
 * \param g: [const fe25519] Second addend.
 */
void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g);

/**
 * \brief Conditionally swap two field elements in constant time.
 *
 * Conditionally swaps the field elements \a f and \a g if the condition bit \a b is nonzero.
 * This function operates in constant time to prevent timing attacks.
 *
 * \param f: [fe25519] First field element; may be swapped.
 * \param g: [fe25519] Second field element; may be swapped.
 * \param b: [uint32_t] Condition bit; if nonzero, \a f and \a g are swapped.
 */
void fe25519_cswap(fe25519 f, fe25519 g, uint32_t b);

/**
 * \brief Subtract one field element from another.
 *
 * Computes the difference \a h = \a f - \a g.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] Minuend field element.
 * \param g: [const fe25519] Subtrahend field element.
 *
 * \remarks
 * Preconditions: \a f and \a g are bounded by specific constants.
 * Postconditions: \a h is bounded by specified limits.
 */
void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g);

/**
 * \brief Negate a field element.
 *
 * Computes the negation \a h = -\a f.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] Field element to negate.
 */
void fe25519_neg(fe25519 h, const fe25519 f);

/**
 * \brief Conditionally move a field element in constant time.
 *
 * Conditionally moves the field element \a g into \a f if the condition bit \a b is set.
 * This operation is performed in constant time.
 *
 * \param f: [fe25519] Destination field element; modified in place.
 * \param g: [const fe25519] Source field element.
 * \param b: [uint32_t] Condition bit; if set, \a g is moved into \a f.
 */
void fe25519_cmov(fe25519 f, const fe25519 g, uint32_t b);

/**
 * \brief Determine if a field element is negative.
 *
 * Converts the field element \a f to its 32-byte representation and returns the least significant bit.
 *
 * \param f: [const fe25519] The field element to check.
 *
 * \return [int32_t] Returns nonzero if \a f is negative; otherwise, zero.
 */
int32_t fe25519_isnegative(const fe25519 f);

/**
 * \brief Determine if a field element is zero.
 *
 * Converts the field element \a f to its 32-byte representation and checks if all bytes are zero.
 *
 * \param f: [const fe25519] The field element to check.
 *
 * \return [int32_t] Returns nonzero if \a f is zero; otherwise, zero.
 */
int32_t fe25519_iszero(const fe25519 f);

/**
 * \brief Multiply two field elements.
 *
 * Computes the product \a h = \a f * \a g.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] First factor.
 * \param g: [const fe25519] Second factor.
 */
void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g);

/**
 * \brief Multiply a field element by a scalar.
 *
 * Computes \a h = \a f * \a n, where \a n is a 32-bit scalar.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] Field element to be multiplied.
 * \param n: [uint32_t] Scalar multiplier.
 */
void fe25519_mul32(fe25519 h, const fe25519 f, uint32_t n);

/**
 * \brief Square a field element.
 *
 * Computes the square \a h = \a f^2.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] Field element to square.
 */
void fe25519_sq(fe25519 h, const fe25519 f);

/**
 * \brief Compute 2 * f^2.
 *
 * Computes \a h = 2 * (\a f^2).
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] Field element to square and double.
 */
void fe25519_sq2(fe25519 h, const fe25519 f);

/**
 * \brief Convert a 32-byte array to a field element.
 *
 * Interprets a 32-byte little-endian array \a s as a field element and stores it in \a h.
 *
 * \param h: [fe25519] Destination field element.
 * \param s: [const uint8_t*] Source byte array.
 */
void fe25519_frombytes(fe25519 h, const uint8_t* s);

/**
 * \brief Reduce a field element modulo 2^255 - 19.
 *
 * Computes the canonical representative of the field element \a f modulo (2^255 - 19)
 * and stores the result in \a h.
 *
 * \param h: [fe25519] Destination field element.
 * \param f: [const fe25519] Field element to reduce.
 */
void fe25519_reduce(fe25519 h, const fe25519 f);

/**
 * \brief Convert a field element to a 32-byte array.
 *
 * Serializes the field element \a h into a 32-byte little-endian representation stored in \a s.
 *
 * \param s: [uint8_t*] Destination byte array.
 * \param h: [const fe25519] Field element to serialize.
 */
void fe25519_tobytes(uint8_t* s, const fe25519 h);

/**
 * \brief Compute the multiplicative inverse of a field element.
 *
 * Computes the multiplicative inverse of \a z in the field and stores the result in \a out.
 * If \a z is zero, the result is undefined.
 *
 * \param out: [fe25519] Destination field element for the inverse.
 * \param z: [const fe25519] Field element to invert.
 */
void fe25519_invert(fe25519 out, const fe25519 z);

/**
 * \brief Convert a point from P1P1 to P3 coordinates.
 *
 * Converts a point in the intermediate P1P1 coordinate system to the extended P3 representation.
 *
 * \param r [ge25519_p3*] Pointer to the output point in P3 coordinates.
 * \param p [const ge25519_p1p1*] Pointer to the input point in P1P1 coordinates.
 */
void ge25519_p1p1_to_p3(ge25519_p3* r, const ge25519_p1p1* p);

/**
 * \brief Convert a point from P1P1 to P2 coordinates.
 *
 * Converts a point in the intermediate P1P1 coordinate system to the projective P2 representation.
 *
 * \param r [ge25519_p2*] Pointer to the output point in P2 coordinates.
 * \param p [const ge25519_p1p1*] Pointer to the input point in P1P1 coordinates.
 */
void ge25519_p1p1_to_p2(ge25519_p2* r, const ge25519_p1p1* p);

/**
 * \brief Multiply the base point by a scalar.
 *
 * Computes the scalar multiplication h = a * BasePoint, where a is a 32-byte scalar.
 *
 * \param h [ge25519_p3*] Pointer to the output point in P3 coordinates.
 * \param a [const uint8_t*] Pointer to a 32-byte scalar.
 */
void ge25519_scalarmult_base(ge25519_p3* h, const uint8_t* a);

/**
 * \brief Compress a point in P3 coordinates to a 32-byte representation.
 *
 * Converts a point in extended P3 coordinates to its compressed 32-byte form.
 *
 * \param s [uint8_t*] Pointer to the output 32-byte array.
 * \param h [const ge25519_p3*] Pointer to the input point in P3 coordinates.
 */
void ge25519_p3_tobytes(uint8_t* s, const ge25519_p3* h);

/**
 * \brief Check if a compressed point is canonical.
 *
 * Verifies whether the given 32-byte compressed point is in canonical form.
 *
 * \param s [const uint8_t*] Pointer to the 32-byte compressed representation.
 * \return [int32_t] Returns 1 if the point is canonical; 0 otherwise.
 */
int32_t ge25519_is_canonical(const uint8_t* s);

/**
 * \brief Determine if a compressed point has small order.
 *
 * Checks whether the given 32-byte compressed point has small order, which is considered insecure.
 *
 * \param s [const uint8_t[32]] The 32-byte compressed point.
 * \return [int32_t] Returns 1 if the point has small order; 0 otherwise.
 */
int32_t ge25519_has_small_order(const uint8_t s[32]);

/**
 * \brief Decode and conditionally negate a compressed point.
 *
 * Decodes a 32-byte compressed point into extended P3 coordinates and conditionally negates the X-coordinate
 * to enforce a canonical representation.
 *
 * \param h [ge25519_p3*] Pointer to the output point in P3 coordinates.
 * \param s [const uint8_t*] Pointer to the 32-byte compressed point.
 * \return [int32_t] Returns 0 on success, or -1 if the decoding fails.
 */
int32_t ge25519_frombytes_negate_vartime(ge25519_p3* h, const uint8_t* s);

/**
 * \brief Convert a point from P3 coordinates to a cached representation.
 *
 * Converts a point in extended P3 coordinates into a cached format to accelerate point addition.
 *
 * \param r [ge25519_cached*] Pointer to the output cached point.
 * \param p [const ge25519_p3*] Pointer to the input point in P3 coordinates.
 */
void ge25519_p3_to_cached(ge25519_cached* r, const ge25519_p3* p);

/**
 * \brief Add a cached point to a point.
 *
 * Computes the sum of a point in P3 coordinates and a cached point, storing the result in the P1P1 representation.
 *
 * \param r [ge25519_p1p1*] Pointer to the output point in P1P1 coordinates.
 * \param p [const ge25519_p3*] Pointer to the input point in P3 coordinates.
 * \param q [const ge25519_cached*] Pointer to the cached point.
 */
void ge25519_add_cached(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_cached* q);

/**
 * \brief Subtract a precomputed point from a point.
 *
 * Computes the subtraction r = p - q, where p is in P3 coordinates and q is in precomputed form,
 * and stores the result in the P1P1 representation.
 *
 * \param r [ge25519_p1p1*] Pointer to the output point in P1P1 coordinates.
 * \param p [const ge25519_p3*] Pointer to the input point in P3 coordinates.
 * \param q [const ge25519_precomp*] Pointer to the precomputed point.
 */
void ge25519_sub_precomp(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_precomp* q);

/**
 * \brief Compute a double scalar multiplication.
 *
 * Computes the expression r = a * A + b * B, where A is an arbitrary point and B is the base point.
 * The result is returned in the P2 coordinate representation using a variable-time algorithm.
 *
 * \param r [ge25519_p2*] Pointer to the output point in P2 coordinates.
 * \param a [const uint8_t*] Pointer to the scalar for point A.
 * \param A [const ge25519_p3*] Pointer to the point A in P3 coordinates.
 * \param b [const uint8_t*] Pointer to the scalar for the base point.
 */
void ge25519_double_scalarmult_vartime(ge25519_p2* r, const uint8_t* a, const ge25519_p3* A, const uint8_t* b);

/**
 * \brief Subtract a cached point from a point.
 *
 * Computes the difference r = p - q, where p is in P3 coordinates and q is in cached form,
 * storing the result in the P1P1 representation.
 *
 * \param r [ge25519_p1p1*] Pointer to the output point in P1P1 coordinates.
 * \param p [const ge25519_p3*] Pointer to the input point in P3 coordinates.
 * \param q [const ge25519_cached*] Pointer to the cached point.
 */
void ge25519_sub_cached(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_cached* q);

/**
 * \brief Compress a point in P2 coordinates to a 32-byte representation.
 *
 * Converts a point in the P2 coordinate representation to its compressed 32-byte form.
 *
 * \param s [uint8_t*] Pointer to the output 32-byte array.
 * \param h [const ge25519_p2*] Pointer to the input point in P2 coordinates.
 */
void ge25519_tobytes(uint8_t* s, const ge25519_p2* h);

/**
 * \brief Clamp a secret scalar.
 *
 * Clamps the 32-byte secret scalar to ensure it conforms to the Ed25519 key format.
 *
 * \param k [uint8_t*] Pointer to the 32-byte scalar to be clamped.
 */
void sc25519_clamp(uint8_t* k);

/**
 * \brief Check if a compressed point has small order.
 *
 * Determines whether the given 32-byte compressed point is of small order,
 * which is insecure for cryptographic operations.
 *
 * \param s [const uint8_t[32]] The 32-byte compressed point.
 * \return [int32_t] Returns non-zero if the point has small order, 0 otherwise.
 */
int32_t ed25519_small_order(const uint8_t s[32]);

/**
 * \brief Check if a scalar is canonical.
 *
 * Verifies that the given 32-byte scalar is in its canonical form.
 *
 * \param s [const uint8_t[32]] Pointer to the 32-byte scalar.
 * \return [int32_t] Returns non-zero if the scalar is canonical, 0 otherwise.
 */
int32_t sc25519_is_canonical(const uint8_t s[32]);

/**
 * \brief Compute s = a * b + c for scalars.
 *
 * Computes the scalar multiplication of two 32-byte scalars a and b, adds a third scalar c,
 * and stores the result in s.
 *
 * \param s [uint8_t[32]] Output scalar.
 * \param a [const uint8_t[32]] The first scalar operand.
 * \param b [const uint8_t[32]] The second scalar operand.
 * \param c [const uint8_t[32]] The scalar addend.
 */
void sc25519_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]);

/**
 * \brief Reduce a 64-byte scalar modulo 2^255 - 19.
 *
 * This function takes a 64-byte little-endian representation of an integer and
 * reduces it modulo the prime 2^255 - 19, producing a canonical form suitable
 * for use as a field element in the Ed25519 elliptic curve. The reduction is
 * performed by splitting the input into 24 limbs (each containing up to 21 or 26 bits),
 * then applying a series of multiplications, additions, subtractions, and carry propagations.
 *
 * The algorithm is carefully optimized to handle the non-uniform limb sizes and
 * ensures that the final output fits within the desired bit bounds for each limb.
 * The result is written back into the input array \p s, replacing its original contents.
 *
 * \param s [uint8_t*] A pointer to a 64-byte array representing the scalar to be reduced.
 */
void sc25519_reduce(uint8_t s[64]);

/**
 * \brief Performs a constant-time comparison of two byte arrays.
 *
 * This function compares two byte arrays, \a x and \a y, each of length \a n, in constant time.
 * It computes the bitwise XOR for each corresponding byte and accumulates the result using bitwise OR.
 * The final result is processed to return 0 if the arrays are identical, or -1 if any byte differs.
 *
 * \param x [const uint8_t*]  Pointer to the first byte array.
 * \param y [const uint8_t*]  Pointer to the second byte array.
 * \param n [size_t]          The number of bytes to compare.
 *
 * \return [int32_t] Returns 0 if all \a n bytes of \a x and \a y are equal; returns -1 if they differ.
 */
int32_t qsc_sc25519_verify(const uint8_t* x, const uint8_t* y, const size_t n);

#endif

