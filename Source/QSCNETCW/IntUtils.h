/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation
 * are proprietary to QRCS and its authorized licensors and are protected under
 * applicable U.S. and international copyright, patent, and trade secret laws.
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

#ifndef QSCNETCW_INTUTILS_H
#define QSCNETCW_INTUTILS_H

#include "Common.h"
#include "..\QSC\intutils.h"

namespace QSCNETCW
{
    /// <summary>
    /// Managed wrapper for the intutils.h functions, providing a set of integer manipulation,
    /// comparison, and conversion operations for .NET applications.
    /// </summary>
    public ref class IntUtils abstract sealed
    {
    public:

        /// <summary>
        /// Compares two arrays of bytes for equality (non-constant time).
        /// </summary>
        /// <param name="a">The first array.</param>
        /// <param name="b">The second array.</param>
        /// <param name="length">The number of bytes to compare.</param>
        /// <returns>True if arrays are equal, otherwise false.</returns>
        static bool AreEqual8(array<Byte>^ a, array<Byte>^ b, size_t length);

        /// <summary>
        /// Converts an 8-bit array to a 16-bit big-endian integer.
        /// </summary>
        /// <param name="input">The source array, at least 2 bytes long.</param>
        /// <returns>The 16-bit big-endian integer.</returns>
        static UInt16 BE8To16(array<Byte>^ input);

        /// <summary>
        /// Converts an 8-bit array to a 32-bit big-endian integer.
        /// </summary>
        /// <param name="input">The source array, at least 4 bytes long.</param>
        /// <returns>The 32-bit big-endian integer.</returns>
        static UInt32 BE8To32(array<Byte>^ input);

        /// <summary>
        /// Converts an 8-bit array to a 64-bit big-endian integer.
        /// </summary>
        /// <param name="input">The source array, at least 8 bytes long.</param>
        /// <returns>The 64-bit big-endian integer.</returns>
        static UInt64 BE8To64(array<Byte>^ input);

        /// <summary>
        /// Converts a 16-bit integer to a big-endian array (2 bytes).
        /// </summary>
        /// <param name="output">The destination array (at least 2 bytes).</param>
        /// <param name="value">The 16-bit integer.</param>
        /// <returns>True if operation succeeds, otherwise false.</returns>
        static bool BE16To8(array<Byte>^ output, UInt16 value);

        /// <summary>
        /// Converts a 32-bit integer to a big-endian array (4 bytes).
        /// </summary>
        static bool BE32To8(array<Byte>^ output, UInt32 value);

        /// <summary>
        /// Converts a 64-bit integer to a big-endian array (8 bytes).
        /// </summary>
        static bool BE64To8(array<Byte>^ output, UInt64 value);

        /// <summary>
        /// Increments an array treated as a big-endian integer.
        /// </summary>
        /// <param name="output">The array to increment.</param>
        /// <param name="length">The length of the array.</param>
        static bool BE8Increment(array<Byte>^ output, size_t length);

        /// <summary>
        /// Reverses bits in the integer x up to a specified number of bits.
        /// </summary>
        static size_t BitReverse(size_t x, UInt32 bits);

        /// <summary>
        /// Reverses all bits of a 64-bit integer.
        /// </summary>
        static UInt64 BitReverseU64(UInt64 x);

        /// <summary>
        /// Reverses all bits of a 32-bit integer.
        /// </summary>
        static UInt32 BitReverseU32(UInt32 x);

        /// <summary>
        /// Reverses all bits of a 16-bit integer.
        /// </summary>
        static UInt16 BitReverseU16(UInt16 x);

        /// <summary>
        /// Computes the absolute value of a double.
        /// </summary>
        static double CalculateAbs(double a);

        /// <summary>
        /// Computes the exponential function e^x for a double x.
        /// </summary>
        static double CalculateExp(double x);

        /// <summary>
        /// Equivalent to the C library's fabs function (absolute value of a double).
        /// </summary>
        static double CalculateFabs(double x);

        /// <summary>
        /// Computes the natural log of x without using math.h.
        /// </summary>
        static double CalculateLog(double x);

        /// <summary>
        /// Computes the square root of x using an iterative method.
        /// </summary>
        static double CalculateSqrt(double x);

        /// <summary>
        /// Sets count bytes of an 8-bit array to zero.
        /// </summary>
        static bool Clear8(array<Byte>^ a, size_t count);

        /// <summary>
        /// Sets count elements of a 16-bit array to zero.
        /// </summary>
        static bool Clear16(array<UInt16>^ a, size_t count);

        /// <summary>
        /// Sets count elements of a 32-bit array to zero.
        /// </summary>
        static bool Clear32(array<UInt32>^ a, size_t count);

        /// <summary>
        /// Sets count elements of a 64-bit array to zero.
        /// </summary>
        static bool Clear64(array<UInt64>^ a, size_t count);

        /// <summary>
        /// Performs a constant-time conditional move on two byte arrays:
        /// if cond is 1, copy source to dest, otherwise do nothing.
        /// </summary>
        static bool Cmov(array<Byte>^ dest, array<Byte>^ source, size_t length, Byte cond);

        /// <summary>
        /// Expands a mask in constant time.
        /// </summary>
        static size_t ExpandMask(size_t x);

        /// <summary>
        /// Checks if two size_t integers x and y are equal in a constant-time manner.
        /// </summary>
        static bool IntsAreEqual(size_t x, size_t y);

        /// <summary>
        /// Checks if x is greater than or equal to y in constant time.
        /// </summary>
        static bool IsGte(size_t x, size_t y);

        /// <summary>
        /// Converts a hex string into a byte array of a specified length.
        /// </summary>
        static bool HexToBin(String^ hexstr, array<Byte>^ output, size_t outlen);

        /// <summary>
        /// Converts a byte array into a hex string.
        /// </summary>
        static bool BinToHex(array<Byte>^ input, String^% hexstr);

        /// <summary>
        /// Increments a byte array treated as a little-endian integer.
        /// </summary>
        static bool LE8Increment(array<Byte>^ output, size_t length);

        /// <summary>
        /// Byte-swaps a set of 32-bit integers (AVX only).
        /// </summary>
        static bool Bswap32(array<UInt32>^ dest, array<UInt32>^ source, size_t length);

        /// <summary>
        /// Byte-swaps a set of 64-bit integers (AVX only).
        /// </summary>
        static bool Bswap64(array<UInt64>^ dest, array<UInt64>^ source, size_t length);

        /// <summary>
        /// Increments the low 64 bits of a 128-bit vector (little-endian) by one (AVX).
        /// </summary>
        static bool LeIncrementX128(IntPtr counterPtr);

        /// <summary>
        /// Increments the low 64 bits of a 512-bit vector (little-endian) by one (AVX512).
        /// </summary>
        static bool LeIncrementX512(IntPtr counterPtr);

        /// <summary>
        /// Reverses bytes of a 128-bit vector (AVX).
        /// </summary>
        static bool ReverseBytesX128(IntPtr inputPtr, IntPtr outputPtr);

        /// <summary>
        /// Reverses bytes of a 512-bit vector (AVX512).
        /// </summary>
        static bool ReverseBytesX512(IntPtr inputPtr, IntPtr outputPtr);

        /// <summary>
        /// Converts an 8-bit array to a 16-bit little-endian integer.
        /// </summary>
        static UInt16 LE8To16(array<Byte>^ input);

        /// <summary>
        /// Converts an 8-bit array to a 32-bit little-endian integer.
        /// </summary>
        static UInt32 LE8To32(array<Byte>^ input);

        /// <summary>
        /// Converts an 8-bit array to a 64-bit little-endian integer.
        /// </summary>
        static UInt64 LE8To64(array<Byte>^ input);

        /// <summary>
        /// Converts a 16-bit integer to a little-endian array (2 bytes).
        /// </summary>
        static bool LE16To8(array<Byte>^ output, UInt16 value);

        /// <summary>
        /// Converts a 32-bit integer to a little-endian array (4 bytes).
        /// </summary>
        static bool LE32To8(array<Byte>^ output, UInt32 value);

        /// <summary>
        /// Converts a 64-bit integer to a little-endian array (8 bytes).
        /// </summary>
        static bool LE64To8(array<Byte>^ output, UInt64 value);

        /// <summary>
        /// Returns the maximum of two size_t integers.
        /// </summary>
        static size_t Max(size_t a, size_t b);

        /// <summary>
        /// Returns the minimum of two size_t integers.
        /// </summary>
        static size_t Min(size_t a, size_t b);

        /// <summary>
        /// Counts the number of bits set in a 32-bit unsigned integer.
        /// </summary>
        static UInt32 Popcount32(UInt32 v);

        /// <summary>
        /// Rotates a 32-bit integer value left by shift bits.
        /// </summary>
        static UInt32 Rotl32(UInt32 value, size_t shift);

        /// <summary>
        /// Rotates a 64-bit integer value left by shift bits.
        /// </summary>
        static UInt64 Rotl64(UInt64 value, size_t shift);

        /// <summary>
        /// Rotates a 32-bit integer value right by shift bits.
        /// </summary>
        static UInt32 Rotr32(UInt32 value, size_t shift);

        /// <summary>
        /// Rotates a 64-bit integer value right by shift bits.
        /// </summary>
        static UInt64 Rotr64(UInt64 value, size_t shift);

        /// <summary>
        /// Compares two byte arrays in constant time. Returns 0 if equal, nonzero otherwise.
        /// </summary>
        static int Verify(array<Byte>^ a, array<Byte>^ b, size_t length);
    };
}

#endif
