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

#ifndef QSCNETCW_MEMUTILS_H
#define QSCNETCW_MEMUTILS_H

#include "Common.h"
#include "..\QSC\memutils.h"

namespace QSCNETCW
{
    /// <summary>
    /// Managed wrapper for the memory utilities in memutils.h.
    /// </summary>
    public ref class MemUtils abstract sealed
    {
    public:

        /// <summary>
        /// Flush a cache line at the given address.
        /// </summary>
        static bool FlushCacheLine(IntPtr address);

        /// <summary>
        /// Prefetch memory to L1 cache.
        /// </summary>
        static bool PrefetchL1(array<Byte>^ data, size_t length);

        /// <summary>
        /// Prefetch memory to L2 cache.
        /// </summary>
        static bool PrefetchL2(array<Byte>^ data, size_t length);

        /// <summary>
        /// Prefetch memory to L3 cache.
        /// </summary>
        static bool PrefetchL3(array<Byte>^ data, size_t length);

        /// <summary>
        /// Allocate a block of memory (returning pointer as <see cref="IntPtr"/>).
        /// </summary>
        static IntPtr Malloc(size_t length);

        /// <summary>
        /// Reallocate a memory block to a new size.
        /// </summary>
        static IntPtr Realloc(IntPtr blockPtr, size_t length);

        /// <summary>
        /// Free a memory block created with Malloc.
        /// </summary>
        static void AllocFree(IntPtr blockPtr);

        /// <summary>
        /// Allocate an aligned block of memory.
        /// </summary>
        static IntPtr AlignedAlloc(int32_t alignment, size_t length);

        /// <summary>
        /// Reallocate an aligned memory block to a new size.
        /// </summary>
        static IntPtr AlignedRealloc(IntPtr blockPtr, size_t length);

        /// <summary>
        /// Free an aligned memory block.
        /// </summary>
        static void AlignedFree(IntPtr blockPtr);

        /// <summary>
        /// Clear (erase) a block of memory.
        /// </summary>
        static bool Clear(array<Byte>^ output, size_t length);

        /// <summary>
        /// Check if all array members are the same.
        /// </summary>
        static bool ArrayUniform(array<Byte>^ data, size_t length);

        /// <summary>
        /// Compare two arrays for equality.
        /// </summary>
        static bool AreEqual(array<Byte>^ a, array<Byte>^ b, size_t length);

        /// <summary>
        /// Compare two 16-byte arrays for equality.
        /// </summary>
        static bool AreEqual128(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Compare two 32-byte arrays for equality.
        /// </summary>
        static bool AreEqual256(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Compare two 64-byte arrays for equality.
        /// </summary>
        static bool AreEqual512(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Copy a block of memory from input to output.
        /// </summary>
        static bool Copy(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Move a block of memory, erasing the previous location.
        /// </summary>
        static bool Move(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Compare two big-endian 128-bit arrays (16 bytes) to check if A &gt; B.
        /// </summary>
        static bool GreaterThanBE128(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Compare two big-endian 256-bit arrays (32 bytes) to check if A &gt; B.
        /// </summary>
        static bool GreaterThanBE256(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Compare two big-endian 512-bit arrays (64 bytes) to check if A &gt; B.
        /// </summary>
        static bool GreaterThanBE512(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Compare two little-endian 128-bit arrays (16 bytes) to check if A &gt; B.
        /// </summary>
        static bool GreaterThanLE128(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Compare two little-endian 256-bit arrays (32 bytes) to check if A &gt; B.
        /// </summary>
        static bool GreaterThanLE256(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Compare two little-endian 512-bit arrays (64 bytes) to check if A &gt; B.
        /// </summary>
        static bool GreaterThanLE512(array<Byte>^ a, array<Byte>^ b);

        /// <summary>
        /// Securely erase a block of memory.
        /// </summary>
        static bool SecureErase(array<Byte>^ block, size_t length);

        /// <summary>
        /// Securely free a memory block allocated externally.
        /// </summary>
        static bool SecureFree(IntPtr blockPtr, size_t length);

        /// <summary>
        /// Allocate a secure block of memory and return a pointer.
        /// </summary>
        static IntPtr SecureMalloc(size_t length);

        /// <summary>
        /// Set a block of memory to a specific value.
        /// </summary>
        static bool SetValue(array<Byte>^ output, size_t length, Byte value);

        /// <summary>
        /// Bitwise XOR two blocks of memory.
        /// </summary>
        static bool Xor(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Bitwise XOR a block of memory with a single byte value.
        /// </summary>
        static bool Xorv(array<Byte>^ output, Byte value, size_t length);

        /// <summary>
        /// Check if an array is entirely zeroed.
        /// </summary>
        static bool Zeroed(array<Byte>^ data, size_t length);
    };
}

#endif
