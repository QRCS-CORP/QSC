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
 * Written by: John Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSCNETCW_SECRAND_H
#define QSCNETCW_SECRAND_H

#include "Common.h"
#include "..\QSC\secrand.h"

namespace QSCNETCW
{
    /// <summary>
    /// A non-static C++/CLI wrapper for the <c>secrand.h</c> module, which provides
    /// a global-based secure random generator. You must call <c>Initialize</c> before
    /// calling any <c>Next</c> or <c>Generate</c> methods.
    /// </summary>
    public ref class SecRand
    {
    public:
        /// <summary>
        /// Constructs an uninitialized SecRand instance. You must call <see cref="Initialize"/>
        /// before generating random data.
        /// </summary>
        SecRand();

        /// <summary>
        /// Destructor that disposes the global secrand state.
        /// </summary>
        ~SecRand();

        /// <summary>
        /// Finalizer that disposes the global secrand state if not already done.
        /// </summary>
        !SecRand();

        /// <summary>
        /// Initializes the global <c>secrand</c> state with the specified seed
        /// (32 or 64 bytes) and optional customization array.
        /// </summary>
        /// <param name="seed">The primary seed; must be 32 or 64 bytes in length.</param>
        /// <param name="seedLength">Number of bytes in <paramref name="seed"/>.</param>
        /// <param name="custom">Optional customization array. May be null or empty.</param>
        /// <param name="custLength">Number of bytes in <paramref name="custom"/>.</param>
        void Initialize(array<Byte>^ seed, size_t seedLength, array<Byte>^ custom, size_t custLength);

        /// <summary>
        /// Disposes the global secrand state, zeroizing any internal memory. The instance is invalid afterward.
        /// </summary>
        void Destroy();

        /// <summary>
        /// Generates random bytes into the specified <paramref name="output"/> array.
        /// You must have called <see cref="Initialize"/> before calling this method.
        /// </summary>
        /// <param name="output">
        /// The array to fill with random bytes.
        /// </param>
        /// <param name="length">
        /// Number of bytes to generate. Must not exceed <c>output->LongLength</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> if generation succeeds, <c>false</c> otherwise.
        /// </returns>
        bool Generate(array<Byte>^ output, size_t length);

        /// <summary>
        /// Returns a signed 8-bit random integer from the global secrand generator.
        /// </summary>
        SByte NextChar();

        /// <summary>
        /// Returns an unsigned 8-bit random integer.
        /// </summary>
        Byte NextUChar();

        /// <summary>
        /// Returns a random double-precision floating-point number in [0, 1).
        /// </summary>
        double NextDouble();

        /// <summary>
        /// Returns a signed 16-bit random integer.
        /// </summary>
        Int16 NextInt16();

        /// <summary>
        /// Returns a signed 16-bit random integer in [0, max].
        /// </summary>
        Int16 NextInt16Max(Int16 maximum);

        /// <summary>
        /// Returns a signed 16-bit random integer in [min, max].
        /// </summary>
        Int16 NextInt16MaxMin(Int16 maximum, Int16 minimum);

        /// <summary>
        /// Returns an unsigned 16-bit random integer.
        /// </summary>
        UInt16 NextUInt16();

        /// <summary>
        /// Returns an unsigned 16-bit random integer in [0, max].
        /// </summary>
        UInt16 NextUInt16Max(UInt16 maximum);

        /// <summary>
        /// Returns an unsigned 16-bit random integer in [min, max].
        /// </summary>
        UInt16 NextUInt16MaxMin(UInt16 maximum, UInt16 minimum);

        /// <summary>
        /// Returns a signed 32-bit random integer.
        /// </summary>
        Int32 NextInt32();

        /// <summary>
        /// Returns a signed 32-bit random integer in [0, max].
        /// </summary>
        Int32 NextInt32Max(Int32 maximum);

        /// <summary>
        /// Returns a signed 32-bit random integer in [min, max].
        /// </summary>
        Int32 NextInt32MaxMin(Int32 maximum, Int32 minimum);

        /// <summary>
        /// Returns an unsigned 32-bit random integer.
        /// </summary>
        UInt32 NextUInt32();

        /// <summary>
        /// Returns an unsigned 32-bit random integer in [0, max].
        /// </summary>
        UInt32 NextUInt32Max(UInt32 maximum);

        /// <summary>
        /// Returns an unsigned 32-bit random integer in [min, max].
        /// </summary>
        UInt32 NextUInt32MaxMin(UInt32 maximum, UInt32 minimum);

        /// <summary>
        /// Returns a signed 64-bit random integer.
        /// </summary>
        Int64 NextInt64();

        /// <summary>
        /// Returns a signed 64-bit random integer in [0, max].
        /// </summary>
        Int64 NextInt64Max(Int64 maximum);

        /// <summary>
        /// Returns a signed 64-bit random integer in [min, max].
        /// </summary>
        Int64 NextInt64MaxMin(Int64 maximum, Int64 minimum);

        /// <summary>
        /// Returns an unsigned 64-bit random integer.
        /// </summary>
        UInt64 NextUInt64();

        /// <summary>
        /// Returns an unsigned 64-bit random integer in [0, max].
        /// </summary>
        UInt64 NextUInt64Max(UInt64 maximum);

        /// <summary>
        /// Returns an unsigned 64-bit random integer in [min, max].
        /// </summary>
        UInt64 NextUInt64MaxMin(UInt64 maximum, UInt64 minimum);

    private:
        bool m_isInitialized;
    };
}

#endif
