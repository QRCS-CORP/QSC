/*********************************************************************************
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
 * This software is subject to the Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL). The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 **********************************************************************************/

#ifndef QSCNETCW_CHACHA_H
#define QSCNETCW_CHACHA_H

#include "Common.h"
#include "..\QSC\chacha.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a .NET-friendly wrapper around the ChaCha20 stream cipher.
    /// </summary>
    public ref class CHACHA
    {
    public:

        /// <summary>
        /// Constructs an uninitialized CHACHA instance. You must call <c>Initialize</c>
        /// before calling <c>SetAssociated</c>, <c>Transform</c>, or <c>ExtendedTransform</c>.
        /// </summary>
        CHACHA();

        /// <summary>
        /// Destructor that securely disposes of the native CHACHA state.
        /// </summary>
        ~CHACHA();

        /// <summary>
        /// Finalizer that disposes of the native CHACHA state if not already done.
        /// </summary>
        !CHACHA();

        /// <summary>
        /// Initializes the ChaCha20 cipher state with a specified key and nonce.
        /// </summary>
        /// 
        /// <remarks>
        /// <para>
        /// The key can be either 16 bytes (128-bit) or 32 bytes (256-bit) in length.
        /// The nonce must be exactly 8 bytes in length.
        /// </para>
        /// <para>
        /// This function pins the managed <c>key</c> and <c>nonce</c> arrays so they
        /// can be safely passed to the native ChaCha20 initialization function.
        /// </para>
        /// </remarks>
        /// 
        /// <param name="key">The secret key (16 or 32 bytes)</param>
        /// <param name="nonce">The nonce (8 bytes)</param>
        /// <returns>
        /// <c>true</c> if the initialization parameters are valid and the state
        /// was successfully initialized; otherwise, <c>false</c>.
        /// </returns>
        bool Initialize(array<Byte>^ key, array<Byte>^ nonce);

        /// <summary>
        /// Encrypts or decrypts a block of data using the ChaCha20 cipher.
        /// </summary>
        ///
        /// <remarks>
        /// <para>
        /// Since ChaCha20 is a stream cipher, the same function is used for both
        /// encryption and decryption. The caller must ensure that both
        /// <c>output</c> and <c>input</c> arrays are at least <c>length</c> in size.
        /// </para>
        /// <para>
        /// This function pins the managed <c>output</c> and <c>input</c> arrays so they
        /// can be safely passed to the native ChaCha20 transform function.
        /// </para>
        /// </remarks>
        ///
        /// <param name="output">
        /// The array where transformed bytes are written.
        /// </param>
        /// <param name="input">
        /// The array containing data to be encrypted or decrypted.
        /// </param>
        /// <param name="length">
        /// The number of bytes to process.
        /// </param>
        /// <returns>
        /// <c>true</c> if the transform succeeded (valid lengths and arrays),
        /// otherwise <c>false</c>.
        /// </returns>
        bool Transform(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Destroys the ChaCha20 cipher state, securely clearing sensitive data.
        /// </summary>
        ///
        /// <remarks>
        /// This function calls the native ChaCha20 disposal routine, which wipes
        /// the internal state.
        /// </remarks>
        void Destroy();

    private:
        qsc_chacha_state* m_state;
        bool m_isInitialized;
    };
}

#endif
