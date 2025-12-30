/* 2026 Quantum Resistant Cryptographic Solutions Corporation
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
