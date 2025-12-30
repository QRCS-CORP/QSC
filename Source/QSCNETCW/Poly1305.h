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

#ifndef QSCNETCW_POLY1305_H
#define QSCNETCW_POLY1305_H

#include "Common.h"
#include "..\QSC\poly1305.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper around the Poly1305 MAC algorithm.
    /// 
    /// This class allows for both incremental (update + finalize) usage as well as
    /// one-shot computation (via the static <c>Compute</c> method).
    /// </summary>
    public ref class Poly1305
    {
    public:
        /// <summary>
        /// Constructs a Poly1305 instance by initializing the internal state with the given key.
        /// </summary>
        /// <param name="key">
        /// A managed byte array containing the 32-byte secret key (<c>QSC_POLY1305_KEY_SIZE</c>).
        /// </param>
        Poly1305(array<Byte>^ key);

        /// <summary>
        /// Destructor that disposes of the native Poly1305 state.
        /// </summary>
        ~Poly1305();

        /// <summary>
        /// Finalizer that disposes of the native Poly1305 state if not already done.
        /// </summary>
        !Poly1305();

        /// <summary>
        /// Updates the MAC state with one 16-byte block of message data.
        /// This method only absorbs exactly one block of data (16 bytes).
        /// </summary>
        /// <param name="block">
        /// A 16-byte array containing the message block.
        /// </param>
        void BlockUpdate(array<Byte>^ block);

        /// <summary>
        /// Erases the native Poly1305 state, clearing sensitive information.
        /// </summary>
        void Destroy();

        /// <summary>
        /// Updates the MAC state with additional message data in any size.
        /// </summary>
        /// <param name="message">
        /// The array containing the message bytes to process.
        /// </param>
        /// <param name="msglen">
        /// The number of bytes in <paramref name="message"/> to process.
        /// </param>
        void Update(array<Byte>^ message, size_t msglen);

        /// <summary>
        /// Finalizes the MAC computation and writes the 16-byte MAC to the provided array.
        /// This method resets the internal state to a finalized condition.
        /// </summary>
        /// <param name="mac">
        /// The array to receive the 16-byte MAC (<c>QSC_POLY1305_MAC_SIZE</c>).
        /// </param>
        void Finalize(array<Byte>^ mac);

        /// <summary>
        /// Resets the Poly1305 internal state to all zeros without generating a MAC.
        /// You must re-initialize if you wish to compute a new MAC after reset.
        /// </summary>
        void Reset();

        /// <summary>
        /// Computes the Poly1305 MAC of the given message with the specified 32-byte key in one shot.
        /// </summary>
        /// <param name="output">
        /// The array to receive the 16-byte MAC (<c>QSC_POLY1305_MAC_SIZE</c>).
        /// </param>
        /// <param name="message">
        /// The array containing the message to process.
        /// </param>
        /// <param name="msglen">
        /// The length of the message in <paramref name="message"/>.
        /// </param>
        /// <param name="key">
        /// The 32-byte key (<c>QSC_POLY1305_KEY_SIZE</c>).
        /// </param>
        static void Compute(array<Byte>^ output, array<Byte>^ message, size_t msglen, array<Byte>^ key);

        /// <summary>
        /// Verifies a given MAC against a message and key by recomputing and comparing.
        /// </summary>
        /// <param name="code">
        /// The 16-byte MAC code to verify (<c>QSC_POLY1305_MAC_SIZE</c>).
        /// </param>
        /// <param name="message">
        /// The array containing the message data.
        /// </param>
        /// <param name="msglen">
        /// The length of the message.
        /// </param>
        /// <param name="key">
        /// The 32-byte key.
        /// </param>
        /// <returns>
        /// An integer result where 0 typically means equality/success, and nonzero indicates failure.
        /// </returns>
        static int Verify(array<Byte>^ code, array<Byte>^ message, size_t msglen, array<Byte>^ key);

    private:
        qsc_poly1305_state* m_state;
        bool m_isInitialized;
    };
}

#endif
