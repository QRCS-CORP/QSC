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
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSCNETCW_QMAC_H
#define QSCNETCW_QMAC_H

#include "Common.h"
#include "..\QSC\qmac.h"

namespace QSCNETCW
{
    /// <summary>
    /// Specifies the QMAC mode types.
    /// </summary>
    public enum class QmacModes : System::UInt32
    {
        /// <summary>
        /// QMAC-256 mode
        /// </summary>
        Qmac256 = 0x00,

        /// <summary>
        /// QMAC-512 mode
        /// </summary>
        Qmac512 = 0x01
    };

    /// <summary>
    /// Managed wrapper around the QMAC (Quantum-Safe Message Authentication Code) API.
    /// This class supports both incremental usage (Initialize -> Update -> Finalize)
    /// and a one-shot usage via the static <c>Compute</c> method.
    /// </summary>
    public ref class QMAC
    {
    public:
        /// <summary>
        /// Constructs an uninitialized QMAC instance. You must call <c>Initialize</c>
        /// before calling <c>Update</c> or <c>Finalize</c>.
        /// </summary>
        QMAC();

        /// <summary>
        /// Destructor that securely disposes of the native QMAC state.
        /// </summary>
        ~QMAC();

        /// <summary>
        /// Finalizer that disposes of the native QMAC state if not already done.
        /// </summary>
        !QMAC();

        /// <summary>
        /// Initializes the QMAC state using the specified key parameters.
        /// </summary>
        /// <param name="key">The key array (e.g., 32 bytes).</param>
        /// <param name="nonce">Optional nonce array (or null if not used).</param>
        /// <param name="info">Optional info array (or null if not used).</param>
        /// <param name="mode">The QMAC mode, e.g. <c>QmacModes::Qmac256</c>.</param>
        void Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, QmacModes mode);

        /// <summary>
        /// Updates the QMAC state with the specified block(s) of message data.
        /// For best performance, supply multiples of <c>QSC_QMAC_BLOCK_SIZE</c> in <paramref name="length"/>.
        /// </summary>
        /// <param name="message">A byte array containing the message data.</param>
        /// <param name="length">The number of bytes in <paramref name="message"/> to process.</param>
        void Update(array<Byte>^ message, size_t length);

        /// <summary>
        /// Finalizes the QMAC state, producing the computed MAC. 
        /// The instance is left in a disposed state afterward.
        /// </summary>
        /// <param name="output">A byte array to receive the MAC, 
        /// at least <c>QSC_QMAC_MAC_SIZE</c> bytes long.</param>
        void Finalize(array<Byte>^ output);

        /// <summary>
        /// Disposes of the QMAC state by zeroizing all sensitive fields.
        /// </summary>
        void Destroy();

        /// <summary>
        /// Computes a QMAC code in one shot, without needing to create an instance.
        /// </summary>
        /// <param name="output">A byte array to receive the MAC (<c>QSC_QMAC_MAC_SIZE</c> bytes).</param>
        /// <param name="key">The key array.</param>
        /// <param name="nonce">Optional nonce array (or null).</param>
        /// <param name="info">Optional info array (or null).</param>
        /// <param name="mode">One of the <c>QmacModes</c> enumeration values.</param>
        /// <param name="message">The message data array.</param>
        /// <param name="length">The number of message bytes to process.</param>
        static void Compute(array<Byte>^ output, array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, QmacModes mode, array<Byte>^ message, size_t length);

    private:
        qsc_qmac_state* m_state;
        bool m_isInitialized;
    };
}

#endif
