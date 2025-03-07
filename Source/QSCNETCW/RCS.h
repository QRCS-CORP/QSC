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

#ifndef QSCNETCW_RCS_H
#define QSCNETCW_RCS_H

#include "Common.h"
#include "..\QSC\rcs.h"

namespace QSCNETCW
{
    /// <summary>
    /// Specifies the RCS cipher type, e.g. RCS256 or RCS512.
    /// </summary>
    public enum class RcsCipherType : System::UInt32
    {
        /// <summary>
        /// RCS-256 cipher mode
        /// </summary>
        Rcs256 = 0x01,

        /// <summary>
        /// RCS-512 cipher mode
        /// </summary>
        Rcs512 = 0x02
    };

    /// <summary>
    /// Managed wrapper around the RCS (Rijndael-256 Authenticated Cipher Stream) API.
    /// This class supports incremental usage: Initialize -> SetAssociated (optional) -> Transform or ExtendedTransform -> Dispose.
    /// </summary>
    public ref class RCS
    {
    public:
        /// <summary>
        /// Constructs an uninitialized RCS instance. You must call <c>Initialize</c>
        /// before calling <c>SetAssociated</c>, <c>Transform</c>, or <c>ExtendedTransform</c>.
        /// </summary>
        RCS();

        /// <summary>
        /// Destructor that securely disposes of the native RCS state.
        /// </summary>
        ~RCS();

        /// <summary>
        /// Finalizer that disposes of the native RCS state if not already done.
        /// </summary>
        !RCS();

        /// <summary>
        /// Initializes the RCS state using the specified key parameters and encryption/decryption mode.
        /// </summary>
        /// <param name="key">The cipher key array (e.g. 32 bytes for RCS-256 or 64 bytes for RCS-512).</param>
        /// <param name="nonce">The nonce array (<c>QSC_RCS_NONCE_SIZE</c> bytes), or null if not used.</param>
        /// <param name="info">Optional info array for cSHAKE tweak, or null if not used.</param>
        /// <param name="encrypt">Set to true for encryption, false for decryption.</param>
        /// <param name="cipherType">One of the <c>RcsCipherType</c> values, e.g. <c>RcsCipherType::Rcs256</c>.</param>
        void Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encrypt, RcsCipherType cipherType);

        /// <summary>
        /// Sets the associated data used to authenticate the message.
        /// Must be called after <c>Initialize</c> and before each transform call.
        /// The data is erased after each transform call.
        /// </summary>
        /// <param name="data">Byte array containing the associated data.</param>
        /// <param name="length">Number of bytes to process in <paramref name="data"/>.</param>
        void SetAssociated(array<Byte>^ data, size_t length);

        /// <summary>
        /// Retrieves the current nonce from the state. 
        /// If reusing a nonce/key, call this after the final transform.
        /// </summary>
        /// <param name="nonce">The array to receive the nonce (<c>QSC_RCS_NONCE_SIZE</c> bytes).</param>
        void StoreNonce(array<Byte>^ nonce);

        /// <summary>
        /// Transforms (encrypts or decrypts) the input array.
        /// If in encryption mode, the MAC is appended to the ciphertext.
        /// If in decryption mode, the MAC is checked. If invalid, returns false and does not decrypt.
        /// </summary>
        /// <param name="output">The array to receive the transformed data (or plaintext).</param>
        /// <param name="input">The array containing input data (plaintext or ciphertext).</param>
        /// <param name="length">Number of bytes to process (excluding the MAC in decryption mode).</param>
        /// <returns>True if transform is successful (valid MAC), otherwise false.</returns>
        bool Transform(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Extended transform supporting multiple calls for large data.
        /// On the last call, set <paramref name="finalize"/> to true to finalize authentication.
        /// </summary>
        /// <param name="output">Array to receive the transformed data.</param>
        /// <param name="input">Array containing the input data.</param>
        /// <param name="length">Number of bytes to process.</param>
        /// <param name="finalize">Set to true on the final call to complete authentication.</param>
        /// <returns>True if transform is successful (valid MAC), otherwise false.</returns>
        bool ExtendedTransform(array<Byte>^ output, array<Byte>^ input, size_t length, bool finalize);

        /// <summary>
        /// Disposes of the RCS state by zeroizing all sensitive fields.
        /// The instance is left in a disposed state after this call.
        /// </summary>
        void Destroy();

    private:
        qsc_rcs_state* m_state;
        bool m_isInitialized;
    };
}

#endif

