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

