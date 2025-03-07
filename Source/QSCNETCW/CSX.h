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
 */

#ifndef QSCNETCW_CSX_H
#define QSCNETCW_CSX_H

#include "Common.h"
#include "..\QSC\csx.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper for the CSX-512 cipher, a ChaCha-based authenticated stream cipher extension.
    /// </summary>
    public ref class CSX
    {
    public:
        /// <summary>
        /// Initializes a new instance of the <c>CSX</c> class and allocates the native state.
        /// </summary>
        CSX();

        /// <summary>
        /// Destructor that calls <see cref="Destroy"/> to release native resources.
        /// </summary>
        ~CSX();

        /// <summary>
        /// Finalizer that calls <see cref="Destroy"/> if not already done.
        /// </summary>
        !CSX();

        /// <summary>
        /// Initializes the CSX state with the specified key, nonce, and optional info.
        /// </summary>
        /// <param name="key">
        /// The cipher key. Must be <c>QSC_CSX_KEY_SIZE</c> bytes (64 bytes) for CSX-512.
        /// </param>
        /// <param name="nonce">
        /// The nonce or IV. Must be <c>QSC_CSX_NONCE_SIZE</c> bytes (16 bytes).
        /// </param>
        /// <param name="info">
        /// An optional tweak or salt array. May be <c>null</c> if not needed.
        /// </param>
        /// <param name="encryption">
        /// If <c>true</c>, initializes the cipher for encryption; otherwise decryption.
        /// </param>
        /// <returns>
        /// <c>true</c> if initialization succeeds; otherwise <c>false</c>.
        /// </returns>
        bool Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encryption);

        /// <summary>
        /// Sets the associated data used for authentication. Must be called after <see cref="Initialize"/> and before each transform.
        /// </summary>
        /// <param name="data">
        /// Associated data array. May contain headers, domain-specific info, etc.
        /// </param>
        /// <param name="length">
        /// Number of bytes in <paramref name="data"/> to process.
        /// </param>
        /// <returns>
        /// <c>true</c> if associated data was set successfully; otherwise <c>false</c>.
        /// </returns>
        bool SetAssociated(array<Byte>^ data, size_t length);

        /// <summary>
        /// Retrieves the current nonce from the state.
        /// </summary>
        /// <param name="nonce">
        /// A byte array to receive the nonce. Must be at least <c>QSC_CSX_NONCE_SIZE</c> bytes.
        /// </param>
        /// <returns>
        /// <c>true</c> on success; otherwise <c>false</c>.
        /// </returns>
        bool StoreNonce(array<Byte>^ nonce);

        /// <summary>
        /// Encrypts or decrypts the input array and appends/verifies a MAC code.
        /// </summary>
        /// <param name="output">
        /// Buffer for the ciphertext (encrypt) or plaintext (decrypt).
        /// </param>
        /// <param name="input">
        /// Plaintext or ciphertext to process.
        /// </param>
        /// <param name="length">
        /// Number of bytes to process in <paramref name="input"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> if transform succeeds and MAC (if present) is valid; otherwise <c>false</c>.
        /// </returns>
        bool Transform(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Encrypts or decrypts large data in multiple calls, appending/verifying a MAC on the final call.
        /// </summary>
        /// <param name="output">
        /// Buffer for the ciphertext (encrypt) or plaintext (decrypt).
        /// </param>
        /// <param name="input">
        /// Plaintext or ciphertext to process.
        /// </param>
        /// <param name="length">
        /// Number of bytes to process in <paramref name="input"/>.
        /// </param>
        /// <param name="finalize">
        /// Set <c>true</c> on the last call to complete MAC generation/verification.
        /// </param>
        /// <returns>
        /// <c>true</c> if transform succeeds and MAC (if present) is valid; otherwise <c>false</c>.
        /// </returns>
        bool ExtendedTransform(array<Byte>^ output, array<Byte>^ input, size_t length, bool finalize);

        /// <summary>
        /// Disposes the native cipher state, clearing sensitive data from memory.
        /// </summary>
        void Destroy();

    private:
        qsc_csx_state* m_state;
        bool m_isInitialized;
    };
}

#endif
