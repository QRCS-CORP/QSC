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

#ifndef QSCNETCW_ECDH_H
#define QSCNETCW_ECDH_H

#include "Common.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper around the ECDH key encapsulation mechanism using Curve25519.
    /// </summary>
    public ref class ECDH abstract sealed
    {
    public:

        /// <summary>
        /// Get the private key size.
        /// </summary>
        /// <returns>
        /// The byte size of the private key array.
        /// </returns>
        static size_t PrivateKeySize();

        /// <summary>
        /// Get the public key size.
        /// </summary>
        /// <returns>
        /// The byte size of the public key array.
        /// </returns>
        static size_t PublicKeySize();

        /// <summary>
        /// Get the ciphertext size.
        /// </summary>
        /// <returns>
        /// The byte size of the ciphertext array.
        /// </returns>
        static size_t CipherTextSize();

        /// <summary>
        /// Derives a shared secret from the local private key and a peer's public key.
        /// The secret must be sized to <c>QSC_ECDH_SHAREDSECRET_SIZE</c> bytes.
        /// </summary>
        /// <param name="secret">
        /// A managed byte array to receive the derived shared secret (32 bytes).
        /// </param>
        /// <param name="privateKey">
        /// The private key array (32 bytes).
        /// </param>
        /// <param name="publicKey">
        /// The peer's public key array (32 bytes).
        /// </param>
        /// <returns>
        /// <c>true</c> on success, otherwise <c>false</c>.
        /// </returns>
        static bool KeyExchange(array<Byte>^ secret, array<Byte>^ privateKey, array<Byte>^ publicKey);

        /// <summary>
        /// Generates a public/private key pair using the specified random generator callback.
        /// </summary>
        /// <param name="publicKey">
        /// The public key output array (32 bytes).
        /// </param>
        /// <param name="privateKey">
        /// The private key output array (32 bytes).
        /// </param>
        /// <returns>
        /// <c>true</c> if the key pair was generated successfully, otherwise <c>false</c>.
        /// </returns>
        static bool GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey);

        /// <summary>
        /// Generates a public/private key pair using a supplied seed array (32 bytes).
        /// </summary>
        /// <param name="publicKey">
        /// The public key output array (32 bytes).
        /// </param>
        /// <param name="privateKey">
        /// The private key output array (32 bytes).
        /// </param>
        /// <param name="seed">
        /// A seed array (32 bytes) used to deterministically produce the keys.
        /// </param>
        /// <returns>
        /// <c>true</c> if the key pair was generated successfully, otherwise <c>false</c>.
        /// </returns>
        static bool GenerateSeededKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey, array<Byte>^ seed);
    };
}

#endif
