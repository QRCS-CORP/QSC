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

#ifndef QSCNETCW_MCELIECE_H
#define QSCNETCW_MCELIECE_H

#include "Common.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper around the McEliece Key Encapsulation Mechanism (KEM).
    /// </summary>
    public ref class McEliece abstract sealed
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
        /// Decapsulates the shared secret from a ciphertext using the private key.
        /// </summary>
        /// <param name="secret">Output array for the 32-byte shared secret.</param>
        /// <param name="ciphertext">Ciphertext array (<c>QSC_MCELIECE_CIPHERTEXT_SIZE</c> bytes).</param>
        /// <param name="privateKey">Private key array (<c>QSC_MCELIECE_PRIVATEKEY_SIZE</c> bytes).</param>
        /// <returns><c>true</c> on success, otherwise <c>false</c>.</returns>
        static bool Decapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey);

        /// <summary>
        /// Alternative name for decapsulation (functionally identical).
        /// </summary>
        static bool Decrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey);

        /// <summary>
        /// Encapsulates a shared secret, producing ciphertext from a public key.
        /// </summary>
        /// <param name="secret">Output array for the 32-byte shared secret.</param>
        /// <param name="ciphertext">Output array for ciphertext (<c>QSC_MCELIECE_CIPHERTEXT_SIZE</c> bytes).</param>
        /// <param name="publicKey">Public key array (<c>QSC_MCELIECE_PUBLICKEY_SIZE</c> bytes).</param>
        /// <returns><c>true</c> on success, otherwise <c>false</c>.</returns>
        static bool Encapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey);

        /// <summary>
        /// Encrypts to encapsulate a shared secret using a specified seed, instead of RNG callback.
        /// </summary>
        static bool Encrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey, array<Byte>^ seed);

        /// <summary>
        /// Generates a McEliece key pair (public/private).
        /// </summary>
        /// <param name="publicKey">Output for the public key (<c>QSC_MCELIECE_PUBLICKEY_SIZE</c> bytes).</param>
        /// <param name="privateKey">Output for the private key (<c>QSC_MCELIECE_PRIVATEKEY_SIZE</c> bytes).</param>
        /// <returns><c>true</c> on success, otherwise <c>false</c>.</returns>
        static bool GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey);
    };
}

#endif
