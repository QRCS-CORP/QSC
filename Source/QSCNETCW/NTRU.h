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

#ifndef QSCNETCW_NTRU_H
#define QSCNETCW_NTRU_H

#include "Common.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a static .NET wrapper around the NTRU (NTRU CCA-secure KEM) API.
    /// </summary>
    public ref class NTRU abstract sealed
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
        /// Decapsulates the shared secret using a private key.
        /// </summary>
        /// <param name="secret">
        /// A managed byte array to receive the shared secret.
        /// Must be at least <c>QSC_NTRU_SHAREDSECRET_SIZE</c> bytes.
        /// </param>
        /// <param name="ciphertext">
        /// The NTRU ciphertext (at least <c>QSC_NTRU_CIPHERTEXT_SIZE</c> bytes).
        /// </param>
        /// <param name="privateKey">
        /// The private key array (at least <c>QSC_NTRU_PRIVATEKEY_SIZE</c> bytes).
        /// </param>
        /// <returns>True if decapsulation is successful, otherwise false.</returns>
        static bool Decapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey);

        /// <summary>
        /// Decrypts the shared secret using a private key (functionally identical to decapsulate).
        /// </summary>
        /// <param name="secret">
        /// A managed byte array to receive the shared secret.
        /// </param>
        /// <param name="ciphertext">
        /// The NTRU ciphertext.
        /// </param>
        /// <param name="privateKey">
        /// The private key array.
        /// </param>
        /// <returns>True if decryption is successful, otherwise false.</returns>
        static bool Decrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey);

        /// <summary>
        /// Encapsulates a shared secret using a public key.
        /// </summary>
        /// <param name="secret">
        /// A managed byte array to receive the derived shared secret.
        /// Must be at least <c>QSC_NTRU_SHAREDSECRET_SIZE</c> bytes.
        /// </param>
        /// <param name="ciphertext">
        /// An array to receive the ciphertext (at least <c>QSC_NTRU_CIPHERTEXT_SIZE</c> bytes).
        /// </param>
        /// <param name="publicKey">
        /// The public key array (at least <c>QSC_NTRU_PUBLICKEY_SIZE</c> bytes).
        /// </param>
        /// <returns>True if operation is successful, otherwise false.</returns>
        static bool Encapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey);

        /// <summary>
        /// Encrypts to encapsulate a shared secret using a seed instead of an RNG callback.
        /// </summary>
        /// <param name="secret">
        /// A managed byte array to receive the derived shared secret.
        /// </param>
        /// <param name="ciphertext">
        /// An array to receive the ciphertext.
        /// </param>
        /// <param name="publicKey">
        /// The public key array.
        /// </param>
        /// <param name="seed">
        /// A byte array for the random seed (exactly <c>QSC_NTRU_SEED_SIZE</c> bytes).
        /// </param>
        /// <returns>True if operation is successful, otherwise false.</returns>
        static bool Encrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey, array<Byte>^ seed);

        /// <summary>
        /// Generates a public/private key pair for the NTRU KEM.
        /// </summary>
        /// <param name="publicKey">
        /// The byte array to receive the public key (<c>QSC_NTRU_PUBLICKEY_SIZE</c> bytes).
        /// </param>
        /// <param name="privateKey">
        /// The byte array to receive the private key (<c>QSC_NTRU_PRIVATEKEY_SIZE</c> bytes).
        /// </param>
        /// <returns>True if the key pair was generated successfully, otherwise false.</returns>
        static bool GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey);
    };
}

#endif
