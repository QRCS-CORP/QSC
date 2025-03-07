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

#ifndef QSCNETCW_ECDSA_H
#define QSCNETCW_ECDSA_H

#include "Common.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper around the ECDSA (Elliptic Curve Digital Signature Algorithm)
    /// operating over the Ed25519 elliptic curve.
    /// </summary>
    public ref class ECDSA abstract sealed
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
        /// Get the signature size.
        /// </summary>
        /// <returns>
        /// The byte size of the signature array.
        /// </returns>
        static size_t SignatureSize();

        /// <summary>
        /// Generates a public/private key pair using a 32-byte random seed.
        /// </summary>
        /// <param name="publicKey">
        /// A 32-byte array for the public verification key.
        /// </param>
        /// <param name="privateKey">
        /// A 64-byte array for the private signature key.
        /// </param>
        /// <param name="seed">
        /// A 32-byte seed array for deterministic key generation.
        /// </param>
        /// <returns>
        /// <c>true</c> if keys are generated successfully, otherwise <c>false</c>.
        /// </returns>
        static bool GenerateSeededKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey, array<Byte>^ seed);

        /// <summary>
        /// Generates a public/private key pair using a random callback function.
        /// </summary>
        /// <param name="publicKey">
        /// A 32-byte array for the public verification key.
        /// </param>
        /// <param name="privateKey">
        /// A 64-byte array for the private signature key.
        /// </param>
        /// <returns>
        /// <c>true</c> if keys are generated successfully, otherwise <c>false</c>.
        /// </returns>
        static bool GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey);

        /// <summary>
        /// Signs a message, writing the signature + message to <paramref name="signedMsg"/>.
        /// </summary>
        /// <param name="signedMsg">
        /// An array large enough to hold <paramref name="messageLength"/> + QSC_ECDSA_SIGNATURE_SIZE.
        /// The signature is prepended before the original message in this array.
        /// </param>
        /// <param name="signedMsgLength">
        /// Receives the total length of the signed message (signature + original message).
        /// </param>
        /// <param name="message">
        /// The original message to sign.
        /// </param>
        /// <param name="messageLength">
        /// The length of the original message.
        /// </param>
        /// <param name="privateKey">
        /// The private signature key (64 bytes).
        /// </param>
        /// <returns>
        /// <c>true</c> if signing is successful, otherwise <c>false</c>.
        /// </returns>
        static bool Sign(array<Byte>^ signedMsg, size_t% signedMsgLength, array<Byte>^ message, size_t messageLength, array<Byte>^ privateKey);

        /// <summary>
        /// Verifies a signed message. If valid, extracts the original message into <paramref name="message"/>.
        /// </summary>
        /// <param name="message">
        /// A buffer to receive the extracted message on success.
        /// </param>
        /// <param name="messageLength">
        /// Receives the length of the extracted message.
        /// </param>
        /// <param name="signedMsg">
        /// The array holding signature + original message.
        /// </param>
        /// <param name="signedMsgLength">
        /// The total length of <paramref name="signedMsg"/>.
        /// </param>
        /// <param name="publicKey">
        /// The public verification key (32 bytes).
        /// </param>
        /// <returns>
        /// <c>true</c> if the signature is valid, otherwise <c>false</c>.
        /// </returns>
        static bool Verify(array<Byte>^ message, size_t% messageLength, array<Byte>^ signedMsg, size_t signedMsgLength, array<Byte>^ publicKey);
    };
}

#endif

