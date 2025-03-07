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

#ifndef QSCNETCW_DILITHIUM_H
#define QSCNETCW_DILITHIUM_H

#include "Common.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper around the Dilithium post-quantum digital signature scheme.
    /// </summary>
    public ref class Dilithium abstract sealed
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
        /// Generates a Dilithium public/private key pair.
        /// </summary>
        /// <param name="publicKey">
        /// A managed byte array for the public key. Must be sized to QSC_DILITHIUM_PUBLICKEY_SIZE.
        /// </param>
        /// <param name="privateKey">
        /// A managed byte array for the private key. Must be sized to QSC_DILITHIUM_PRIVATEKEY_SIZE.
        /// </param>
        /// <returns>
        /// <c>true</c> if the key pair was generated successfully; otherwise <c>false</c>.
        /// </returns>
        static bool GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey);

        /// <summary>
        /// Signs a message, placing the signature and message into the signedMsg buffer.
        /// </summary>
        /// <param name="signedMsg">
        /// A buffer to receive the signature followed by the message. Must be at least (messageLength + QSC_DILITHIUM_SIGNATURE_SIZE) bytes.
        /// </param>
        /// <param name="signedMsgLength">
        /// On success, receives the length of the signed message (signature plus original message).
        /// </param>
        /// <param name="message">
        /// The original message to be signed.
        /// </param>
        /// <param name="messageLength">
        /// The length of the original message in <paramref name="message"/>.
        /// </param>
        /// <param name="privateKey">
        /// The private key. Must be sized to QSC_DILITHIUM_PRIVATEKEY_SIZE.
        /// </param>
        /// <returns>
        /// <c>true</c> on success; otherwise <c>false</c>.
        /// </returns>
        static bool Sign(array<Byte>^ signedMsg, size_t% signedMsgLength, array<Byte>^ message, size_t messageLength, array<Byte>^ privateKey);

        /// <summary>
        /// Extended signing function that includes a context parameter.
        /// </summary>
        /// <param name="signedMsg">
        /// A buffer to receive the signature followed by the message. Must be at least (messageLength + QSC_DILITHIUM_SIGNATURE_SIZE) bytes.
        /// </param>
        /// <param name="signedMsgLength">
        /// On success, receives the length of the signed message (signature plus original message).
        /// </param>
        /// <param name="message">
        /// The original message to be signed.
        /// </param>
        /// <param name="messageLength">
        /// The length of the original message in <paramref name="message"/>.
        /// </param>
        /// <param name="context">
        /// Optional context data.
        /// </param>
        /// <param name="contextLength">
        /// The length of the context data in <paramref name="context"/>.
        /// </param>
        /// <param name="privateKey">
        /// The private key. Must be sized to QSC_DILITHIUM_PRIVATEKEY_SIZE.
        /// </param>
        /// <returns>
        /// <c>true</c> on success; otherwise <c>false</c>.
        /// </returns>
        static bool SignEx(array<Byte>^ signedMsg, size_t% signedMsgLength, array<Byte>^ message, size_t messageLength, array<Byte>^ context, size_t contextLength, array<Byte>^ privateKey);

        /// <summary>
        /// Verifies a signed message with a public key, extracting the original message if valid.
        /// </summary>
        /// <param name="message">
        /// A buffer to receive the extracted original message on success.
        /// </param>
        /// <param name="messageLength">
        /// On success, receives the length of the extracted original message.
        /// </param>
        /// <param name="signedMsg">
        /// The signed message (signature + original message).
        /// </param>
        /// <param name="signedMsgLength">
        /// The length of <paramref name="signedMsg"/>.
        /// </param>
        /// <param name="publicKey">
        /// The public key. Must be sized to QSC_DILITHIUM_PUBLICKEY_SIZE.
        /// </param>
        /// <returns>
        /// <c>true</c> if the signature is valid; otherwise <c>false</c>.
        /// </returns>
        static bool Verify(array<Byte>^ message, size_t% messageLength, array<Byte>^ signedMsg, size_t signedMsgLength, array<Byte>^ publicKey);

        /// <summary>
        /// Extended verify function that includes a context parameter.
        /// </summary>
        /// <param name="message">
        /// A buffer to receive the extracted original message on success.
        /// </param>
        /// <param name="messageLength">
        /// On success, receives the length of the extracted original message.
        /// </param>
        /// <param name="signedMsg">
        /// The signed message (signature + original message).
        /// </param>
        /// <param name="signedMsgLength">
        /// The length of <paramref name="signedMsg"/>.
        /// </param>
        /// <param name="context">
        /// Optional context data.
        /// </param>
        /// <param name="contextLength">
        /// The length of the context data in <paramref name="context"/>.
        /// </param>
        /// <param name="publicKey">
        /// The public key. Must be sized to QSC_DILITHIUM_PUBLICKEY_SIZE.
        /// </param>
        /// <returns>
        /// <c>true</c> if the signature is valid; otherwise <c>false</c>.
        /// </returns>
        static bool VerifyEx(array<Byte>^ message, size_t% messageLength, array<Byte>^ signedMsg, size_t signedMsgLength, array<Byte>^ context, size_t contextLength, array<Byte>^ publicKey);
    };
}

#endif
