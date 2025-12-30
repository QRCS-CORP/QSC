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
