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

