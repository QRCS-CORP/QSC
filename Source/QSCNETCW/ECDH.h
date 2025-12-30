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
