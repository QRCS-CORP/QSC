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

#ifndef QSCNETCW_KYBER_H
#define QSCNETCW_KYBER_H

#include "Common.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper around the Kyber CCA-secure Key Encapsulation Mechanism.
    /// </summary>
    public ref class Kyber abstract sealed
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
        /// Performs key decapsulation, deriving the shared secret from a ciphertext and secret key.
        /// </summary>
        /// <param name="secret">Output array for the 32-byte shared secret.</param>
        /// <param name="ciphertext">Input ciphertext array (size <c>QSC_KYBER_CIPHERTEXT_SIZE</c>).</param>
        /// <param name="privateKey">Secret key array (size <c>QSC_KYBER_PRIVATEKEY_SIZE</c>).</param>
        /// <returns><c>true</c> on success; otherwise <c>false</c>.</returns>
        static bool Decapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey);

        /// <summary>
        /// Encapsulates a shared secret, producing a ciphertext from a public key.
        /// </summary>
        /// <param name="secret">Output array for the 32-byte shared secret.</param>
        /// <param name="ciphertext">Output array for the ciphertext (size <c>QSC_KYBER_CIPHERTEXT_SIZE</c>).</param>
        /// <param name="publicKey">Public key array (size <c>QSC_KYBER_PUBLICKEY_SIZE</c>).</param>
        /// <returns><c>true</c> on success; otherwise <c>false</c>.</returns>
        static bool Encapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey);

        /// <summary>
        /// Generates a public/private key pair for the Kyber KEM.
        /// </summary>
        /// <param name="publicKey">Output array for the public key (size <c>QSC_KYBER_PUBLICKEY_SIZE</c>).</param>
        /// <param name="privateKey">Output array for the secret key (size <c>QSC_KYBER_PRIVATEKEY_SIZE</c>).</param>
        /// <returns><c>true</c> on success; otherwise <c>false</c>.</returns>
        static bool GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey);
    };
}

#endif
