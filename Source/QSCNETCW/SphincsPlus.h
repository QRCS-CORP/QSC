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

#ifndef QSCNETCW_SPHINCSPLUS_H
#define QSCNETCW_SPHINCSPLUS_H

#include "Common.h"

namespace QSCNETCW
{
    /// <summary>
    /// A static .NET wrapper for the SPHINCS+ signature scheme, as defined in sphincsplus.h.
    /// 
    /// The current compile-time definitions (e.g. QSC_SPHINCSPLUS_S3S192SHAKERS) determine
    /// the sizes of keys and signature, which are reflected in QSC_SPHINCSPLUS_PUBLICKEY_SIZE,
    /// QSC_SPHINCSPLUS_PRIVATEKEY_SIZE, and QSC_SPHINCSPLUS_SIGNATURE_SIZE.
    /// </summary>
    public ref class SphincsPlus abstract sealed
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
        /// Generates a SPHINCS+ public/private key pair.
        /// </summary>
        /// <param name="publicKey">
        /// A byte array at least QSC_SPHINCSPLUS_PUBLICKEY_SIZE in length.
        /// </param>
        /// <param name="privateKey">
        /// A byte array at least QSC_SPHINCSPLUS_PRIVATEKEY_SIZE in length.
        /// </param>
        static void GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey);

        /// <summary>
        /// Signs a message, returning signature concatenated with original message.
        /// </summary>
        /// <param name="signedMsg">
        /// A byte array large enough to hold the message plus QSC_SPHINCSPLUS_SIGNATURE_SIZE.
        /// </param>
        /// <param name="smsgLen">
        /// On return, the number of bytes used in signedMsg.
        /// </param>
        /// <param name="message">
        /// The original message to be signed.
        /// </param>
        /// <param name="msgLen">
        /// Number of bytes in <paramref name="message"/>.
        /// </param>
        /// <param name="privateKey">
        /// The private key array (size QSC_SPHINCSPLUS_PRIVATEKEY_SIZE).
        /// </param>
        static void Sign(array<Byte>^ signedMsg, [System::Runtime::InteropServices::Out] size_t% smsgLen, array<Byte>^ message, size_t msgLen, array<Byte>^ privateKey);

        /// <summary>
        /// Verifies a signed message with the public key, recovering the original message if valid.
        /// </summary>
        /// <param name="message">
        /// A buffer to receive the recovered message.
        /// </param>
        /// <param name="msgLen">
        /// On return, the number of bytes of the recovered message.
        /// </param>
        /// <param name="signedMsg">
        /// The signed message buffer containing signature + original message.
        /// </param>
        /// <param name="smsgLen">
        /// Number of bytes in signedMsg.
        /// </param>
        /// <param name="publicKey">
        /// The public verification-key array (size QSC_SPHINCSPLUS_PUBLICKEY_SIZE).
        /// </param>
        /// <returns>
        /// True if verification succeeds, otherwise false.
        /// </returns>
        static bool Verify(array<Byte>^ message, [System::Runtime::InteropServices::Out] size_t% msgLen, array<Byte>^ signedMsg, size_t smsgLen, array<Byte>^ publicKey);
    };
}

#endif
