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
 *
 * Written by: John Underhill
 * Contact: john.underhill@protonmail.com
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
