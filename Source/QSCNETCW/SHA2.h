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

#ifndef QSCNETCW_SHA2_H
#define QSCNETCW_SHA2_H

#include "Common.h"
#include "..\QSC\sha2.h"

namespace QSCNETCW
{
    /// <summary>
    /// An static class for SHA2-256 usage.
    /// </summary>
    public ref class SHA256 abstract sealed
    {
    public:

        /// <summary>
        /// Computes a SHA2-256 digest in one call.
        /// </summary>
        /// <param name="output">32-byte buffer for the hash.</param>
        /// <param name="message">Data to hash.</param>
        /// <param name="msgLen">Length of <paramref name="message"/>.</param>
        static void Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen);
    };

    /// <summary>
    /// An static class for SHA2-384 usage.
    /// </summary>
    public ref class SHA384 abstract sealed
    {
    public:

        /// <summary>
        /// Computes a SHA2-384 digest in one call.
        /// </summary>
        /// <param name="output">48-byte buffer for the hash.</param>
        /// <param name="message">Data to hash.</param>
        /// <param name="msgLen">Length of <paramref name="message"/>.</param>
        static void Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen);
    };

    /// <summary>
    /// An static class for SHA2-512 usage.
    /// </summary>
    public ref class SHA512 abstract sealed
    {
    public:

        /// <summary>
        /// Computes a SHA2-512 digest in one call.
        /// </summary>
        /// <param name="output">64-byte buffer for the hash.</param>
        /// <param name="message">Data to hash.</param>
        /// <param name="msgLen">Length of <paramref name="message"/>.</param>
        static void Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen);
    };

    /// <summary>
    /// An static class for HMAC(SHA2-256) usage.
    /// </summary>
    public ref class HMAC256 abstract sealed
    {
    public:

        /// <summary>
        /// Computes a HMAC-256 MAC in one call.
        /// </summary>
        /// <param name="output">32-byte buffer for the hash.</param>
        /// <param name="message">Data to hash.</param>
        /// <param name="msgLen">Length of <paramref name="message"/>.</param>
        static void Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen);
    };

    /// <summary>
    /// An static class for HMAC(SHA2-512) usage.
    /// </summary>
    public ref class HMAC512 abstract sealed
    {
    public:

        /// <summary>
        /// Computes a HMAC-512 MAC in one call.
        /// </summary>
        /// <param name="output">64-byte buffer for the hash.</param>
        /// <param name="message">Data to hash.</param>
        /// <param name="msgLen">Length of <paramref name="message"/>.</param>
        static void Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen);
    };

    /// <summary>
    /// Static class for HKDF expansions or extractions using SHA2-256 or SHA2-512.
    /// </summary>
    public ref class HKDF abstract sealed
    {
    public:

        /// <summary>
        /// Computes a HKDF-256 Expansion.
        /// </summary>
        /// <param name="output">The output buffer.</param>
        /// <param name="outLen">The desired output length.</param>
        /// <param name="key">The input key.</param>
        /// <param name="keyLen">The length of the input key.</param>
        /// <param name="info">The optional info string.</param>
        /// <param name="infoLen">The length the input string.</param>
        static void HKDF256Expand(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ info, size_t infoLen);

        /// <summary>
        /// Computes a HKDF-256 Extraction.
        /// </summary>
        /// <param name="output">The output buffer.</param>
        /// <param name="outLen">The desired output length.</param>
        /// <param name="key">The input key.</param>
        /// <param name="keyLen">The length of the input key.</param>
        /// <param name="salt">The optional info string.</param>
        /// <param name="saltLen">The length the input string.</param>
        static void HKDF256Extract(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ salt, size_t saltLen);

        /// <summary>
        /// Computes a HKDF-512 Expansion in one call.
        /// </summary>
        /// <param name="output">The output buffer.</param>
        /// <param name="outLen">The desired output length.</param>
        /// <param name="key">The input key.</param>
        /// <param name="keyLen">The length of the input key.</param>
        /// <param name="info">The optional info string.</param>
        /// <param name="infoLen">The length the input string.</param>
        static void HKDF512Expand(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ info, size_t infoLen);

        /// <summary>
        /// Computes a HKDF-512 Extraction.
        /// </summary>
        /// <param name="output">The output buffer.</param>
        /// <param name="outLen">The desired output length.</param>
        /// <param name="key">The input key.</param>
        /// <param name="keyLen">The length of the input key.</param>
        /// <param name="salt">The optional info string.</param>
        /// <param name="saltLen">The length the input string.</param>
        static void HKDF512Extract(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ salt, size_t saltLen);
    };
}

#endif
