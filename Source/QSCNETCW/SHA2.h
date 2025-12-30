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
