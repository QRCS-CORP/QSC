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

#ifndef QSCNETCW_SHA3_H
#define QSCNETCW_SHA3_H

#include "Common.h"
#include "..\QSC\sha3.h"

namespace QSCNETCW
{
    /// <summary>
    /// Enumeration of Keccak / SHA3 rates: 128, 256, 512 bits
    /// </summary>
    public enum class KeccakRate : System::UInt32
    {
        /// <summary>
        /// No bit rate was selected
        /// </summary>
        None = qsc_keccak_rate_none,

        /// <summary>
        /// Keccak 128-bit rate (168 bytes)
        /// </summary>
        Rate128 = qsc_keccak_rate_128,

        /// <summary>
        /// Keccak 256-bit rate (136 bytes)
        /// </summary>
        Rate256 = qsc_keccak_rate_256,

        /// <summary>
        /// Keccak 512-bit rate (72 bytes)
        /// </summary>
        Rate512 = qsc_keccak_rate_512
    };

    //-------------------------
    // SHA3
    //-------------------------

    /// <summary>
    /// Static class for an SHA3 process.
    /// </summary>
    public ref class SHA3 abstract sealed
    {
    public:

        /// <summary>
        /// One-shot compute for short form SHA3-128, producing a 16-byte digest.
        /// </summary>
        static void Compute128(array<Byte>^ output, array<Byte>^ message, size_t msgLen);

        /// <summary>
        /// One-shot compute for short form SHA3-256, producing a 32-byte digest.
        /// </summary>
        static void Compute256(array<Byte>^ output, array<Byte>^ message, size_t msgLen);

        /// <summary>
        /// One-shot compute for short form SHA3-512, producing a 64-byte digest.
        /// </summary>
        static void Compute512(array<Byte>^ output, array<Byte>^ message, size_t msgLen);
    };

    //-------------------------
    // SHAKE
    //-------------------------

    /// <summary>
    /// Static class for SHAKE usage.
    /// </summary>
    public ref class SHAKE abstract sealed
    {
    public:

        /// <summary>
        /// Short-form compute for SHAKE-128. 
        /// </summary>
        static void Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen);

        /// <summary>
        /// Short-form compute for SHAKE-256. 
        /// </summary>
        static void Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen);

        /// <summary>
        /// Short-form compute for SHAKE-512. 
        /// </summary>
        static void Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen);
    };

    //-------------------------
    // cSHAKE
    //-------------------------

    /// <summary>
    /// Static class for cSHAKE usage.
    /// </summary>
    public ref class CSHAKE abstract sealed
    {
    public:

        /// <summary>
        /// Short-form cSHAKE-128 with name + custom.
        /// </summary>
        static void Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form cSHAKE-256 with name + custom.
        /// </summary>
        static void Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form cSHAKE-512 with name + custom.
        /// </summary>
        static void Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen);
    };

    //-------------------------
    // KMAC
    //-------------------------

    /// <summary>
    /// Static class for KMAC usage.
    /// </summary>
    public ref class KMAC abstract sealed
    {
    public:

        /// <summary>
        /// Short-form KMAC-128.
        /// </summary>
        static void Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form KMAC-256.
        /// </summary>
        static void Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form KMAC-512.
        /// </summary>
        static void Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen);
    };
}

#endif // QSCNETCW_SHA3_H
