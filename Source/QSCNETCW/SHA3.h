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
        None = 0x00,

        /// <summary>
        /// Keccak 128-bit rate (168 bytes)
        /// </summary>
        Rate128 = 0xA8,

        /// <summary>
        /// Keccak 256-bit rate (136 bytes)
        /// </summary>
        Rate256 = 0x88,

        /// <summary>
        /// Keccak 512-bit rate (72 bytes)
        /// </summary>
        Rate512 = 0x48
    };

    //-------------------------
    // SHA3
    //-------------------------

    /// <summary>
    /// Non-static class for an incremental SHA3 process.
    /// Use <c>Initialize</c>, <c>Update</c>, then <c>Finalize</c>.
    /// </summary>
    public ref class SHA3
    {
    public:
        /// <summary>
        /// Constructs an uninitialized SHA3 instance. Must call <c>Initialize</c> before use.
        /// </summary>
        SHA3();

        /// <summary>
        /// Destructor calls <c>Dispose</c>.
        /// </summary>
        ~SHA3();

        /// <summary>
        /// Finalizer calls <c>Dispose</c>.
        /// </summary>
        !SHA3();

        /// <summary>
        /// Initializes the internal state for a given rate (128, 256, or 512).
        /// </summary>
        /// <param name="rate">One of the <see cref="KeccakRate"/> values.</param>
        void Initialize(KeccakRate rate);

        /// <summary>
        /// Updates the hash with the specified message data.
        /// </summary>
        /// <param name="message">Data array.</param>
        /// <param name="msgLen">Number of bytes to process.</param>
        void Update(array<Byte>^ message, size_t msgLen);

        /// <summary>
        /// Finalizes the hash, writing the digest to <paramref name="output"/>.
        /// Resets the instance.
        /// </summary>
        /// <param name="output">Byte array to receive the digest. Must be sized to match the rate: 16,32, or 64 bytes if you want the entire output.</param>
        void Finalize(array<Byte>^ output);

        /// <summary>
        /// Disposes the internal state. The instance cannot be reused.
        /// </summary>
        void Destroy();

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

    private:
        qsc_keccak_state* m_state;
        KeccakRate m_rate;
        bool m_isInitialized;
    };

    //-------------------------
    // SHAKE
    //-------------------------

    /// <summary>
    /// Non-static class for an incremental SHAKE usage (long form).
    /// Use <c>Initialize</c>, then <c>SqueezeBlocks</c> to generate output.
    /// </summary>
    public ref class SHAKE
    {
    public:
        SHAKE();
        ~SHAKE();
        !SHAKE();

        /// <summary>
        /// Initializes the SHAKE state with the specified key and rate.
        /// </summary>
        void Initialize(KeccakRate rate, array<Byte>^ key, size_t keyLen);

        /// <summary>
        /// Squeezes output blocks from the state, writing to <paramref name="output"/>.
        /// Each block is <c>rate</c> bytes for the chosen bit rate.
        /// </summary>
        /// <param name="output">Byte array to receive the data, must be multiple of block size.</param>
        /// <param name="nblocks">Number of blocks to output.</param>
        void SqueezeBlocks(array<Byte>^ output, size_t nblocks);

        /// <summary>
        /// Disposes the internal Keccak state.
        /// </summary>
        void Destroy();

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

    private:
        qsc_keccak_state* m_state;
        KeccakRate m_rate;
        bool m_isInitialized;
    };

    //-------------------------
    // cSHAKE
    //-------------------------

    /// <summary>
    /// Non-static class for an incremental cSHAKE usage (long form).
    /// Allows user to absorb name, custom, and key, then squeeze output blocks.
    /// </summary>
    public ref class CSHAKE
    {
    public:
        CSHAKE();
        ~CSHAKE();
        !CSHAKE();

        /// <summary>
        /// Initializes the cSHAKE state with key, name, and custom arrays.
        /// </summary>
        void Initialize(KeccakRate rate, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Squeezes output blocks from the cSHAKE state.
        /// </summary>
        void SqueezeBlocks(array<Byte>^ output, size_t nblocks);

        /// <summary>
        /// Update the cSHAKE state (absorbing more key data).
        /// Typically called before final squeezes.
        /// </summary>
        void Update(array<Byte>^ key, size_t keyLen);

        /// <summary>
        /// Disposes the internal state.
        /// </summary>
        void Destroy();

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

    private:
        qsc_keccak_state* m_state;
        KeccakRate m_rate;
        bool m_isInitialized;
    };

    //-------------------------
    // KMAC
    //-------------------------

    /// <summary>
    /// Non-static class for an incremental KMAC usage.
    /// Allows user to absorb message in multiple updates, then finalize to produce the MAC.
    /// </summary>
    public ref class KMAC
    {
    public:
        KMAC();
        ~KMAC();
        !KMAC();

        /// <summary>
        /// Initializes the KMAC state with a key + custom string, e.g. KMAC-256 or KMAC-512.
        /// </summary>
        void Initialize(KeccakRate rate, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Updates the KMAC state with message data.
        /// </summary>
        void Update(array<Byte>^ message, size_t msgLen);

        /// <summary>
        /// Finalizes the MAC, writing up to <paramref name="outLen"/> bytes into <paramref name="output"/>.
        /// </summary>
        bool Finalize(array<Byte>^ output, size_t outLen);

        /// <summary>
        /// Disposes the internal state.
        /// </summary>
        void Destroy();

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

    private:
        qsc_keccak_state* m_state;
        KeccakRate m_rate;
        bool m_isInitialized;
    };
}

#endif // QSCNETCW_SHA3_H
