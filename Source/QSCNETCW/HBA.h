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

#ifndef QSCNETCW_HBA_H
#define QSCNETCW_HBA_H

#include "Common.h"
#include "..\QSC\aes.h"

namespace QSCNETCW
{
	/// <summary>
    /// Provides a managed wrapper for the HBA-256 AEAD scheme, which combines AES-256 in CTR mode with KMAC or HMAC for authentication.
    /// This class wraps the <c>qsc_aes_hba256_state</c> and related functions from the QSC library.
    /// </summary>
    public ref class HBA256
    {
    public:
        /// <summary>
        /// Constructs a new instance of the HBA256 wrapper and allocates the native state.
        /// </summary>
        HBA256();

        /// <summary>
        /// Destructor that disposes the native HBA-256 state.
        /// </summary>
        ~HBA256();

        /// <summary>
        /// Finalizer that disposes the native HBA-256 state if not already done.
        /// </summary>
        !HBA256();

        /// <summary>
        /// Initializes the HBA-256 state for authenticated encryption or decryption.
        /// </summary>
        /// <param name="key">Managed byte array containing the AES key.</param>
        /// <param name="nonce">Managed byte array containing the nonce or IV.</param>
        /// <param name="info">An optional byte array for additional key information.</param>
        /// <param name="encrypt">
        /// <c>true</c> for encryption mode, <c>false</c> for decryption mode.
        /// </param>
        /// <returns>
        /// <c>true</c> if initialization succeeds; otherwise <c>false</c>.
        /// </returns>
        bool Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encrypt);

        /// <summary>
        /// Sets the associated (non-encrypted) data for HBA-256.
        /// This data is authenticated but not encrypted.
        /// </summary>
        /// <param name="data">Managed byte array containing the associated data.</param>
        /// <param name="length">Number of bytes of associated data.</param>
        /// <returns>
        /// <c>true</c> if the associated data is set successfully; otherwise <c>false</c>.
        /// </returns>
        bool SetAssociated(array<Byte>^ data, size_t length);

        /// <summary>
        /// Transforms data using HBA-256. 
        /// In encryption mode, it encrypts the input and appends a MAC; in decryption mode, it verifies the MAC before decrypting.
        /// </summary>
        /// <param name="output">Buffer for encrypted or decrypted data.</param>
        /// <param name="input">Input data (plaintext for encryption or ciphertext + MAC for decryption).</param>
        /// <param name="length">Length of the data to encrypt or decrypt.</param>
        /// <returns>
        /// <c>true</c> if the operation succeeds and the MAC is valid (in decryption); otherwise <c>false</c>.
        /// </returns>
        bool Transform(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Erases the native HBA-256 state, clearing sensitive information.
        /// </summary>
        void Destroy();

    private:
        qsc_aes_hba256_state* m_state;
        bool m_isInitialized;
    };
}

#endif