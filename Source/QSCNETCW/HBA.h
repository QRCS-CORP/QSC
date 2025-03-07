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