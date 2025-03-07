#ifndef QSCNETCW_AES_H
#define QSCNETCW_AES_H

#include "Common.h"
#include "..\QSC\aes.h"

namespace QSCNETCW
{
    /// <summary>
    /// Specifies the supported AES cipher types (AES-128 or AES-256).
    /// </summary>
    public enum class AesCipherType : unsigned int
    {
        /// <summary>Represents AES-128 (128-bit key).</summary>
        Aes128 = qsc_aes_cipher_128,

        /// <summary>Represents AES-256 (256-bit key).</summary>
        Aes256 = qsc_aes_cipher_256
    };

    /// <summary>
    /// Provides a managed wrapper around the QSC AES functionality.
    /// 
    /// This class allows you to initialize the AES state for either encryption or decryption,
    /// and to perform AES operations such as CBC and CTR transforms. Internally, it uses
    /// the <c>qsc_aes_state</c> structure from the native QSC library.
    /// </summary>
    public ref class AES
    {
    public:
        /// <summary>
        /// Initializes an instance of the AES wrapper and allocates the native state.
        /// </summary>
        AES();

        /// <summary>
        /// Destructor that disposes the native AES state.
        /// </summary>
        ~AES();

        /// <summary>
        /// Finalizer that disposes the native AES state if not already done.
        /// </summary>
        !AES();

        /// <summary>
        /// Sets up the AES state with the specified key parameters.
        /// </summary>
        /// <param name="key">Managed byte array containing the AES key.</param>
        /// <param name="nonce">Managed byte array containing the nonce or IV.</param>
        /// <param name="info">An optional managed byte array for additional key information.</param>
        /// <param name="encryption">
        /// If <c>true</c>, initializes for encryption; otherwise for decryption. Note that for CTR mode,
        /// AES is always effectively in encryption mode.
        /// </param>
        /// <param name="ctype">
        /// Specifies whether to use AES-128 or AES-256.
        /// </param>
        /// <returns>
        /// <c>true</c> if initialization succeeds; otherwise <c>false</c>.
        /// </returns>
        bool Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encryption, AesCipherType ctype);

        /// <summary>
        /// Performs AES encryption in CBC mode, applying PKCS#7 padding automatically.
        /// </summary>
        /// <param name="output">Buffer to receive the ciphertext. Must be large enough to hold <paramref name="length"/> bytes.</param>
        /// <param name="input">The plaintext data.</param>
        /// <param name="length">Number of bytes to encrypt.</param>
        /// <returns>
        /// <c>true</c> if the encryption succeeds; otherwise <c>false</c>.
        /// </returns>
        bool CBCEncrypt(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Performs AES decryption in CBC mode, removing PKCS#7 padding. 
        /// The actual plaintext size is returned in <paramref name="outputLength"/>.
        /// </summary>
        /// <param name="output">Buffer to receive the decrypted bytes.</param>
        /// <param name="outputLength">Receives the number of valid plaintext bytes.</param>
        /// <param name="input">The ciphertext data to be decrypted.</param>
        /// <param name="length">Number of ciphertext bytes to decrypt.</param>
        /// <returns>
        /// <c>true</c> if the decryption succeeds; otherwise <c>false</c>.
        /// </returns>
        bool CBCDecrypt(array<Byte>^ output, size_t% outputLength, array<Byte>^ input, size_t length);

        /// <summary>
        /// Transforms data using AES in CTR mode with a big-endian counter.
        /// Encryption and decryption are the same in CTR mode.
        /// </summary>
        /// <param name="output">Buffer to receive the transformed data.</param>
        /// <param name="input">The data to encrypt or decrypt.</param>
        /// <param name="length">Number of bytes to process.</param>
        /// <returns>
        /// <c>true</c> if the operation succeeds; otherwise <c>false</c>.
        /// </returns>
        bool CTRBETransform(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Transforms data using AES in CTR mode with a little-endian counter.
        /// Encryption and decryption are the same in CTR mode.
        /// </summary>
        /// <param name="output">Buffer to receive the transformed data.</param>
        /// <param name="input">The data to encrypt or decrypt.</param>
        /// <param name="length">Number of bytes to process.</param>
        /// <returns>
        /// <c>true</c> if the operation succeeds; otherwise <c>false</c>.
        /// </returns>
        bool CTRLETransform(array<Byte>^ output, array<Byte>^ input, size_t length);

        /// <summary>
        /// Erases the native AES state, clearing sensitive information.
        /// </summary>
        void Destroy();

    private:
        qsc_aes_state* m_state;
        bool m_isInitialized;
    };
}

#endif