/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained
 * herein are proprietary to QRCS and its suppliers and may be covered by
 * U.S. and Foreign Patents, patents in process, and are protected by trade secret
 * or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSCNETCW_POLY1305_H
#define QSCNETCW_POLY1305_H

#include "Common.h"
#include "..\QSC\poly1305.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper around the Poly1305 MAC algorithm.
    /// 
    /// This class allows for both incremental (update + finalize) usage as well as
    /// one-shot computation (via the static <c>Compute</c> method).
    /// </summary>
    public ref class Poly1305
    {
    public:
        /// <summary>
        /// Constructs a Poly1305 instance by initializing the internal state with the given key.
        /// </summary>
        /// <param name="key">
        /// A managed byte array containing the 32-byte secret key (<c>QSC_POLY1305_KEY_SIZE</c>).
        /// </param>
        Poly1305(array<Byte>^ key);

        /// <summary>
        /// Destructor that disposes of the native Poly1305 state.
        /// </summary>
        ~Poly1305();

        /// <summary>
        /// Finalizer that disposes of the native Poly1305 state if not already done.
        /// </summary>
        !Poly1305();

        /// <summary>
        /// Updates the MAC state with one 16-byte block of message data.
        /// This method only absorbs exactly one block of data (16 bytes).
        /// </summary>
        /// <param name="block">
        /// A 16-byte array containing the message block.
        /// </param>
        void BlockUpdate(array<Byte>^ block);

        /// <summary>
        /// Updates the MAC state with additional message data in any size.
        /// </summary>
        /// <param name="message">
        /// The array containing the message bytes to process.
        /// </param>
        /// <param name="msglen">
        /// The number of bytes in <paramref name="message"/> to process.
        /// </param>
        void Update(array<Byte>^ message, size_t msglen);

        /// <summary>
        /// Finalizes the MAC computation and writes the 16-byte MAC to the provided array.
        /// This method resets the internal state to a finalized condition.
        /// </summary>
        /// <param name="mac">
        /// The array to receive the 16-byte MAC (<c>QSC_POLY1305_MAC_SIZE</c>).
        /// </param>
        void Finalize(array<Byte>^ mac);

        /// <summary>
        /// Resets the Poly1305 internal state to all zeros without generating a MAC.
        /// You must re-initialize if you wish to compute a new MAC after reset.
        /// </summary>
        void Reset();

        /// <summary>
        /// Computes the Poly1305 MAC of the given message with the specified 32-byte key in one shot.
        /// </summary>
        /// <param name="output">
        /// The array to receive the 16-byte MAC (<c>QSC_POLY1305_MAC_SIZE</c>).
        /// </param>
        /// <param name="message">
        /// The array containing the message to process.
        /// </param>
        /// <param name="msglen">
        /// The length of the message in <paramref name="message"/>.
        /// </param>
        /// <param name="key">
        /// The 32-byte key (<c>QSC_POLY1305_KEY_SIZE</c>).
        /// </param>
        static void Compute(array<Byte>^ output, array<Byte>^ message, size_t msglen, array<Byte>^ key);

        /// <summary>
        /// Verifies a given MAC against a message and key by recomputing and comparing.
        /// </summary>
        /// <param name="code">
        /// The 16-byte MAC code to verify (<c>QSC_POLY1305_MAC_SIZE</c>).
        /// </param>
        /// <param name="message">
        /// The array containing the message data.
        /// </param>
        /// <param name="msglen">
        /// The length of the message.
        /// </param>
        /// <param name="key">
        /// The 32-byte key.
        /// </param>
        /// <returns>
        /// An integer result where 0 typically means equality/success, and nonzero indicates failure.
        /// </returns>
        static int Verify(array<Byte>^ code, array<Byte>^ message, size_t msglen, array<Byte>^ key);

    private:
        qsc_poly1305_state* m_state;
        bool m_isInitialized;
    };
}

#endif
