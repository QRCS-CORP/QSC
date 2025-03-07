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
 */

#ifndef QSCNETCW_ENCODING_H
#define QSCNETCW_ENCODING_H

#include "Common.h"
#include "..\QSC\encoding.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides wrappers for encoding and decoding operations:
    /// Base64, Hex, PEM, and BER/DER.
    /// </summary>
    public ref class Encoding abstract sealed
    {
    public:

        // -- Base64 --

        /// <summary>
        /// Decodes a Base64 string into a byte array.
        /// </summary>
        /// <param name="output">
        /// A byte array to receive the decoded data.
        /// </param>
        /// <param name="outputLength">
        /// The maximum capacity of <paramref name="output"/>.
        /// </param>
        /// <param name="input">
        /// The Base64-encoded input string.
        /// </param>
        /// <param name="inputLength">
        /// The length of <paramref name="input"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> on success; <c>false</c> otherwise.
        /// </returns>
        static bool Base64Decode(array<Byte>^ output, size_t outputLength, String^ input, size_t inputLength);

        /// <summary>
        /// Returns the decoded size (in bytes) of the specified Base64 string.
        /// </summary>
        static size_t Base64DecodedSize(String^ input, size_t length);

        /// <summary>
        /// Encodes a byte array into a Base64 string.
        /// </summary>
        /// <param name="output">
        /// A managed string buffer to store the encoded Base64.
        /// </param>
        /// <param name="outputCapacity">
        /// The maximum characters that <paramref name="output"/> can hold.
        /// </param>
        /// <param name="input">
        /// The byte array to encode.
        /// </param>
        /// <param name="inputLength">
        /// The number of bytes in <paramref name="input"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> on success; <c>false</c> if buffer is too small.
        /// </returns>
        static bool Base64Encode(String^% output, size_t outputCapacity, array<Byte>^ input, size_t inputLength);

        /// <summary>
        /// Returns the size of the character array required to hold the Base64-encoded string.
        /// </summary>
        static size_t Base64EncodedSize(size_t length);

        /// <summary>
        /// Checks if a single character is valid within Base64 encoding.
        /// </summary>
        static bool Base64IsValidChar(char value);

        // -- Hex --

        /// <summary>
        /// Decodes a hexadecimal string into binary data.
        /// </summary>
        static bool HexDecode(String^ input, size_t inputLength, array<Byte>^ output, size_t outputLength, size_t% decodedLength);

        /// <summary>
        /// Encodes binary data into a hex string.
        /// </summary>
        static bool HexEncode(array<Byte>^ input, size_t inputLength, String^% output, size_t outputCapacity);

        // -- PEM --

        /// <summary>
        /// Decodes a PEM-formatted string into binary data.
        /// </summary>
        static bool PemDecode(String^ input, array<Byte>^ output, size_t outputLength, size_t% decodedLength);

        /// <summary>
        /// Encodes binary data into a PEM-formatted string.
        /// </summary>
        static bool PemEncode(String^ label, String^% output, size_t outputCapacity, array<Byte>^ data, size_t dataLength);

        // -- BER/DER (raw pointers) --

        /// <summary>
        /// Decodes a BER element from the provided buffer, returning a pointer to a newly allocated element.
        /// </summary>
        static IntPtr BERDecodeElement(array<Byte>^ buffer, size_t bufferLength, size_t% consumed);

        /// <summary>
        /// Encodes a BER element (given as pointer) into the output buffer.
        /// </summary>
        static size_t BEREncodeElement(IntPtr elementPtr, array<Byte>^ output, size_t outputLength);

        /// <summary>
        /// Decodes a DER element from the provided buffer, returning a pointer to a newly allocated element.
        /// </summary>
        static IntPtr DERDecodeElement(array<Byte>^ buffer, size_t bufferLength, size_t% consumed);

        /// <summary>
        /// Encodes an ASN.1 element using DER. If indefinite length is used, it fails (returns 0).
        /// </summary>
        static size_t DEREncodeElement(IntPtr elementPtr, array<Byte>^ output, size_t outputLength);

        /// <summary>
        /// Frees the memory used by a BER element pointer returned by decode calls.
        /// </summary>
        static void FreeBERElement(IntPtr elementPtr);
    };
}

#endif
