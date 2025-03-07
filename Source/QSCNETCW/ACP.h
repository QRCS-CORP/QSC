#ifndef QSCNETCW_ACP_H
#define QSCNETCW_ACP_H

#include "Common.h"
#include "..\QSC\acp.h"

namespace QSCNETCW 
{
    /// <summary>
    /// Provides a managed wrapper for the Auto Entropy Collection Provider (ACP) from the QSC cryptographic library.
    /// 
    /// The ACP aggregates entropy from various system sources including hardware randomness (via RDRAND),
    /// system statistics, and platform-specific providers (e.g., CryptGenRandom on Windows and /dev/urandom on POSIX systems).
    /// The collected entropy is processed using the cSHAKE-512 algorithm to generate cryptographically secure pseudorandom data.
    /// </summary>
    public ref class ACP abstract sealed
    {
    public:

        /// <summary>
        /// Generates cryptographically secure random bytes and stores them in the specified buffer.
        /// </summary>
        /// <param name="buffer">A managed array of bytes to receive the random data.</param>
        /// <param name="length">The number of random bytes to generate and store in the buffer.</param>
        /// <returns>
        /// A boolean indicating success (<c>true</c>) or failure (<c>false</c>).
        /// </returns>
        static bool GenerateRandomBytes(array<Byte>^ buffer, size_t length);

        /// <summary>
        /// Generates a cryptographically secure random 16-bit unsigned integer.
        /// </summary>
        /// <returns>A 16-bit unsigned integer derived from high-quality random data.</returns>
        static uint16_t GetRandomUInt16();

        /// <summary>
        /// Generates a cryptographically secure random 32-bit unsigned integer.
        /// </summary>
        /// <returns>A 32-bit unsigned integer derived from high-quality random data.</returns>
        static uint32_t GetRandomUInt32();

        /// <summary>
        /// Generates a cryptographically secure random 64-bit unsigned integer.
        /// </summary>
        /// <returns>A 64-bit unsigned integer derived from high-quality random data.</returns>
        static uint64_t GetRandomUInt64();
    };
}

#endif
