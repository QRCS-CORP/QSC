#include "SHA2.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    //----------------
    // SHA2-256
    //----------------

    void SHA256::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA2_256_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha256_compute(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //----------------
    // SHA2-384
    //----------------

    void SHA384::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA2_384_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha384_compute(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //----------------
    // SHA2-512
    //----------------

    void SHA512::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA2_512_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha512_compute(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //----------------
    // HMAC-256
    //----------------

    void HMAC256::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= QSC_HMAC_256_MAC_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_hmac256_compute(pinnedOut, pinnedMsg, msgLen, pinnedKey, keyLen);
        }
    }

    //----------------
    // HMAC-512
    //----------------

    void HMAC512::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= QSC_HMAC_512_MAC_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_hmac512_compute(pinnedOut, pinnedMsg, msgLen, pinnedKey, keyLen);
        }
    }

    //----------------
    // HKDF
    //----------------

    void HKDF::HKDF256Expand(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ info, size_t infoLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* infPtr = nullptr;

            if (info != nullptr && infoLen > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];

                infPtr = pinnedInfo;
            }

            qsc_hkdf256_expand(pinnedOut, outLen, pinnedKey, keyLen, infPtr, infoLen);
        }
    }

    void HKDF::HKDF256Extract(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ salt, size_t saltLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* sPtr = nullptr;

            if (salt != nullptr && saltLen > 0)
            {
                pin_ptr<Byte> pinnedSalt = &salt[0];

                sPtr = pinnedSalt;
            }

            qsc_hkdf256_extract(pinnedOut, outLen, pinnedKey, keyLen, sPtr, saltLen);
        }
    }

    void HKDF::HKDF512Expand(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ info, size_t infoLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* infPtr = nullptr;

            if (info != nullptr && infoLen > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];

                infPtr = pinnedInfo;
            }

            qsc_hkdf512_expand(pinnedOut, outLen, pinnedKey, keyLen, infPtr, infoLen);
        }
    }

    void HKDF::HKDF512Extract(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ salt, size_t saltLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* sPtr = nullptr;

            if (salt != nullptr && saltLen > 0)
            {
                pin_ptr<Byte> pinnedSalt = &salt[0];

                sPtr = pinnedSalt;
            }

            qsc_hkdf512_extract(pinnedOut, outLen, pinnedKey, keyLen, sPtr, saltLen);
        }
    }
}
