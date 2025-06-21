#include "SHA3.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    //
    // SHA3
    //

    void SHA3::Compute128(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA3_128_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha3_compute128(pinnedOut, pinnedMsg, msgLen);
        }
    }

    void SHA3::Compute256(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA3_256_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha3_compute256(pinnedOut, pinnedMsg, msgLen);
        }
    }

    void SHA3::Compute512(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA3_512_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha3_compute512(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //
    // SHAKE
    //

    void SHAKE::Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_shake128_compute(pinnedOut, outLen, pinnedKey, keyLen);
        }
    }

    void SHAKE::Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_shake256_compute(pinnedOut, outLen, pinnedKey, keyLen);
        }
    }

    void SHAKE::Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_shake512_compute(pinnedOut, outLen, pinnedKey, keyLen);
        }
    }

    //
    // CSHAKE
    //

    void CSHAKE::Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = nullptr;
            pin_ptr<Byte> pinnedName = nullptr;
            pin_ptr<Byte> pinnedCust = nullptr;

            const uint8_t* namePtr = nullptr;
            const uint8_t* custPtr = nullptr;

            if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
            {
                pinnedKey = &key[0];
            }

            if (name != nullptr && name->LongLength >= static_cast<long>(nameLen))
            {
                pinnedName = &name[0];
                namePtr = pinnedName;
            }

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_cshake128_compute(pinnedOut, outLen, pinnedKey, keyLen, namePtr, nameLen, custPtr, custLen);
        }
    }

    void CSHAKE::Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = nullptr;
            pin_ptr<Byte> pinnedName = nullptr;
            pin_ptr<Byte> pinnedCust = nullptr;

            const uint8_t* namePtr = nullptr;
            const uint8_t* custPtr = nullptr;

            if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
            {
                pinnedKey = &key[0];
            }

            if (name != nullptr && name->LongLength >= static_cast<long>(nameLen))
            {
                pinnedName = &name[0];
                namePtr = pinnedName;
            }

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_cshake256_compute(pinnedOut, outLen, pinnedKey, keyLen, namePtr, nameLen, custPtr, custLen);
        }
    }

    void CSHAKE::Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = nullptr;
            pin_ptr<Byte> pinnedName = nullptr;
            pin_ptr<Byte> pinnedCust = nullptr;

            const uint8_t* namePtr = nullptr;
            const uint8_t* custPtr = nullptr;

            if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
            {
                pinnedKey = &key[0];
            }

            if (name != nullptr && name->LongLength >= static_cast<long>(nameLen))
            {
                pinnedName = &name[0];
                namePtr = pinnedName;
            }

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_cshake512_compute(pinnedOut, outLen, pinnedKey, keyLen, namePtr, nameLen, custPtr, custLen);
        }
    }

    //
    // KMAC
    //

    void KMAC::Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* custPtr = nullptr;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pin_ptr<Byte> pinnedCust = &custom[0];

                custPtr = pinnedCust;
            }

            qsc_kmac128_compute(pinnedOut, outLen, pinnedMsg, msgLen, pinnedKey, keyLen, custPtr, custLen);
        }
    }

    void KMAC::Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* custPtr = nullptr;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pin_ptr<Byte> pinnedCust = &custom[0];

                custPtr = pinnedCust;
            }

            qsc_kmac256_compute(pinnedOut, outLen, pinnedMsg, msgLen, pinnedKey, keyLen, custPtr, custLen);
        }
    }

    void KMAC::Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* custPtr = nullptr;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pin_ptr<Byte> pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_kmac512_compute(pinnedOut, outLen, pinnedMsg, msgLen, pinnedKey, keyLen, custPtr, custLen);
        }
    }
}
