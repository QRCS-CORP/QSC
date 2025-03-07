#include "ACP.h"

namespace QSCNETCW 
{

    bool ACP::GenerateRandomBytes(array<Byte>^ buffer, size_t length)
    {
        bool res;

        res = false;

        if (buffer != nullptr && length <= static_cast<size_t>(buffer->LongLength) && length <= QSC_ACP_SEED_MAX)
        {
            // Pin the array so the garbage collector does not relocate it
            pin_ptr<Byte> pinnedBuffer = &buffer[0];

            // Call the native function to generate random bytes
            res = qsc_acp_generate(pinnedBuffer, length);
        }

        return res;
    }

    uint16_t ACP::GetRandomUInt16()
    {
        return qsc_acp_uint16();
    }

    uint32_t ACP::GetRandomUInt32()
    {
        return qsc_acp_uint32();
    }

    uint64_t ACP::GetRandomUInt64()
    {
        return qsc_acp_uint64();
    }
}
