#include "RDP.h"

namespace QSCNETCW
{
    bool RDP::Generate(array<Byte>^ output, size_t length)
    {
        bool res;

        res = false;

        if (output != nullptr && length <= static_cast<size_t>(output->LongLength) && length <= QSC_RDP_SEED_MAX)
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            res = qsc_rdp_generate(pinnedOut, length);
        }

        return res;
    }

    System::UInt16 RDP::GetUInt16()
    {
        return static_cast<System::UInt16>(qsc_rdp_uint16());
    }

    System::UInt32 RDP::GetUInt32()
    {
        return static_cast<System::UInt32>(qsc_rdp_uint32());
    }

    System::UInt64 RDP::GetUInt64()
    {
        return static_cast<System::UInt64>(qsc_rdp_uint64());
    }
}
