#include "CSP.h"

namespace QSCNETCW
{
    bool CSP::Generate(array<Byte>^ output, size_t length)
    {
        bool res;

        res = false;

        if (output != nullptr && length <= static_cast<size_t>(output->LongLength) && length <= QSC_CSP_SEED_MAX)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            res = qsc_csp_generate(pinnedOut, length);
        }

        return res;
    }

    UInt16 CSP::GetRandomUInt16()
    {
        UInt16 val;

        val = static_cast<UInt16>(qsc_csp_uint16());

        return val;
    }

    UInt32 CSP::GetRandomUInt32()
    {
        UInt32 val;

        val = static_cast<UInt32>(qsc_csp_uint32());

        return val;
    }

    UInt64 CSP::GetRandomUInt64()
    {
        UInt64 val;

        val = static_cast<UInt64>(qsc_csp_uint64());

        return val;
    }
}
