#include "SecRand.h"

namespace QSCNETCW
{
    SecRand::SecRand()
        : m_isInitialized(false)
    {
    }

    SecRand::~SecRand()
    {
        this->!SecRand();
    }

    SecRand::!SecRand()
    {
        Destroy();
    }

    void SecRand::Initialize(array<Byte>^ seed, size_t seedLength, array<Byte>^ custom, size_t custLength)
    {
        if (seed != nullptr && seed->LongLength >= static_cast<long>(seedLength))
        {
            pin_ptr<Byte> pinnedSeed = &seed[0];
            const uint8_t* customPtr = nullptr;
            size_t customLen = 0;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLength))
            {
                pin_ptr<Byte> pinnedCustom = &custom[0];
                customPtr = pinnedCustom;
                customLen = custLength;
            }

            qsc_secrand_initialize(pinnedSeed, seedLength, customPtr, customLen);
            m_isInitialized = true;
        }
    }

    void SecRand::Destroy()
    {
        if (m_isInitialized)
        {
            qsc_secrand_dispose();
            m_isInitialized = false;
        }
    }

    bool SecRand::Generate(array<Byte>^ output, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                res = qsc_secrand_generate(pinnedOut, length);
            }
        }

        return res;
    }

    SByte SecRand::NextChar()
    {
        SByte res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<SByte>(qsc_secrand_next_char());
        }

        return res;
    }

    Byte SecRand::NextUChar()
    {
        Byte res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Byte>(qsc_secrand_next_uchar());
        }

        return res;
    }

    double SecRand::NextDouble()
    {
        double res;

        res = 0.0;

        if (m_isInitialized == true)
        {
            res = qsc_secrand_next_double();
        }

        return res;
    }

    Int16 SecRand::NextInt16()
    {
        Int16 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int16>(qsc_secrand_next_int16());
        }

        return res;
    }

    Int16 SecRand::NextInt16Max(Int16 maximum)
    {
        Int16 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int16>(qsc_secrand_next_int16_max(maximum));
        }

        return res;
    }

    Int16 SecRand::NextInt16MaxMin(Int16 maximum, Int16 minimum)
    {
        Int16 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int16>(qsc_secrand_next_int16_maxmin(maximum, minimum));
        }

        return res;
    }

    UInt16 SecRand::NextUInt16()
    {
        UInt16 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt16>(qsc_secrand_next_uint16());
        }

        return res;
    }

    UInt16 SecRand::NextUInt16Max(UInt16 maximum)
    {
        UInt16 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt16>(qsc_secrand_next_uint16_max(maximum));
        }

        return res;
    }

    UInt16 SecRand::NextUInt16MaxMin(UInt16 maximum, UInt16 minimum)
    {
        UInt16 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt16>(qsc_secrand_next_uint16_maxmin(maximum, minimum));
        }

        return res;
    }

    Int32 SecRand::NextInt32()
    {
        Int32 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int32>(qsc_secrand_next_int32());
        }

        return res;
    }

    Int32 SecRand::NextInt32Max(Int32 maximum)
    {
        Int32 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int32>(qsc_secrand_next_int32_max(maximum));
        }

        return res;
    }

    Int32 SecRand::NextInt32MaxMin(Int32 maximum, Int32 minimum)
    {
        Int32 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int32>(qsc_secrand_next_int32_maxmin(maximum, minimum));
        }

        return res;
    }

    UInt32 SecRand::NextUInt32()
    {
        UInt32 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt32>(qsc_secrand_next_uint32());
        }

        return res;
    }

    UInt32 SecRand::NextUInt32Max(UInt32 maximum)
    {
        UInt32 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt32>(qsc_secrand_next_uint32_max(maximum));
        }

        return res;
    }

    UInt32 SecRand::NextUInt32MaxMin(UInt32 maximum, UInt32 minimum)
    {
        UInt32 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt32>(qsc_secrand_next_uint32_maxmin(maximum, minimum));
        }

        return res;
    }

    Int64 SecRand::NextInt64()
    {
        Int64 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int64>(qsc_secrand_next_int64());
        }

        return res;
    }

    Int64 SecRand::NextInt64Max(Int64 maximum)
    {
        Int64 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int64>(qsc_secrand_next_int64_max(maximum));
        }

        return res;
    }

    Int64 SecRand::NextInt64MaxMin(Int64 maximum, Int64 minimum)
    {
        Int64 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<Int64>(qsc_secrand_next_int64_maxmin(maximum, minimum));
        }

        return res;
    }

    UInt64 SecRand::NextUInt64()
    {
        UInt64 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt64>(qsc_secrand_next_uint64());
        }

        return res;
    }

    UInt64 SecRand::NextUInt64Max(UInt64 maximum)
    {
        UInt64 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt64>(qsc_secrand_next_uint64_max(maximum));
        }

        return res;
    }

    UInt64 SecRand::NextUInt64MaxMin(UInt64 maximum, UInt64 minimum)
    {
        UInt64 res;

        res = 0;

        if (m_isInitialized == true)
        {
            res = static_cast<UInt64>(qsc_secrand_next_uint64_maxmin(maximum, minimum));
        }

        return res;
    }
}
