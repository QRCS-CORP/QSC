#include "CSG.h"

namespace QSCNETCW
{
    CSG::CSG()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_csg_state();
    }

    CSG::~CSG()
    {
        Destroy();
    }

    CSG::!CSG()
    {
        Destroy();
    }

    bool CSG::Initialize(array<Byte>^ seed, array<Byte>^ info, bool predres)
    {
        bool res;

        res = false;

        if (seed != nullptr)
        {
            pin_ptr<Byte> pinnedSeed = &seed[0];
            size_t seedLen = static_cast<size_t>(seed->LongLength);

            const uint8_t* infPtr = nullptr;
            size_t infLen = 0;

            if (info != nullptr && info->LongLength > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];

                infPtr = pinnedInfo;
                infLen = static_cast<size_t>(info->LongLength);
            }

            qsc_csg_initialize(m_state, pinnedSeed, seedLen, infPtr, infLen, predres);
            m_isInitialized = true;
            res = true;
        }

        return res;
    }

    bool CSG::Generate(array<Byte>^ output, size_t otplen)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr)
        {
            if (otplen <= static_cast<size_t>(output->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];

                qsc_csg_generate(m_state, pinnedOut, otplen);
                res = true;
            }
        }

        return res;
    }

    bool CSG::Update(array<Byte>^ seed)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && seed != nullptr)
        {
            pin_ptr<Byte> pinnedSeed = &seed[0];

            size_t seedLen = static_cast<size_t>(seed->LongLength);
            qsc_csg_update(m_state, pinnedSeed, seedLen);
            res = true;
        }

        return res;
    }

    void CSG::Destroy()
    {
        if (m_state != nullptr)
        {
            qsc_csg_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}