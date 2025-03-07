#include "HCG.h"

namespace QSCNETCW
{
    HCG::HCG()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_hcg_state();
        m_isInitialized = true;
    }

    HCG::~HCG()
    {
        Destroy();
    }

    HCG::!HCG()
    {
        Destroy();
    }

    bool HCG::Initialize(array<Byte>^ seed, size_t seedLength, array<Byte>^ info, size_t infoLength, bool pres)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && m_state != nullptr && seed != nullptr)
        {
            if (seed->LongLength >= static_cast<long>(seedLength))
            {
                pin_ptr<Byte> pinnedSeed = &seed[0];
                const uint8_t* pinfo = nullptr;
                size_t ilen = 0;

                if (info != nullptr && info->LongLength >= static_cast<long>(infoLength))
                {
                    pin_ptr<Byte> pinnedInfo = &info[0];
                    pinfo = pinnedInfo;
                    ilen = infoLength;
                }

                qsc_hcg_initialize(m_state, pinnedSeed, seedLength, pinfo, ilen, pres);
                res = true;
            }
        }

        return res;
    }

    bool HCG::Generate(array<Byte>^ output, size_t outputLength)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && m_state != nullptr && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outputLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                qsc_hcg_generate(m_state, pinnedOut, outputLength);
                res = true;
            }
        }

        return res;
    }

    bool HCG::Update(array<Byte>^ seed, size_t seedLength)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && m_state != nullptr && seed != nullptr)
        {
            if (seed->LongLength >= static_cast<long>(seedLength))
            {
                pin_ptr<Byte> pinnedSeed = &seed[0];
                qsc_hcg_update(m_state, pinnedSeed, seedLength);
                res = true;
            }
        }

        return res;
    }

    void HCG::Destroy()
    {
        if (m_isInitialized == true && m_state != nullptr)
        {
            qsc_hcg_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}