#include "SCB.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    SCB::SCB()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_scb_state();
    }

    SCB::~SCB()
    {
        this->!SCB();
    }

    SCB::!SCB()
    {
        Destroy();
    }

    void SCB::Initialize(array<Byte>^ seed, size_t seedLength, array<Byte>^ info, size_t infoLength, size_t cpuCost, size_t memCost)
    {
        if (m_isInitialized)
        {
            Destroy();
        }

        if (seed != nullptr && seed->LongLength >= static_cast<long>(seedLength))
        {
            pin_ptr<Byte> pinnedSeed = &seed[0];
            const uint8_t* infPtr = nullptr;
            size_t infLen = 0;

            if (info != nullptr && info->LongLength >= static_cast<long>(infoLength))
            {
                pin_ptr<Byte> pinnedInfo = &info[0];
                infPtr = pinnedInfo;
                infLen = infoLength;
            }

            qsc_scb_initialize(m_state, pinnedSeed, seedLength, infPtr, infLen, cpuCost, memCost);
            m_isInitialized = true;
        }
    }

    void SCB::Generate(array<Byte>^ output, size_t outLength)
    {
        if (m_isInitialized == true && output != nullptr)
        {
            if (output->LongLength >= static_cast<long>(outLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                qsc_scb_generate(m_state, pinnedOut, outLength);
            }
        }
    }

    void SCB::Update(array<Byte>^ seed, size_t seedLength)
    {
        if (m_isInitialized == true && seed != nullptr)
        {
            if (seed->LongLength >= static_cast<long>(seedLength))
            {
                pin_ptr<Byte> pinnedSeed = &seed[0];
                qsc_scb_update(m_state, pinnedSeed, seedLength);
            }
        }
    }

    void SCB::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_scb_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}
