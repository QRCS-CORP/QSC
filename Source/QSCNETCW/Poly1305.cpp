#include "Poly1305.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    Poly1305::Poly1305(array<Byte>^ key)
        : m_state(nullptr), m_isInitialized(false)
    {
        if (key != nullptr && key->LongLength >= QSC_POLY1305_KEY_SIZE)
        {
            m_state = new qsc_poly1305_state();
            pin_ptr<Byte> pinnedKey = &key[0];
            qsc_poly1305_initialize(m_state, pinnedKey);
            m_isInitialized = true;
        }
    }

    Poly1305::~Poly1305()
    {
        this->!Poly1305();
    }

    Poly1305::!Poly1305()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            // Optionally call reset to wipe the internal state
            qsc_poly1305_reset(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }

    void Poly1305::BlockUpdate(array<Byte>^ block)
    {
        if (m_isInitialized == true && block != nullptr && block->LongLength >= QSC_POLY1305_BLOCK_SIZE)
        {
            pin_ptr<Byte> pinnedBlock = &block[0];
            qsc_poly1305_blockupdate(m_state, pinnedBlock);
        }
    }

    void Poly1305::Update(array<Byte>^ message, size_t msglen)
    {
        if (m_isInitialized == true && message != nullptr && message->LongLength >= static_cast<long>(msglen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];
            qsc_poly1305_update(m_state, pinnedMsg, msglen);
        }
    }

    void Poly1305::Finalize(array<Byte>^ mac)
    {
        if (m_isInitialized == true && mac != nullptr && mac->LongLength >= QSC_POLY1305_MAC_SIZE)
        {
            pin_ptr<Byte> pinnedMac = &mac[0];
            qsc_poly1305_finalize(m_state, pinnedMac);
            // Optionally mark as no longer valid, or reinitialize if you want multiple calls
            m_isInitialized = false;
        }
    }

    void Poly1305::Reset()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_poly1305_reset(m_state);
        }
    }

    void Poly1305::Compute(array<Byte>^ output, array<Byte>^ message, size_t msglen, array<Byte>^ key)
    {
        if (output != nullptr && output->LongLength >= QSC_POLY1305_MAC_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msglen) &&
            key != nullptr && key->LongLength >= QSC_POLY1305_KEY_SIZE)
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_poly1305_compute(pinnedOut, pinnedMsg, msglen, pinnedKey);
        }
    }

    int Poly1305::Verify(array<Byte>^ code, array<Byte>^ message, size_t msglen, array<Byte>^ key)
    {
        int res;

        if (code != nullptr && code->LongLength >= QSC_POLY1305_MAC_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msglen) &&
            key != nullptr && key->LongLength >= QSC_POLY1305_KEY_SIZE)
        {
            pin_ptr<Byte> pinnedCode = &code[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            res = qsc_poly1305_verify(pinnedCode, pinnedMsg, msglen, pinnedKey);
        }
        else
        {
            res = -1; 
        }

        return res;
    }
}
