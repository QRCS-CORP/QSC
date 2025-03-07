#include "QMAC.h"

namespace QSCNETCW
{
    QMAC::QMAC()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_qmac_state();
    }

    QMAC::~QMAC()
    {
        this->!QMAC();
    }

    QMAC::!QMAC()
    {
        Destroy();
    }

    void QMAC::Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, QmacModes mode)
    {
        if (m_isInitialized)
        {
            Destroy();
        }

        if (key != nullptr && key->Length >= QSC_QMAC_KEY_SIZE)
        {
            qsc_qmac_keyparams kp = { 0 };

            pin_ptr<Byte> pinnedKey = &key[0];
            kp.key = pinnedKey;
            kp.keylen = static_cast<size_t>(key->Length);

            if (nonce != nullptr && nonce->Length > 0)
            {
                pin_ptr<Byte> pinnedNonce = &nonce[0];
                kp.nonce = pinnedNonce;
                kp.noncelen = static_cast<size_t>(nonce->Length);
            }

            if (info != nullptr && info->Length > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];
                kp.info = pinnedInfo;
                kp.infolen = static_cast<size_t>(info->Length);
            }

            kp.mode = static_cast<qsc_qmac_modes>(mode);

            qsc_qmac_initialize(m_state, &kp);
            m_isInitialized = true;
        }
    }

    void QMAC::Update(array<Byte>^ message, size_t length)
    {
        if (m_isInitialized == true && message != nullptr && 
            message->LongLength >= static_cast<long>(length))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];
            qsc_qmac_update(m_state, pinnedMsg, length);
        }
    }

    void QMAC::Finalize(array<Byte>^ output)
    {
        if (m_isInitialized == true && output != nullptr && 
            output->LongLength >= QSC_QMAC_MAC_SIZE)
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            qsc_qmac_finalize(m_state, pinnedOut);
            m_isInitialized = false;
        }
    }

    void QMAC::Destroy()
    {
        if (m_isInitialized == true && m_state != nullptr)
        {
            qsc_qmac_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }

    void QMAC::Compute(array<Byte>^ output, array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, QmacModes mode, array<Byte>^ message, size_t length)
    {
        if (output != nullptr && output->Length >= QSC_QMAC_MAC_SIZE &&
            key != nullptr && key->Length >= QSC_QMAC_KEY_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(length))
        {
            qsc_qmac_keyparams kp = { 0 };

            pin_ptr<Byte> pinnedKey = &key[0];
            kp.key = pinnedKey;
            kp.keylen = static_cast<size_t>(key->Length);

            if (nonce != nullptr && nonce->Length > 0)
            {
                pin_ptr<Byte> pinnedNonce = &nonce[0];
                kp.nonce = pinnedNonce;
                kp.noncelen = static_cast<size_t>(nonce->Length);
            }

            if (info != nullptr && info->Length > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];
                kp.info = pinnedInfo;
                kp.infolen = static_cast<size_t>(info->Length);
            }

            kp.mode = static_cast<qsc_qmac_modes>(mode);

            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_qmac_compute(pinnedOut, &kp, pinnedMsg, length);
        }
    }
}
