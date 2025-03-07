#include "HBA.h"

namespace QSCNETCW
{
    HBA256::HBA256()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_aes_hba256_state();
    }

    HBA256::~HBA256()
    {
        Destroy();
    }

    HBA256::!HBA256()
    {
        Destroy();
    }

    bool HBA256::Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encrypt)
    {
        bool res;

        res = false;

        if (key != nullptr && nonce != nullptr)
        {
            qsc_aes_keyparams kp = { 0 };
            pin_ptr<Byte> pinnedKey = &key[0];
            pin_ptr<Byte> pinnedNonce = &nonce[0];

            kp.key = pinnedKey;
            kp.keylen = static_cast<size_t>(key->LongLength);
            kp.nonce = pinnedNonce;

            if (info != nullptr && info->LongLength > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];

                kp.info = pinnedInfo;
                kp.infolen = static_cast<size_t>(info->LongLength);
            }

            qsc_aes_hba256_initialize(m_state, &kp, encrypt);
            m_isInitialized = true;
            res = true;
        }

        return res;
    }

    bool HBA256::SetAssociated(array<Byte>^ data, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && data != nullptr)
        {
            if (length <= static_cast<size_t>(data->LongLength))
            {
                pin_ptr<Byte> pinnedData = &data[0];

                qsc_aes_hba256_set_associated(m_state, pinnedData, length);
                res = true;
            }
        }

        return res;
    }

    bool HBA256::Transform(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(input->LongLength) && length <= static_cast<size_t>(output->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                res = qsc_aes_hba256_transform(m_state, pinnedOut, pinnedIn, length);
            }
        }

        return res;
    }

    void HBA256::Destroy()
    {
        if (m_state != nullptr)
        {
            qsc_aes_hba256_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}