#include "CSX.h"

namespace QSCNETCW
{
    CSX::CSX()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_csx_state();
    }

    CSX::~CSX()
    {
        Destroy();
    }

    CSX::!CSX()
    {
        Destroy();
    }

    bool CSX::Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encryption)
    {
        bool res;

        res = false;

        if (m_state != nullptr && key != nullptr && nonce != nullptr)
        {
            qsc_csx_keyparams kp = { 0 };
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

            qsc_csx_initialize(m_state, &kp, encryption);
            m_isInitialized = true;
            res = true;
        }

        return res;
    }

    bool CSX::SetAssociated(array<Byte>^ data, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && data != nullptr)
        {
            if (length <= static_cast<size_t>(data->LongLength))
            {
                pin_ptr<Byte> pinnedData = &data[0];

                qsc_csx_set_associated(m_state, pinnedData, length);
                res = true;
            }
        }

        return res;
    }

    bool CSX::StoreNonce(array<Byte>^ nonce)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && nonce != nullptr)
        {
            if (nonce->LongLength >= QSC_CSX_NONCE_SIZE)
            {
                pin_ptr<Byte> pinnedNonce = &nonce[0];

                qsc_csx_store_nonce(m_state, pinnedNonce);
                res = true;
            }
        }

        return res;
    }

    bool CSX::Transform(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(output->LongLength) &&
                length <= static_cast<size_t>(input->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                res = qsc_csx_transform(m_state, pinnedOut, pinnedIn, length);
            }
        }

        return res;
    }

    bool CSX::ExtendedTransform(array<Byte>^ output, array<Byte>^ input, size_t length, bool finalize)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(output->LongLength) &&
                length <= static_cast<size_t>(input->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                res = qsc_csx_extended_transform(m_state, pinnedOut, pinnedIn, length, finalize);
            }
        }

        return res;
    }

    void CSX::Destroy()
    {
        if (m_state != nullptr)
        {
            qsc_csx_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}