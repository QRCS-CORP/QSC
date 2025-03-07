#include "RCS.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    RCS::RCS()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_rcs_state();
    }

    RCS::~RCS()
    {
        this->!RCS();
    }

    RCS::!RCS()
    {
        Destroy();
    }

    void RCS::Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encrypt, RcsCipherType cipherType)
    {
        if (m_isInitialized)
        {
            Destroy();
        }

        if (key != nullptr)
        {
            qsc_rcs_keyparams kp = { 0 };
            pin_ptr<Byte> pinnedKey = &key[0];
            kp.key = pinnedKey;
            kp.keylen = static_cast<size_t>(key->LongLength);

            if (nonce != nullptr && nonce->Length >= QSC_RCS_NONCE_SIZE)
            {
                pin_ptr<Byte> pinnedNonce = &nonce[0];
                kp.nonce = pinnedNonce;
            }

            if (info != nullptr && info->Length > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];
                kp.info = pinnedInfo;
                kp.infolen = static_cast<size_t>(info->LongLength);
            }

            qsc_rcs_initialize(m_state, &kp, encrypt);
            m_state->ctype = static_cast<rcs_cipher_type>(cipherType);
            m_isInitialized = true;
        }
    }

    void RCS::SetAssociated(array<Byte>^ data, size_t length)
    {
        if (m_isInitialized == true && data != nullptr && data->LongLength >= static_cast<long>(length))
        {
            pin_ptr<Byte> pinnedData = &data[0];
            qsc_rcs_set_associated(m_state, pinnedData, length);
        }
    }

    void RCS::StoreNonce(array<Byte>^ nonce)
    {
        if (m_isInitialized == true && nonce != nullptr && nonce->LongLength >= QSC_RCS_NONCE_SIZE)
        {
            pin_ptr<Byte> pinnedNonce = &nonce[0];
            qsc_rcs_store_nonce(m_state, pinnedNonce);
        }
    }

    bool RCS::Transform(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length) && input->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                res = qsc_rcs_transform(m_state, pinnedOut, pinnedIn, length);
            }
        }

        return res;
    }

    bool RCS::ExtendedTransform(array<Byte>^ output, array<Byte>^ input, size_t length, bool finalize)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (output->LongLength >= static_cast<long>(length) && input->LongLength >= static_cast<long>(length))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                res = qsc_rcs_extended_transform(m_state, pinnedOut, pinnedIn, length, finalize);
            }
        }

        return res;
    }

    void RCS::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_rcs_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}