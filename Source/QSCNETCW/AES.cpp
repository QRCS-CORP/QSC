#include "AES.h"

namespace QSCNETCW
{
    AES::AES()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_aes_state();
    }

    AES::~AES()
    {
        Destroy();
    }

    AES::!AES()
    {
        Destroy();
    }

    bool AES::Initialize(array<Byte>^ key, array<Byte>^ nonce, array<Byte>^ info, bool encryption, AesCipherType ctype)
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

            qsc_aes_initialize(m_state, &kp, encryption, static_cast<qsc_aes_cipher_type>(ctype));
            m_isInitialized = true;
            res = true;
        }

        return res;
    }

    bool AES::CBCEncrypt(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(input->LongLength) && length <= static_cast<size_t>(output->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                qsc_aes_cbc_encrypt(m_state, pinnedOut, pinnedIn, length);
                res = true;
            }
        }

        return res;
    }

    bool AES::CBCDecrypt(array<Byte>^ output, size_t% outputLength, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(input->LongLength) && length <= static_cast<size_t>(output->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];
                size_t outLen = 0;

                qsc_aes_cbc_decrypt(m_state, pinnedOut, &outLen, pinnedIn, length);
                outputLength = outLen;
                res = true;
            }
        }

        return res;
    }

    bool AES::CTRBETransform(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(input->LongLength) && length <= static_cast<size_t>(output->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                qsc_aes_ctrbe_transform(m_state, pinnedOut, pinnedIn, length);
                res = true;
            }
        }

        return res;
    }

    bool AES::CTRLETransform(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(input->LongLength) && length <= static_cast<size_t>(output->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                qsc_aes_ctrle_transform(m_state, pinnedOut, pinnedIn, length);
                res = true;
            }
        }

        return res;
    }

    void AES::Destroy()
    {
        if (m_state != nullptr)
        {
            qsc_aes_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}