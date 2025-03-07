#include "CHACHA.h"

namespace QSCNETCW
{
    CHACHA::CHACHA()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_chacha_state();
    }

    CHACHA::~CHACHA()
    {
        this->!CHACHA();
    }

    CHACHA::!CHACHA()
    {
        Destroy();
    }

    bool CHACHA::Initialize(array<Byte>^ key, array<Byte>^ nonce)
    {
        bool res;

        res = false;

        if (key != nullptr && nonce != nullptr)
        {
            const size_t keyLen = static_cast<size_t>(key->LongLength);
            const size_t nonceLen = static_cast<size_t>(nonce->LongLength);

            // Key must be 16 or 32 bytes; nonce must be 8 bytes.
            if ((keyLen == QSC_CHACHA_KEY128_SIZE || keyLen == QSC_CHACHA_KEY256_SIZE) && (nonceLen == QSC_CHACHA_NONCE_SIZE))
            {
                pin_ptr<Byte> pinnedKey = &key[0];
                pin_ptr<Byte> pinnedNonce = &nonce[0];
                qsc_chacha_keyparams kp;

                kp.key = pinnedKey;
                kp.keylen = keyLen;
                kp.nonce = pinnedNonce;

                qsc_chacha_initialize(m_state, &kp);
                m_isInitialized = true;
                res = true;
            }
        }

        return res;
    }

    bool CHACHA::Transform(array<Byte>^ output, array<Byte>^ input, size_t length)
    {
        bool res = false;

        if (m_isInitialized == true && output != nullptr && input != nullptr)
        {
            if (length <= static_cast<size_t>(output->LongLength) && length <= static_cast<size_t>(input->LongLength))
            {
                pin_ptr<Byte> pinnedOut = &output[0];
                pin_ptr<Byte> pinnedIn = &input[0];

                qsc_chacha_transform(m_state, pinnedOut, pinnedIn, length);
                res = true;
            }
        }

        return res;
    }

    void CHACHA::Destroy()
    {
        if (m_isInitialized == true && m_state != nullptr)
        {
            qsc_chacha_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }
}
