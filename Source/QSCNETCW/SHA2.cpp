#include "SHA2.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    //----------------
    // SHA2-256
    //----------------

    SHA256::SHA256()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_sha256_state();
        qsc_sha256_initialize(m_state);
        m_isInitialized = true;
    }

    SHA256::~SHA256()
    {
        this->!SHA256();
    }

    SHA256::!SHA256()
    {
        Destroy();
    }

    void SHA256::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_sha256_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }

    void SHA256::Update(array<Byte>^ message, size_t msgLen)
    {
        if (m_isInitialized == true && message != nullptr && 
            message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha256_update(m_state, pinnedMsg, msgLen);
        }
    }

    void SHA256::Finalize(array<Byte>^ output)
    {
        if (m_isInitialized == true && output != nullptr &&
            output->LongLength >= QSC_SHA2_256_HASH_SIZE)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_sha256_finalize(m_state, pinnedOut);
            m_isInitialized = false;
        }
    }

    void SHA256::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA2_256_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha256_compute(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //----------------
    // SHA2-384
    //----------------

    SHA384::SHA384()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_sha384_state();
        qsc_sha384_initialize(m_state);
        m_isInitialized = true;
    }

    SHA384::~SHA384()
    {
        this->!SHA384();
    }

    SHA384::!SHA384()
    {
        Destroy();
    }

    void SHA384::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_sha384_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }

    void SHA384::Update(array<Byte>^ message, size_t msgLen)
    {
        if (m_isInitialized == true && message != nullptr &&
            message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha384_update(m_state, pinnedMsg, msgLen);
        }
    }

    void SHA384::Finalize(array<Byte>^ output)
    {
        if (m_isInitialized == true && output != nullptr &&
            output->LongLength >= QSC_SHA2_384_HASH_SIZE)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_sha384_finalize(m_state, pinnedOut);
            m_isInitialized = false;
        }
    }

    void SHA384::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA2_384_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha384_compute(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //----------------
    // SHA2-512
    //----------------

    SHA512::SHA512()
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_sha512_state();
        qsc_sha512_initialize(m_state);
        m_isInitialized = true;
    }

    SHA512::~SHA512()
    {
        this->!SHA512();
    }

    SHA512::!SHA512()
    {
        Destroy();
    }

    void SHA512::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_sha512_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }

    void SHA512::Update(array<Byte>^ message, size_t msgLen)
    {
        if (m_isInitialized == true && message != nullptr &&
            message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha512_update(m_state, pinnedMsg, msgLen);
        }
    }

    void SHA512::Finalize(array<Byte>^ output)
    {
        if (m_isInitialized == true && output != nullptr &&
            output->LongLength >= QSC_SHA2_512_HASH_SIZE)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_sha512_finalize(m_state, pinnedOut);
            m_isInitialized = false;
        }
    }

    void SHA512::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA2_512_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha512_compute(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //----------------
    // HMAC-256
    //----------------

    HMAC256::HMAC256(array<Byte>^ key, size_t keyLen)
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_hmac256_state();

        if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_hmac256_initialize(m_state, pinnedKey, keyLen);
            m_isInitialized = true;
        }
    }

    HMAC256::~HMAC256()
    {
        this->!HMAC256();
    }

    HMAC256::!HMAC256()
    {
        Destroy();
    }

    void HMAC256::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_hmac256_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }

    void HMAC256::Update(array<Byte>^ message, size_t msgLen)
    {
        if (m_isInitialized == true && message != nullptr &&
            message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_hmac256_update(m_state, pinnedMsg, msgLen);
        }
    }

    void HMAC256::Finalize(array<Byte>^ output)
    {
        if (m_isInitialized == true && output != nullptr &&
            output->Length >= QSC_HMAC_256_MAC_SIZE)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_hmac256_finalize(m_state, pinnedOut);
            m_isInitialized = false;
        }
    }

    void HMAC256::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= QSC_HMAC_256_MAC_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_hmac256_compute(pinnedOut, pinnedMsg, msgLen, pinnedKey, keyLen);
        }
    }

    //----------------
    // HMAC-512
    //----------------

    HMAC512::HMAC512(array<Byte>^ key, size_t keyLen)
        : m_state(nullptr), m_isInitialized(false)
    {
        m_state = new qsc_hmac512_state();

        if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_hmac512_initialize(m_state, pinnedKey, keyLen);
            m_isInitialized = true;
        }
    }

    HMAC512::~HMAC512()
    {
        this->!HMAC512();
    }

    HMAC512::!HMAC512()
    {
        Destroy();
    }

    void HMAC512::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_hmac512_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
    }

    void HMAC512::Update(array<Byte>^ message, size_t msgLen)
    {
        if (m_isInitialized == true && message != nullptr &&
            message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_hmac512_update(m_state, pinnedMsg, msgLen);
        }
    }

    void HMAC512::Finalize(array<Byte>^ output)
    {
        if (m_isInitialized == true && output != nullptr &&
            output->Length >= QSC_HMAC_512_MAC_SIZE)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_hmac512_finalize(m_state, pinnedOut);
            m_isInitialized = false;
        }
    }

    void HMAC512::Compute(array<Byte>^ output, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= QSC_HMAC_512_MAC_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_hmac512_compute(pinnedOut, pinnedMsg, msgLen, pinnedKey, keyLen);
        }
    }

    //----------------
    // HKDF
    //----------------

    void HKDF::HKDF256Expand(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ info, size_t infoLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* infPtr = nullptr;

            if (info != nullptr && infoLen > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];

                infPtr = pinnedInfo;
            }

            qsc_hkdf256_expand(pinnedOut, outLen, pinnedKey, keyLen, infPtr, infoLen);
        }
    }

    void HKDF::HKDF256Extract(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ salt, size_t saltLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* sPtr = nullptr;

            if (salt != nullptr && saltLen > 0)
            {
                pin_ptr<Byte> pinnedSalt = &salt[0];

                sPtr = pinnedSalt;
            }

            qsc_hkdf256_extract(pinnedOut, outLen, pinnedKey, keyLen, sPtr, saltLen);
        }
    }

    void HKDF::HKDF512Expand(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ info, size_t infoLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* infPtr = nullptr;

            if (info != nullptr && infoLen > 0)
            {
                pin_ptr<Byte> pinnedInfo = &info[0];

                infPtr = pinnedInfo;
            }

            qsc_hkdf512_expand(pinnedOut, outLen, pinnedKey, keyLen, infPtr, infoLen);
        }
    }

    void HKDF::HKDF512Extract(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ salt, size_t saltLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* sPtr = nullptr;

            if (salt != nullptr && saltLen > 0)
            {
                pin_ptr<Byte> pinnedSalt = &salt[0];

                sPtr = pinnedSalt;
            }

            qsc_hkdf512_extract(pinnedOut, outLen, pinnedKey, keyLen, sPtr, saltLen);
        }
    }
}
