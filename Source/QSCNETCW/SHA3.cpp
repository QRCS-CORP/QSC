#include "SHA3.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    //
    // SHA3
    //

    SHA3::SHA3()
        : m_state(nullptr), m_rate(KeccakRate::None), m_isInitialized(false)
    {
        m_state = new qsc_keccak_state();
    }

    SHA3::~SHA3()
    {
        this->!SHA3();
    }

    SHA3::!SHA3()
    {
        Destroy();
    }

    void SHA3::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_keccak_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
        m_rate = KeccakRate::None;
    }

    void SHA3::Initialize(KeccakRate rate)
    {
        if (m_isInitialized)
        {
            Destroy();
        }

        qsc_sha3_initialize(m_state);
        m_rate = rate;
        m_isInitialized = true;
    }

    void SHA3::Update(array<Byte>^ message, size_t msgLen)
    {
        if (m_isInitialized == true && message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];
            qsc_sha3_update(m_state, static_cast<qsc_keccak_rate>(m_rate), pinnedMsg, msgLen);
        }
    }

    void SHA3::Finalize(array<Byte>^ output)
    {
        if (m_isInitialized == true && output != nullptr)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_sha3_finalize(m_state, static_cast<qsc_keccak_rate>(m_rate), pinnedOut);
            m_isInitialized = false;
        }
    }

    void SHA3::Compute128(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA3_128_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha3_compute128(pinnedOut, pinnedMsg, msgLen);
        }
    }

    void SHA3::Compute256(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA3_256_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha3_compute256(pinnedOut, pinnedMsg, msgLen);
        }
    }

    void SHA3::Compute512(array<Byte>^ output, array<Byte>^ message, size_t msgLen)
    {
        if (output != nullptr && output->Length >= QSC_SHA3_512_HASH_SIZE &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_sha3_compute512(pinnedOut, pinnedMsg, msgLen);
        }
    }

    //
    // SHAKE
    //

    SHAKE::SHAKE()
        : m_state(nullptr), m_rate(KeccakRate::None), m_isInitialized(false)
    {
        m_state = new qsc_keccak_state();
    }

    SHAKE::~SHAKE()
    {
        this->!SHAKE();
    }

    SHAKE::!SHAKE()
    {
        Destroy();
    }

    void SHAKE::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_keccak_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
        m_rate = KeccakRate::None;
    }

    void SHAKE::Initialize(KeccakRate rate, array<Byte>^ key, size_t keyLen)
    {
        if (m_isInitialized)
        {
            Destroy();
        }

        m_rate = rate;
        qsc_keccak_initialize_state(m_state);

        if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_shake_initialize(m_state, static_cast<qsc_keccak_rate>(rate), pinnedKey, keyLen);
        }

        m_isInitialized = true;
    }

    void SHAKE::SqueezeBlocks(array<Byte>^ output, size_t nblocks)
    {
        if (m_isInitialized == true && output != nullptr)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_shake_squeezeblocks(m_state, static_cast<qsc_keccak_rate>(m_rate), pinnedOut, nblocks);
        }
    }

    void SHAKE::Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_shake128_compute(pinnedOut, outLen, pinnedKey, keyLen);
        }
    }

    void SHAKE::Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_shake256_compute(pinnedOut, outLen, pinnedKey, keyLen);
        }
    }

    void SHAKE::Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_shake512_compute(pinnedOut, outLen, pinnedKey, keyLen);
        }
    }

    //
    // CSHAKE
    //

    CSHAKE::CSHAKE()
        : m_state(nullptr), m_rate(KeccakRate::None), m_isInitialized(false)
    {
        m_state = new qsc_keccak_state();
    }

    CSHAKE::~CSHAKE()
    {
        this->!CSHAKE();
    }

    CSHAKE::!CSHAKE()
    {
        Destroy();
    }

    void CSHAKE::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_keccak_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
        m_rate = KeccakRate::None;
    }

    void CSHAKE::Initialize(KeccakRate rate, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen)
    {
        if (m_isInitialized)
        {
            Destroy();
        }

        m_rate = rate;
        qsc_keccak_initialize_state(m_state);
        pin_ptr<Byte> pinnedKey = nullptr;
        pin_ptr<Byte> pinnedName = nullptr;
        pin_ptr<Byte> pinnedCust = nullptr;

        const uint8_t* namePtr = nullptr;
        const uint8_t* custPtr = nullptr;

        if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pinnedKey = &key[0];
        }

        if (name != nullptr && name->LongLength >= static_cast<long>(nameLen))
        {
            pinnedName = &name[0];
            namePtr = pinnedName;
        }

        if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
        {
            pinnedCust = &custom[0];
            custPtr = pinnedCust;
        }

        qsc_cshake_initialize(m_state, static_cast<qsc_keccak_rate>(rate), pinnedKey, keyLen, namePtr, nameLen, custPtr, custLen);
        m_isInitialized = true;
    }

    void CSHAKE::SqueezeBlocks(array<Byte>^ output, size_t nblocks)
    {
        if (m_isInitialized == true && output != nullptr)
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_cshake_squeezeblocks(m_state, static_cast<qsc_keccak_rate>(m_rate), pinnedOut, nblocks);
        }
    }

    void CSHAKE::Update(array<Byte>^ key, size_t keyLen)
    {
        if (m_isInitialized == true && key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedKey = &key[0];

            qsc_cshake_update(m_state, static_cast<qsc_keccak_rate>(m_rate), pinnedKey, keyLen);
        }
    }

    void CSHAKE::Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = nullptr;
            pin_ptr<Byte> pinnedName = nullptr;
            pin_ptr<Byte> pinnedCust = nullptr;

            const uint8_t* namePtr = nullptr;
            const uint8_t* custPtr = nullptr;

            if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
            {
                pinnedKey = &key[0];
            }

            if (name != nullptr && name->LongLength >= static_cast<long>(nameLen))
            {
                pinnedName = &name[0];
                namePtr = pinnedName;
            }

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_cshake128_compute(pinnedOut, outLen, pinnedKey, keyLen, namePtr, nameLen, custPtr, custLen);
        }
    }

    void CSHAKE::Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = nullptr;
            pin_ptr<Byte> pinnedName = nullptr;
            pin_ptr<Byte> pinnedCust = nullptr;

            const uint8_t* namePtr = nullptr;
            const uint8_t* custPtr = nullptr;

            if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
            {
                pinnedKey = &key[0];
            }

            if (name != nullptr && name->LongLength >= static_cast<long>(nameLen))
            {
                pinnedName = &name[0];
                namePtr = pinnedName;
            }

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_cshake256_compute(pinnedOut, outLen, pinnedKey, keyLen, namePtr, nameLen, custPtr, custLen);
        }
    }

    void CSHAKE::Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->Length >= static_cast<long>(outLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedKey = nullptr;
            pin_ptr<Byte> pinnedName = nullptr;
            pin_ptr<Byte> pinnedCust = nullptr;

            const uint8_t* namePtr = nullptr;
            const uint8_t* custPtr = nullptr;

            if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
            {
                pinnedKey = &key[0];
            }

            if (name != nullptr && name->LongLength >= static_cast<long>(nameLen))
            {
                pinnedName = &name[0];
                namePtr = pinnedName;
            }

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_cshake512_compute(pinnedOut, outLen, pinnedKey, keyLen, namePtr, nameLen, custPtr, custLen);
        }
    }

    //
    // KMAC
    //

    KMAC::KMAC()
        : m_state(nullptr), m_rate(KeccakRate::None), m_isInitialized(false)
    {
        m_state = new qsc_keccak_state();
    }

    KMAC::~KMAC()
    {
        this->!KMAC();
    }

    KMAC::!KMAC()
    {
        Destroy();
    }

    void KMAC::Destroy()
    {
        if (m_isInitialized && m_state != nullptr)
        {
            qsc_keccak_dispose(m_state);
            delete m_state;
            m_state = nullptr;
        }

        m_isInitialized = false;
        m_rate = KeccakRate::None;
    }

    void KMAC::Initialize(KeccakRate rate, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen)
    {
        if (m_isInitialized)
        {
            Destroy();
        }

        qsc_keccak_initialize_state(m_state);
        m_rate = rate;

        if (key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* custPtr = nullptr;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pin_ptr<Byte> pinnedCust = &custom[0];

                custPtr = pinnedCust;
            }

            qsc_kmac_initialize(m_state, static_cast<qsc_keccak_rate>(rate), pinnedKey, keyLen, custPtr, custLen);
            m_isInitialized = true;
        }
    }

    void KMAC::Update(array<Byte>^ message, size_t msgLen)
    {
        if (m_isInitialized == true && message != nullptr && message->LongLength >= static_cast<long>(msgLen))
        {
            pin_ptr<Byte> pinnedMsg = &message[0];

            qsc_kmac_update(m_state, static_cast<qsc_keccak_rate>(m_rate), pinnedMsg, msgLen);
        }
    }

    bool KMAC::Finalize(array<Byte>^ output, size_t outLen)
    {
        bool res;

        res = false;

        if (m_isInitialized == true && output != nullptr && output->LongLength >= static_cast<long>(outLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];

            qsc_kmac_finalize(m_state, static_cast<qsc_keccak_rate>(m_rate), pinnedOut, outLen);
            m_isInitialized = false;
            res = true;
        }

        return res;
    }

    void KMAC::Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* custPtr = nullptr;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pin_ptr<Byte> pinnedCust = &custom[0];

                custPtr = pinnedCust;
            }

            qsc_kmac128_compute(pinnedOut, outLen, pinnedMsg, msgLen, pinnedKey, keyLen, custPtr, custLen);
        }
    }

    void KMAC::Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* custPtr = nullptr;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pin_ptr<Byte> pinnedCust = &custom[0];

                custPtr = pinnedCust;
            }

            qsc_kmac256_compute(pinnedOut, outLen, pinnedMsg, msgLen, pinnedKey, keyLen, custPtr, custLen);
        }
    }

    void KMAC::Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen)
    {
        if (output != nullptr && output->LongLength >= static_cast<long>(outLen) &&
            message != nullptr && message->LongLength >= static_cast<long>(msgLen) &&
            key != nullptr && key->LongLength >= static_cast<long>(keyLen))
        {
            pin_ptr<Byte> pinnedOut = &output[0];
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedKey = &key[0];
            const uint8_t* custPtr = nullptr;

            if (custom != nullptr && custom->LongLength >= static_cast<long>(custLen))
            {
                pin_ptr<Byte> pinnedCust = &custom[0];
                custPtr = pinnedCust;
            }

            qsc_kmac512_compute(pinnedOut, outLen, pinnedMsg, msgLen, pinnedKey, keyLen, custPtr, custLen);
        }
    }
}
