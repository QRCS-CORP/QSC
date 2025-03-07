#include "ECDH.h"
#include "..\QSC\acp.h"
#include "..\QSC\ecdh.h"

namespace QSCNETCW
{
    size_t ECDH::PrivateKeySize()
    {
        return QSC_ECDH_PRIVATEKEY_SIZE;
    }

    size_t ECDH::PublicKeySize()
    {
        return QSC_ECDH_PUBLICKEY_SIZE;
    }

    size_t ECDH::CipherTextSize()
    {
        return QSC_ECDH_SHAREDSECRET_SIZE;
    }

    bool ECDH::KeyExchange(array<Byte>^ secret, array<Byte>^ privateKey, array<Byte>^ publicKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && privateKey != nullptr && publicKey != nullptr)
        {
            if (secret->LongLength >= QSC_ECDH_SHAREDSECRET_SIZE &&
                privateKey->LongLength >= QSC_ECDH_PRIVATEKEY_SIZE &&
                publicKey->LongLength >= QSC_ECDH_PUBLICKEY_SIZE)
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];

                res = qsc_ecdh_key_exchange(pinnedSec, pinnedSk, pinnedPk);
            }
        }

        return res;
    }

    bool ECDH::GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr)
        {
            if (publicKey->LongLength >= QSC_ECDH_PUBLICKEY_SIZE &&
                privateKey->LongLength >= QSC_ECDH_PRIVATEKEY_SIZE)
            {
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                qsc_ecdh_generate_keypair(pinnedPk, pinnedSk, &qsc_acp_generate);
                res = true;
            }
        }

        return res;
    }

    bool ECDH::GenerateSeededKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey, array<Byte>^ seed)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr && seed != nullptr)
        {
            if (publicKey->LongLength >= QSC_ECDH_PUBLICKEY_SIZE &&
                privateKey->LongLength >= QSC_ECDH_PRIVATEKEY_SIZE &&
                seed->LongLength >= QSC_ECDH_SEED_SIZE)
            {
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];
                pin_ptr<Byte> pinnedSeed = &seed[0];

                qsc_ecdh_generate_seeded_keypair(pinnedPk, pinnedSk, pinnedSeed);
                res = true;
            }
        }

        return res;
    }
}