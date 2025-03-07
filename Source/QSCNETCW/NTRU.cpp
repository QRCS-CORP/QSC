#include "NTRU.h"
#include "..\QSC\acp.h"
#include "..\QSC\ntru.h"

namespace QSCNETCW
{
    size_t NTRU::PrivateKeySize()
    {
        return QSC_NTRU_PRIVATEKEY_SIZE;
    }

    size_t NTRU::PublicKeySize()
    {
        return QSC_NTRU_PUBLICKEY_SIZE;
    }

    size_t NTRU::CipherTextSize()
    {
        return QSC_NTRU_CIPHERTEXT_SIZE;
    }

    bool NTRU::Decapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && privateKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_NTRU_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_NTRU_CIPHERTEXT_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_NTRU_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                res = qsc_ntru_decapsulate(pinnedSec, pinnedCt, pinnedSk);
            }
        }

        return res;
    }

    bool NTRU::Decrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && privateKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_NTRU_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_NTRU_CIPHERTEXT_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_NTRU_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                res = qsc_ntru_decrypt(pinnedSec, pinnedCt, pinnedSk);
            }
        }

        return res;
    }

    bool NTRU::Encapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && publicKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_NTRU_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_NTRU_CIPHERTEXT_SIZE) &&
                publicKey->LongLength >= static_cast<long>(QSC_NTRU_PUBLICKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];

                qsc_ntru_encapsulate(pinnedSec, pinnedCt, pinnedPk, &qsc_acp_generate);
            }
        }

        return res;
    }

    bool NTRU::Encrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey, array<Byte>^ seed)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && publicKey != nullptr && seed != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_NTRU_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_NTRU_CIPHERTEXT_SIZE) &&
                publicKey->LongLength >= static_cast<long>(QSC_NTRU_PUBLICKEY_SIZE) &&
                seed->LongLength >= static_cast<long>(QSC_NTRU_SEED_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSeed = &seed[0];

                qsc_ntru_encrypt(pinnedSec, pinnedCt, pinnedPk, pinnedSeed);
            }
        }

        return res;
    }

    bool NTRU::GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr)
        {
            if (publicKey->LongLength >= static_cast<long>(QSC_NTRU_PUBLICKEY_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_NTRU_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                qsc_ntru_generate_keypair(pinnedPk, pinnedSk, &qsc_acp_generate);
            }
        }

        return true;
    }
}