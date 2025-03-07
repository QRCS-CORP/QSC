#include "McEliece.h"
#include "..\QSC\acp.h"
#include "..\QSC\mceliece.h"

namespace QSCNETCW
{
    size_t McEliece::PrivateKeySize()
    {
        return QSC_MCELIECE_PRIVATEKEY_SIZE;
    }

    size_t McEliece::PublicKeySize()
    {
        return QSC_MCELIECE_PUBLICKEY_SIZE;
    }

    size_t McEliece::CipherTextSize()
    {
        return QSC_MCELIECE_CIPHERTEXT_SIZE;
    }

    bool McEliece::Decapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && privateKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_MCELIECE_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_MCELIECE_CIPHERTEXT_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_MCELIECE_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                res = qsc_mceliece_decapsulate(pinnedSec, pinnedCt, pinnedSk);
            }
        }

        return res;
    }

    bool McEliece::Decrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && privateKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_MCELIECE_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_MCELIECE_CIPHERTEXT_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_MCELIECE_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                res = qsc_mceliece_decrypt(pinnedSec, pinnedCt, pinnedSk);
            }
        }

        return res;
    }

    bool McEliece::Encapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && publicKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_MCELIECE_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_MCELIECE_CIPHERTEXT_SIZE) &&
                publicKey->LongLength >= static_cast<long>(QSC_MCELIECE_PUBLICKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];

                qsc_mceliece_encapsulate(pinnedSec, pinnedCt, pinnedPk, &qsc_acp_generate);
                res = true;
            }
        }

        return res;
    }

    bool McEliece::Encrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey, array<Byte>^ seed)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && publicKey != nullptr && seed != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_MCELIECE_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_MCELIECE_CIPHERTEXT_SIZE) &&
                publicKey->LongLength >= static_cast<long>(QSC_MCELIECE_PUBLICKEY_SIZE) &&
                seed->LongLength >= static_cast<long>(QSC_MCELIECE_SEED_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSeed = &seed[0];

                qsc_mceliece_encrypt(pinnedSec, pinnedCt, pinnedPk, pinnedSeed);
                res = true;
            }
        }

        return res;
    }

    bool McEliece::GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr)
        {
            if (publicKey->LongLength >= static_cast<long>(QSC_MCELIECE_PUBLICKEY_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_MCELIECE_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                qsc_mceliece_generate_keypair(pinnedPk, pinnedSk, &qsc_acp_generate);
                res = true;
            }
        }

        return res;
    }
}