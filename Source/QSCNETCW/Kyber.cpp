#include "Kyber.h"
#include "..\QSC\acp.h"
#include "..\QSC\kyber.h"

namespace QSCNETCW
{
    size_t Kyber::PrivateKeySize()
    {
        return QSC_KYBER_PRIVATEKEY_SIZE;
    }

    size_t Kyber::PublicKeySize()
    {
        return QSC_KYBER_PUBLICKEY_SIZE;
    }

    size_t Kyber::CipherTextSize()
    {
        return QSC_KYBER_CIPHERTEXT_SIZE;
    }

    bool Kyber::Decapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && privateKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_KYBER_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_KYBER_CIPHERTEXT_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_KYBER_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                res = qsc_kyber_decapsulate(pinnedSec, pinnedCt, pinnedSk);
            }
        }

        return res;
    }

    bool Kyber::Decrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && privateKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_KYBER_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_KYBER_CIPHERTEXT_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_KYBER_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                res = qsc_kyber_decrypt(pinnedSec, pinnedCt, pinnedSk);
            }
        }

        return res;
    }

    bool Kyber::Encapsulate(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && publicKey != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_KYBER_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_KYBER_CIPHERTEXT_SIZE) &&
                publicKey->LongLength >= static_cast<long>(QSC_KYBER_PUBLICKEY_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];

                qsc_kyber_encapsulate(pinnedSec, pinnedCt, pinnedPk, &qsc_acp_generate);
                res = true;
            }
        }

        return res;
    }

    bool Kyber::Encrypt(array<Byte>^ secret, array<Byte>^ ciphertext, array<Byte>^ publicKey, array<Byte>^ seed)
    {
        bool res;

        res = false;

        if (secret != nullptr && ciphertext != nullptr && publicKey != nullptr && seed != nullptr)
        {
            if (secret->LongLength >= static_cast<long>(QSC_KYBER_SHAREDSECRET_SIZE) &&
                ciphertext->LongLength >= static_cast<long>(QSC_KYBER_CIPHERTEXT_SIZE) &&
                publicKey->LongLength >= static_cast<long>(QSC_KYBER_PUBLICKEY_SIZE) &&
                seed->LongLength >= static_cast<long>(QSC_KYBER_SEED_SIZE))
            {
                pin_ptr<Byte> pinnedSec = &secret[0];
                pin_ptr<Byte> pinnedCt = &ciphertext[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSeed = &seed[0];

                qsc_kyber_encrypt(pinnedSec, pinnedCt, pinnedPk, pinnedSeed);
                res = true;
            }
        }

        return res;
    }

    bool Kyber::GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr)
        {
            if (publicKey->LongLength >= static_cast<long>(QSC_KYBER_PUBLICKEY_SIZE) &&
                privateKey->LongLength >= static_cast<long>(QSC_KYBER_PRIVATEKEY_SIZE))
            {
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                qsc_kyber_generate_keypair(pinnedPk, pinnedSk, &qsc_acp_generate);
                res = true;
            }
        }

        return res;
    }
}
