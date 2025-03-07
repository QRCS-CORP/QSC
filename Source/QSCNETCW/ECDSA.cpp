#include "ECDSA.h"
#include "..\QSC\acp.h"
#include "..\QSC\ecdsa.h"

namespace QSCNETCW
{
    size_t ECDSA::PrivateKeySize()
    {
        return QSC_ECDSA_PRIVATEKEY_SIZE;
    }

    size_t ECDSA::PublicKeySize()
    {
        return QSC_ECDSA_PUBLICKEY_SIZE;
    }

    size_t ECDSA::SignatureSize()
    {
        return QSC_ECDSA_SIGNATURE_SIZE;
    }

    bool ECDSA::GenerateSeededKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey, array<Byte>^ seed)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr && seed != nullptr)
        {
            if (publicKey->LongLength >= QSC_ECDSA_PUBLICKEY_SIZE &&
                privateKey->LongLength >= QSC_ECDSA_PRIVATEKEY_SIZE &&
                seed->LongLength >= QSC_ECDSA_SEED_SIZE)
            {
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];
                pin_ptr<Byte> pinnedSeed = &seed[0];

                qsc_ecdsa_generate_seeded_keypair(pinnedPk, pinnedSk, pinnedSeed);
                res = true;
            }
        }

        return res;
    }

    bool ECDSA::GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr)
        {
            if (publicKey->LongLength >= QSC_ECDSA_PUBLICKEY_SIZE &&
                privateKey->LongLength >= QSC_ECDSA_PRIVATEKEY_SIZE)
            {
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                qsc_ecdsa_generate_keypair(pinnedPk, pinnedSk, &qsc_acp_generate);
                res = true;
            }
        }

        return res;
    }

    bool ECDSA::Sign(array<Byte>^ signedMsg, size_t% signedMsgLength, array<Byte>^ message, size_t messageLength, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (signedMsg != nullptr && message != nullptr && privateKey != nullptr)
        {
            if (privateKey->LongLength >= QSC_ECDSA_PRIVATEKEY_SIZE &&
                signedMsg->LongLength >= static_cast<long>(messageLength + QSC_ECDSA_SIGNATURE_SIZE) &&
                messageLength <= static_cast<size_t>(message->LongLength))
            {
                pin_ptr<Byte> pinnedSig = &signedMsg[0];
                pin_ptr<Byte> pinnedMsg = &message[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];
                size_t smlen = 0;

                qsc_ecdsa_sign(pinnedSig, &smlen, pinnedMsg, messageLength, pinnedSk);
                signedMsgLength = smlen;
                res = true;
            }
        }

        return res;
    }

    bool ECDSA::Verify(array<Byte>^ message, size_t% messageLength, array<Byte>^ signedMsg, size_t signedMsgLength, array<Byte>^ publicKey)
    {
        bool res;

        res = false;

        if (message != nullptr && signedMsg != nullptr && publicKey != nullptr)
        {
            if (publicKey->LongLength >= QSC_ECDSA_PUBLICKEY_SIZE &&
                signedMsgLength <= static_cast<size_t>(signedMsg->LongLength) &&
                message->LongLength > 0)
            {
                pin_ptr<Byte> pinnedMsg = &message[0];
                pin_ptr<Byte> pinnedSig = &signedMsg[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];
                size_t mlen = 0;

                res = qsc_ecdsa_verify(pinnedMsg, &mlen, pinnedSig, signedMsgLength, pinnedPk);

                if (res == true)
                {
                    messageLength = mlen;
                }
            }
        }

        return res;
    }
}