#include "Dilithium.h"
#include "..\QSC\acp.h"
#include "..\QSC\dilithium.h"

namespace QSCNETCW
{
    size_t Dilithium::PrivateKeySize()
    {
        return QSC_DILITHIUM_PRIVATEKEY_SIZE;
    }

    size_t Dilithium::PublicKeySize()
    {
        return QSC_DILITHIUM_PUBLICKEY_SIZE;
    }

    size_t Dilithium::SignatureSize()
    {
        return QSC_DILITHIUM_SIGNATURE_SIZE;
    }

    bool Dilithium::GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (publicKey != nullptr && privateKey != nullptr)
        {
            if (publicKey->LongLength >= QSC_DILITHIUM_PUBLICKEY_SIZE &&
                privateKey->LongLength >= QSC_DILITHIUM_PRIVATEKEY_SIZE)
            {
                pin_ptr<Byte> pk = &publicKey[0];
                pin_ptr<Byte> sk = &privateKey[0];

                qsc_dilithium_generate_keypair(pk, sk, &qsc_acp_generate);
                res = true;
            }
        }

        return res;
    }

    bool Dilithium::Sign(array<Byte>^ signedMsg, size_t% signedMsgLength, array<Byte>^ message, size_t messageLength, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (signedMsg != nullptr && message != nullptr && privateKey != nullptr)
        {
            if (signedMsg->LongLength >= static_cast<long>(messageLength + QSC_DILITHIUM_SIGNATURE_SIZE) &&
                privateKey->LongLength >= QSC_DILITHIUM_PRIVATEKEY_SIZE &&
                messageLength <= static_cast<size_t>(message->LongLength))
            {
                pin_ptr<Byte> pinnedSig = &signedMsg[0];
                pin_ptr<Byte> pinnedMsg = &message[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                size_t smlen = 0;
                qsc_dilithium_sign(pinnedSig, &smlen, pinnedMsg, messageLength, pinnedSk, &qsc_acp_generate);
                signedMsgLength = smlen;
                res = true;
            }
        }

        return res;
    }

    bool Dilithium::SignEx(array<Byte>^ signedMsg, size_t% signedMsgLength, array<Byte>^ message, size_t messageLength, array<Byte>^ context, size_t contextLength, array<Byte>^ privateKey)
    {
        bool res;

        res = false;

        if (signedMsg != nullptr && message != nullptr && privateKey != nullptr)
        {
            if (signedMsg->LongLength >= static_cast<long>(messageLength + QSC_DILITHIUM_SIGNATURE_SIZE) &&
                privateKey->LongLength >= QSC_DILITHIUM_PRIVATEKEY_SIZE &&
                messageLength <= static_cast<size_t>(message->LongLength))
            {
                pin_ptr<Byte> pinnedSig = &signedMsg[0];
                pin_ptr<Byte> pinnedMsg = &message[0];
                pin_ptr<Byte> pinnedSk = &privateKey[0];

                const uint8_t* ctxPtr = nullptr;

                if (context != nullptr && contextLength <= static_cast<size_t>(context->LongLength))
                {
                    pin_ptr<Byte> pinnedCtx = &context[0];
                    ctxPtr = pinnedCtx;
                }

                size_t smlen = 0;

                qsc_dilithium_sign_ex(pinnedSig, &smlen, pinnedMsg, messageLength, ctxPtr, contextLength, pinnedSk, &qsc_acp_generate);
                signedMsgLength = smlen;
                res = true;
            }
        }

        return res;
    }

    bool Dilithium::Verify(array<Byte>^ message, size_t% messageLength, array<Byte>^ signedMsg, size_t signedMsgLength, array<Byte>^ publicKey)
    {
        bool res;

        res = false;

        if (message != nullptr && signedMsg != nullptr && publicKey != nullptr)
        {
            if (signedMsgLength <= static_cast<size_t>(signedMsg->LongLength) &&
                publicKey->LongLength >= QSC_DILITHIUM_PUBLICKEY_SIZE &&
                message->LongLength > 0)
            {
                pin_ptr<Byte> pinnedMsg = &message[0];
                pin_ptr<Byte> pinnedSig = &signedMsg[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];

                size_t mlen = 0;
                res = qsc_dilithium_verify(pinnedMsg, &mlen, pinnedSig, signedMsgLength, pinnedPk);

                if (res == true)
                {
                    messageLength = mlen;
                }
            }
        }

        return res;
    }

    bool Dilithium::VerifyEx(array<Byte>^ message, size_t% messageLength, array<Byte>^ signedMsg, size_t signedMsgLength, array<Byte>^ context, size_t contextLength, array<Byte>^ publicKey)
    {
        bool res;

        res = false;

        if (message != nullptr && signedMsg != nullptr && publicKey != nullptr)
        {
            if (signedMsgLength <= static_cast<size_t>(signedMsg->LongLength) &&
                publicKey->LongLength >= QSC_DILITHIUM_PUBLICKEY_SIZE &&
                message->LongLength > 0)
            {
                pin_ptr<Byte> pinnedMsg = &message[0];
                pin_ptr<Byte> pinnedSig = &signedMsg[0];
                pin_ptr<Byte> pinnedPk = &publicKey[0];

                const uint8_t* ctxPtr = nullptr;

                if (context != nullptr && contextLength <= static_cast<size_t>(context->LongLength))
                {
                    pin_ptr<Byte> pinnedCtx = &context[0];

                    ctxPtr = pinnedCtx;
                }

                size_t mlen = 0;
                res = qsc_dilithium_verify_ex(pinnedMsg, &mlen, pinnedSig, signedMsgLength, ctxPtr, contextLength, pinnedPk);

                if (res == true)
                {
                    messageLength = mlen;
                }
            }
        }

        return res;
    }
}