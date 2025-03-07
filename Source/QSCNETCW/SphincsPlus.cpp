#include "SphincsPlus.h"
#include "..\QSC\acp.h"
#include "..\QSC\sphincsplus.h"

namespace QSCNETCW
{
    size_t SphincsPlus::PrivateKeySize()
    {
        return QSC_SPHINCSPLUS_PRIVATEKEY_SIZE;
    }

    size_t SphincsPlus::PublicKeySize()
    {
        return QSC_SPHINCSPLUS_PUBLICKEY_SIZE;
    }

    size_t SphincsPlus::SignatureSize()
    {
        return QSC_SPHINCSPLUS_SIGNATURE_SIZE;
    }

    void SphincsPlus::GenerateKeypair(array<Byte>^ publicKey, array<Byte>^ privateKey)
    {
        if (publicKey != nullptr && privateKey != nullptr)
        {
            pin_ptr<Byte> pinnedPub = &publicKey[0];
            pin_ptr<Byte> pinnedPriv = &privateKey[0];

            qsc_sphincsplus_generate_keypair(pinnedPub, pinnedPriv, &qsc_acp_generate);
        }
    }

    void SphincsPlus::Sign(array<Byte>^ signedMsg, [System::Runtime::InteropServices::Out] size_t% smsgLen, array<Byte>^ message, size_t msgLen, array<Byte>^ privateKey)
    {
        smsgLen = 0;

        if (signedMsg != nullptr && message != nullptr && privateKey != nullptr)
        {
            if (message->LongLength >= static_cast<long>(msgLen))
            {
                pin_ptr<Byte> pinnedSm = &signedMsg[0];
                pin_ptr<Byte> pinnedMsg = &message[0];
                pin_ptr<Byte> pinnedPriv = &privateKey[0];
                size_t tmpLen = 0;

                qsc_sphincsplus_sign(pinnedSm, &tmpLen, pinnedMsg, msgLen, pinnedPriv, &qsc_acp_generate);
                smsgLen = tmpLen;
            }
        }
    }

    bool SphincsPlus::Verify(array<Byte>^ message, [System::Runtime::InteropServices::Out] size_t% msgLen, array<Byte>^ signedMsg, size_t smsgLen, array<Byte>^ publicKey)
    {
        bool res;

        res = false;
        msgLen = 0;

        if (message != nullptr && signedMsg != nullptr && publicKey != nullptr)
        {
            pin_ptr<Byte> pinnedMsg = &message[0];
            pin_ptr<Byte> pinnedSm = &signedMsg[0];
            pin_ptr<Byte> pinnedPub = &publicKey[0];
            size_t tmpLen = 0;

            res = qsc_sphincsplus_verify(pinnedMsg, &tmpLen, pinnedSm, smsgLen, pinnedPub);

            if (res == true)
            {
                msgLen = tmpLen;
            }
        }

        return res;
    }
}
