#include "ecdsa.h"
#include "memutils.h"
#if defined(QSC_ECDSA_S1P256)
#   include "ecdsap256base.h"
#elif defined(QSC_ECDSA_S3P384)
#   include "ecdsap384base.h"
#elif defined(QSC_ECDSA_S5P521)
#   include "ecdsap521base.h"
#endif

int32_t qsc_ecdsa_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    int32_t res;

    res = -1;

    if (publickey != NULL && privatekey != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = qsc_p256_publickey_from_privatekey(publickey, privatekey);
#elif defined(QSC_ECDSA_S3P384)
        res = qsc_p384_publickey_from_privatekey(publickey, privatekey);
#elif defined(QSC_ECDSA_S5P521)
        res = qsc_p521_publickey_from_privatekey(publickey, privatekey);
#endif
    }

    return res;
}

bool qsc_ecdsa_publickey_from_sec1(uint8_t* publickey, const uint8_t* secpub)
{
    bool res;

    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(secpub != NULL);

    res = false;

    if (publickey != NULL && secpub != NULL)
    {
        if (secpub[0U] == 0x04U)
        {
            qsc_memutils_copy(publickey, secpub + 1U, QSC_ECDSA_PUBLICKEY_SIZE);
            res = true;
        }
    }

    return res;
}

void qsc_ecdsa_publickey_to_sec1(uint8_t* secpub, const uint8_t* publickey)
{
    QSC_ASSERT(secpub != NULL);
    QSC_ASSERT(publickey != NULL);

    if (secpub != NULL && publickey != NULL)
    {
        secpub[0U] = 0x04U;
        qsc_memutils_copy(secpub + 1U, publickey, QSC_ECDSA_PUBLICKEY_SIZE);
    }
}

bool qsc_ecdsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    bool res;

    res = false;

    if (publickey != NULL && privatekey != NULL && seed != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = (qsc_p256_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S3P384)
        res = (qsc_p384_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S5P521)
        res = (qsc_p521_keypair(publickey, privatekey, seed) == 0);
#endif
    }

    return res;
}

bool qsc_ecdsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(rng_generate != NULL);

    uint8_t seed[QSC_ECDSA_SEED_SIZE] = { 0U };
    bool res;

    res = false;

    if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
    {
        res = rng_generate(seed, sizeof(seed));

        if (res == true)
        {
#if defined(QSC_ECDSA_S1P256)
            res = (qsc_p256_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S3P384)
            res = (qsc_p384_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S5P521)
            res = (qsc_p521_keypair(publickey, privatekey, seed) == 0);
#endif
            if (res == false)
            {
                qsc_memutils_secure_erase(publickey, QSC_ECDSA_PUBLICKEY_SIZE);
                qsc_memutils_secure_erase(privatekey, QSC_ECDSA_PRIVATEKEY_SIZE);
            }

            qsc_memutils_secure_erase(seed, sizeof(seed));
        }
    }

    return res;
}

bool qsc_ecdsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    bool res;

    res = false;

    if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = (qsc_p256_sign(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S3P384)
        res = (qsc_p384_sign(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S5P521)
        res = (qsc_p521_sign(signedmsg, smsglen, message, msglen, privatekey) == 0);
#endif
        if (res == false)
        {
            qsc_memutils_secure_erase(signedmsg, msglen + QSC_ECDSA_SIGNATURE_SIZE);
            
            if (smsglen != NULL)
            {
                *smsglen = 0U;
            }
        }
    }

    return res;
}

bool qsc_ecdsa_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    bool res;

    res = false;

    if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = (qsc_p256_sign_scalar(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S3P384)
        res = (qsc_p384_sign_scalar(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S5P521)
        res = (qsc_p521_sign_scalar(signedmsg, smsglen, message, msglen, privatekey) == 0);
#endif
        if (res == false)
        {
            qsc_memutils_secure_erase(signedmsg, msglen + QSC_ECDSA_SIGNATURE_SIZE);

            if (smsglen != NULL)
            {
                *smsglen = 0U;
            }
        }
    }

    return res;
}

bool qsc_ecdsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(msglen != NULL);
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(smsglen >  QSC_ECDSA_SIGNATURE_SIZE);

    bool res;

    res = false;

    if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL && smsglen > QSC_ECDSA_SIGNATURE_SIZE)
    {
#if defined(QSC_ECDSA_S1P256)
        res = qsc_p256_verify(message, msglen, signedmsg, smsglen, publickey);
#elif defined(QSC_ECDSA_S3P384)
        res = qsc_p384_verify(message, msglen, signedmsg, smsglen, publickey);
#elif defined(QSC_ECDSA_S5P521)
        res = qsc_p521_verify(message, msglen, signedmsg, smsglen, publickey);
#endif
    }

    return res;
}
