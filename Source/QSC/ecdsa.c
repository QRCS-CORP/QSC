#include "ecdsa.h"
#include "ecdsap256base.h"
#include "memutils.h"
#include <string.h>

static size_t qsc_ecdsa_der_strip_integer(const uint8_t* in, size_t inlen)
{
    size_t i = 0U;

    while (i + 1U < inlen && in[i] == 0x00U)
    {
        ++i;
    }

    return i;
}

static bool qsc_ecdsa_der_read_len(const uint8_t* input, size_t inplen, size_t* offset, size_t* length)
{
    uint8_t b;
    bool res;

    res = false;

    if (*offset < inplen)
    {
        b = input[*offset];
        *offset += 1U;

        if ((b & 0x80U) == 0U)
        {
            *length = (size_t)b;
            return (*offset + *length <= inplen);
        }

        if (b == 0x81U)
        {
            if (*offset < inplen)
            {
                *length = (size_t)input[*offset];
                *offset += 1U;
                res = (*offset + *length <= inplen);
            }
        }
    }

    return res;
}

static void qsc_ecdsa_der_write_len(uint8_t* output, size_t* offset, size_t len)
{
    if (len < 128U)
    {
        output[*offset] = (uint8_t)len;
        *offset += 1U;
    }
    else
    {
        output[*offset] = 0x81U;
        output[*offset + 1U] = (uint8_t)len;
        *offset += 2U;
    }
}

int32_t qsc_ecdsa_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    int32_t res;

    res = -1;

    if (publickey != NULL && privatekey != NULL)
    {
        res = qsc_p256_publickey_from_privatekey(publickey, privatekey);
    }

    return res;
}

bool qsc_ecdsa_publickey_from_sec1(uint8_t* publickey, const uint8_t* secpub)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(secpub != NULL);

    bool res;

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

bool qsc_ecdsa_publickey_from_spki(uint8_t* publickey, const uint8_t* spkider, size_t spkilen)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(spkider != NULL);

    bool res;

    res = false;

    if (publickey != NULL && spkider != NULL)
    {
        static const uint8_t spki_prefix[26] =
        {
            0x30U, 0x59U, 0x30U, 0x13U, 0x06U, 0x07U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U,
            0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U, 0x03U, 0x42U, 0x00U
        };

        if (spkilen == QSC_ECDSA_SPKI_DER_SIZE)
        {
            if (qsc_memutils_are_equal(spkider, spki_prefix, sizeof(spki_prefix)) == true)
            {
                if (spkider[26U] == 0x04U)
                {
                    qsc_memutils_copy(publickey, spkider + 27U, QSC_ECDSA_PUBLICKEY_SIZE);
                    res = true;
                }
            }
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

void qsc_ecdsa_publickey_to_spki(uint8_t* spkider, const uint8_t* publickey)
{
    QSC_ASSERT(spkider != NULL);
    QSC_ASSERT(publickey != NULL);

    if (spkider != NULL && publickey != NULL)
    {
        static const uint8_t spki_prefix[26] =
        {
            0x30U, 0x59U, 0x30U, 0x13U, 0x06U, 0x07U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U,
            0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U, 0x03U, 0x42U, 0x00U
        };

        qsc_memutils_copy(spkider, spki_prefix, sizeof(spki_prefix));
        spkider[26U] = 0x04U;
        qsc_memutils_copy(spkider + 27U, publickey, QSC_ECDSA_PUBLICKEY_SIZE);
    }
}

bool qsc_ecdsa_signature_to_der(uint8_t* dersig, size_t* derlen, const uint8_t* signature)
{
    QSC_ASSERT(dersig != NULL);
    QSC_ASSERT(derlen != NULL);
    QSC_ASSERT(signature != NULL);

    size_t offset;
    size_t rlen;
    size_t rskip;
    size_t seqlen;
    size_t slen;
    size_t sskip;
    bool res;
    bool rpad;
    bool spad;

    res = false;

    if (dersig != NULL && derlen != NULL && signature != NULL)
    {
        offset = 0U;
        const uint8_t* r = signature;
        const uint8_t* s = signature + 32U;
        rskip = qsc_ecdsa_der_strip_integer(r, 32U);
        sskip = qsc_ecdsa_der_strip_integer(s, 32U);

        r += rskip;
        s += sskip;
        rlen = 32U - rskip;
        slen = 32U - sskip;

        rpad = ((r[0] & 0x80U) != 0U);
        spad = ((s[0] & 0x80U) != 0U);

        seqlen = 2U + (rpad ? 1U : 0U) + rlen + 2U + (spad ? 1U : 0U) + slen;
        dersig[offset] = 0x30U;
        ++offset;
        qsc_ecdsa_der_write_len(dersig, &offset, seqlen);
        dersig[offset] = 0x02U;
        ++offset;
        qsc_ecdsa_der_write_len(dersig, &offset, rlen + (rpad ? 1U : 0U));

        if (rpad)
        {
            dersig[offset] = 0x00U;
            ++offset;
        }

        qsc_memutils_copy(dersig + offset, r, rlen);
        offset += rlen;
        dersig[offset] = 0x02U;
        ++offset;
        qsc_ecdsa_der_write_len(dersig, &offset, slen + (spad ? 1U : 0U));

        if (spad)
        {
            dersig[offset] = 0x00U;
            ++offset;
        }

        qsc_memutils_copy(dersig + offset, s, slen);
        offset += slen;
        *derlen = offset;
        res = true;
    }

    return res;
}

bool qsc_ecdsa_signature_from_der(uint8_t* signature, const uint8_t* dersig, size_t derlen)
{
    QSC_ASSERT(signature != NULL);
    QSC_ASSERT(dersig != NULL);
    
    const uint8_t* rp;
    const uint8_t* sp;
    size_t offset;
    size_t ilen;
    size_t rlen;
    size_t seqlen;
    size_t slen;
    bool res;

    res = false;

    if (signature != NULL && dersig != NULL)
    {
        offset = 0U;
        qsc_memutils_clear(signature, QSC_ECDSA_SIGNATURE_SIZE);

        if (derlen >= 8U && derlen <= QSC_ECDSA_SIGNATURE_DER_MAX_SIZE)
        {
            if (dersig[offset] == 0x30U)
            {
                ++offset;
                if (qsc_ecdsa_der_read_len(dersig, derlen, &offset, &seqlen) == true)
                {
                    if (offset + seqlen == derlen)
                    {
                        if (offset < derlen && dersig[offset] == 0x02U)
                        {
                            ++offset;

                            if (qsc_ecdsa_der_read_len(dersig, derlen, &offset, &ilen) == true)
                            {
                                if (ilen != 0U && ilen <= 33U && offset + ilen <= derlen)
                                {
                                    rp = dersig + offset;
                                    rlen = ilen;
                                    offset += ilen;

                                    if (offset < derlen && dersig[offset++] == 0x02U)
                                    {
                                        if (qsc_ecdsa_der_read_len(dersig, derlen, &offset, &ilen) == true)
                                        {
                                            if (ilen != 0U && ilen <= 33U && offset + ilen <= derlen)
                                            {
                                                sp = dersig + offset;
                                                slen = ilen;
                                                offset += ilen;

                                                if (offset == derlen)
                                                {
                                                    if (rlen > 1U && rp[0] == 0x00U)
                                                    {
                                                        if ((rp[1] & 0x80U) != 0U)
                                                        {
                                                            ++rp;
                                                            --rlen;
                                                        }
                                                    }

                                                    if (slen > 1U && sp[0U] == 0x00U)
                                                    {
                                                        if ((sp[1] & 0x80U) != 0U)
                                                        {
                                                            ++sp;
                                                            --slen;
                                                        }
                                                    }

                                                    if (rlen != 0U && rlen <= 32U && slen != 0U && slen <= 32U)
                                                    {
                                                        if ((rp[0U] & 0x80U) == 0U && (sp[0U] & 0x80U) == 0U)
                                                        {
                                                            qsc_memutils_copy(signature + (32U - rlen), rp, rlen);
                                                            qsc_memutils_copy(signature + 32U + (32U - slen), sp, slen);
                                                            res = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return res;
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
        qsc_p256_keypair(publickey, privatekey, seed);
        res = true;
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
            res = qsc_p256_keypair(publickey, privatekey, seed) == 0;

            if (res == false)
            {
                qsc_memutils_secure_erase(publickey, QSC_ECDSA_SEC1_PUBLICKEY_SIZE);
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
        if (qsc_p256_sign(signedmsg, smsglen, message, msglen, privatekey) == 0)
        {
            res = true;
        }
        else
        {
            qsc_memutils_clear(signedmsg, msglen + QSC_ECDSA_SIGNATURE_SIZE);
            
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
        if (qsc_p256_sign_scalar(signedmsg, smsglen, message, msglen, privatekey) == 0)
        {
            res = true;
        }
        else
        {
            qsc_memutils_clear(signedmsg, msglen + QSC_ECDSA_SIGNATURE_SIZE);

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

    if (message != NULL && msglen != NULL && signedmsg != NULL && smsglen > QSC_ECDSA_SIGNATURE_SIZE)
    {
        res = qsc_p256_verify(message, msglen, signedmsg, smsglen, publickey);
    }

    return res;
}
