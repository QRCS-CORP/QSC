#include "eddsa448base.h"
#include "ed448.h"
#include "sha3.h"
#include "memutils.h"

static const uint8_t DOM4_PREFIX[10U] = 
{
    'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0x00U, 0x00U
};

static void shake256_dom4_hash(uint8_t* out, size_t outlen, const uint8_t** parts, const size_t* lens, size_t nparts)
{
    qsc_keccak_state state = { 0 };

    if (out != NULL && parts != NULL && lens != NULL)
    {
        qsc_keccak_initialize_state(&state);

        /* absorb dom4(F,C) exactly as message bytes */
        qsc_keccak_incremental_absorb(&state, (uint32_t)qsc_keccak_rate_256, DOM4_PREFIX, sizeof(DOM4_PREFIX));

        /* absorb the remaining transcript parts in order */
        for (size_t i = 0U; i < nparts; ++i)
        {
            if (parts[i] != NULL && lens[i] != 0U)
            {
                qsc_keccak_incremental_absorb(&state, (uint32_t)qsc_keccak_rate_256, parts[i], lens[i]);
            }
        }

        /* finalize as SHAKE, then squeeze XOF output */
        qsc_keccak_incremental_finalize(&state, (uint32_t)qsc_keccak_rate_256, QSC_KECCAK_SHAKE_DOMAIN_ID);
        qsc_keccak_incremental_squeeze(&state, (size_t)qsc_keccak_rate_256, out, outlen);

        qsc_keccak_dispose(&state);
    }
}

static void qsc_sc448_prune_secret(uint8_t k[57U])
{
    /* RFC 8032 Ed448 secret scalar pruning */
    k[0U] &= 0xFCU;
    k[55U] |= 0x80U;
    k[56U] = 0x00U;
}

void qsc_ed448_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(rng_generate != NULL);

    uint8_t seed[ED448_SEED_SIZE] = { 0U };

    if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
    {
        if (rng_generate(seed, ED448_SEED_SIZE) == true)
        {
            uint8_t expanded[114U] = { 0U };

            /* expand seed: H = SHAKE256(seed, 114) */
            qsc_shake256_compute(expanded, 114U, seed, ED448_SEED_SIZE);

            /* clamp the scalar (lower 57 bytes of H) per RFC 8032 5.2.5 */
            expanded[0U] &= 252U;   /* clear bits 0 and 1 */
            expanded[55U] |= 128U;   /* set bit 447 */
            expanded[56U] = 0U;     /* clear byte 56 (the scalar is 448 bits, not 456) */

            /* compute public key A = scalar * B */
            qsc_ge448_p3 A;
            qsc_ge448_scalarmult_base(&A, expanded);
            qsc_ge448_p3_to_bytes(publickey, &A);

            /* store private key as seed || public key */
            qsc_memutils_copy(privatekey, seed, ED448_SEED_SIZE);
            qsc_memutils_copy(privatekey + ED448_SEED_SIZE, publickey, ED448_PUBLICKEY_SIZE);

            /* secure clear of expanded scalar */
            qsc_memutils_secure_erase(expanded, sizeof(expanded));
        }
        else
        {
            qsc_memutils_secure_erase(publickey, ED448_PUBLICKEY_SIZE);
            qsc_memutils_secure_erase(privatekey, ED448_PRIVATEKEY_SIZE);
        }
    }
}

void qsc_ed448_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    uint8_t expanded[114U] = { 0U };

    if (publickey != NULL && privatekey != NULL && seed != NULL)
    {
        /* expand seed: H = SHAKE256(seed, 114) */
        qsc_shake256_compute(expanded, 114U, seed, ED448_SEED_SIZE);

        /* clamp the scalar (lower 57 bytes of H) per RFC 8032 5.2.5 */
        expanded[0U] &= 252U;   /* clear bits 0 and 1 */
        expanded[55U] |= 128U;   /* set bit 447 */
        expanded[56U] = 0U;     /* clear byte 56 (the scalar is 448 bits, not 456) */

        /* compute public key A = scalar * B */
        qsc_ge448_p3 A;
        qsc_ge448_scalarmult_base(&A, expanded);
        qsc_ge448_p3_to_bytes(publickey, &A);

        /* store private key as seed || public key */
        qsc_memutils_copy(privatekey, seed, ED448_SEED_SIZE);
        qsc_memutils_copy(privatekey + ED448_SEED_SIZE, publickey, ED448_PUBLICKEY_SIZE);

        /* secure clear of expanded scalar */
        qsc_memutils_secure_erase(expanded, sizeof(expanded));
    }
}

bool qsc_ed448_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    uint8_t az[114U] = { 0U };
    uint8_t nonce[114U] = { 0U };
    uint8_t hram[114U] = { 0U };
    uint8_t R[57U] = { 0U };
    uint8_t S[57U] = { 0U };
    uint8_t seed[57U] = { 0U };
    uint8_t pubkey[57U] = { 0U };
    uint8_t a[57U] = { 0U };
    const uint8_t* rdom[2U];
    const uint8_t* hdom[3U];
    size_t rlens[2U] = { 0U };
    size_t hlens[3U] = { 0U };
    qsc_ge448_p3 A;
    qsc_ge448_p3 Rp;
    bool res;

    res = false;

    if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
    {
        /* privatekey = seed || publickey */
        qsc_memutils_copy(seed, privatekey, 57U);
        qsc_memutils_copy(pubkey, privatekey + 57U, 57U);

        /* az = SHAKE256(seed, 114) */
        qsc_shake256_compute(az, sizeof(az), seed, 57U);

        /* prune secret scalar a */
        qsc_memutils_copy(a, az, 57U);
        qsc_sc448_prune_secret(a);

        /* r = H(dom4, az[57..113], M) mod l */
        rdom[0U] = az + 57U;
        rdom[1U] = message;
        rlens[0U] = 57U;
        rlens[1U] = msglen;
        shake256_dom4_hash(nonce, sizeof(nonce), rdom, rlens, 2U);
        qsc_sc448_reduce(nonce);

        /* R = [r]B */
        qsc_ge448_scalarmult_base(&Rp, nonce);
        qsc_ge448_p3_to_bytes(R, &Rp);

        /* k = H(dom4, R, A, M) mod l */
        hdom[0U] = R;
        hdom[1U] = pubkey;
        hdom[2U] = message;
        hlens[0U] = 57U;
        hlens[1U] = 57U;
        hlens[2U] = msglen;
        shake256_dom4_hash(hram, sizeof(hram), hdom, hlens, 3U);
        qsc_sc448_reduce(hram);

        /* S = (r + k * a) mod l */
        qsc_sc448_muladd(S, hram, a, nonce);

        /* signedmsg = R || S || M */
        qsc_memutils_copy(signedmsg, R, 57U);
        qsc_memutils_copy(signedmsg + 57U, S, 57U);

        if (msglen != 0U)
        {
            qsc_memutils_copy(signedmsg + 114U, message, msglen);
        }

        *smsglen = 114U + msglen;

        qsc_memutils_secure_erase(az, sizeof(az));
        qsc_memutils_secure_erase(nonce, sizeof(nonce));
        qsc_memutils_secure_erase(hram, sizeof(hram));
        qsc_memutils_secure_erase(seed, sizeof(seed));
        qsc_memutils_secure_erase(a, sizeof(a));
        qsc_memutils_secure_erase(R, sizeof(R));
        qsc_memutils_secure_erase(S, sizeof(S));
        qsc_memutils_secure_erase(&A, sizeof(A));
        qsc_memutils_secure_erase(&Rp, sizeof(Rp));
        res = true;
    }

    return res;
}

bool qsc_ed448_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(msglen != NULL);
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(publickey != NULL);

    qsc_ge448_p3 A;
    qsc_ge448_p2 Rcheck;
    uint8_t hram[114U] = { 0U };
    uint8_t checker[57U] = { 0U };
    const uint8_t* R;
    const uint8_t* S;
    const uint8_t* smsg;
    const uint8_t* hdom[3U];
    size_t hlens[3U];
    size_t mlenin;
    bool res;

    res = false;
    *msglen = 0U;

    if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL)
    {
        if (smsglen >= 114U)
        {
            R = signedmsg;
            S = signedmsg + 57U;
            smsg = signedmsg + 114U;
            mlenin = smsglen - 114U;

            if (qsc_sc448_is_canonical(S) != 0)
            {
                if (qsc_ge448_is_canonical(R) != 0)
                {
                    if (qsc_ge448_has_small_order(publickey) == 0)
                    {
                        if (qsc_ge448_from_bytes_negate_vartime(&A, publickey) == 0)
                        {
                            /* k = H(dom4, R, A, M) mod l */
                            hdom[0U] = R;
                            hdom[1U] = publickey;
                            hdom[2U] = smsg;
                            hlens[0U] = 57U;
                            hlens[1U] = 57U;
                            hlens[2U] = mlenin;
                            shake256_dom4_hash(hram, sizeof(hram), hdom, hlens, 3U);
                            qsc_sc448_reduce(hram);

                            /* Check [S]B = R + [k]A */
                            qsc_ge448_double_scalarmult_vartime(&Rcheck, hram, &A, S);
                            qsc_ge448_to_bytes(checker, &Rcheck);

                            if (qsc_memutils_are_equal(checker, R, 57U) == true)
                            {
                                if (mlenin != 0U)
                                {
                                    qsc_memutils_copy(message, smsg, mlenin);
                                }

                                *msglen = mlenin;
                                res = true;
                            }

                            qsc_memutils_secure_erase(hram, sizeof(hram));
                            qsc_memutils_secure_erase(checker, sizeof(checker));
                            qsc_memutils_secure_erase(&A, sizeof(A));
                            qsc_memutils_secure_erase(&Rcheck, sizeof(Rcheck));
                        }
                    }
                }
            }
        }
    }

    return res;
}
