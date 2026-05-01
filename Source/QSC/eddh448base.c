#include "eddh448base.h"
#include "ed448.h"
#include "memutils.h"

/* ============================================================
 * X448 Montgomery ladder (RFC 7748 5)
 *
 * The curve is: v^2 = u^3 + A*u^2 + u over GF(2^448 - 2^224 - 1)
 * with A = 156326 and A24 = (A - 2) / 4 = 39081.
 * ============================================================ */

#define A24_448 39081U

static const uint8_t X448_BASE_U[56U] =
{
    5U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
};

static void x448_scalarmult(uint8_t out[56U], const uint8_t k[56U], const uint8_t u[56U])
{
    qsc_fe448 a;
    qsc_fe448 b;
    qsc_fe448 aa;
    qsc_fe448 bb;
    qsc_fe448 c;
    qsc_fe448 cb;
    qsc_fe448 d;
    qsc_fe448 da;
    qsc_fe448 e;
    qsc_fe448 t0;
    qsc_fe448 x1;
    qsc_fe448 x2;
    qsc_fe448 z2;
    qsc_fe448 x3;
    qsc_fe448 z3;
    qsc_fe448 zinv;
    uint32_t swap;

    if (out != NULL && k != NULL && u != NULL)
    {
        qsc_fe448_from_bytes(x1, u);
        qsc_fe448_1(x2);
        qsc_fe448_0(z2);
        qsc_fe448_copy(x3, x1);
        qsc_fe448_1(z3);
        swap = 0U;

        for (int32_t i = 447; i >= 0; --i)
        {
            const uint32_t kbit = ((uint32_t)k[(size_t)i >> 3] >> ((uint32_t)i & 7U)) & 1U;

            swap ^= kbit;
            qsc_fe448_cswap(x2, x3, swap);
            qsc_fe448_cswap(z2, z3, swap);
            swap = kbit;

            qsc_fe448_add(a, x2, z2);
            qsc_fe448_sub(b, x2, z2);
            qsc_fe448_sq(aa, a);
            qsc_fe448_sq(bb, b);
            qsc_fe448_sub(e, aa, bb);
            qsc_fe448_add(c, x3, z3);
            qsc_fe448_sub(d, x3, z3);
            qsc_fe448_mul(da, d, a);
            qsc_fe448_mul(cb, c, b);
            qsc_fe448_add(t0, da, cb);
            qsc_fe448_sq(x3, t0);
            qsc_fe448_sub(t0, da, cb);
            qsc_fe448_sq(t0, t0);
            qsc_fe448_mul(z3, x1, t0);
            qsc_fe448_mul(x2, aa, bb);
            qsc_fe448_mul32(t0, e, A24_448);
            qsc_fe448_add(t0, aa, t0);
            qsc_fe448_mul(z2, e, t0);
        }

        qsc_fe448_cswap(x2, x3, swap);
        qsc_fe448_cswap(z2, z3, swap);

        qsc_fe448_invert(zinv, z2);
        qsc_fe448_mul(x2, x2, zinv);
        qsc_fe448_to_bytes(out, x2);
    }
}

void qsc_crypto_scalarmult_curve448_ref10_base(uint8_t* q, const uint8_t* n)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);

    if (q != NULL && n != NULL)
    {
        x448_scalarmult(q, n, X448_BASE_U);
    }
}

void qsc_crypto_scalarmult_curve448_ref10(uint8_t* r, const uint8_t* n, const uint8_t* q)
{
    QSC_ASSERT(r != NULL);
    QSC_ASSERT(n != NULL);
    QSC_ASSERT(q != NULL);

    if (r != NULL && n != NULL && q != NULL)
    {
        x448_scalarmult(r, n, q);
    }
}

void qsc_crypto_sc448_clamp(uint8_t * k)
{
    qsc_sc448_clamp(k);
}

void qsc_crypto_scalarmult_curve448(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);
    QSC_ASSERT(p != NULL);

    uint8_t kclamped[QSC_X448_PRIVATEKEY_SIZE] = { 0U };

    if (q != NULL && n != NULL && p != NULL)
    {
        qsc_memutils_copy(kclamped, n, sizeof(kclamped));
        qsc_sc448_clamp(kclamped);
        x448_scalarmult(q, kclamped, p);
        qsc_memutils_secure_erase(kclamped, sizeof(kclamped));
    }
}

void qsc_x448_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(rng_generate != NULL);

    uint8_t ktmp[QSC_X448_PRIVATEKEY_SIZE] = { 0U };

    if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
    {
        if (rng_generate(privatekey, QSC_X448_PRIVATEKEY_SIZE) == true)
        {
            qsc_memutils_copy(ktmp, privatekey, QSC_X448_PRIVATEKEY_SIZE);
            qsc_sc448_clamp(ktmp);
            qsc_crypto_scalarmult_curve448_ref10_base(publickey, ktmp);
            qsc_memutils_secure_erase(ktmp, sizeof(ktmp));
        }
        else
        {
            qsc_memutils_clear(publickey, QSC_X448_PUBLICKEY_SIZE);
            qsc_memutils_clear(privatekey, QSC_X448_PRIVATEKEY_SIZE);
        }
    }
}

void qsc_x448_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    uint8_t ktmp[QSC_X448_PRIVATEKEY_SIZE] = { 0U };

    if (publickey != NULL && privatekey != NULL && seed != NULL)
    {
        qsc_memutils_copy(privatekey, seed, QSC_X448_PRIVATEKEY_SIZE);
        qsc_memutils_copy(ktmp, seed, QSC_X448_PRIVATEKEY_SIZE);
        qsc_sc448_clamp(ktmp);
        qsc_crypto_scalarmult_curve448_ref10_base(publickey, ktmp);
        qsc_memutils_secure_erase(ktmp, sizeof(ktmp));
    }
}

bool qsc_x448_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(secret != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(publickey != NULL);

    uint8_t acc;

    acc = 0U;

    if (secret != NULL && privatekey != NULL && publickey != NULL)
    {
        qsc_crypto_scalarmult_curve448(secret, privatekey, publickey);

        for (size_t i = 0U; i < QSC_X448_SECRET_SIZE; ++i)
        {
            acc |= secret[i];
        }
    }

    return (acc != 0U);
}
