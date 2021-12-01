#include "ecdhbase.h"
#include "consoleutils.h"
#include "csp.h"
#include "ec25519.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"

static void edwards_to_montgomery(fe25519 montgomeryX, const fe25519 edwardsY, const fe25519 edwardsZ)
{
    fe25519 tempX;
    fe25519 tempZ;

    fe25519_add(tempX, edwardsZ, edwardsY);
    fe25519_sub(tempZ, edwardsZ, edwardsY);
    fe25519_invert(tempZ, tempZ);
    fe25519_mul(montgomeryX, tempX, tempZ);
}

static int32_t crypto_scalarmult_curve25519_ref10_base(uint8_t* q, const uint8_t* n)
{
    uint8_t* t = q;
    ge25519_p3 A;
    fe25519 pk;

    for (size_t i = 0; i < 32; ++i)
    {
        t[i] = n[i];
    }

    sc25519_clamp(t);
    ge25519_scalarmult_base(&A, t);
    edwards_to_montgomery(pk, A.y, A.z);
    fe25519_tobytes(q, pk);

    return 0;
}

static int32_t crypto_scalarmult_curve25519_ref10(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    uint8_t* t;
    fe25519 a;
    fe25519 b;
    fe25519 aa;
    fe25519 bb;
    fe25519 cb;
    fe25519 da;
    fe25519 e;
    fe25519 x1;
    fe25519 x2;
    fe25519 x3;
    fe25519 z2;
    fe25519 z3;
    uint32_t pos;
    uint32_t swap;
    uint32_t bit;
    int32_t res;

    t = q;
    res = 0;

    if (ed25519_small_order(p) == 0)
    {
        for (size_t i = 0; i < 32; ++i)
        {
            t[i] = n[i];
        }

        sc25519_clamp(t);
        fe25519_frombytes(x1, p);
        fe25519_1(x2);
        fe25519_0(z2);
        fe25519_copy(x3, x1);
        fe25519_1(z3);

        swap = 0;
        pos = 255;

        do
        {
            --pos;
            bit = (uint32_t)t[pos / 8] >> (pos & 7);
            bit &= 1UL;
            swap ^= bit;
            fe25519_cswap(x2, x3, swap);
            fe25519_cswap(z2, z3, swap);
            swap = bit;
            fe25519_add(a, x2, z2);
            fe25519_sub(b, x2, z2);
            fe25519_sq(aa, a);
            fe25519_sq(bb, b);
            fe25519_mul(x2, aa, bb);
            fe25519_sub(e, aa, bb);
            fe25519_sub(da, x3, z3);
            fe25519_mul(da, da, a);
            fe25519_add(cb, x3, z3);
            fe25519_mul(cb, cb, b);
            fe25519_add(x3, da, cb);
            fe25519_sq(x3, x3);
            fe25519_sub(z3, da, cb);
            fe25519_sq(z3, z3);
            fe25519_mul(z3, z3, x1);
            fe25519_mul32(z2, e, 121666);
            fe25519_add(z2, z2, bb);
            fe25519_mul(z2, z2, e);
        } while (pos > 0);

        fe25519_cswap(x2, x3, swap);
        fe25519_cswap(z2, z3, swap);
        fe25519_invert(z2, z2);
        fe25519_mul(x2, x2, z2);
        fe25519_tobytes(q, x2);
    }
    else
    {
        res = -1;
    }

    return res;
}

static int32_t crypto_scalarmult_curve25519(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    uint8_t d;

    d = 0;

    if (crypto_scalarmult_curve25519_ref10(q, n, p) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < EC25519_CURVE_SIZE; ++i)
    {
        d |= q[i];
    }

    return -(1 & ((d - 1) >> 8));
}

bool qsc_ed25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
    int32_t res;

    res = 0;

    if (crypto_scalarmult_curve25519(secret, privatekey, publickey) != 0)
    {
        res = -1;
    }

    return (res == 0);
}

void qsc_ed25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    uint8_t tseed[QSC_SHA2_512_HASH_SIZE] = { 0 };

    qsc_sha512_compute(tseed, seed, EC25519_SEED_SIZE);
    qsc_memutils_copy(privatekey, tseed, EC25519_SEED_SIZE);
    crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
}


