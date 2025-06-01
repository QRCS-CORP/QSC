#include "ecdhbase.h"
#include "consoleutils.h"
#include "csp.h"
#include "ec25519.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"


#define EC25519_A24 121666U

static void edwards_to_montgomery(qsc_fe25519 montgomeryX, const qsc_fe25519 edwardsY, const qsc_fe25519 edwardsZ)
{
    qsc_fe25519 tempX;
    qsc_fe25519 tempZ;

    qsc_fe25519_add(tempX, edwardsZ, edwardsY);
    qsc_fe25519_sub(tempZ, edwardsZ, edwardsY);
    qsc_fe25519_invert(tempZ, tempZ);
    qsc_fe25519_mul(montgomeryX, tempX, tempZ);
}

static int32_t crypto_scalarmult_curve25519_ref10_base(uint8_t* q, const uint8_t* n)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);

    uint8_t* t;
    qsc_ge25519_p3 A;
    qsc_fe25519 pk;

    t = q;

    for (size_t i = 0U; i < 32U; ++i)
    {
        t[i] = n[i];
    }

    qsc_sc25519_clamp(t);
    qsc_ge25519_scalarmult_base(&A, t);
    edwards_to_montgomery(pk, A.y, A.z);
    qsc_fe25519_to_bytes(q, pk);

    return 0;
}

static int32_t crypto_scalarmult_curve25519_ref10(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    QSC_ASSERT(q != NULL);
    QSC_ASSERT(n != NULL);
    QSC_ASSERT(p != NULL);

    uint8_t* t;
    qsc_fe25519 a;
    qsc_fe25519 b;
    qsc_fe25519 aa;
    qsc_fe25519 bb;
    qsc_fe25519 cb;
    qsc_fe25519 da;
    qsc_fe25519 e;
    qsc_fe25519 x1;
    qsc_fe25519 x2;
    qsc_fe25519 x3;
    qsc_fe25519 z2;
    qsc_fe25519 z3;
    uint32_t pos;
    uint32_t swap;
    uint32_t bit;
    uint32_t valid;

    t = q;

    valid = (qsc_ed25519_small_order(p) == 0U);

    for (size_t i = 0U; i < 32U; ++i)
    {
        t[i] = n[i];
    }

    qsc_sc25519_clamp(t);
    qsc_fe25519_from_bytes(x1, p);
    qsc_fe25519_1(x2);
    qsc_fe25519_0(z2);
    qsc_fe25519_copy(x3, x1);
    qsc_fe25519_1(z3);

    swap = 0U;
    pos = 255U;

    do
    {
        --pos;
        bit = (uint32_t)t[pos / 8U] >> (pos & 7U);
        bit &= 1U;
        swap ^= bit;
        qsc_fe25519_cswap(x2, x3, swap);
        qsc_fe25519_cswap(z2, z3, swap);
        swap = bit;
        qsc_fe25519_add(a, x2, z2);
        qsc_fe25519_sub(b, x2, z2);
        qsc_fe25519_sq(aa, a);
        qsc_fe25519_sq(bb, b);
        qsc_fe25519_mul(x2, aa, bb);
        qsc_fe25519_sub(e, aa, bb);
        qsc_fe25519_sub(da, x3, z3);
        qsc_fe25519_mul(da, da, a);
        qsc_fe25519_add(cb, x3, z3);
        qsc_fe25519_mul(cb, cb, b);
        qsc_fe25519_add(x3, da, cb);
        qsc_fe25519_sq(x3, x3);
        qsc_fe25519_sub(z3, da, cb);
        qsc_fe25519_sq(z3, z3);
        qsc_fe25519_mul(z3, z3, x1);
        qsc_fe25519_mul32(z2, e, EC25519_A24);
        qsc_fe25519_add(z2, z2, bb);
        qsc_fe25519_mul(z2, z2, e);
    } while (pos > 0U);

    qsc_fe25519_cswap(x2, x3, swap);
    qsc_fe25519_cswap(z2, z3, swap);
    qsc_fe25519_invert(z2, z2);
    qsc_fe25519_mul(x2, x2, z2);
    qsc_fe25519_to_bytes(q, x2);

    return (int32_t)(-((int32_t)valid) & 0);
}

static int32_t crypto_scalarmult_curve25519(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
    QSC_ASSERT(q != NULL);
	QSC_ASSERT(n != NULL);
	QSC_ASSERT(p != NULL);

    uint8_t d;
    int32_t err;
    uint32_t success;

    err = crypto_scalarmult_curve25519_ref10(q, n, p);
    d = 0U;

    for (size_t i = 0U; i < EC25519_CURVE_SIZE; ++i)
    {
        d |= q[i];
    }

    success = (uint32_t)(err == 0);

    return -((int32_t)1 - (int32_t)success);
}

bool qsc_ed25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
	QSC_ASSERT(secret != NULL);
    QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

    int32_t res;

    res = 0;

    if (secret != NULL && privatekey != NULL && publickey != NULL)
    {
        res = (crypto_scalarmult_curve25519(secret, privatekey, publickey));
    }

    return (res == 0);
}

void qsc_ed25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(seed != NULL);
    
    uint8_t tseed[QSC_SHA2_512_HASH_SIZE] = { 0U };

    qsc_sha512_compute(tseed, seed, EC25519_SEED_SIZE);
    qsc_memutils_copy(privatekey, tseed, EC25519_SEED_SIZE);
    crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
}


