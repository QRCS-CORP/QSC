#include "qmac.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* irreducible pentanomial GF(2^256):
 * m(x) = x^256 + x^10 + x^5 + x^2 + 1
 * (lexicographically first low-weight irreducible binary polynomial for 256 bits,
 * see NIST low-weight polynomial tables and CMAC/GCM discussions) */


#if !defined(QSC_SYSTEM_HAS_AVX) || !defined(QSC_SYSTEM_X86)

/* Constant-time portable 32 x 32 carryless multiplication. */
static uint64_t qmac_clmul32_ref(uint32_t x, uint32_t y)
{
    const uint64_t mask = 0x1111111111111111ULL;
    uint64_t r;
    uint64_t xi[4U];
    uint64_t yi[4U];
    size_t i;
    size_t j;

    xi[0U] = (uint64_t)x & mask;
    xi[1U] = ((uint64_t)x >> 1U) & mask;
    xi[2U] = ((uint64_t)x >> 2U) & mask;
    xi[3U] = ((uint64_t)x >> 3U) & mask;
    yi[0U] = (uint64_t)y & mask;
    yi[1U] = ((uint64_t)y >> 1U) & mask;
    yi[2U] = ((uint64_t)y >> 2U) & mask;
    yi[3U] = ((uint64_t)y >> 3U) & mask;
    r = 0U;

    for (i = 0U; i < 4U; ++i)
    {
        for (j = 0U; j < 4U; ++j)
        {
            r ^= ((xi[i] * yi[j]) & mask) << (i + j);
        }
    }

    return r;
}

/* Constant-time portable 64 x 64 carryless multiplication. */
static void qmac_clmul64_ref(uint64_t r[2], uint64_t x, uint64_t y)
{
    uint64_t p00;
    uint64_t p01;
    uint64_t p10;
    uint64_t p11;
    uint64_t pmid;

    p00 = qmac_clmul32_ref((uint32_t)x, (uint32_t)y);
    p01 = qmac_clmul32_ref((uint32_t)x, (uint32_t)(y >> 32U));
    p10 = qmac_clmul32_ref((uint32_t)(x >> 32U), (uint32_t)y);
    p11 = qmac_clmul32_ref((uint32_t)(x >> 32U), (uint32_t)(y >> 32U));
    pmid = p01 ^ p10;

    r[0U] = p00 ^ (pmid << 32U);
    r[1U] = p11 ^ (pmid >> 32U);
}

static void qmac_clmul128_ref(uint64_t r[4], const uint64_t a[2], const uint64_t b[2])
{
    uint64_t p00[2U];
    uint64_t p01[2U];
    uint64_t p10[2U];
    uint64_t p11[2U];
    uint64_t t[2U];

    qmac_clmul64_ref(p00, a[0U], b[0U]);
    qmac_clmul64_ref(p01, a[0U], b[1U]);
    qmac_clmul64_ref(p10, a[1U], b[0U]);
    qmac_clmul64_ref(p11, a[1U], b[1U]);

    t[0U] = p01[0U] ^ p10[0U];
    t[1U] = p01[1U] ^ p10[1U];

    r[0U] = p00[0U];
    r[1U] = p00[1U] ^ t[0U];
    r[2U] = p11[0U] ^ t[1U];
    r[3U] = p11[1U];
}

static void qmac_clmul256_ref(uint64_t r[8], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t a0[2U];
    uint64_t a1[2U];
    uint64_t b0[2U];
    uint64_t b1[2U];
    uint64_t ax[2U];
    uint64_t bx[2U];
    uint64_t mid[4U];
    uint64_t p0[4U];
    uint64_t p1[4U];
    uint64_t p2[4U];
    size_t i;

    a0[0U] = a[0U];
    a0[1U] = a[1U];
    a1[0U] = a[2U];
    a1[1U] = a[3U];
    b0[0U] = b[0U];
    b0[1U] = b[1U];
    b1[0U] = b[2U];
    b1[1U] = b[3U];
    ax[0U] = a0[0U] ^ a1[0U];
    ax[1U] = a0[1U] ^ a1[1U];
    bx[0U] = b0[0U] ^ b1[0U];
    bx[1U] = b0[1U] ^ b1[1U];

    qmac_clmul128_ref(p0, a0, b0);
    qmac_clmul128_ref(p1, a1, b1);
    qmac_clmul128_ref(p2, ax, bx);

    for (i = 0U; i < 4U; ++i)
    {
        mid[i] = p0[i] ^ p1[i] ^ p2[i];
    }

    r[0U] = p0[0U];
    r[1U] = p0[1U];
    r[2U] = p0[2U] ^ mid[0U];
    r[3U] = p0[3U] ^ mid[1U];
    r[4U] = mid[2U] ^ p1[0U];
    r[5U] = mid[3U] ^ p1[1U];
    r[6U] = p1[2U];
    r[7U] = p1[3U];
}

#endif

/* Reduce a 512-bit carryless product modulo x^256 + x^10 + x^5 + x^2 + 1. */
static void qmac_reduce256(uint64_t r[4], const uint64_t p[8])
{
    const uint64_t h0 = p[4U];
    const uint64_t h1 = p[5U];
    const uint64_t h2 = p[6U];
    const uint64_t h3 = p[7U];
    uint64_t overflow;

    r[0U] = p[0U] ^ h0;
    r[1U] = p[1U] ^ h1;
    r[2U] = p[2U] ^ h2;
    r[3U] = p[3U] ^ h3;

    r[0U] ^= h0 << 2U;
    r[1U] ^= (h1 << 2U) | (h0 >> 62U);
    r[2U] ^= (h2 << 2U) | (h1 >> 62U);
    r[3U] ^= (h3 << 2U) | (h2 >> 62U);
    overflow = h3 >> 62U;

    r[0U] ^= h0 << 5U;
    r[1U] ^= (h1 << 5U) | (h0 >> 59U);
    r[2U] ^= (h2 << 5U) | (h1 >> 59U);
    r[3U] ^= (h3 << 5U) | (h2 >> 59U);
    overflow ^= h3 >> 59U;

    r[0U] ^= h0 << 10U;
    r[1U] ^= (h1 << 10U) | (h0 >> 54U);
    r[2U] ^= (h2 << 10U) | (h1 >> 54U);
    r[3U] ^= (h3 << 10U) | (h2 >> 54U);
    overflow ^= h3 >> 54U;

    r[0U] ^= overflow;
    r[0U] ^= overflow << 2U;
    r[0U] ^= overflow << 5U;
    r[0U] ^= overflow << 10U;
}

/* Multiply in GF(2^256) with modulus x^256 + x^10 + x^5 + x^2 + 1.
 * Inputs a, b are 256-bit values (4 x uint64_t, little endian).
 * Output r is 256-bit (4 x uint64_t, little endian).
 */
static void qmac_gfmul256_poly(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t prod[8] = { 0U };

#if defined(QSC_SYSTEM_HAS_AVX) && defined(QSC_SYSTEM_X86)
    qsc_memutils_clmulepi64_si256(prod, a, b);
#else
    qmac_clmul256_ref(prod, a, b);
#endif

    qmac_reduce256(r, prod);
}

static void qmac_block_update(qsc_qmac_state* ctx, const uint64_t* x)
{
	/* y = y ^ x */
    qsc_memutils_xor((uint8_t*)ctx->Y, (const uint8_t*)x, QSC_QMAC_BLOCK_SIZE);
	/* y = (y * h) mod P(y) */
    qmac_gfmul256_poly(ctx->Y, ctx->H, ctx->Y);
}

static void qmac_process_bytes(qsc_qmac_state* ctx, const uint8_t* message)
{
    uint64_t x[QSC_QMAC_STATE_SIZE] = { 0U, 0U, 0U, 0U };

    qsc_memutils_copy((uint8_t*)x, message, QSC_QMAC_BLOCK_SIZE);
    qmac_block_update(ctx, x);
    qsc_memutils_secure_erase(x, sizeof(x));
}

static void qmac_compute_final(uint8_t* tag, qsc_qmac_state* ctx)
{
    uint8_t lbuf[QSC_QMAC_BLOCK_SIZE] = { 0U };

    ctx->buffer[ctx->position] = 0x80U;

    if (ctx->position + 1U < QSC_QMAC_BLOCK_SIZE)
    {
        qsc_memutils_clear(ctx->buffer + ctx->position + 1U, QSC_QMAC_BLOCK_SIZE - ctx->position - 1U);
    }

    qmac_process_bytes(ctx, ctx->buffer);
    qsc_memutils_clear(ctx->buffer, QSC_QMAC_BLOCK_SIZE);

    qsc_intutils_le64to8(lbuf, ctx->msglen);
    lbuf[QSC_QMAC_BLOCK_SIZE - 1U] = 0x01U;
    qmac_process_bytes(ctx, lbuf);
    qsc_memutils_secure_erase(lbuf, sizeof(lbuf));

    /* apply the finalization key: y = y ^ f */
    qsc_memutils_xor((uint8_t*)ctx->Y, (const uint8_t*)ctx->F, QSC_QMAC_BLOCK_SIZE);

    /* copy the tag: t = y */
	qsc_memutils_copy(tag, (const uint8_t*)ctx->Y, QSC_QMAC_BLOCK_SIZE);
}

void qsc_qmac_compute(uint8_t* output, qsc_qmac_keyparams* keyparams, const uint8_t* message, size_t msglen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(keyparams != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(msglen != 0U);

    if (output != NULL && keyparams != NULL && message != NULL && msglen != 0U)
    {
        qsc_qmac_state ctx = { 0U };

        qsc_qmac_initialize(&ctx, keyparams);
        qsc_qmac_update(&ctx, message, msglen);
        qsc_qmac_finalize(&ctx, output);
    }
}

void qsc_qmac_dispose(qsc_qmac_state* ctx)
{
    QSC_ASSERT(ctx != NULL);

    if (ctx != NULL)
    {
        qsc_memutils_secure_erase(ctx->F, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_secure_erase(ctx->H, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_secure_erase(ctx->Y, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_secure_erase(ctx->buffer, QSC_QMAC_BLOCK_SIZE);
        ctx->msglen = 0U;
        ctx->position = 0U;
        ctx->initialized = false;
    }
}

void qsc_qmac_finalize(qsc_qmac_state* ctx, uint8_t* output)
{
    QSC_ASSERT(ctx != NULL);
    QSC_ASSERT(output != NULL);

    if (ctx != NULL && output != NULL && ctx->initialized == true)
    {
        /* finalize the state */
        qmac_compute_final(output, ctx);
        /* dispose of the state */
        qsc_qmac_dispose(ctx);
    }
}

void qsc_qmac_initialize(qsc_qmac_state* ctx, qsc_qmac_keyparams* keyparams)
{
    QSC_ASSERT(ctx != NULL);
    QSC_ASSERT(keyparams != NULL);

    if (ctx != NULL && keyparams != NULL)
    {
        qsc_keccak_state kstate = { 0U };
	    uint8_t sbuf[QSC_KECCAK_256_RATE] = { 0U };

        qsc_memutils_secure_erase(ctx->Y, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_secure_erase(ctx->buffer, QSC_QMAC_BLOCK_SIZE);
        ctx->msglen = 0U;
        ctx->position = 0U;

        /* initialize the SHAKE instance */
        qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, keyparams->key, keyparams->keylen, keyparams->nonce, keyparams->noncelen, keyparams->info, keyparams->infolen);
        /* generate the subkeys H and F */
        qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1U);

        /* copy the hash subkey */
        qsc_memutils_copy((uint8_t*)ctx->H, sbuf, QSC_QMAC_BLOCK_SIZE);
        /* copy the finalization key */
        qsc_memutils_copy((uint8_t*)ctx->F, sbuf + QSC_QMAC_BLOCK_SIZE, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_secure_erase(sbuf, sizeof(sbuf));
        qsc_keccak_dispose(&kstate);

        ctx->initialized = true;
    }
}

void qsc_qmac_update(qsc_qmac_state* ctx, const uint8_t* message, size_t msglen)
{
    QSC_ASSERT(ctx != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(msglen != 0U);

    size_t mlen;
    size_t mpos;

    mpos = 0U;

    if (ctx != NULL && message != NULL && msglen != 0U && ctx->initialized == true)
    {
        ctx->msglen += (uint64_t)msglen;

        if (ctx->position != 0U)
        {
            mlen = QSC_QMAC_BLOCK_SIZE - ctx->position;

            if (mlen > msglen)
            {
                mlen = msglen;
            }

            qsc_memutils_copy(ctx->buffer + ctx->position, message, mlen);
            ctx->position += mlen;
            mpos += mlen;
            msglen -= mlen;

            if (ctx->position == QSC_QMAC_BLOCK_SIZE)
            {
                qmac_process_bytes(ctx, ctx->buffer);
                qsc_memutils_clear(ctx->buffer, QSC_QMAC_BLOCK_SIZE);
                ctx->position = 0U;
            }
        }

        while (msglen >= QSC_QMAC_BLOCK_SIZE)
        {
            qmac_process_bytes(ctx, message + mpos);
            mpos += QSC_QMAC_BLOCK_SIZE;
            msglen -= QSC_QMAC_BLOCK_SIZE;
        }

        if (msglen != 0U)
        {
            qsc_memutils_copy(ctx->buffer, message + mpos, msglen);
            ctx->position = msglen;
        }
    }
}
