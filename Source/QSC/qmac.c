#include "qmac.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* irreducible pentanomial GF(2^256):
 * m(x) = x^256 + x^10 + x^5 + x^2 + 1
 * (lexicographically first low-weight irreducible binary polynomial for 256 bits,
 * see NIST low-weight polynomial tables and CMAC/GCM discussions) */

/* Multiply in GF(2^256) with modulus x^256 + x^10 + x^5 + x^2 + 1.
 * Inputs a, b are 256-bit values (4 x uint64_t, little endian).
 * Output r is 256-bit (4 x uint64_t, little endian).
 * We:
 *   1. Compute the 512-bit carryless product with qsc_memutils_clmulepi64_si256.
 *   2. Reduce it modulo x^256 + x^10 + x^5 + x^2 + 1 by bit-level polynomial division.
 */
static void qmac_gfmul256_poly(uint64_t r[4U], const uint64_t a[4U], const uint64_t b[4U])
{
    uint64_t prod[8U] = { 0U };
    uint64_t x[8U];

    /* step 1: 512-bit carryless product, using CLMUL (AVX) when available */
    qsc_memutils_clmulepi64_si256(prod, a, b);

    /* make a working copy */
    for (size_t i = 0U; i < 8U; ++i)
    {
        x[i] = prod[i];
    }

    /* step 2: reduction modulo m(x) = x^256 + x^10 + x^5 + x^2 + 1
     *
     * For each bit i >= 256:
     *   x^i = x^{i-256} * x^256 ≡ x^{i-256} * (x^10 + x^5 + x^2 + 1)
     *        = x^{i-256+10} + x^{i-256+5} + x^{i-256+2} + x^{i-256}.
     *
     * So whenever bit i is set, we clear it and XOR bits at:
     *   base = i - 256
     *   base + 10, base + 5, base + 2, base + 0.
     */
    for (int32_t bit = 511; bit >= 256; --bit)
    {
        int32_t word = bit >> 6;
        int32_t off = bit & 63;
        uint64_t mask = (uint64_t)1ULL << off;

        if ((x[word] & mask) != 0U)
        {
            /* clear bit i */
            x[word] ^= mask;

            const int32_t base = bit - 256;
            /* shifts corresponding to {0, 2, 5, 10} */
            static const int32_t shifts[4] = { 0, 2, 5, 10 };

            for (size_t j = 0U; j < 4U; ++j)
            {
                const int32_t tbit = base + shifts[j];
                const int32_t tword = tbit >> 6;
                const int32_t toff = tbit & 63;
                x[tword] ^= (uint64_t)1ULL << toff;
            }
        }
    }

    /* now x[0..3] hold the degree < 256 representative */
    for (size_t i = 0U; i < 4U; ++i)
    {
        r[i] = x[i];
    }
}

static void qmac_block_update(qsc_qmac_state* ctx, const uint64_t* x)
{
#if defined(QSC_MISRA_FULL_COMPLIANCE)
    for (size_t i = 0U; i < QSC_QMAC_BLOCK_SIZE / sizeof(uint64_t); ++i)
    {
        ctx->Y[i] ^= x[i];
    }
#else
	/* y = y ^ x */
    qsc_memutils_xor((uint8_t*)ctx->Y, (const uint8_t*)x, QSC_QMAC_BLOCK_SIZE);
#endif

	/* y = (y * h) mod P(y) */
    qmac_gfmul256_poly(ctx->Y, ctx->H, ctx->Y);
}

static void qmac_compute_final(uint8_t* tag, qsc_qmac_state* ctx)
{
#if defined(QSC_MISRA_FULL_COMPLIANCE)
    for (size_t i = 0U; i < QSC_QMAC_BLOCK_SIZE / sizeof(uint64_t); ++i)
    {
        ctx->Y[i] ^= ctx->F[i];
    }
#else
    /* apply the finalization key: y = y ^ f */
    qsc_memutils_xor((uint8_t*)ctx->Y, (const uint8_t*)ctx->F, QSC_QMAC_BLOCK_SIZE);
#endif

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
        qsc_memutils_clear(ctx->F, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_clear(ctx->H, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_clear(ctx->Y, QSC_QMAC_BLOCK_SIZE);
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

        qsc_memutils_clear(ctx->Y, QSC_QMAC_BLOCK_SIZE);

        if (keyparams->mode == qsc_qmac_mode_512)
        {
            /* initialize the SHAKE instance */
            qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, keyparams->key, keyparams->keylen, keyparams->nonce, keyparams->noncelen, keyparams->info, keyparams->infolen);
            /* generate the subkeys H and F */
            qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, sbuf, 1U);
        }
        else
        {
            qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, keyparams->key, keyparams->keylen, keyparams->nonce, keyparams->noncelen, keyparams->info, keyparams->infolen);
            qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1U);
        }

        /* copy the hash subkey */
        qsc_memutils_copy((uint8_t*)ctx->H, sbuf, QSC_QMAC_BLOCK_SIZE);
        /* copy the finalization key */
        qsc_memutils_copy((uint8_t*)ctx->F, sbuf + QSC_QMAC_BLOCK_SIZE, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_clear(sbuf, sizeof(sbuf));
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
        while (msglen > 0U)
        {
            uint64_t x[QSC_QMAC_STATE_SIZE] = { 0U, 0U, 0U, 0U };

            /* copy the message bytes */
            mlen = msglen >= QSC_QMAC_BLOCK_SIZE ? QSC_QMAC_BLOCK_SIZE : msglen;
            qsc_memutils_copy((uint8_t*)x, message + mpos, mlen);
            /* run the permutation */
            qmac_block_update(ctx, x);
            msglen -= mlen;
            mpos += mlen;
        }
    }
}


