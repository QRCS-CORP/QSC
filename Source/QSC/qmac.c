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
static void qmac_gfmul256_poly(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) 
{
    const int32_t shifts[4] = { 0, 2, 5, 10 };
    uint64_t prod[8] = { 0U };
    uint64_t mask;
    int32_t oft;
    int32_t tbit;
    int32_t word;

    qsc_memutils_clmulepi64_si256(prod, a, b);

    for (int32_t bit = 511; bit >= 256; --bit)
    {
        const int32_t base = bit - 256;
        word = bit >> 6;
        oft = bit & 63;
        mask = (uint64_t)0 - ((prod[word] >> oft) & 1ULL);

        for (size_t j = 0; j < 4; ++j) 
        {
            tbit = base + shifts[j];
            prod[tbit >> 6] ^= mask & ((uint64_t)1ULL << (tbit & 63));
        }
    }

    for (size_t i = 0; i < 4; ++i)
    {
        r[i] = prod[i];
    }
}

static void qmac_block_update(qsc_qmac_state* ctx, const uint64_t* x)
{
	/* y = y ^ x */
    qsc_memutils_xor((uint8_t*)ctx->Y, (const uint8_t*)x, QSC_QMAC_BLOCK_SIZE);
	/* y = (y * h) mod P(y) */
    qmac_gfmul256_poly(ctx->Y, ctx->H, ctx->Y);
}

static void qmac_compute_final(uint8_t* tag, qsc_qmac_state* ctx)
{
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


