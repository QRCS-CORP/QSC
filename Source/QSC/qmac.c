#include "qmac.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#if defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_HAS_AVX512)
#   include "intrinsics.h"
#endif

/* irreducible polynomial trinomial GF(2^256) : x^256 + x^19 + 1 */

#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_X86)

static inline __m256i qmac_shift256_left_19(__m256i x)
{
    uint64_t lanes[4U];
    uint64_t carry;

    carry = 0;
    _mm256_storeu_si256((__m256i*)lanes, x);

    for (size_t i = 0U; i < 4U; i++) 
    {
        uint64_t tmp = lanes[i];
        lanes[i] = (tmp << 19) | carry;
        carry = tmp >> (64U - 19U);
    }

    /* The final carry contains the bits that overflowed past bit 255.
    * According to our field, x^256 ≡ x^19 + 1, so every 1-bit in the overflow
    * should be folded back into the result in two places: as a contribution at bit 0 and at bit 19.
    * For each 1-bit in 'carry', we XOR in a 1 at position i and a 1 at position (i+19).
    * In our simplified fix we assume that 'carry' fits in 19 bits.
    * We fold it into the least significant lane. */
    lanes[0U] ^= carry;         /* fold the carry as if multiplied by 1 */
    lanes[0U] ^= carry << 19;   /* fold the carry as if multiplied by x ^ 19 */

    return _mm256_loadu_si256((const __m256i*)lanes);
}

static void qmac_gfmul256_poly19(uint64_t r[4U], const uint64_t a[4U], const uint64_t b[4U])
{
    uint64_t prod[8U] = { 0U };

    qsc_memutils_clmulepi64_si256(prod, a, b);

    /* load the lower 256 bits(prod[0..3]) and upper 256 bits(prod[4..7]) into __m256i vectors */
    __m256i L = _mm256_loadu_si256((const __m256i*)prod);
    __m256i H = _mm256_loadu_si256((const __m256i*)(prod + 4U));

    /* compute H << 19, with the fixed function that folds in the final carry */
    __m256i H_shift = qmac_shift256_left_19(H);
    /* the reduction : r = L ^(H ^ (H << 19)) */
    __m256i red = _mm256_xor_si256(H, H_shift);
    __m256i res = _mm256_xor_si256(L, red);

    _mm256_storeu_si256((__m256i*)r, res);
}

#elif defined(QSC_SYSTEM_HAS_AVX) && defined(QSC_SYSTEM_X86)

static inline void qmac_shift256_left_19(__m128i in[2U], __m128i out[2U])
{
    uint64_t lanes[4U];
    uint64_t carry = 0U;
    
    /* extract the 256-bit value into four 64-bit lanes */
    _mm_storeu_si128((__m128i*)lanes, in[0U]);
    _mm_storeu_si128((__m128i*)(lanes + 2U), in[1U]);
    
    for (int32_t i = 0U; i < 4U; ++i) 
    {
        uint64_t tmp = lanes[i];
        lanes[i] = (tmp << 19) | carry;
        carry = tmp >> (64U - 19U);
    }
    
    /* fold the final carry (overflow from lane 3) into lane 0
     * in GF(2) addition is xor; so we xor in the carry and carry<<19 */
    lanes[0U] ^= carry;
    lanes[0U] ^= carry << 19;
    
    /* reload the lanes into two __m128i registers */
    out[0U] = _mm_loadu_si128((const __m128i*)lanes);
    out[1U] = _mm_loadu_si128((const __m128i*)(lanes + 2U));
}

static void qmac_gfmul256_poly19(uint64_t r[4U], const uint64_t a[4U], const uint64_t b[4U])
{
    uint64_t prod[8U] = { 0U };
    
    /* compute the full 512 - bit product using the verified cmul function */
    qsc_memutils_clmulepi64_si256(prod, a, b);
    
    /* load the lower 256 bits(prod[0..3]) into two __m128i registers */
    __m128i L[2U];
    /* loads prod[0U] and prod[1U] */
    L[0U] = _mm_loadu_si128((const __m128i*) prod);
    /* loads prod[2U] and prod[3U] */
    L[1U] = _mm_loadu_si128((const __m128i*)(prod + 2U));
    
    /* load the upper 256 bits(prod[4..7]) into two __m128i registers */
    __m128i H[2U];
    /* loads prod[4U] and prod[5U] */
    H[0U] = _mm_loadu_si128((const __m128i*)(prod + 4U));
    /* loads prod[6U] and prod[7U] */
    H[1U] = _mm_loadu_si128((const __m128i*)(prod + 6U));
    
    /* compute H << 19 with proper carry propagation */
    __m128i H_shift[2U];
    qmac_shift256_left_19(H, H_shift);
    
    /* reduction: compute red = H xor (H << 19) */
    __m128i red0 = _mm_xor_si128(H[0U], H_shift[0U]);
    __m128i red1 = _mm_xor_si128(H[1U], H_shift[1U]);
    
    /* final result : res = L xor red */
    __m128i res0 = _mm_xor_si128(L[0U], red0);
    __m128i res1 = _mm_xor_si128(L[1U], red1);
    
    /* store the final 256-bit result into the output array r */
    _mm_storeu_si128((__m128i*)r, res0);
    _mm_storeu_si128((__m128i*)(r + 2U), res1);
}

#else

static void qmac_shift256_left_19_fold(const uint64_t in[4U], int32_t shift, uint64_t out[4U])
{
    uint64_t tmp[5U];
    uint64_t carry;

    carry = 0U;

    for (size_t i = 0U; i < 4U; i++) 
    {
        uint64_t t = in[i];
        tmp[i] = (t << shift) | carry;
        carry = t >> (64U - shift);
    }

    tmp[4U] = carry;
    /* fold the final carry into lane 0
     * in GF(2), addition is xor. Thus, for the final carry 'c', we do:
     * tmp[0] ^= c  and  tmp[0] ^= c << shift */
    tmp[0U] ^= tmp[4U];
    tmp[0U] ^= tmp[4U] << shift;
    
    /* return the lower 256 bits (words 0..3) */
    for (size_t i = 0U; i < 4U; i++)
    {
        out[i] = tmp[i];
    }
}

static void qmac_reduce_320_to_256_poly19(uint64_t x[5U])
{
    const int32_t deg = 256;
    /* poly represents x^19 + 1 */
    const uint64_t poly = (1ULL << 19) | 1ULL;
    
    for (int32_t i = 274; i >= deg; i--) 
    {
        uint64_t carry;
        size_t j;
        int32_t bit;
        int32_t shift;
        int32_t word;

        word = i / 64U;
        bit = i % 64U;

        if (x[word] & (1ULL << bit)) 
        {
            uint64_t tmp;

            x[word] ^= (1ULL << bit);
            shift = i - deg;

            uint64_t poly320[5U] = { 0U };
            /* poly fits in one word */
            poly320[0U] = poly;
            uint64_t pshift[5U] = { 0U };
            carry = 0U;
            
            for (j = 0U; j < 5U; j++)
            {
                tmp = poly320[j];
                pshift[j] = (tmp << shift) | carry;
                carry = tmp >> (64U - shift);
            }
            
            for (j = 0U; j < 5U; j++)
            {
                x[j] ^= pshift[j];
            }
        }
    }

    x[4U] = 0U;
}

static void qmac_gfmul256_poly19(uint64_t r[4U], const uint64_t a[4U], const uint64_t b[4U])
{
    uint64_t prod[8U] = { 0U };

    qsc_memutils_clmulepi64_si256(prod, a, b);
    
    uint64_t pa[4U];
    uint64_t pb[4U];

    for (size_t i = 0U; i < 4U; ++i) 
    {
        pa[i] = prod[i];
        pb[i] = prod[i + 4U];
    }
    
    /* build a 320-bit container for pb */
    uint64_t b320[5U] = { pb[0U], pb[1U], pb[2U], pb[3U], 0U };
    
    /* compute t19 = b320 << 19, with folding of the final carry */
    uint64_t t19[4U] = { 0U };
    qmac_shift256_left_19_fold(b320, 19U, t19);
    
    /* form q320 = b320 xor t19. We build a 5-word result */
    uint64_t q320[5U];

    for (size_t i = 0U; i < 4U; i++)
    {
        q320[i] = b320[i] ^ t19[i];
    }

    /* typically zero after the shift and fold */
    q320[4U] = b320[4U];
    
    /* reduce q320 modulo m(x) = x^256 + x^19 + 1 */
    qmac_reduce_320_to_256_poly19(q320);
    
    /* final result is r = pa xor (the reduced q320's lower 256 bits) */
    for (size_t i = 0U; i < 4U; i++)
    {
        r[i] = pa[i] ^ q320[i];
    }
}

#endif

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
    qmac_gfmul256_poly19(ctx->Y, ctx->H, ctx->Y);
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


