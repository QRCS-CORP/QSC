#include "qmac.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#if defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_HAS_AVX512)
#   include "intrinsics.h"
#endif

/* irreducible polynomial trinomial GF(2^256) : x^256 + x^19 + 1 */

#if defined(QSC_SYSTEM_HAS_AVX2)

static inline __m256i qmac_shift256_left_19(__m256i x)
{
    uint64_t lanes[4];
    uint64_t carry;

    carry = 0;
    _mm256_storeu_si256((__m256i*)lanes, x);

    for (int32_t i = 0; i < 4; i++) 
    {
        uint64_t tmp = lanes[i];
        lanes[i] = (tmp << 19) | carry;
        carry = tmp >> (64 - 19);
    }

    /* The final carry contains the bits that overflowed past bit 255.
    * According to our field, x^256 ≡ x^19 + 1, so every 1-bit in the overflow
    * should be folded back into the result in two places: as a contribution at bit 0 and at bit 19.
    * For each 1-bit in 'carry', we XOR in a 1 at position i and a 1 at position (i+19).
    * In our simplified fix we assume that 'carry' fits in 19 bits.
    * We fold it into the least significant lane. */
    lanes[0] ^= carry;         /* fold the carry as if multiplied by 1 */
    lanes[0] ^= carry << 19;   /* fold the carry as if multiplied by x ^ 19 */

    return _mm256_loadu_si256((const __m256i*)lanes);
}

static void qmac_gfmul256_poly19(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t prod[8] = { 0 };

    qsc_memutils_clmulepi64_si256(prod, a, b);

    /* load the lower 256 bits(prod[0..3]) and upper 256 bits(prod[4..7]) into __m256i vectors */
    __m256i L = _mm256_loadu_si256((const __m256i*)prod);
    __m256i H = _mm256_loadu_si256((const __m256i*)(prod + 4));

    /* compute H << 19, with the fixed function that folds in the final carry */
    __m256i H_shift = qmac_shift256_left_19(H);
    /* the reduction : r = L ^(H ^ (H << 19)) */
    __m256i red = _mm256_xor_si256(H, H_shift);
    __m256i res = _mm256_xor_si256(L, red);

    _mm256_storeu_si256((__m256i*)r, res);
}

#elif defined(QSC_SYSTEM_HAS_AVX)

static inline void qmac_shift256_left_19(__m128i in[2], __m128i out[2])
{
    uint64_t lanes[4];
    uint64_t carry = 0;
    
    /* extract the 256-bit value into four 64-bit lanes */
    _mm_storeu_si128((__m128i*)lanes, in[0]);
    _mm_storeu_si128((__m128i*)(lanes + 2), in[1]);
    
    for (int32_t i = 0; i < 4; i++) 
    {
        uint64_t tmp = lanes[i];
        lanes[i] = (tmp << 19) | carry;
        carry = tmp >> (64 - 19);
    }
    
    /* fold the final carry (overflow from lane 3) into lane 0
     * in GF(2) addition is xor; so we xor in the carry and carry<<19 */
    lanes[0] ^= carry;
    lanes[0] ^= carry << 19;
    
    /* reload the lanes into two __m128i registers */
    out[0] = _mm_loadu_si128((const __m128i*)lanes);
    out[1] = _mm_loadu_si128((const __m128i*)(lanes + 2));
}

static void qmac_gfmul256_poly19(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t prod[8] = { 0 };
    
    /* compute the full 512 - bit product using the verified cmul function */
    qsc_memutils_clmulepi64_si256(prod, a, b);
    
    /* load the lower 256 bits(prod[0..3]) into two __m128i registers */
    __m128i L[2];
    /* loads prod[0] and prod[1] */
    L[0] = _mm_loadu_si128((const __m128i*) prod);
    /* loads prod[2] and prod[3] */
    L[1] = _mm_loadu_si128((const __m128i*)(prod + 2));
    
    /* load the upper 256 bits(prod[4..7]) into two __m128i registers */
    __m128i H[2];
    /* loads prod[4] and prod[5] */
    H[0] = _mm_loadu_si128((const __m128i*)(prod + 4));
    /* loads prod[6] and prod[7] */
    H[1] = _mm_loadu_si128((const __m128i*)(prod + 6));
    
    /* compute H << 19 with proper carry propagation */
    __m128i H_shift[2];
    qmac_shift256_left_19(H, H_shift);
    
    /* reduction: compute red = H xor (H << 19) */
    __m128i red0 = _mm_xor_si128(H[0], H_shift[0]);
    __m128i red1 = _mm_xor_si128(H[1], H_shift[1]);
    
    /* final result : res = L xor red */
    __m128i res0 = _mm_xor_si128(L[0], red0);
    __m128i res1 = _mm_xor_si128(L[1], red1);
    
    /* store the final 256-bit result into the output array r */
    _mm_storeu_si128((__m128i*)r, res0);
    _mm_storeu_si128((__m128i*)(r + 2), res1);
}

#else

static void qmac_shift256_left_19_fold(const uint64_t in[4], int32_t shift, uint64_t out[4])
{
    uint64_t tmp[5];
    uint64_t carry = 0;

    for (size_t i = 0; i < 4; i++) 
    {
        uint64_t t = in[i];
        tmp[i] = (t << shift) | carry;
        carry = t >> (64 - shift);
    }

    tmp[4] = carry;
    /* fold the final carry into lane 0
     * in GF(2), addition is xor. Thus, for the final carry 'c', we do:
     * tmp[0] ^= c  and  tmp[0] ^= c << shift */
    tmp[0] ^= tmp[4];
    tmp[0] ^= tmp[4] << shift;
    
    /* return the lower 256 bits (words 0..3) */
    for (size_t i = 0; i < 4; i++)
    {
        out[i] = tmp[i];
    }
}

static void qmac_reduce_320_to_256_poly19(uint64_t x[5])
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

        word = i / 64;
        bit = i % 64;

        if (x[word] & (1ULL << bit)) 
        {
            uint64_t tmp;

            x[word] ^= (1ULL << bit);
            shift = i - deg;

            uint64_t poly320[5] = { 0 };
            /* poly fits in one word */
            poly320[0] = poly;
            uint64_t pshift[5] = { 0 };
            carry = 0;
            
            for (j = 0; j < 5; j++)
            {
                tmp = poly320[j];
                pshift[j] = (tmp << shift) | carry;
                carry = tmp >> (64 - shift);
            }
            
            for (j = 0; j < 5; j++)
            {
                x[j] ^= pshift[j];
            }
        }
    }

    x[4] = 0;
}

static void qmac_gfmul256_poly19(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t prod[8] = { 0 };

    qsc_memutils_clmulepi64_si256(prod, a, b);
    
    uint64_t pa[4];
    uint64_t pb[4];

    for (size_t i = 0; i < 4; ++i) 
    {
        pa[i] = prod[i];
        pb[i] = prod[i + 4];
    }
    
    /* build a 320-bit container for pb */
    uint64_t b320[5] = { pb[0], pb[1], pb[2], pb[3], 0 };
    
    /* compute t19 = b320 << 19, with folding of the final carry */
    uint64_t t19[4] = { 0 };
    qmac_shift256_left_19_fold(b320, 19, t19);
    
    /* form q320 = b320 xor t19. We build a 5-word result */
    uint64_t q320[5];

    for (size_t i = 0; i < 4; i++)
    {
        q320[i] = b320[i] ^ t19[i];
    }

    /* typically zero after the shift and fold */
    q320[4] = b320[4];
    
    /* reduce q320 modulo m(x) = x^256 + x^19 + 1 */
    qmac_reduce_320_to_256_poly19(q320);
    
    /* final result is r = pa xor (the reduced q320's lower 256 bits) */
    for (size_t i = 0; i < 4; i++)
    {
        r[i] = pa[i] ^ q320[i];
    }
}

#endif

static void qmac_block_update(qsc_qmac_state* ctx, const uint64_t* x)
{
	/* y = y ^ x */
    qsc_memutils_xor((uint8_t*)ctx->Y, (uint8_t*)x, QSC_QMAC_BLOCK_SIZE);
	/* y = (y * h) mod P(y) */
    qmac_gfmul256_poly19(ctx->Y, ctx->H, ctx->Y);
}

static void qmac_compute_final(uint8_t* tag, qsc_qmac_state* ctx)
{
    /* apply the finalization key: y = y ^ f */
    qsc_memutils_xor((uint8_t*)ctx->Y, (uint8_t*)ctx->F, QSC_QMAC_BLOCK_SIZE);
    /* copy the tag: t = y */
	qsc_memutils_copy(tag, (uint8_t*)ctx->Y, QSC_QMAC_BLOCK_SIZE);
}

void qsc_qmac_compute(uint8_t* output, qsc_qmac_keyparams* keyparams, const uint8_t* message, size_t msglen)
{
    assert(output != NULL);
    assert(keyparams != NULL);
    assert(message != NULL);
    assert(msglen != 0);

    if (output != NULL && keyparams != NULL && message != NULL && msglen != 0)
    {
        qsc_qmac_state ctx = { 0 };

        qsc_qmac_initialize(&ctx, keyparams);
        qsc_qmac_update(&ctx, message, msglen);
        qsc_qmac_finalize(&ctx, output);
    }
}

void qsc_qmac_dispose(qsc_qmac_state* ctx)
{
    assert(ctx != NULL);

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx->F, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_clear((uint8_t*)ctx->H, QSC_QMAC_BLOCK_SIZE);
        qsc_memutils_clear((uint8_t*)ctx->Y, QSC_QMAC_BLOCK_SIZE);
        ctx->initialized = false;
    }
}

void qsc_qmac_finalize(qsc_qmac_state* ctx, uint8_t* output)
{
    assert(ctx != NULL);
    assert(output != NULL);

    if (ctx != NULL && output != NULL && ctx->initialized == true)
    {
        /* finalize the state */
        qmac_compute_final(output, ctx);
    }
}

void qsc_qmac_initialize(qsc_qmac_state* ctx, qsc_qmac_keyparams* keyparams)
{
    assert(ctx != NULL);
    assert(keyparams != NULL);

    if (ctx != NULL && keyparams != NULL)
    {
        qsc_keccak_state kstate = { 0 };
	    uint8_t sbuf[QSC_KECCAK_256_RATE] = { 0 };

        qsc_memutils_clear((uint8_t*)ctx->Y, QSC_QMAC_BLOCK_SIZE);

        if (keyparams->mode == qsc_qmac_mode_512)
        {
            /* initialize the SHAKE instance */
            qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, keyparams->key, keyparams->keylen, keyparams->nonce, keyparams->noncelen, keyparams->info, keyparams->infolen);
            /* generate the subkeys H and F */
            qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, sbuf, 1);
        }
        else
        {
            qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, keyparams->key, keyparams->keylen, keyparams->nonce, keyparams->noncelen, keyparams->info, keyparams->infolen);
            qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1);
        }

        /* copy the hash subkey */
        qsc_memutils_copy((uint8_t*)ctx->H, sbuf, QSC_QMAC_BLOCK_SIZE);
        /* copy the finalization key */
        qsc_memutils_copy((uint8_t*)ctx->F, sbuf + QSC_QMAC_BLOCK_SIZE, QSC_QMAC_BLOCK_SIZE);

        ctx->initialized = true;
    }
}

void qsc_qmac_update(qsc_qmac_state* ctx, const uint8_t* message, size_t msglen)
{
    assert(ctx != NULL);
    assert(message != NULL);
    assert(msglen != 0);

	size_t mlen;
	size_t mpos;

	mpos = 0;

    if (ctx != NULL && message != NULL && msglen != 0 && ctx->initialized == true)
    {
        while (msglen > 0)
        {
            uint64_t x[QSC_QMAC_STATE_SIZE] = { 0, 0, 0, 0 };

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


