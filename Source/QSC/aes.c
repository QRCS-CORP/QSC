#include "aes.h"
#include "intutils.h"
#include "memutils.h"

/*!
\def AES128_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-128.
*/
#define AES128_ROUND_COUNT 10U

/*!
\def AES256_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-256.
*/
#define AES256_ROUND_COUNT 14U

/*!
\def ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
#if defined(QSC_SYSTEM_AESNI_ENABLED)
#	define ROUNDKEY_ELEMENT_SIZE 16U
#else
#	define ROUNDKEY_ELEMENT_SIZE 4U
#	define AES_PREFETCH_TABLES
#endif

/*!
\def AES_NONCE_SIZE
* The size byte size of the qsc_aes_mode_ctr nonce and qsc_aes_mode_cbc initialization vector.
*/
#define AES_NONCE_SIZE QSC_AES_BLOCK_SIZE

/*!
\def AES128_ROUNDKEY_SIZE
* The size of the AES-128 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_aes_state struct.
*/
#define AES128_ROUNDKEY_SIZE ((AES128_ROUND_COUNT + 1U) * (QSC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def AES256_ROUNDKEY_SIZE
* The size of the AES-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_aes_state struct.
*/
#define AES256_ROUNDKEY_SIZE ((AES256_ROUND_COUNT + 1U) * (QSC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/* AVX512 */

/*!
\def AVX512_BLOCK_SIZE
* The size byte size of an AVX512 block
*/
#define AVX512_BLOCK_SIZE (4U * QSC_AES_BLOCK_SIZE)

/* HBA */

/*!
\def HBA_INFO_SIZE
* The HBA version information array length.
*/
#define HBA_INFO_SIZE 16U

/*!
\def HBA256_MKEY_SIZE
* The size of the hba-256 mac key array
*/
#define HBA256_MKEY_SIZE 32U

/*!
\def HBA512_MKEY_SIZE
* The size of the hba-512 mac key array
*/
#define HBA512_MKEY_SIZE 64U

/*!
\def HBA_NAME_SIZE
* The HBA implementation specific name array length.
*/
#if defined(QSC_HBA_KMAC_EXTENSION)
#	define HBA_NAME_SIZE 29U
#else
#	define HBA_NAME_SIZE 33U
#endif

/*!
\def GCM_BITS_PER_BYTE
* The number of bits per byte used in GCM.
*/
#define GCM_BITS_PER_BYTE  8U

/* aes-ni and table-based fallback functions */

#if defined(QSC_SYSTEM_AESNI_ENABLED)

static void aes_beincrement_x128(__m128i* counter)
{
	/* increment the entire AES-CTR big-endian 128-bit block counter */
	__m128i tmp;
	uint64_t low;

	qsc_intutils_reverse_bytes_x128(counter, &tmp);
	low = (uint64_t)_mm_cvtsi128_si64(tmp);
	tmp = _mm_add_epi64(tmp, _mm_set_epi64x((low == UINT64_MAX) ? 1LL : 0LL, 1LL));
	qsc_intutils_reverse_bytes_x128(&tmp, counter);
}

static void aes_leincrement_x128(__m128i* counter)
{
	uint64_t low;

	low = (uint64_t)_mm_cvtsi128_si64(*counter);
	*counter = _mm_add_epi64(*counter, _mm_set_epi64x((low == UINT64_MAX) ? 1LL : 0LL, 1LL));
}

static void aes_decrypt_block(const qsc_aes_state* ctx, __m128i* output, const __m128i* input)
{
	const size_t RNDCNT = ctx->roundkeylen - 2U;
	size_t keyctr;

	keyctr = 0U;
	*output = _mm_xor_si128(*input, ctx->roundkeys[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm_aesdec_si128(*output, ctx->roundkeys[keyctr]);
	}

	++keyctr;
	*output = _mm_aesdeclast_si128(*output, ctx->roundkeys[keyctr]);
}

static void aes_encrypt_block(const qsc_aes_state* ctx, __m128i* output, const __m128i* input)
{
	const size_t RNDCNT = ctx->roundkeylen - 2U;
	size_t keyctr;

	keyctr = 0U;
	*output = _mm_xor_si128(*input, ctx->roundkeys[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm_aesenc_si128(*output, ctx->roundkeys[keyctr]);
	}

	++keyctr;
	*output = _mm_aesenclast_si128(*output, ctx->roundkeys[keyctr]);
}

#if defined(QSC_SYSTEM_HAS_VAES512)
static void aes_beincrement_x512(__m512i* counter)
{
	__m512i tmp;

	qsc_intutils_reverse_bytes_x512(counter, &tmp);
	tmp = _mm512_add_epi64(tmp, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4));
	qsc_intutils_reverse_bytes_x512(&tmp, counter);
}

static void aes_load128to512(__m128i* input, __m512i* output)
{
	*output = _mm512_setzero_si512();
	*output = _mm512_inserti32x4(*output, *input, 0);
	*output = _mm512_inserti32x4(*output, *input, 1);
	*output = _mm512_inserti32x4(*output, *input, 2);
	*output = _mm512_inserti32x4(*output, *input, 3);
}

static void aes_decrypt_blockw(qsc_aes_state* ctx, __m512i* output, const __m512i* input)
{
	const size_t RNDCNT = ctx->roundkeylen - 2U;
	size_t keyctr;

	keyctr = 0U;
	*output = _mm512_xor_si512(*input, ctx->roundkeysw[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm512_aesdec_epi128(*output, ctx->roundkeysw[keyctr]);
	}

	++keyctr;
	*output = _mm512_aesdeclast_epi128(*output, ctx->roundkeysw[keyctr]);
}

static void aes_encrypt_blockw(qsc_aes_state* ctx, __m512i* output, const __m512i* input)
{
	const size_t RNDCNT = ctx->roundkeylen - 2U;
	size_t keyctr;

	keyctr = 0U;
	*output = _mm512_xor_si512(*input, ctx->roundkeysw[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm512_aesenc_epi128(*output, ctx->roundkeysw[keyctr]);
	}

	++keyctr;
	*output = _mm512_aesenclast_epi128(*output, ctx->roundkeysw[keyctr]);
}
#endif

static void aes_expand_rot(__m128i* key, size_t index, size_t offset)
{
	__m128i pkb;

	pkb = key[index - offset];
	key[index] = _mm_shuffle_epi32(key[index], 0xFF);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	key[index] = _mm_xor_si128(pkb, key[index]);
}

static void aes_expand_sub(__m128i* key, size_t index, size_t offset)
{
	__m128i pkb;

	pkb = key[index - offset];
	key[index] = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(key[index - 1U], 0x00), 0xAA);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	key[index] = _mm_xor_si128(pkb, key[index]);
}

static void aes_standard_expand(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams)
{
	size_t kwords;

	/* key in 32-bit words */
	kwords = keyparams->keylen / 4U;

	if (kwords == 8U)
	{
		ctx->roundkeys[0U] = _mm_loadu_si128((const __m128i*)keyparams->key);
		ctx->roundkeys[1U] = _mm_loadu_si128((const __m128i*)(keyparams->key + 16U));
		ctx->roundkeys[2U] = _mm_aeskeygenassist_si128(ctx->roundkeys[1U], 0x01);
		aes_expand_rot(ctx->roundkeys, 2U, 2U);
		aes_expand_sub(ctx->roundkeys, 3U, 2U);
		ctx->roundkeys[4U] = _mm_aeskeygenassist_si128(ctx->roundkeys[3U], 0x02);
		aes_expand_rot(ctx->roundkeys, 4U, 2U);
		aes_expand_sub(ctx->roundkeys, 5U, 2U);
		ctx->roundkeys[6U] = _mm_aeskeygenassist_si128(ctx->roundkeys[5U], 0x04);
		aes_expand_rot(ctx->roundkeys, 6U, 2U);
		aes_expand_sub(ctx->roundkeys, 7U, 2U);
		ctx->roundkeys[8U] = _mm_aeskeygenassist_si128(ctx->roundkeys[7U], 0x08);
		aes_expand_rot(ctx->roundkeys, 8U, 2U);
		aes_expand_sub(ctx->roundkeys, 9U, 2U);
		ctx->roundkeys[10U] = _mm_aeskeygenassist_si128(ctx->roundkeys[9U], 0x10);
		aes_expand_rot(ctx->roundkeys, 10U, 2U);
		aes_expand_sub(ctx->roundkeys, 11U, 2U);
		ctx->roundkeys[12U] = _mm_aeskeygenassist_si128(ctx->roundkeys[11U], 0x20);
		aes_expand_rot(ctx->roundkeys, 12U, 2U);
		aes_expand_sub(ctx->roundkeys, 13U, 2U);
		ctx->roundkeys[14U] = _mm_aeskeygenassist_si128(ctx->roundkeys[13U], 0x40);
		aes_expand_rot(ctx->roundkeys, 14U, 2U);
	}
	else
	{
		ctx->roundkeys[0U] = _mm_loadu_si128((const __m128i*)keyparams->key);
		ctx->roundkeys[1U] = _mm_aeskeygenassist_si128(ctx->roundkeys[0U], 0x01);
		aes_expand_rot(ctx->roundkeys, 1U, 1U);
		ctx->roundkeys[2U] = _mm_aeskeygenassist_si128(ctx->roundkeys[1U], 0x02);
		aes_expand_rot(ctx->roundkeys, 2U, 1U);
		ctx->roundkeys[3U] = _mm_aeskeygenassist_si128(ctx->roundkeys[2U], 0x04);
		aes_expand_rot(ctx->roundkeys, 3U, 1U);
		ctx->roundkeys[4U] = _mm_aeskeygenassist_si128(ctx->roundkeys[3U], 0x08);
		aes_expand_rot(ctx->roundkeys, 4U, 1U);
		ctx->roundkeys[5U] = _mm_aeskeygenassist_si128(ctx->roundkeys[4U], 0x10);
		aes_expand_rot(ctx->roundkeys, 5U, 1U);
		ctx->roundkeys[6U] = _mm_aeskeygenassist_si128(ctx->roundkeys[5U], 0x20);
		aes_expand_rot(ctx->roundkeys, 6U, 1U);
		ctx->roundkeys[7U] = _mm_aeskeygenassist_si128(ctx->roundkeys[6U], 0x40);
		aes_expand_rot(ctx->roundkeys, 7U, 1U);
		ctx->roundkeys[8U] = _mm_aeskeygenassist_si128(ctx->roundkeys[7U], 0x80);
		aes_expand_rot(ctx->roundkeys, 8U, 1U);
		ctx->roundkeys[9U] = _mm_aeskeygenassist_si128(ctx->roundkeys[8U], 0x1B);
		aes_expand_rot(ctx->roundkeys, 9U, 1U);
		ctx->roundkeys[10U] = _mm_aeskeygenassist_si128(ctx->roundkeys[9U], 0x36);
		aes_expand_rot(ctx->roundkeys, 10U, 1U);
	}
}

void qsc_aes_initialize(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption, qsc_aes_cipher_type ctype)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	if (ctx != NULL)
	{
		qsc_aes_dispose(ctx);
	}

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL &&
		((ctype == qsc_aes_cipher_128 && keyparams->keylen == QSC_AES128_KEY_SIZE) ||
		(ctype == qsc_aes_cipher_256 && keyparams->keylen == QSC_AES256_KEY_SIZE)))
	{
		size_t i;
		size_t j;

		if (keyparams->nonce != NULL && keyparams->noncelen == QSC_AES_BLOCK_SIZE)
		{
			ctx->nonce = (uint8_t*)keyparams->nonce;
		}

		qsc_memutils_secure_erase(ctx->roundkeys, sizeof(ctx->roundkeys));

		if (ctype == qsc_aes_cipher_256)
		{
			ctx->roundkeylen = AES256_ROUNDKEY_SIZE;
			ctx->rounds = 14U;
			aes_standard_expand(ctx, keyparams);
		}
		else if (ctype == qsc_aes_cipher_128)
		{
			ctx->roundkeylen = AES128_ROUNDKEY_SIZE;
			ctx->rounds = 10U;
			aes_standard_expand(ctx, keyparams);
		}
		else
		{
			ctx->roundkeylen = 0U;
		}

		/* inverse cipher */
		if (encryption == false && ctx->roundkeylen != 0U)
		{
			__m128i tmp;

			tmp = ctx->roundkeys[0U];
			ctx->roundkeys[0U] = ctx->roundkeys[ctx->roundkeylen - 1U];
			ctx->roundkeys[ctx->roundkeylen - 1U] = tmp;

			for (i = 1U, j = ctx->roundkeylen - 2U; i < j; ++i, --j)
			{
				tmp = _mm_aesimc_si128(ctx->roundkeys[i]);
				ctx->roundkeys[i] = _mm_aesimc_si128(ctx->roundkeys[j]);
				ctx->roundkeys[j] = tmp;
			}

			ctx->roundkeys[i] = _mm_aesimc_si128(ctx->roundkeys[i]);
		}

#if defined(QSC_SYSTEM_HAS_VAES512)

		qsc_memutils_secure_erase(ctx->roundkeysw, sizeof(ctx->roundkeysw));

		for (i = 0U; i < ctx->rounds + 1U; ++i)
		{
			aes_load128to512(&ctx->roundkeys[i], &ctx->roundkeysw[i]);
		}
#endif
	}
}

/* CBC mode */

void qsc_aes_cbc_decrypt(qsc_aes_state* ctx, uint8_t* output, size_t* outlen, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outlen != NULL);

	if (outlen != NULL)
	{
		*outlen = 0U;
	}

	if (ctx != NULL && input != NULL && output != NULL && outlen != NULL &&
		ctx->roundkeylen != 0U && ctx->nonce != NULL &&
		length >= QSC_AES_BLOCK_SIZE && length % QSC_AES_BLOCK_SIZE == 0U)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t len;
		size_t oft;

		oft = 0U;

#if defined(QSC_SYSTEM_AESNI_ENABLED) && defined(QSC_SYSTEM_HAS_VAES512)
		while (length > AVX512_BLOCK_SIZE)
		{
			__m512i inpw;
			__m512i ivtw;
			__m512i otpw;
			uint8_t ivtb[AVX512_BLOCK_SIZE] = { 0U };

			qsc_memutils_copy(ivtb, ctx->nonce, QSC_AES_BLOCK_SIZE);
			qsc_memutils_copy(ivtb + QSC_AES_BLOCK_SIZE, input + oft, 3U * QSC_AES_BLOCK_SIZE);
			ivtw = _mm512_loadu_si512((const void*)ivtb);
			inpw = _mm512_loadu_si512((const void*)(input + oft));
			aes_decrypt_blockw(ctx, &otpw, &inpw);
			otpw = _mm512_xor_si512(otpw, ivtw);

			/* Preserve ciphertext before an in-place output store. */
			qsc_memutils_copy(ctx->nonce, input + oft + AVX512_BLOCK_SIZE - QSC_AES_BLOCK_SIZE, QSC_AES_BLOCK_SIZE);
			_mm512_storeu_si512((void*)(output + oft), otpw);
			length -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;
		}
#endif

		while (length > QSC_AES_BLOCK_SIZE)
		{
			qsc_aes_cbc_decrypt_block(ctx, output + oft, input + oft);
			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		qsc_aes_cbc_decrypt_block(ctx, tmpb, input + oft);
		len = qsc_pkcs7_padding_length(tmpb);

		if (len != 0U)
		{
			if (len < QSC_AES_BLOCK_SIZE)
			{
				qsc_memutils_copy(output + oft, tmpb, QSC_AES_BLOCK_SIZE - len);
			}

			*outlen = oft + QSC_AES_BLOCK_SIZE - len;
		}
		else
		{
			qsc_memutils_secure_erase(output, oft + QSC_AES_BLOCK_SIZE);
		}

		qsc_memutils_secure_erase(tmpb, sizeof(tmpb));
	}
}

void qsc_aes_cbc_encrypt(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL || length == 0U);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && (input != NULL || length == 0U) && output != NULL &&
		ctx->roundkeylen != 0U && ctx->nonce != NULL && length <= SIZE_MAX - QSC_AES_BLOCK_SIZE)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t oft;

		oft = 0U;

		while (length >= QSC_AES_BLOCK_SIZE)
		{
			qsc_aes_cbc_encrypt_block(ctx, output + oft, input + oft);
			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		if (length != 0U)
		{
			qsc_memutils_copy(tmpb, input + oft, length);
		}

		qsc_pkcs7_add_padding(tmpb, QSC_AES_BLOCK_SIZE - length);
		qsc_aes_cbc_encrypt_block(ctx, output + oft, tmpb);
		qsc_memutils_secure_erase(tmpb, sizeof(tmpb));
	}
}

void qsc_aes_cbc_decrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL)
	{
		__m128i inp;
		__m128i ivt;
		__m128i otp;

		inp = _mm_loadu_si128((const __m128i*)input);
		ivt = _mm_loadu_si128((const __m128i*)ctx->nonce);

		aes_decrypt_block(ctx, &otp, &inp);
		otp = _mm_xor_si128(otp, ivt);

		_mm_storeu_si128((__m128i*)ctx->nonce, inp);
		_mm_storeu_si128((__m128i*)output, otp);
	}
}

void qsc_aes_cbc_encrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL)
	{
		__m128i inp;
		__m128i ivt;
		__m128i otp;

		inp = _mm_loadu_si128((const __m128i*)input);
		ivt = _mm_loadu_si128((const __m128i*)ctx->nonce);

		ivt = _mm_xor_si128(ivt, inp);
		aes_encrypt_block(ctx, &otp, &ivt);

		_mm_storeu_si128((__m128i*)ctx->nonce, otp);
		_mm_storeu_si128((__m128i*)output, otp);
	}
}

/* CTR mode */

/* CTR hardware batching is deliberately kept within the AES-NI build.  All
 * counter arithmetic is public-nonce dependent.  The rare full-width carry
 * path is preserved for both byte orders.  This avoids weakening the AES-CTR
 * counter semantics when a SIMD batch crosses the low-64-bit boundary. */
#define AES_CTR_XMM_BATCH 8U
#define AES_CTR_YMM_BATCH 8U
#define AES_CTR_ZMM_BATCH 16U

#if defined(QSC_SYSTEM_HAS_VAES512)
#define AES_CTR_HAS_VAES512
#elif defined(QSC_SYSTEM_HAS_VAES256) || (defined(__VAES__) && defined(__AVX2__))
#define AES_CTR_HAS_VAES256
#endif

static void aes_ctr_store_be64(uint8_t* dest, uint64_t value)
{
	/* serialize the low half of an AES-CTR big-endian counter */
    size_t i;

    for (i = 0U; i < 8U; ++i)
    {
        dest[i] = (uint8_t)(value >> (56U - (i * 8U)));
    }
}

static void aes_ctr_prepare(uint8_t* dest, const uint8_t* nonce, uint64_t low, size_t count, bool be)
{
	/* prepare consecutive CTR blocks without carrying into the upper half */
    size_t i;

    for (i = 0U; i < count; ++i)
    {
        qsc_memutils_copy(dest + (i * QSC_AES_BLOCK_SIZE), nonce, QSC_AES_BLOCK_SIZE);

        if (be == true)
        {
            aes_ctr_store_be64(dest + (i * QSC_AES_BLOCK_SIZE) + 8U, low + (uint64_t)i);
        }
        else
        {
            qsc_intutils_le64to8(dest + (i * QSC_AES_BLOCK_SIZE), low + (uint64_t)i);
        }
    }
}

static void aes_ctr_encrypt_xmm8(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, const uint8_t* nonce, uint64_t advanced, bool be)
{
	/* encrypt eight independent CTR blocks using eight interleaved XMM states */
    __m128i x0;
    __m128i x1;
    __m128i x2;
    __m128i x3;
    __m128i x4;
    __m128i x5;
    __m128i x6;
    __m128i x7;
    __m128i rk;
    size_t r;

    {
        __m128i ctr;
        __m128i rev;
        __m128i initial;
        __m128i inc;

        initial = _mm_loadu_si128((const __m128i*)nonce);
        rev = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);

        if (be == true)
        {
            initial = _mm_shuffle_epi8(initial, rev);
        }

        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 0U));
        ctr = _mm_add_epi64(initial, inc);
        x0 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 1U));
        ctr = _mm_add_epi64(initial, inc);
        x1 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 2U));
        ctr = _mm_add_epi64(initial, inc);
        x2 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 3U));
        ctr = _mm_add_epi64(initial, inc);
        x3 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 4U));
        ctr = _mm_add_epi64(initial, inc);
        x4 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 5U));
        ctr = _mm_add_epi64(initial, inc);
        x5 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 6U));
        ctr = _mm_add_epi64(initial, inc);
        x6 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
        inc = _mm_set_epi64x(0LL, (int64_t)(advanced + 7U));
        ctr = _mm_add_epi64(initial, inc);
        x7 = be ? _mm_shuffle_epi8(ctr, rev) : ctr;
    }

    rk = ctx->roundkeys[0U];
    x0 = _mm_xor_si128(x0, rk);
    x1 = _mm_xor_si128(x1, rk);
    x2 = _mm_xor_si128(x2, rk);
    x3 = _mm_xor_si128(x3, rk);
    x4 = _mm_xor_si128(x4, rk);
    x5 = _mm_xor_si128(x5, rk);
    x6 = _mm_xor_si128(x6, rk);
    x7 = _mm_xor_si128(x7, rk);

    for (r = 1U; r < ctx->rounds; ++r)
    {
        rk = ctx->roundkeys[r];
        x0 = _mm_aesenc_si128(x0, rk);
        x1 = _mm_aesenc_si128(x1, rk);
        x2 = _mm_aesenc_si128(x2, rk);
        x3 = _mm_aesenc_si128(x3, rk);
        x4 = _mm_aesenc_si128(x4, rk);
        x5 = _mm_aesenc_si128(x5, rk);
        x6 = _mm_aesenc_si128(x6, rk);
        x7 = _mm_aesenc_si128(x7, rk);
    }

    rk = ctx->roundkeys[ctx->rounds];
    x0 = _mm_aesenclast_si128(x0, rk);
    x1 = _mm_aesenclast_si128(x1, rk);
    x2 = _mm_aesenclast_si128(x2, rk);
    x3 = _mm_aesenclast_si128(x3, rk);
    x4 = _mm_aesenclast_si128(x4, rk);
    x5 = _mm_aesenclast_si128(x5, rk);
    x6 = _mm_aesenclast_si128(x6, rk);
    x7 = _mm_aesenclast_si128(x7, rk);

    _mm_storeu_si128((__m128i*)(output + 0U), _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)(input + 0U))));
    _mm_storeu_si128((__m128i*)(output + 16U), _mm_xor_si128(x1, _mm_loadu_si128((const __m128i*)(input + 16U))));
    _mm_storeu_si128((__m128i*)(output + 32U), _mm_xor_si128(x2, _mm_loadu_si128((const __m128i*)(input + 32U))));
    _mm_storeu_si128((__m128i*)(output + 48U), _mm_xor_si128(x3, _mm_loadu_si128((const __m128i*)(input + 48U))));
    _mm_storeu_si128((__m128i*)(output + 64U), _mm_xor_si128(x4, _mm_loadu_si128((const __m128i*)(input + 64U))));
    _mm_storeu_si128((__m128i*)(output + 80U), _mm_xor_si128(x5, _mm_loadu_si128((const __m128i*)(input + 80U))));
    _mm_storeu_si128((__m128i*)(output + 96U), _mm_xor_si128(x6, _mm_loadu_si128((const __m128i*)(input + 96U))));
    _mm_storeu_si128((__m128i*)(output + 112U), _mm_xor_si128(x7, _mm_loadu_si128((const __m128i*)(input + 112U))));
}

#if defined(AES_CTR_HAS_VAES256)

static void aes_ctr_encrypt_ymm8(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, const uint8_t* nonce, uint64_t advanced, bool be)
{
	/* encrypt eight CTR blocks in four 256-bit VAES vectors */
    __m256i x0;
    __m256i x1;
    __m256i x2;
    __m256i x3;
    __m256i rk;
    size_t r;

    {
        __m256i initial;
        __m256i rev;

        initial = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)nonce));
        rev = _mm256_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
                                  15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
        if (be == true)
        {
            initial = _mm256_shuffle_epi8(initial, rev);
        }

        x0 = _mm256_add_epi64(initial, _mm256_set_epi64x(0LL, (int64_t)(advanced + 1U), 0LL, (int64_t)(advanced + 0U)));
        x1 = _mm256_add_epi64(initial, _mm256_set_epi64x(0LL, (int64_t)(advanced + 3U), 0LL, (int64_t)(advanced + 2U)));
        x2 = _mm256_add_epi64(initial, _mm256_set_epi64x(0LL, (int64_t)(advanced + 5U), 0LL, (int64_t)(advanced + 4U)));
        x3 = _mm256_add_epi64(initial, _mm256_set_epi64x(0LL, (int64_t)(advanced + 7U), 0LL, (int64_t)(advanced + 6U)));

        if (be == true)
        {
            x0 = _mm256_shuffle_epi8(x0, rev);
            x1 = _mm256_shuffle_epi8(x1, rev);
            x2 = _mm256_shuffle_epi8(x2, rev);
            x3 = _mm256_shuffle_epi8(x3, rev);
        }
    }

    rk = _mm256_broadcastsi128_si256(ctx->roundkeys[0U]);
    x0 = _mm256_xor_si256(x0, rk);
    x1 = _mm256_xor_si256(x1, rk);
    x2 = _mm256_xor_si256(x2, rk);
    x3 = _mm256_xor_si256(x3, rk);

    for (r = 1U; r < ctx->rounds; ++r)
    {
        rk = _mm256_broadcastsi128_si256(ctx->roundkeys[r]);
        x0 = _mm256_aesenc_epi128(x0, rk);
        x1 = _mm256_aesenc_epi128(x1, rk);
        x2 = _mm256_aesenc_epi128(x2, rk);
        x3 = _mm256_aesenc_epi128(x3, rk);
    }

    rk = _mm256_broadcastsi128_si256(ctx->roundkeys[ctx->rounds]);
    x0 = _mm256_aesenclast_epi128(x0, rk);
    x1 = _mm256_aesenclast_epi128(x1, rk);
    x2 = _mm256_aesenclast_epi128(x2, rk);
    x3 = _mm256_aesenclast_epi128(x3, rk);

    _mm256_storeu_si256((__m256i*)(output + 0U), _mm256_xor_si256(x0, _mm256_loadu_si256((const __m256i*)(input + 0U))));
    _mm256_storeu_si256((__m256i*)(output + 32U), _mm256_xor_si256(x1, _mm256_loadu_si256((const __m256i*)(input + 32U))));
    _mm256_storeu_si256((__m256i*)(output + 64U), _mm256_xor_si256(x2, _mm256_loadu_si256((const __m256i*)(input + 64U))));
    _mm256_storeu_si256((__m256i*)(output + 96U), _mm256_xor_si256(x3, _mm256_loadu_si256((const __m256i*)(input + 96U))));
}
#endif

#if defined(AES_CTR_HAS_VAES512)

static void aes_ctr_encrypt_zmm16(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, const uint8_t* nonce, uint64_t advanced, bool be)
{
	/* encrypt sixteen CTR blocks in four 512-bit VAES vectors */
    __m512i x0;
    __m512i x1;
    __m512i x2;
    __m512i x3;
    __m512i rk;
    size_t r;

    {
        __m512i initial;
        __m512i rev;

        initial = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)nonce));
        rev = _mm512_broadcast_i32x4(_mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0));

        if (be == true)
        {
            initial = _mm512_shuffle_epi8(initial, rev);
        }

        x0 = _mm512_add_epi64(initial, _mm512_set_epi64(0LL,(int64_t)(advanced+3U), 0LL,(int64_t)(advanced+2U), 0LL,(int64_t)(advanced+1U), 0LL,(int64_t)(advanced+0U)));
        x1 = _mm512_add_epi64(initial, _mm512_set_epi64(0LL,(int64_t)(advanced+7U), 0LL,(int64_t)(advanced+6U), 0LL,(int64_t)(advanced+5U), 0LL,(int64_t)(advanced+4U)));
        x2 = _mm512_add_epi64(initial, _mm512_set_epi64(0LL,(int64_t)(advanced+11U), 0LL,(int64_t)(advanced+10U), 0LL,(int64_t)(advanced+9U), 0LL,(int64_t)(advanced+8U)));
        x3 = _mm512_add_epi64(initial, _mm512_set_epi64(0LL,(int64_t)(advanced+15U), 0LL,(int64_t)(advanced+14U), 0LL,(int64_t)(advanced+13U), 0LL,(int64_t)(advanced+12U)));

        if (be == true)
        {
            x0 = _mm512_shuffle_epi8(x0, rev);
            x1 = _mm512_shuffle_epi8(x1, rev);
            x2 = _mm512_shuffle_epi8(x2, rev);
            x3 = _mm512_shuffle_epi8(x3, rev);
        }
    }

    rk = ctx->roundkeysw[0U];
    x0 = _mm512_xor_si512(x0, rk);
    x1 = _mm512_xor_si512(x1, rk);
    x2 = _mm512_xor_si512(x2, rk);
    x3 = _mm512_xor_si512(x3, rk);

    for (r = 1U; r < ctx->rounds; ++r)
    {
        rk = ctx->roundkeysw[r];
        x0 = _mm512_aesenc_epi128(x0, rk);
        x1 = _mm512_aesenc_epi128(x1, rk);
        x2 = _mm512_aesenc_epi128(x2, rk);
        x3 = _mm512_aesenc_epi128(x3, rk);
    }

    rk = ctx->roundkeysw[ctx->rounds];
    x0 = _mm512_aesenclast_epi128(x0, rk);
    x1 = _mm512_aesenclast_epi128(x1, rk);
    x2 = _mm512_aesenclast_epi128(x2, rk);
    x3 = _mm512_aesenclast_epi128(x3, rk);

    _mm512_storeu_si512((void*)(output + 0U), _mm512_xor_si512(x0, _mm512_loadu_si512((const void*)(input + 0U))));
    _mm512_storeu_si512((void*)(output + 64U), _mm512_xor_si512(x1, _mm512_loadu_si512((const void*)(input + 64U))));
    _mm512_storeu_si512((void*)(output + 128U), _mm512_xor_si512(x2, _mm512_loadu_si512((const void*)(input + 128U))));
    _mm512_storeu_si512((void*)(output + 192U), _mm512_xor_si512(x3, _mm512_loadu_si512((const void*)(input + 192U))));
}
#endif

static QSC_NO_INLINE void aes_ctr_fullwidth(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool be)
{
	/* apply CTR with exact 128-bit arithmetic at carry boundaries */
    uint8_t stream[QSC_AES_BLOCK_SIZE] = { 0U };
    size_t pos;
    size_t take;
    size_t j;

    pos = 0U;

    while (pos < length)
    {
        take = length - pos;

        if (take > QSC_AES_BLOCK_SIZE)
        {
            take = QSC_AES_BLOCK_SIZE;
        }

        qsc_aes_ecb_encrypt_block(ctx, stream, ctx->nonce);

        for (j = 0U; j < take; ++j)
        {
            output[pos + j] = (uint8_t)(input[pos + j] ^ stream[j]);
        }

        if (be == true)
        {
            qsc_intutils_be8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);
        }
        else
        {
            qsc_intutils_le8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);
        }

        pos += take;
    }

    qsc_memutils_secure_erase(stream, sizeof(stream));
}

static void aes_ctr_transform_batched(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool be)
{
	/* AES-NI/VAES CTR-BE or CTR-LE using prechecked 64-bit counter lanes */
    uint8_t counters[QSC_AES_BLOCK_SIZE];
    uint8_t stream[QSC_AES_BLOCK_SIZE] = { 0U };
    uint64_t low;
    uint64_t advanced;
    size_t blockcount;
    size_t batch;
    size_t pos;
    size_t j;
    size_t remaining;

    blockcount = length / QSC_AES_BLOCK_SIZE;
    blockcount += ((length % QSC_AES_BLOCK_SIZE) != 0U) ? 1U : 0U;
    low = (be == true) ? qsc_intutils_be8to64(ctx->nonce + 8U) : qsc_intutils_le8to64(ctx->nonce);

    if ((uint64_t)blockcount > (UINT64_MAX - low))
    {
        aes_ctr_fullwidth(ctx, output, input, length, be);
    }
    else
    {
        pos = 0U;
        advanced = 0U;

#if defined(AES_CTR_HAS_VAES512)
        batch = AES_CTR_ZMM_BATCH;
#elif defined(AES_CTR_HAS_VAES256)
        batch = AES_CTR_YMM_BATCH;
#else
        batch = AES_CTR_XMM_BATCH;
#endif

        while (length - pos >= (batch * QSC_AES_BLOCK_SIZE))
        {
            #if defined(AES_CTR_HAS_VAES512)
            aes_ctr_encrypt_zmm16(ctx, output + pos, input + pos, ctx->nonce, advanced, be);
#elif defined(AES_CTR_HAS_VAES256)
            aes_ctr_encrypt_ymm8(ctx, output + pos, input + pos, ctx->nonce, advanced, be);
#else
            aes_ctr_encrypt_xmm8(ctx, output + pos, input + pos, ctx->nonce, advanced, be);
#endif

            pos += batch * QSC_AES_BLOCK_SIZE;
            advanced += (uint64_t)batch;
        }

        while (pos < length)
        {
            remaining = length - pos;

            if (remaining > QSC_AES_BLOCK_SIZE)
            {
                remaining = QSC_AES_BLOCK_SIZE;
            }

            aes_ctr_prepare(counters, ctx->nonce, low + advanced, 1U, be);
            qsc_aes_ecb_encrypt_block(ctx, stream, counters);

            for (j = 0U; j < remaining; ++j)
            {
                output[pos + j] = (uint8_t)(input[pos + j] ^ stream[j]);
            }

            ++advanced;
            pos += remaining;
        }

        if (be == true)
        {
            aes_ctr_store_be64(ctx->nonce + 8U, low + (uint64_t)blockcount);
        }
        else
        {
            qsc_intutils_le64to8(ctx->nonce, low + (uint64_t)blockcount);
        }
    }

    qsc_memutils_secure_erase(counters, sizeof(counters));
    qsc_memutils_secure_erase(stream, sizeof(stream));
}

void qsc_aes_ctrbe_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
    QSC_ASSERT(ctx != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(input != output);
    QSC_ASSERT(length != 0U);

    if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL && input != output && length != 0U)
    {
        aes_ctr_transform_batched(ctx, output, input, length, true);
    }
}

void qsc_aes_ctrle_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
    QSC_ASSERT(ctx != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(length != 0U);

    if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL && length != 0U)
    {
        aes_ctr_transform_batched(ctx, output, input, length, false);
    }
}

/* ECB mode */

void qsc_aes_ecb_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && input != NULL && output != NULL)
	{
		__m128i inp;
		__m128i otp;

		inp = _mm_loadu_si128((const __m128i*)input);
		aes_decrypt_block(ctx, &otp, &inp);
		_mm_storeu_si128((__m128i*)output, otp);
	}
}

void qsc_aes_ecb_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && input != NULL && output != NULL)
	{
		__m128i inp;
		__m128i otp;

		inp = _mm_loadu_si128((const __m128i*)input);
		aes_encrypt_block(ctx, &otp, &inp);
		_mm_storeu_si128((__m128i*)output, otp);
	}
}

void qsc_aes_dispose(qsc_aes_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	/* erase the ctx members */

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->roundkeys, sizeof(ctx->roundkeys));

#if defined(QSC_SYSTEM_HAS_VAES512)
		qsc_memutils_secure_erase(ctx->roundkeysw, sizeof(ctx->roundkeysw));
#endif
		ctx->roundkeylen = 0U;
		ctx->rounds = 0U;
		ctx->nonce = NULL;
	}
}

#else

/* rijndael rcon, and s-box constant tables */

static const QSC_CACHE_ALIGNED uint32_t rcon[30U] =
{
	0x00000000UL, 0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL, 0x20000000UL, 0x40000000UL,
	0x80000000UL, 0x1B000000UL, 0x36000000UL, 0x6C000000UL, 0xD8000000UL, 0xAB000000UL, 0x4D000000UL, 0x9A000000UL,
	0x2F000000UL, 0x5E000000UL, 0xBC000000UL, 0x63000000UL, 0xC6000000UL, 0x97000000UL, 0x35000000UL, 0x6A000000UL,
	0xD4000000UL, 0xB3000000UL, 0x7D000000UL, 0xFA000000UL, 0xEF000000UL, 0xC5000000UL
};

#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)

static inline void aes_swapn(uint32_t cl, uint32_t ch, uint32_t s, uint32_t* x, uint32_t* y)
{
	uint32_t a = *x;
	uint32_t b = *y;

	*x = (a & cl) | ((b & cl) << s);
	*y = ((a & ch) >> s) | (b & ch);
}
  
static inline void aes_swap2(uint32_t* x, uint32_t* y)
{
	/* 0101... / 1010...  (1-bit lanes) */
	aes_swapn(0x55555555U, 0xAAAAAAAAU, 1U, x, y);
}

static inline void aes_swap4(uint32_t* x, uint32_t* y)
{
	/* 0011... / 1100...  (2-bit lanes) */
	aes_swapn(0x33333333U, 0xCCCCCCCCU, 2U, x, y);
}

static inline void aes_swap8(uint32_t* x, uint32_t* y)
{
	/* 0000 1111... / 1111 0000...  (4-bit lanes) */
	aes_swapn(0x0F0F0F0FU, 0xF0F0F0F0U, 4U, x, y);
}

static void aes_ct_ortho(uint32_t* q)
{
	aes_swap2(&q[0U], &q[1U]);
	aes_swap2(&q[2U], &q[3U]);
	aes_swap2(&q[4U], &q[5U]);
	aes_swap2(&q[6U], &q[7U]);

	aes_swap4(&q[0U], &q[2U]);
	aes_swap4(&q[1U], &q[3U]);
	aes_swap4(&q[4U], &q[6U]);
	aes_swap4(&q[5U], &q[7U]);

	aes_swap8(&q[0U], &q[4U]);
	aes_swap8(&q[1U], &q[5U]);
	aes_swap8(&q[2U], &q[6U]);
	aes_swap8(&q[3U], &q[7U]);
}

static void aes_ct_sbox(uint32_t* q)
{
	/* Adapted from bearssl, author Thomas Pornin.
	 * This S-box implementation is a straightforward translation of
	 * the circuit described by Boyar and Peralta in "A new
	 * combinational logic minimization technique with applications
	 * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	 *
	 * Note that variables x* (input) and s* (output) are numbered
	 * in "reverse" order (x0 is the high bit, x7 is the low bit). */

	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t s4;
	uint32_t s5;
	uint32_t s6;
	uint32_t s7;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;
	uint32_t t4;
	uint32_t t5;
	uint32_t t6;
	uint32_t t7;
	uint32_t t8;
	uint32_t t9;
	uint32_t t10;
	uint32_t t11;
	uint32_t t12;
	uint32_t t13;
	uint32_t t14;
	uint32_t t15;
	uint32_t t16;
	uint32_t t17;
	uint32_t t18;
	uint32_t t19;
	uint32_t t20;
	uint32_t t21;
	uint32_t t22;
	uint32_t t23;
	uint32_t t24;
	uint32_t t25;
	uint32_t t26;
	uint32_t t27;
	uint32_t t28;
	uint32_t t29;
	uint32_t t30;
	uint32_t t31;
	uint32_t t32;
	uint32_t t33;
	uint32_t t34;
	uint32_t t35;
	uint32_t t36;
	uint32_t t37;
	uint32_t t38;
	uint32_t t39;
	uint32_t t40;
	uint32_t t41;
	uint32_t t42;
	uint32_t t43;
	uint32_t t44;
	uint32_t t45;
	uint32_t t46;
	uint32_t t47;
	uint32_t t48;
	uint32_t t49;
	uint32_t t50;
	uint32_t t51;
	uint32_t t52;
	uint32_t t53;
	uint32_t t54;
	uint32_t t55;
	uint32_t t56;
	uint32_t t57;
	uint32_t t58;
	uint32_t t59;
	uint32_t t60;
	uint32_t t61;
	uint32_t t62;
	uint32_t t63;
	uint32_t t64;
	uint32_t t65;
	uint32_t t66;
	uint32_t t67;
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t x4;
	uint32_t x5;
	uint32_t x6;
	uint32_t x7;
	uint32_t y1;
	uint32_t y2;
	uint32_t y3;
	uint32_t y4;
	uint32_t y5;
	uint32_t y6;
	uint32_t y7;
	uint32_t y8;
	uint32_t y9;
	uint32_t y10;
	uint32_t y11;
	uint32_t y12;
	uint32_t y13;
	uint32_t y14;
	uint32_t y15;
	uint32_t y16;
	uint32_t y17;
	uint32_t y18;
	uint32_t y19;
	uint32_t y20;
	uint32_t y21;
	uint32_t z0;
	uint32_t z1;
	uint32_t z2;
	uint32_t z3;
	uint32_t z4;
	uint32_t z5;
	uint32_t z6;
	uint32_t z7;
	uint32_t z8;
	uint32_t z9;
	uint32_t z10;
	uint32_t z11;
	uint32_t z12;
	uint32_t z13;
	uint32_t z14;
	uint32_t z15;
	uint32_t z16;
	uint32_t z17;

	x0 = q[7U];
	x1 = q[6U];
	x2 = q[5U];
	x3 = q[4U];
	x4 = q[3U];
	x5 = q[2U];
	x6 = q[1U];
	x7 = q[0U];

	/* top linear transformation */
	y14 = x3 ^ x5;
	y13 = x0 ^ x6;
	y9 = x0 ^ x3;
	y8 = x0 ^ x5;
	t0 = x1 ^ x2;
	y1 = t0 ^ x7;
	y4 = y1 ^ x3;
	y12 = y13 ^ y14;
	y2 = y1 ^ x0;
	y5 = y1 ^ x6;
	y3 = y5 ^ y8;
	t1 = x4 ^ y12;
	y15 = t1 ^ x5;
	y20 = t1 ^ x1;
	y6 = y15 ^ x7;
	y10 = y15 ^ t0;
	y11 = y20 ^ y9;
	y7 = x7 ^ y11;
	y17 = y10 ^ y11;
	y19 = y10 ^ y8;
	y16 = t0 ^ y11;
	y21 = y13 ^ y16;
	y18 = x0 ^ y16;

	/* non-linear section */
	t2 = y12 & y15;
	t3 = y3 & y6;
	t4 = t3 ^ t2;
	t5 = y4 & x7;
	t6 = t5 ^ t2;
	t7 = y13 & y16;
	t8 = y5 & y1;
	t9 = t8 ^ t7;
	t10 = y2 & y7;
	t11 = t10 ^ t7;
	t12 = y9 & y11;
	t13 = y14 & y17;
	t14 = t13 ^ t12;
	t15 = y8 & y10;
	t16 = t15 ^ t12;
	t17 = t4 ^ t14;
	t18 = t6 ^ t16;
	t19 = t9 ^ t14;
	t20 = t11 ^ t16;
	t21 = t17 ^ y20;
	t22 = t18 ^ y19;
	t23 = t19 ^ y21;
	t24 = t20 ^ y18;

	t25 = t21 ^ t22;
	t26 = t21 & t23;
	t27 = t24 ^ t26;
	t28 = t25 & t27;
	t29 = t28 ^ t22;
	t30 = t23 ^ t24;
	t31 = t22 ^ t26;
	t32 = t31 & t30;
	t33 = t32 ^ t24;
	t34 = t23 ^ t33;
	t35 = t27 ^ t33;
	t36 = t24 & t35;
	t37 = t36 ^ t34;
	t38 = t27 ^ t36;
	t39 = t29 & t38;
	t40 = t25 ^ t39;

	t41 = t40 ^ t37;
	t42 = t29 ^ t33;
	t43 = t29 ^ t40;
	t44 = t33 ^ t37;
	t45 = t42 ^ t41;
	z0 = t44 & y15;
	z1 = t37 & y6;
	z2 = t33 & x7;
	z3 = t43 & y16;
	z4 = t40 & y1;
	z5 = t29 & y7;
	z6 = t42 & y11;
	z7 = t45 & y17;
	z8 = t41 & y10;
	z9 = t44 & y12;
	z10 = t37 & y3;
	z11 = t33 & y4;
	z12 = t43 & y13;
	z13 = t40 & y5;
	z14 = t29 & y2;
	z15 = t42 & y9;
	z16 = t45 & y14;
	z17 = t41 & y8;

	/* bottom linear transformation */
	t46 = z15 ^ z16;
	t47 = z10 ^ z11;
	t48 = z5 ^ z13;
	t49 = z9 ^ z10;
	t50 = z2 ^ z12;
	t51 = z2 ^ z5;
	t52 = z7 ^ z8;
	t53 = z0 ^ z3;
	t54 = z6 ^ z7;
	t55 = z16 ^ z17;
	t56 = z12 ^ t48;
	t57 = t50 ^ t53;
	t58 = z4 ^ t46;
	t59 = z3 ^ t54;
	t60 = t46 ^ t57;
	t61 = z14 ^ t57;
	t62 = t52 ^ t58;
	t63 = t49 ^ t58;
	t64 = z4 ^ t59;
	t65 = t61 ^ t62;
	t66 = z1 ^ t63;
	s0 = t59 ^ t63;
	s6 = t56 ^ ~t62;
	s7 = t48 ^ ~t60;
	t67 = t64 ^ t65;
	s3 = t53 ^ t66;
	s4 = t51 ^ t66;
	s5 = t47 ^ t65;
	s1 = t64 ^ ~s3;
	s2 = t55 ^ ~t67;

	q[7U] = s0;
	q[6U] = s1;
	q[5U] = s2;
	q[4U] = s3;
	q[3U] = s4;
	q[2U] = s5;
	q[1U] = s6;
	q[0U] = s7;
}

static uint32_t sub_word(uint32_t x)
{
	uint32_t q[8U] = { 0U };
	uint32_t res;

	q[0U] = x;
	aes_ct_ortho(q);
	aes_ct_sbox(q);
	aes_ct_ortho(q);

	res = q[0U];
	qsc_memutils_secure_erase(q, sizeof(q));

	return res;
}

static void aes_ct_isbox(uint32_t* q)
{
	/*
	 * adapted from bearssl, author Thomas Pornin
	 * AES S-box is:
	 *   S(x) = A(I(x)) ^ 0x63
	 * where I() is inversion in GF(256), and A() is a linear
	 * transform (0 is formally defined to be its own inverse).
	 * Since inversion is an involution, the inverse S-box can be
	 * computed from the S-box as:
	 *   iS(x) = B(S(B(x ^ 0x63)) ^ 0x63)
	 * where B() is the inverse of A(). Indeed, for any y in GF(256):
	 *   iS(S(y)) = B(A(I(B(A(I(y)) ^ 0x63 ^ 0x63))) ^ 0x63 ^ 0x63) = y
	 *
	 * Note: we reuse the implementation of the forward S-box,
	 * instead of duplicating it here, so that total code size is
	 * lower. By merging the B() transforms into the S-box circuit
	 * we could make faster CBC decryption, but CBC decryption is
	 * already quite faster than CBC encryption because we can
	 * process two blocks in parallel.
	 */

	uint32_t q0;
	uint32_t q1;
	uint32_t q2;
	uint32_t q3;
	uint32_t q4;
	uint32_t q5;
	uint32_t q6;
	uint32_t q7;

	q0 = ~q[0U];
	q1 = ~q[1U];
	q2 = q[2U];
	q3 = q[3U];
	q4 = q[4U];
	q5 = ~q[5U];
	q6 = ~q[6U];
	q7 = q[7U];

	q[7U] = q1 ^ q4 ^ q6;
	q[6U] = q0 ^ q3 ^ q5;
	q[5U] = q7 ^ q2 ^ q4;
	q[4U] = q6 ^ q1 ^ q3;
	q[3U] = q5 ^ q0 ^ q2;
	q[2U] = q4 ^ q7 ^ q1;
	q[1U] = q3 ^ q6 ^ q0;
	q[0U] = q2 ^ q5 ^ q7;

	aes_ct_sbox(q);

	q0 = ~q[0U];
	q1 = ~q[1U];
	q2 = q[2U];
	q3 = q[3U];
	q4 = q[4U];
	q5 = ~q[5U];
	q6 = ~q[6U];
	q7 = q[7U];

	q[7U] = q1 ^ q4 ^ q6;
	q[6U] = q0 ^ q3 ^ q5;
	q[5U] = q7 ^ q2 ^ q4;
	q[4U] = q6 ^ q1 ^ q3;
	q[3U] = q5 ^ q0 ^ q2;
	q[2U] = q4 ^ q7 ^ q1;
	q[1U] = q3 ^ q6 ^ q0;
	q[0U] = q2 ^ q5 ^ q7;
}

//static uint32_t sub_iword(uint32_t x)
//{
//	uint32_t q[8U] = { 0U };
//
//	q[0U] = x;
//	aes_ct_ortho(q);
//	aes_ct_isbox(q);
//	aes_ct_ortho(q);
//
//	return q[0U];
//}

static void aes_sub_bytes(uint8_t* ctx)
{
	uint32_t q[8U] = { 0U };

	q[0U] = ctx[0U];
	q[1U] = ctx[1U];
	q[2U] = ctx[2U];
	q[3U] = ctx[3U];
	q[4U] = ctx[4U];
	q[5U] = ctx[5U];
	q[6U] = ctx[6U];
	q[7U] = ctx[7U];

	aes_ct_ortho(q);
	aes_ct_sbox(q);
	aes_ct_ortho(q);

	ctx[0U] = (uint8_t)q[0U];
	ctx[1U] = (uint8_t)q[1U];
	ctx[2U] = (uint8_t)q[2U];
	ctx[3U] = (uint8_t)q[3U];
	ctx[4U] = (uint8_t)q[4U];
	ctx[5U] = (uint8_t)q[5U];
	ctx[6U] = (uint8_t)q[6U];
	ctx[7U] = (uint8_t)q[7U];

	q[0U] = ctx[8U];
	q[1U] = ctx[9U];
	q[2U] = ctx[10U];
	q[3U] = ctx[11U];
	q[4U] = ctx[12U];
	q[5U] = ctx[13U];
	q[6U] = ctx[14U];
	q[7U] = ctx[15U];

	aes_ct_ortho(q);
	aes_ct_sbox(q);
	aes_ct_ortho(q);

	ctx[8U] = (uint8_t)q[0U];
	ctx[9U] = (uint8_t)q[1U];
	ctx[10U] = (uint8_t)q[2U];
	ctx[11U] = (uint8_t)q[3U];
	ctx[12U] = (uint8_t)q[4U];
	ctx[13U] = (uint8_t)q[5U];
	ctx[14U] = (uint8_t)q[6U];
	ctx[15U] = (uint8_t)q[7U];
	qsc_memutils_secure_erase(q, sizeof(q));
}

#endif

/**
 * \brief Apply the AES S-box independently to the four bytes of a word.
 * \param rot: [uint32_t] Word to substitute; no storage is transferred.
 * \return [uint32_t] Substituted word in the same byte order.
 * \note Reentrant. ARM uses AESE on identical columns so ShiftRows has no effect.
 */
static uint32_t aes_substitution(uint32_t rot)
{
#if defined(QSC_SYSTEM_ARM_AES_ENABLED)
	uint8x16_t tmp;

	tmp = vreinterpretq_u8_u32(vdupq_n_u32(rot));
	tmp = vaeseq_u8(tmp, vdupq_n_u8(0U));

	return vgetq_lane_u32(vreinterpretq_u32_u8(tmp), 0);
#else
	uint32_t val;
	uint32_t res;

	val = rot & 0xFFU;
	res = (uint8_t)sub_word(val);
	val = (rot >> 8U) & 0xFFU;
	res |= ((uint32_t)(uint8_t)sub_word(val) << 8U);
	val = (rot >> 16U) & 0xFFU;
	res |= ((uint32_t)(uint8_t)sub_word(val) << 16U);
	val = (rot >> 24U) & 0xFFU;

	return res | ((uint32_t)((uint8_t)sub_word(val)) << 24U);
#endif
}

#if !defined(QSC_SYSTEM_ARM_AES_ENABLED)

static void aes_invsub_bytes(uint8_t* ctx)
{
	uint32_t q[8U] = { 0U };

	q[0U] = ctx[0U];
	q[1U] = ctx[1U];
	q[2U] = ctx[2U];
	q[3U] = ctx[3U];
	q[4U] = ctx[4U];
	q[5U] = ctx[5U];
	q[6U] = ctx[6U];
	q[7U] = ctx[7U];

	aes_ct_ortho(q);
	aes_ct_isbox(q);
	aes_ct_ortho(q);

	ctx[0U] = (uint8_t)q[0U];
	ctx[1U] = (uint8_t)q[1U];
	ctx[2U] = (uint8_t)q[2U];
	ctx[3U] = (uint8_t)q[3U];
	ctx[4U] = (uint8_t)q[4U];
	ctx[5U] = (uint8_t)q[5U];
	ctx[6U] = (uint8_t)q[6U];
	ctx[7U] = (uint8_t)q[7U];

	q[0U] = ctx[8U];
	q[1U] = ctx[9U];
	q[2U] = ctx[10U];
	q[3U] = ctx[11U];
	q[4U] = ctx[12U];
	q[5U] = ctx[13U];
	q[6U] = ctx[14U];
	q[7U] = ctx[15U];

	aes_ct_ortho(q);
	aes_ct_isbox(q);
	aes_ct_ortho(q);

	ctx[8U] = (uint8_t)q[0U];
	ctx[9U] = (uint8_t)q[1U];
	ctx[10U] = (uint8_t)q[2U];
	ctx[11U] = (uint8_t)q[3U];
	ctx[12U] = (uint8_t)q[4U];
	ctx[13U] = (uint8_t)q[5U];
	ctx[14U] = (uint8_t)q[6U];
	ctx[15U] = (uint8_t)q[7U];
	qsc_memutils_secure_erase(q, sizeof(q));
}

static void aes_add_roundkey(uint8_t* ctx, const uint32_t *skeys)
{
	uint32_t k;

	for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		k = *skeys;
		ctx[i] ^= (uint8_t)(k >> 24U);
		ctx[i + 1U] ^= (uint8_t)(k >> 16U) & 0xFFU;
		ctx[i + 2U] ^= (uint8_t)(k >> 8U) & 0xFFU;
		ctx[i + 3U] ^= (uint8_t)k & 0xFFU;
		++skeys;
	}
}

static uint8_t aes_gf256_reduce(uint32_t x)
{
	uint32_t y;

	y = x >> 8U;

	return (x ^ y ^ (y << 1U) ^ (y << 3U) ^ (y << 4U)) & 0xFFU;
}

static void aes_invmix_columns(uint8_t* ctx)
{
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;

	for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = ctx[i];
		s1 = ctx[i + 1U];
		s2 = ctx[i + 2U];
		s3 = ctx[i + 3U];

		t0 = (s0 << 1U) ^ (s0 << 2U) ^ (s0 << 3U) ^ s1 ^ (s1 << 1U) ^ (s1 << 3U)
			^ s2 ^ (s2 << 2U) ^ (s2 << 3U) ^ s3 ^ (s3 << 3U);

		t1 = s0 ^ (s0 << 3U) ^ (s1 << 1U) ^ (s1 << 2U) ^ (s1 << 3U)
			^ s2 ^ (s2 << 1U) ^ (s2 << 3U) ^ s3 ^ (s3 << 2U) ^ (s3 << 3U);

		t2 = s0 ^ (s0 << 2U) ^ (s0 << 3U) ^ s1 ^ (s1 << 3U)
			^ (s2 << 1U) ^ (s2 << 2U) ^ (s2 << 3U) ^ s3 ^ (s3 << 1U) ^ (s3 << 3U);

		t3 = s0 ^ (s0 << 1U) ^ (s0 << 3U) ^ s1 ^ (s1 << 2U) ^ (s1 << 3U)
			^ s2 ^ (s2 << 3U) ^ (s3 << 1U) ^ (s3 << 2U) ^ (s3 << 3U);

		ctx[i] = aes_gf256_reduce(t0);
		ctx[i + 1U] = aes_gf256_reduce(t1);
		ctx[i + 2U] = aes_gf256_reduce(t2);
		ctx[i + 3U] = aes_gf256_reduce(t3);
	}
}

static void aes_invshift_rows(uint8_t* ctx)
{
	uint8_t tmp;

	tmp = ctx[13U];
	ctx[13U] = ctx[9U];
	ctx[9U] = ctx[5U];
	ctx[5U] = ctx[1U];
	ctx[1U] = tmp;

	tmp = ctx[2U];
	ctx[2U] = ctx[10U];
	ctx[10U] = tmp;
	tmp = ctx[6U];
	ctx[6U] = ctx[14U];
	ctx[14U] = tmp;

	tmp = ctx[3U];
	ctx[3U] = ctx[7U];
	ctx[7U] = ctx[11U];
	ctx[11U] = ctx[15U];
	ctx[15U] = tmp;
}

static void aes_mix_columns(uint8_t* ctx)
{
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;

	for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = ctx[i];
		s1 = ctx[i + 1U];
		s2 = ctx[i + 2U];
		s3 = ctx[i + 3U];

		t0 = (s0 << 1U) ^ s1 ^ (s1 << 1U) ^ s2 ^ s3;
		t1 = s0 ^ (s1 << 1U) ^ s2 ^ (s2 << 1U) ^ s3;
		t2 = s0 ^ s1 ^ (s2 << 1U) ^ s3 ^ (s3 << 1U);
		t3 = s0 ^ (s0 << 1U) ^ s1 ^ s2 ^ (s3 << 1U);

		ctx[i] = (uint8_t)(t0 ^ ((~(t0 >> 8U) + 1U) & 0x0000011BUL));
		ctx[i + 1U] = (uint8_t)(t1 ^ ((~(t1 >> 8U) + 1U) & 0x0000011BUL));
		ctx[i + 2U] = (uint8_t)(t2 ^ ((~(t2 >> 8U) + 1U) & 0x0000011BUL));
		ctx[i + 3U] = (uint8_t)(t3 ^ ((~(t3 >> 8U) + 1U) & 0x0000011BUL));
	}
}

static void aes_shift_rows(uint8_t* ctx)
{
	uint8_t tmp;

	tmp = ctx[1U];
	ctx[1U] = ctx[5U];
	ctx[5U] = ctx[9U];
	ctx[9U] = ctx[13U];
	ctx[13U] = tmp;

	tmp = ctx[2U];
	ctx[2U] = ctx[10U];
	ctx[10U] = tmp;
	tmp = ctx[6U];
	ctx[6U] = ctx[14U];
	ctx[14U] = tmp;

	tmp = ctx[15U];
	ctx[15U] = ctx[11U];
	ctx[11U] = ctx[7U];
	ctx[7U] = ctx[3U];
	ctx[3U] = tmp;
}

static void aes_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	const uint8_t* buf;
	uint8_t s[16U];

	buf = input;
	qsc_memutils_copy(s, buf, QSC_AES_BLOCK_SIZE);
	aes_add_roundkey(s, ctx->roundkeys + (ctx->rounds << 2U));

	for (size_t i = ctx->rounds - 1U; i > 0U; i--)
	{
		aes_invshift_rows(s);
		aes_invsub_bytes(s);
		aes_add_roundkey(s, ctx->roundkeys + (i << 2U));
		aes_invmix_columns(s);
	}

	aes_invshift_rows(s);
	aes_invsub_bytes(s);
	aes_add_roundkey(s, ctx->roundkeys);
	qsc_memutils_copy(output, s, QSC_AES_BLOCK_SIZE);
	qsc_memutils_secure_erase(s, sizeof(s));
}

static void aes_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	uint8_t buf[QSC_AES_BLOCK_SIZE] = { 0U };

	qsc_memutils_copy(buf, input, QSC_AES_BLOCK_SIZE);
	aes_add_roundkey(buf, ctx->roundkeys);

	for (size_t i = 1U; i < ctx->rounds; ++i)
	{
		aes_sub_bytes(buf);
		aes_shift_rows(buf);
		aes_mix_columns(buf);
		aes_add_roundkey(buf, ctx->roundkeys + (i << 2U));
	}

	aes_sub_bytes(buf);
	aes_shift_rows(buf);
	aes_add_roundkey(buf, ctx->roundkeys + (ctx->rounds << 2U));
	qsc_memutils_copy(output, buf, QSC_AES_BLOCK_SIZE);
	qsc_memutils_secure_erase(buf, sizeof(buf));
}

#else

static uint8x16_t aes_load_roundkey_arm(const uint32_t* key)
{
	/* load one round key from the existing big-endian word schedule */
	uint8x16_t tmp;

	/* note reentrant. borrows the input; does not modify it or require SIMD alignment */
	tmp = vreinterpretq_u8_u32(vld1q_u32(key));
#if defined(__AARCH64EL__) || defined(_M_ARM64) || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
	tmp = vrev32q_u8(tmp);
#endif

	return tmp;
}

static void aes_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	/* decrypt one AES block with ARM cryptographic instructions */
	uint8x16_t tmp;
	const uint8x16_t zero = vdupq_n_u8(0U);

	/* note no ownership transfer. reentrant with an immutable schedule and independent
	 * output. Callers validate pointers. Uses the unchanged forward key schedule */
	tmp = veorq_u8(vld1q_u8(input), aes_load_roundkey_arm(ctx->roundkeys + (ctx->rounds * 4U)));

	for (size_t i = ctx->rounds - 1U; i > 0U; --i)
	{
		tmp = vaesdq_u8(tmp, zero);
		tmp = veorq_u8(tmp, aes_load_roundkey_arm(ctx->roundkeys + (i * 4U)));
		tmp = vaesimcq_u8(tmp);
	}

	tmp = vaesdq_u8(tmp, zero);
	tmp = veorq_u8(tmp, aes_load_roundkey_arm(ctx->roundkeys));
	vst1q_u8(output, tmp);
}

static void aes_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	/* encrypt one AES block with ARM cryptographic instructions */
	uint8x16_t tmp;

	tmp = vld1q_u8(input);

	/* note: no ownership transfer. reentrant with an immutable schedule and independent
     * output. callers validate pointers. no secret-indexed memory accesses are added. */
	for (size_t i = 0U; i < ctx->rounds - 1U; ++i)
	{
		tmp = vaeseq_u8(tmp, aes_load_roundkey_arm(ctx->roundkeys + (i * 4U)));
		tmp = vaesmcq_u8(tmp);
	}

	tmp = vaeseq_u8(tmp, aes_load_roundkey_arm(ctx->roundkeys + ((ctx->rounds - 1U) * 4U)));
	tmp = veorq_u8(tmp, aes_load_roundkey_arm(ctx->roundkeys + (ctx->rounds * 4U)));
	vst1q_u8(output, tmp);
}

#endif

static void aes_expand_rot(uint32_t* key, uint32_t keyindex, uint32_t keyoffset, uint32_t rconindex)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = key[subkey] ^ aes_substitution((key[keyindex - 1U] << 8U) | ((key[keyindex - 1U] >> 24U) & 0xFFU)) ^ rcon[rconindex];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1U];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1U];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1U];
}

static void aes_expand_sub(uint32_t* key, uint32_t keyindex, uint32_t keyoffset)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = aes_substitution(key[keyindex - 1U]) ^ key[subkey];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1U];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1U];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1U];
}

static void aes_standard_expand(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams)
{
	/* key in 32 bit words */
	size_t kwords;

	kwords = keyparams->keylen / sizeof(uint32_t);

	if (kwords == 8U)
	{
		ctx->roundkeys[0U] = qsc_intutils_be8to32(keyparams->key);
		ctx->roundkeys[1U] = qsc_intutils_be8to32(keyparams->key + 4U);
		ctx->roundkeys[2U] = qsc_intutils_be8to32(keyparams->key + 8U);
		ctx->roundkeys[3U] = qsc_intutils_be8to32(keyparams->key + 12U);
		ctx->roundkeys[4U] = qsc_intutils_be8to32(keyparams->key + 16U);
		ctx->roundkeys[5U] = qsc_intutils_be8to32(keyparams->key + 20U);
		ctx->roundkeys[6U] = qsc_intutils_be8to32(keyparams->key + 24U);
		ctx->roundkeys[7U] = qsc_intutils_be8to32(keyparams->key + 28U);

		/* k256 r: 8,16U,24U,32,40,48,56 s: 12,20,28,36,44,52 */
		aes_expand_rot(ctx->roundkeys, 8U, 8U, 1U);
		aes_expand_sub(ctx->roundkeys, 12U, 8U);
		aes_expand_rot(ctx->roundkeys, 16U, 8U, 2U);
		aes_expand_sub(ctx->roundkeys, 20U, 8U);
		aes_expand_rot(ctx->roundkeys, 24U, 8U, 3U);
		aes_expand_sub(ctx->roundkeys, 28U, 8U);
		aes_expand_rot(ctx->roundkeys, 32U, 8U, 4U);
		aes_expand_sub(ctx->roundkeys, 36U, 8U);
		aes_expand_rot(ctx->roundkeys, 40U, 8U, 5U);
		aes_expand_sub(ctx->roundkeys, 44U, 8U);
		aes_expand_rot(ctx->roundkeys, 48U, 8U, 6U);
		aes_expand_sub(ctx->roundkeys, 52U, 8U);
		aes_expand_rot(ctx->roundkeys, 56U, 8U, 7U);
	}
	else
	{
		ctx->roundkeys[0U] = qsc_intutils_be8to32(keyparams->key);
		ctx->roundkeys[1U] = qsc_intutils_be8to32(keyparams->key + 4U);
		ctx->roundkeys[2U] = qsc_intutils_be8to32(keyparams->key + 8U);
		ctx->roundkeys[3U] = qsc_intutils_be8to32(keyparams->key + 12U);

		/* k128 r: 4,8,12,16U,20,24,28,32,36,40 */
		aes_expand_rot(ctx->roundkeys, 4U, 4U, 1U);
		aes_expand_rot(ctx->roundkeys, 8U, 4U, 2U);
		aes_expand_rot(ctx->roundkeys, 12U, 4U, 3U);
		aes_expand_rot(ctx->roundkeys, 16U, 4U, 4U);
		aes_expand_rot(ctx->roundkeys, 20U, 4U, 5U);
		aes_expand_rot(ctx->roundkeys, 24U, 4U, 6U);
		aes_expand_rot(ctx->roundkeys, 28U, 4U, 7U);
		aes_expand_rot(ctx->roundkeys, 32U, 4U, 8U);
		aes_expand_rot(ctx->roundkeys, 36U, 4U, 9U);
		aes_expand_rot(ctx->roundkeys, 40U, 4U, 10U);
	}
}

void qsc_aes_initialize(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption, qsc_aes_cipher_type ctype)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	(void)encryption;

	if (ctx != NULL)
	{
		qsc_aes_dispose(ctx);
	}

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL &&
		((ctype == qsc_aes_cipher_128 && keyparams->keylen == QSC_AES128_KEY_SIZE) ||
		(ctype == qsc_aes_cipher_256 && keyparams->keylen == QSC_AES256_KEY_SIZE)))
	{
		if (keyparams->nonce != NULL && keyparams->noncelen == QSC_AES_BLOCK_SIZE)
		{
			ctx->nonce = keyparams->nonce;
		}

		qsc_memutils_secure_erase(ctx->roundkeys, sizeof(ctx->roundkeys));

		if (ctype == qsc_aes_cipher_256)
		{
			ctx->roundkeylen = AES256_ROUNDKEY_SIZE;
			ctx->rounds = 14U;
			aes_standard_expand(ctx, keyparams);
		}
		else if (ctype == qsc_aes_cipher_128)
		{
			ctx->roundkeylen = AES128_ROUNDKEY_SIZE;
			ctx->rounds = 10U;
			aes_standard_expand(ctx, keyparams);
		}
		else
		{
			ctx->rounds = 0U;
			ctx->roundkeylen = 0U;
		}
	}
}

/* CBC mode */

void qsc_aes_cbc_decrypt(qsc_aes_state* ctx, uint8_t* output, size_t* outlen, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outlen != NULL);

	if (outlen != NULL)
	{
		*outlen = 0U;
	}

	if (ctx != NULL && input != NULL && output != NULL && outlen != NULL &&
		ctx->roundkeylen != 0U && ctx->nonce != NULL &&
		length >= QSC_AES_BLOCK_SIZE && length % QSC_AES_BLOCK_SIZE == 0U)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t len;
		size_t oft;

		oft = 0U;

#if defined(QSC_SYSTEM_AESNI_ENABLED) && defined(QSC_SYSTEM_HAS_VAES512)
		while (length > AVX512_BLOCK_SIZE)
		{
			__m512i inpw;
			__m512i ivtw;
			__m512i otpw;
			uint8_t ivtb[AVX512_BLOCK_SIZE] = { 0U };

			qsc_memutils_copy(ivtb, ctx->nonce, QSC_AES_BLOCK_SIZE);
			qsc_memutils_copy(ivtb + QSC_AES_BLOCK_SIZE, input + oft, 3U * QSC_AES_BLOCK_SIZE);
			ivtw = _mm512_loadu_si512((const void*)ivtb);
			inpw = _mm512_loadu_si512((const void*)(input + oft));
			aes_decrypt_blockw(ctx, &otpw, &inpw);
			otpw = _mm512_xor_si512(otpw, ivtw);

			/* preserve ciphertext before an in-place output store */
			qsc_memutils_copy(ctx->nonce, input + oft + AVX512_BLOCK_SIZE - QSC_AES_BLOCK_SIZE, QSC_AES_BLOCK_SIZE);
			_mm512_storeu_si512((void*)(output + oft), otpw);
			length -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;
		}
#endif

		while (length > QSC_AES_BLOCK_SIZE)
		{
			qsc_aes_cbc_decrypt_block(ctx, output + oft, input + oft);
			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		qsc_aes_cbc_decrypt_block(ctx, tmpb, input + oft);
		len = qsc_pkcs7_padding_length(tmpb);

		if (len != 0U)
		{
			if (len < QSC_AES_BLOCK_SIZE)
			{
				qsc_memutils_copy(output + oft, tmpb, QSC_AES_BLOCK_SIZE - len);
			}

			*outlen = oft + QSC_AES_BLOCK_SIZE - len;
		}
		else
		{
			qsc_memutils_secure_erase(output, oft + QSC_AES_BLOCK_SIZE);
		}

		qsc_memutils_secure_erase(tmpb, sizeof(tmpb));
	}
}

void qsc_aes_cbc_encrypt(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL || length == 0U);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && (input != NULL || length == 0U) && output != NULL &&
		ctx->roundkeylen != 0U && ctx->nonce != NULL && length <= SIZE_MAX - QSC_AES_BLOCK_SIZE)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t oft;

		oft = 0U;

		while (length >= QSC_AES_BLOCK_SIZE)
		{
			qsc_aes_cbc_encrypt_block(ctx, output + oft, input + oft);
			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		if (length != 0U)
		{
			qsc_memutils_copy(tmpb, input + oft, length);
		}

		qsc_pkcs7_add_padding(tmpb, QSC_AES_BLOCK_SIZE - length);
		qsc_aes_cbc_encrypt_block(ctx, output + oft, tmpb);
		qsc_memutils_secure_erase(tmpb, sizeof(tmpb));
	}
}

void qsc_aes_cbc_decrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL)
	{
		uint8_t tmpv[QSC_AES_BLOCK_SIZE] = { 0U };

		qsc_memutils_copy(tmpv, input, QSC_AES_BLOCK_SIZE);
		aes_decrypt_block(ctx, output, input);

		for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
		{
			output[i] ^= ctx->nonce[i];
		}

		qsc_memutils_copy(ctx->nonce, tmpv, QSC_AES_BLOCK_SIZE);
	}
}

void qsc_aes_cbc_encrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL)
	{
		for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
		{
			ctx->nonce[i] ^= input[i];
		}

		aes_encrypt_block(ctx, output, ctx->nonce);
		qsc_memutils_copy(ctx->nonce, output, QSC_AES_BLOCK_SIZE);
	}
}

/* CTR mode */

void qsc_aes_ctrbe_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != output);
	QSC_ASSERT(length != 0U);

	size_t i;
	size_t oft;

	if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL && input != output && length != 0U)
	{
		oft = 0U;

		while (length >= QSC_AES_BLOCK_SIZE)
		{
			aes_encrypt_block(ctx, output + oft, ctx->nonce);

			for (i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
			{
				output[oft + i] ^= input[oft + i];
			}

			qsc_intutils_be8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);

			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		if (length != 0U)
		{
			uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0U };

			aes_encrypt_block(ctx, tmpb, ctx->nonce);

			for (i = 0U; i < length; ++i)
			{
				output[oft + i] = tmpb[i] ^ input[oft + i];
			}

			qsc_intutils_be8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);
			qsc_memutils_secure_erase(tmpb, sizeof(tmpb));
		}
	}
}

void qsc_aes_ctrle_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);

	size_t i;
	size_t oft;

	if (ctx != NULL && ctx->roundkeylen != 0U && ctx->nonce != NULL && input != NULL && output != NULL && length != 0U)
	{
		oft = 0U;

		while (length >= QSC_AES_BLOCK_SIZE)
		{
			uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0U };

			aes_encrypt_block(ctx, tmpb, ctx->nonce);

			for (i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
			{
				output[oft + i] = (uint8_t)(input[oft + i] ^ tmpb[i]);
			}

			qsc_memutils_secure_erase(tmpb, sizeof(tmpb));

			qsc_intutils_le8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);

			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		if (length != 0U)
		{
			uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0U };

			aes_encrypt_block(ctx, tmpb, ctx->nonce);

			for (i = 0U; i < length; ++i)
			{
				output[oft + i] = tmpb[i] ^ input[oft + i];
			}

			qsc_intutils_le8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);
			qsc_memutils_secure_erase(tmpb, sizeof(tmpb));
		}
	}
}

/* ECB mode */

void qsc_aes_ecb_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && input != NULL && output != NULL)
	{
		aes_decrypt_block(ctx, output, input);
	}
}

void qsc_aes_ecb_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && ctx->roundkeylen != 0U && input != NULL && output != NULL)
	{
		aes_encrypt_block(ctx, output, input);
	}
}

void qsc_aes_dispose(qsc_aes_state* ctx)
{
	/* erase the ctx members */

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->roundkeys, sizeof(ctx->roundkeys));
		ctx->roundkeylen = 0U;
		ctx->rounds = 0U;
		ctx->nonce = NULL;
	}
}

#endif

/* PKCS7 padding */

void qsc_pkcs7_add_padding(uint8_t* input, size_t length)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	if (input != NULL && length != 0U && length <= QSC_AES_BLOCK_SIZE)
	{
		const size_t PADOFT = QSC_AES_BLOCK_SIZE - length;
		size_t ctr;
		uint8_t code;

		code = (uint8_t)length;
		ctr = PADOFT;

		while (ctr != QSC_AES_BLOCK_SIZE)
		{
			input[ctr] = code;
			++ctr;
		}
	}
}

size_t qsc_pkcs7_padding_length(const uint8_t* input)
{
	uint32_t bad;
	uint32_t count;
	uint32_t i;
	uint32_t mask;

	QSC_ASSERT(input != NULL);

	count = 0U;

	if (input != NULL)
	{
		count = input[QSC_AES_BLOCK_SIZE - 1U];
		bad = ((count - 1U) >> 31U) | ((QSC_AES_BLOCK_SIZE - count) >> 31U);

		/* Examine all sixteen bytes, independent of the padding value. */
		for (i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
		{
			mask = 0U - ((i - count) >> 31U);
			bad |= ((uint32_t)input[QSC_AES_BLOCK_SIZE - 1U - i] ^ count) & mask;
		}

		bad = (bad | (0U - bad)) >> 31U;
		count &= 0U - (bad ^ 1U);
	}

	return (size_t)count;
}

/* Block-cipher counter mode with Hash Based Authentication, -HBA- AEAD authenticated mode */

/* AES-HBA-256 */

#if defined(QSC_HBA_KMAC_AUTH)
static const uint8_t aes_hba256_name[HBA_NAME_SIZE] =
{
	0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x48U, 0x42U, 0x41U, 0x2DU, 0x52U, 0x48U,
	0x58U, 0x53U, 0x32U, 0x35U, 0x36U, 0x2DU, 0x4BU, 0x4DU, 0x41U, 0x43U, 0x32U, 0x35U, 0x36U
};
#else
static const uint8_t aes_hba256_name[HBA_NAME_SIZE] =
{
	0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x48U, 0x42U, 0x41U, 0x2DU, 0x52U, 0x48U,
	0x58U, 0x48U, 0x32U, 0x35U, 0x36U, 0x2DU, 0x48U, 0x4DU, 0x41U, 0x43U, 0x53U, 0x48U, 0x41U, 0x32U, 0x32U, 0x35U, 0x36U
};
#endif

static void aes_hba256_update(qsc_aes_hba256_state* ctx, const uint8_t* input, size_t length)
{
#if defined(QSC_HBA_KMAC_EXTENSION)
	qsc_kmac_update(&ctx->kstate, QSC_KECCAK_256_RATE, input, length);
#else
	qsc_hmac256_update(&ctx->kstate, input, length);
#endif
}

static void aes_hba256_finalize(qsc_aes_hba256_state* ctx, uint8_t* output)
{
	uint8_t mkey[HBA256_MKEY_SIZE] = { 0U };
	uint8_t pctr[sizeof(uint64_t)] = { 0U };
	uint8_t tmpn[HBA_NAME_SIZE] = { 0U };
	uint64_t mctr;

	/* version 1.1a add the nonce, ciphertext, and encoding sizes to the counter */
	mctr = QSC_AES_BLOCK_SIZE + ctx->counter + sizeof(uint64_t);
	/* convert to little endian bytes  */
	qsc_intutils_le64to8(pctr, mctr);
	/* encode with message size, counter, and terminating string sizes */
	aes_hba256_update(ctx, pctr, sizeof(pctr));

#if defined(QSC_HBA_KMAC_AUTH)
	/* mac the data and add the code to the end of the cipher-text output array */
	qsc_kmac_finalize(&ctx->kstate, QSC_KECCAK_256_RATE, output, QSC_HBA256_MAC_SIZE);
#else
	/* mac the data and add the code to the end of the cipher-text output array */
	qsc_hmac256_finalize(&ctx->kstate, output);
#endif

	/* generate the new mac key */
	qsc_memutils_copy(tmpn, aes_hba256_name, HBA_NAME_SIZE);
	/* add 1 + the nonce, and last input size */
	/* append the counter to the end of the mac input array */
	qsc_intutils_le64to8(tmpn, ctx->counter);

#if defined(QSC_HBA_KMAC_AUTH)
	qsc_cshake256_compute(mkey, HBA256_MKEY_SIZE, ctx->mkey, sizeof(ctx->mkey), tmpn, HBA_NAME_SIZE, ctx->cust, ctx->custlen);
	qsc_memutils_copy(ctx->mkey, mkey, HBA256_MKEY_SIZE);
	qsc_kmac_initialize(&ctx->kstate, QSC_KECCAK_256_RATE, ctx->mkey, HBA256_MKEY_SIZE, NULL, 0U);
#else
	/* extract the HKDF key from the ctx mac-key and salt */
	qsc_hkdf256_extract(mkey, HBA256_MKEY_SIZE, ctx->mkey, sizeof(ctx->mkey), tmpn, HBA_NAME_SIZE);
	/* key HKDF Expand and generate the next mac-key to ctx */
	qsc_hkdf256_expand(ctx->mkey, sizeof(ctx->mkey), mkey, HBA256_MKEY_SIZE, ctx->cust, ctx->custlen);
	qsc_hmac256_initialize(&ctx->kstate, ctx->mkey, sizeof(ctx->mkey));
#endif
	qsc_memutils_secure_erase(mkey, sizeof(mkey));
}

static void aes_hba256_genkeys(const qsc_aes_keyparams* keyparams, uint8_t* cprk, uint8_t* mack)
{
#if defined(QSC_HBA_KMAC_EXTENSION)

	qsc_keccak_state kstate = { 0U };
	uint8_t sbuf[QSC_KECCAK_256_RATE] = { 0U };

	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

	/* initialize an instance of cSHAKE */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, keyparams->key, keyparams->keylen, aes_hba256_name, HBA_NAME_SIZE, keyparams->info, keyparams->infolen);

	/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1U);
	qsc_memutils_copy(cprk, sbuf, QSC_AES256_KEY_SIZE);
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1U);
	qsc_memutils_copy(mack, sbuf, HBA256_MKEY_SIZE);
	/* clear the shake buffer and full derivation state */
	qsc_keccak_dispose(&kstate);
	qsc_memutils_secure_erase(sbuf, sizeof(sbuf));

#else

	uint8_t kbuf[QSC_AES256_KEY_SIZE + HBA256_MKEY_SIZE] = { 0U };
	uint8_t genk[QSC_HMAC_256_MAC_SIZE] = { 0U };

	/* extract the HKDF key from the user-key and salt */
	qsc_hkdf256_extract(genk, sizeof(genk), keyparams->key, keyparams->keylen, aes_hba256_name, HBA_NAME_SIZE);

	/* key HKDF Expand and generate the key buffer */
	qsc_hkdf256_expand(kbuf, sizeof(kbuf), genk, sizeof(genk), keyparams->info, keyparams->infolen);

	/* copy the cipher and mac keys from the buffer */
	qsc_memutils_copy(cprk, kbuf, QSC_AES256_KEY_SIZE);
	qsc_memutils_copy(mack, kbuf + QSC_AES256_KEY_SIZE, HBA256_MKEY_SIZE);

	/* clear the buffer */
	qsc_memutils_secure_erase(genk, sizeof(genk));
	qsc_memutils_secure_erase(kbuf, sizeof(kbuf));

#endif
}

void qsc_aes_hba256_dispose(qsc_aes_hba256_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
#if defined(QSC_HBA_KMAC_EXTENSION)
		qsc_keccak_dispose(&ctx->kstate);
#else
		qsc_hmac256_dispose(&ctx->kstate);
#endif

		qsc_aes_dispose(&ctx->cstate);
		qsc_memutils_secure_erase(ctx->cust, sizeof(ctx->cust));
		qsc_memutils_secure_erase(ctx->mkey, sizeof(ctx->mkey));

		ctx->counter = 0U;
		ctx->custlen = 0U;
		ctx->encrypt = false;
	}
}

void qsc_aes_hba256_initialize(qsc_aes_hba256_state* ctx, const qsc_aes_keyparams* keyparams, bool encrypt)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	if (ctx != NULL)
	{
		qsc_aes_hba256_dispose(ctx);
	}

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL &&
		keyparams->keylen == QSC_AES256_KEY_SIZE && keyparams->nonce != NULL &&
		keyparams->noncelen == QSC_AES_BLOCK_SIZE &&
		(keyparams->info != NULL || keyparams->infolen == 0U))
	{
		uint8_t cprk[QSC_AES256_KEY_SIZE] = { 0U };

		ctx->custlen = qsc_intutils_min(keyparams->infolen, sizeof(ctx->cust));

		if (ctx->custlen != 0U)
		{
			qsc_memutils_clear(ctx->cust, sizeof(ctx->cust));
			qsc_memutils_copy(ctx->cust, keyparams->info, ctx->custlen);
		}

		qsc_intutils_clear8(ctx->mkey, sizeof(ctx->mkey));

		/* generate the cipher and mac keys */
		aes_hba256_genkeys(keyparams, cprk, ctx->mkey);

		/* initialize the mac ctx */
#if defined(QSC_HBA_KMAC_EXTENSION)
		qsc_kmac_initialize(&ctx->kstate, QSC_KECCAK_256_RATE, ctx->mkey, HBA256_MKEY_SIZE, NULL, 0U);
#else
		qsc_hmac256_initialize(&ctx->kstate, ctx->mkey, HBA256_MKEY_SIZE);
#endif

		/* initialize the key parameters struct, info is optional */
		qsc_aes_keyparams kp = { .key = cprk, .keylen = QSC_AES256_KEY_SIZE, .nonce = keyparams->nonce, .noncelen = keyparams->noncelen };
		/* initialize the cipher ctx */
		qsc_aes_initialize(&ctx->cstate, &kp, true, qsc_aes_cipher_256);

		/* populate the hba ctx structure with mac-key and counter */
		/* the ctx counter always initializes at 1 */
		ctx->counter = 1U;
		ctx->encrypt = encrypt;
		qsc_memutils_secure_erase(cprk, sizeof(cprk));
	}
}

void qsc_aes_hba256_set_associated(qsc_aes_hba256_state* ctx, const uint8_t* data, size_t datalen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(data != NULL);

	/* process the additional data */
	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && data != NULL &&
		datalen != 0U && datalen <= UINT32_MAX)
	{
		uint8_t actr[sizeof(uint32_t)] = { 0U };

		/* add the additional data to the mac */
		aes_hba256_update(ctx, data, datalen);
		/* 1.1a encode with the ad size */
		qsc_intutils_le32to8(actr, (uint32_t)datalen);
		aes_hba256_update(ctx, actr, sizeof(actr));
	}
}

bool qsc_aes_hba256_transform(qsc_aes_hba256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	bool res;

	res = false;

	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && ctx->cstate.nonce != NULL &&
		input != NULL && output != NULL && length != 0U && length <= SIZE_MAX - QSC_HBA256_MAC_SIZE &&
		ctx->counter <= UINT64_MAX - QSC_AES_BLOCK_SIZE - sizeof(uint64_t) &&
		(uint64_t)length <= UINT64_MAX - QSC_AES_BLOCK_SIZE - sizeof(uint64_t) - ctx->counter)
	{
		/* update the processed bytes counter */
		ctx->counter += length;

		if (ctx->encrypt)
		{
			/* update the mac with the nonce */
			aes_hba256_update(ctx, ctx->cstate.nonce, QSC_AES_BLOCK_SIZE);
			/* use aes counter-mode to encrypt the array */
			qsc_aes_ctrle_transform(&ctx->cstate, output, input, length);
			/* update the mac with the cipher-text */
			aes_hba256_update(ctx, output, length);
			/* mac the cipher-text appending the code to the end of the array */
			aes_hba256_finalize(ctx, output + length);
			res = true;
		}
		else
		{
			uint8_t code[QSC_HBA256_MAC_SIZE] = { 0U };

			/* update the mac with the nonce */
			aes_hba256_update(ctx, ctx->cstate.nonce, QSC_AES_BLOCK_SIZE);
			/* update the mac with the cipher-text */
			aes_hba256_update(ctx, input, length);
			/* mac the cipher-text to the mac */
			aes_hba256_finalize(ctx, code);

			/* test the mac for equality, bypassing the transform if the mac check fails */
			if (qsc_intutils_verify(code, (input + length), QSC_HBA256_MAC_SIZE) == 0U)
			{
				/* use aes counter-mode to decrypt the array */
				qsc_aes_ctrle_transform(&ctx->cstate, output, input, length);
				res = true;
			}

			qsc_memutils_secure_erase(code, sizeof(code));
		}
	}

	return res;
}

/* AES-GCM */

/*! \def GCM_PUBLIC_EMPTY_FINALIZED
 * \brief Internal single-use marker for a completed zero-byte AES-GCM invocation.
 * \note Nonempty GCM messages already have a nonzero ciphertext-bit count.
 * The marker is stored only in the otherwise zero ctlen field, without an ABI change.
 */
#define GCM_PUBLIC_EMPTY_FINALIZED UINT64_C(0x8000000000000000)


/* Optional, compiled-for-one-ISA public-to-private acceleration. The public
 * GCM state remains byte-for-byte unchanged; QSC's scalar/ARM code remains
 * the default, and all public state transitions remain in this module. */
#if defined(QSC_AES_GCM_PUBLIC_INTRINSICS) && defined(QSC_SYSTEM_AESNI_ENABLED) && defined(QSC_SYSTEM_HAS_PCLMUL)
#    include "aes_gcm_intrinsics.h"
#    define QSC_AES_GCM_PUBLIC_INTRINSICS_ACTIVE
#endif

#if defined(QSC_SYSTEM_HAS_PCLMUL)

static void gcm_clmul(const __m128i a, const __m128i b, __m128i* c, __m128i* d)
{
    *c = _mm_clmulepi64_si128(a, b, 0x00);
    *d = _mm_clmulepi64_si128(a, b, 0x11);

    __m128i e = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i f = _mm_clmulepi64_si128(a, b, 0x01);

    f = _mm_xor_si128(f, e);
    e = f;
    f = _mm_srli_si128(f, 8);
    e = _mm_slli_si128(e, 8);
    *d = _mm_xor_si128(*d, f);
    *c = _mm_xor_si128(*c, e);
}

static void gcm_shift(__m128i* c, __m128i* d)
{
    __m128i clo = _mm_slli_epi64(*c, 1);
    __m128i dlo = _mm_slli_epi64(*d, 1);
    __m128i chi = _mm_srli_epi64(*c, 63);
    __m128i dhi = _mm_srli_epi64(*d, 63);
    __m128i xmm5 = _mm_srli_si128(chi, 8);

    chi = _mm_slli_si128(chi, 8);
    dhi = _mm_slli_si128(dhi, 8);
    *c = _mm_or_si128(clo, chi);
    *d = _mm_or_si128(_mm_or_si128(dlo, dhi), xmm5);
}

static __m128i gcm_reduce(__m128i x)
{
    __m128i a = _mm_slli_epi64(x, 63);
    __m128i b = _mm_slli_epi64(x, 62);
    __m128i c = _mm_slli_epi64(x, 57);
    __m128i d = _mm_slli_si128(_mm_xor_si128(_mm_xor_si128(a, b), c), 8);

    return _mm_xor_si128(d, x);
}

static __m128i gcm_mix(__m128i dx)
{
    __m128i e = _mm_srli_epi64(dx, 1);
    __m128i f = _mm_srli_epi64(dx, 2);
    __m128i g = _mm_srli_epi64(dx, 7);
    __m128i eh = _mm_slli_epi64(dx, 63);
    __m128i fh = _mm_slli_epi64(dx, 62);
    __m128i gh = _mm_slli_epi64(dx, 57);
    __m128i hh = _mm_srli_si128(_mm_xor_si128(_mm_xor_si128(eh, fh), gh), 8);

    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(e, f), g), hh), dx);
}

static void gcm_mult(const uint8_t* x, const uint8_t* y, uint8_t* result)
{
	__m128i a = { 0U };
	__m128i b = { 0U };
	__m128i c = { 0U };
	__m128i d = { 0U };

    for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; i++)
	{
        ((uint8_t*)&a)[i] = x[15U - i];
        ((uint8_t*)&b)[i] = y[15U - i];
    }

    gcm_clmul(a, b, &c, &d);
    gcm_shift(&c, &d);

    __m128i dx = gcm_reduce(c);
    __m128i xh = gcm_mix(dx);

    c = _mm_xor_si128(xh, d);

    for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; i++)
	{
        result[i] = ((uint8_t*)&c)[15U - i];
    }
}

#elif defined(QSC_SYSTEM_ARM_AES_ENABLED) && !defined(__AARCH64EB__)

static void gcm_mult(const uint8_t* x, const uint8_t* y, uint8_t* result)
{
	/* multiply GHASH elements using ARM PMULL and polynomial reduction */
	uint64x2_t a;
	uint64x2_t b;
	uint64x2_t low;
	uint64x2_t high;
	uint64x2_t cross;
	uint64_t h0;
	uint64_t h1;
	uint64_t l0;
	uint64_t l1;
	uint64_t carry;

	a = vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(x)));
	b = vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(y)));

	low = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(a, 0), (poly64_t)vgetq_lane_u64(b, 0)));
	high = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(a, 1), (poly64_t)vgetq_lane_u64(b, 1)));
	cross = vreinterpretq_u64_p128(vmull_p64((poly64_t)(vgetq_lane_u64(a, 0) ^ vgetq_lane_u64(a, 1)), (poly64_t)(vgetq_lane_u64(b, 0) ^ vgetq_lane_u64(b, 1))));
	cross = veorq_u64(cross, veorq_u64(low, high));

	l0 = vgetq_lane_u64(low, 0);
	l1 = vgetq_lane_u64(low, 1) ^ vgetq_lane_u64(cross, 0);
	h0 = vgetq_lane_u64(high, 0) ^ vgetq_lane_u64(cross, 1);
	h1 = vgetq_lane_u64(high, 1);
	carry = (h1 >> 63U) ^ (h1 >> 62U) ^ (h1 >> 57U);
	l0 ^= h0 ^ (h0 << 1U) ^ (h0 << 2U) ^ (h0 << 7U);
	l1 ^= h1 ^ (h1 << 1U) ^ (h1 << 2U) ^ (h1 << 7U) ^ (h0 >> 63U) ^ (h0 >> 62U) ^ (h0 >> 57U);
	l0 ^= carry ^ (carry << 1U) ^ (carry << 2U) ^ (carry << 7U);

	low = vcombine_u64(vcreate_u64(l0), vcreate_u64(l1));
	vst1q_u8(result, vrbitq_u8(vreinterpretq_u8_u64(low)));
}

#else

static void gcm_mult(const uint8_t* x, const uint8_t* y, uint8_t* result)
{
	uint8_t v[16] = { 0U };
	uint8_t z[16] = { 0U };
	uint32_t mask;

	qsc_memutils_copy(v, y, 16U);

	for (int32_t i = 0; i < 16; ++i) 
	{
		for (int32_t bit = 7; bit >= 0; --bit)
		{
			uint32_t lsbmask;

			/* constant-time conditional XOR */
			mask = (uint32_t)(0U - ((uint32_t)(x[i] >> bit) & 1U));

			for (int32_t j = 0; j < 16; ++j)
			{
				z[j] ^= (uint8_t)(v[j] & (uint8_t)mask);
			}

			/* constant-time GF reduction */
			lsbmask = (uint32_t)(0U - (uint32_t)(v[15] & 1U));

			for (int32_t j = 15; j > 0; --j)
			{
				v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
			}

			v[0U] >>= 1;
			v[0U] ^= (uint8_t)(0xE1U & (uint8_t)lsbmask);
		}
	}

	qsc_memutils_copy(result, z, 16U);
	qsc_memutils_secure_erase(v, sizeof(v));
	qsc_memutils_secure_erase(z, sizeof(z));
}

#endif

static void ghash_update(uint8_t* s, const uint8_t* block, const uint8_t* h)
{
    uint8_t tmp[QSC_AES_BLOCK_SIZE] = { 0U };

	qsc_memutils_xor(s, block, QSC_AES_BLOCK_SIZE);
    gcm_mult(s, h, tmp);
    qsc_memutils_copy(s, tmp, QSC_AES_BLOCK_SIZE);
	qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

static void gcm_increment(uint8_t* counter)
{
	/* increment the low 32 bits of a GCM counter with fixed work */
	uint32_t value;

	value = qsc_intutils_be8to32(counter + QSC_AES_BLOCK_SIZE - sizeof(uint32_t));
	qsc_intutils_be32to8(counter + QSC_AES_BLOCK_SIZE - sizeof(uint32_t), value + 1U);
}

static void gcm_public_finish_aad(uint8_t hash[16U], uint8_t buffer[16U], const uint8_t j0[16U], const uint8_t h[16U], uint64_t aadbits)
{
	/* complete the caller-provided AAD before authenticating ciphertext */
    if (aadbits != 0U)
    {
        if ((aadbits % 128U) != 0U)
        {
            ghash_update(hash, buffer, h);
        }

        qsc_memutils_copy(buffer, j0, 16U);
        gcm_increment(buffer);
    }
}

static void gcm_public_append_aad(uint8_t hash[16U], uint8_t pending[16U], const uint8_t h[16U], uint64_t* aadbits, const uint8_t* data, size_t datalen)
{
	/* append AAD bytes across multiple calls without padding until finalization */
    size_t consumed;
    size_t pending_len;
    size_t take;

    pending_len = (size_t)((*aadbits / 8U) % 16U);
    consumed = 0U;

    if (pending_len == 0U && datalen != 0U)
    {
        qsc_memutils_clear(pending, 16U);
    }

    while (consumed < datalen)
    {
        take = 16U - pending_len;

        if (take > datalen - consumed)
        {
            take = datalen - consumed;
        }

        qsc_memutils_copy(pending + pending_len, data + consumed, take);
        pending_len += take;
        consumed += take;

        if (pending_len == 16U)
        {
            ghash_update(hash, pending, h);
            pending_len = 0U;

            if (consumed < datalen)
            {
                qsc_memutils_clear(pending, 16U);
            }
        }
    }
    *aadbits += (uint64_t)datalen * 8U;
}

static bool gcm_public_length_valid(uint64_t previous_bits, size_t length)
{
	/* validate the GCM maximum block and bit-length budgets before output */
	bool result;

	result = previous_bits == 0U && (uint64_t)length <= UINT64_C(68719476704);

	return result;
}

#if defined(QSC_AES_GCM_PUBLIC_INTRINSICS_ACTIVE)

static bool gcm_public_fused(const qsc_aes_state* aes, uint8_t counter[16U], uint8_t hash[16U], uint8_t* output, const uint8_t* input, size_t length, bool decrypt)
{
	/* authenticate and transform complete public GCM blocks using private SIMD */
    qsc_gcm_intrinsics_state private_ctx = { 0U };
    bool result;

    result = qsc_gcm_intrinsics_initialize_bounded(&private_ctx, aes, length);

    if (result == true)
    {
        result = qsc_gcm_intrinsics_transform(&private_ctx, counter, hash, output, input, length, 0U, decrypt);
    }

    qsc_gcm_intrinsics_dispose(&private_ctx);

    return result;
}
#endif

/* GCM-AES-128 RFC 5288/5116 */

static void aes_gcm128_finalize(qsc_aes_gcm128_state* ctx, uint8_t* tag)
{
	uint8_t lblock[QSC_AES_BLOCK_SIZE] = { 0U };
	uint8_t tblock[QSC_AES_BLOCK_SIZE] = { 0U };

	/* encode bit-lengths of AAD and ciphertext as two big-endian 64-bit words */
	for (size_t i = 0U; i < GCM_BITS_PER_BYTE; ++i)
	{
		lblock[i] = (uint8_t)(ctx->aadlen >> (56U - GCM_BITS_PER_BYTE * i));
		lblock[GCM_BITS_PER_BYTE + i] = (uint8_t)(ctx->ctlen >> (56U - GCM_BITS_PER_BYTE * i));
	}

	ghash_update(ctx->S, lblock, ctx->H);
	qsc_aes_ecb_encrypt_block(&ctx->cstate, tblock, ctx->J0);

	for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
	{
		tag[i] = tblock[i] ^ ctx->S[i];
	}

	qsc_memutils_secure_erase(lblock, sizeof(lblock));
	qsc_memutils_secure_erase(tblock, sizeof(tblock));
}

bool qsc_aes_gcm128_decrypt(qsc_aes_gcm128_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	
	bool res;

	res = false;

	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && input != NULL && output != NULL &&
        length >= QSC_GCM128_MAC_SIZE &&
        gcm_public_length_valid(ctx->ctlen, length - QSC_GCM128_MAC_SIZE) == true)
	{
		uint8_t ctag[QSC_AES_BLOCK_SIZE] = { 0U };
		uint8_t kstream[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t i;
		size_t clen;

		clen = length - QSC_GCM128_MAC_SIZE;
		gcm_public_finish_aad(ctx->S, ctx->C, ctx->J0, ctx->H, ctx->aadlen);

		/* process full blocks: authenticate ciphertext then decrypt */
		i = 0U;

#if defined(QSC_AES_GCM_PUBLIC_INTRINSICS_ACTIVE)
        if (clen >= 4096U)
        {
            size_t bulk;

            bulk = clen & ~(size_t)15U;
            if (gcm_public_fused(&ctx->cstate, ctx->C, ctx->S, output, input, bulk, true) == true)
            {
                i = bulk;
            }
        }
#endif
        for (; i + QSC_AES_BLOCK_SIZE <= clen; i += QSC_AES_BLOCK_SIZE)
		{
			ghash_update(ctx->S, input + i, ctx->H);
			qsc_aes_ecb_encrypt_block(&ctx->cstate, kstream, ctx->C);

			for (size_t j = 0U; j < QSC_AES_BLOCK_SIZE; ++j)
			{
				output[i + j] = input[i + j] ^ kstream[j];
			}

			gcm_increment(ctx->C);
		}

		/* process any remaining partial block */
		if (i < clen)
		{
			uint8_t block[QSC_AES_BLOCK_SIZE] = { 0U };
			size_t rem;

			rem = clen - i;
			qsc_memutils_copy(block, input + i, rem);
			ghash_update(ctx->S, block, ctx->H);
			qsc_aes_ecb_encrypt_block(&ctx->cstate, kstream, ctx->C);

			for (size_t j = 0U; j < rem; j++)
			{
				output[i + j] = block[j] ^ kstream[j];
			}

			gcm_increment(ctx->C);
		}

		ctx->ctlen += ((uint64_t)clen) * GCM_BITS_PER_BYTE;

		aes_gcm128_finalize(ctx, ctag);
		res = (qsc_intutils_verify(ctag, input + clen, QSC_GCM128_MAC_SIZE) == 0U);

		if (res == false && clen != 0U)
		{
			qsc_memutils_secure_erase(output, clen);
		}
		qsc_memutils_secure_erase(ctag, sizeof(ctag));
		qsc_memutils_secure_erase(kstream, sizeof(kstream));

		if (clen == 0U)
		{
			ctx->ctlen = GCM_PUBLIC_EMPTY_FINALIZED;
		}
	}

	return res;
}

void qsc_aes_gcm128_dispose(qsc_aes_gcm128_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_aes_dispose(&ctx->cstate);
		qsc_memutils_secure_erase(ctx->C, sizeof(ctx->C));
		qsc_memutils_secure_erase(ctx->H, sizeof(ctx->H));
		qsc_memutils_secure_erase(ctx->J0, sizeof(ctx->J0));
		qsc_memutils_secure_erase(ctx->S, sizeof(ctx->S));
		ctx->aadlen = 0U;
		ctx->ctlen = 0U;
		ctx->encrypt = false;
	}
}

void qsc_aes_gcm128_encrypt(qsc_aes_gcm128_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	
	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && output != NULL && input != NULL &&
        (ctx->ctlen == 0U && gcm_public_length_valid(ctx->ctlen, length)) == true &&
        length <= SIZE_MAX - QSC_GCM128_MAC_SIZE)
	{
		uint8_t keystream[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t i;
		gcm_public_finish_aad(ctx->S, ctx->C, ctx->J0, ctx->H, ctx->aadlen);

		/* process full blocks: encrypt then authenticate */
		i = 0U;
#if defined(QSC_AES_GCM_PUBLIC_INTRINSICS_ACTIVE)
        if (length >= 1024U)
        {
            size_t bulk;

            bulk = length & ~(size_t)15U;

            if (gcm_public_fused(&ctx->cstate, ctx->C, ctx->S, output, input, bulk, false) == true)
            {
                i = bulk;
            }
        }
#endif
        for (; i + QSC_AES_BLOCK_SIZE <= length; i += QSC_AES_BLOCK_SIZE)
		{
			qsc_aes_ecb_encrypt_block(&ctx->cstate, keystream, ctx->C);

			for (size_t j = 0U; j < QSC_AES_BLOCK_SIZE; ++j)
			{
				output[i + j] = input[i + j] ^ keystream[j];
			}

			ghash_update(ctx->S, output + i, ctx->H);
			gcm_increment(ctx->C);
		}

		/* process any remaining partial block */
		if (i < length)
		{
			uint8_t block[QSC_AES_BLOCK_SIZE] = { 0U };
			size_t rem;

			rem = length - i;
			qsc_memutils_secure_erase(keystream, QSC_AES_BLOCK_SIZE);
			qsc_aes_ecb_encrypt_block(&ctx->cstate, keystream, ctx->C);

			for (size_t j = 0U; j < rem; ++j)
			{
				block[j] = input[i + j] ^ keystream[j];
				output[i + j] = block[j];
			}

			ghash_update(ctx->S, block, ctx->H);
			gcm_increment(ctx->C);
		}

		ctx->ctlen += ((uint64_t)length) * GCM_BITS_PER_BYTE;

		aes_gcm128_finalize(ctx, output + length);
		qsc_memutils_secure_erase(keystream, sizeof(keystream));

		if (length == 0U)
		{
			ctx->ctlen = GCM_PUBLIC_EMPTY_FINALIZED;
		}
	}
}

void qsc_aes_gcm128_initialize(qsc_aes_gcm128_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	if (ctx != NULL)
	{
		qsc_aes_gcm128_dispose(ctx);
	}

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL &&
		keyparams->keylen == QSC_AES128_KEY_SIZE && keyparams->nonce != NULL &&
		keyparams->noncelen >= 1U && keyparams->noncelen <= QSC_GCM_MAX_NONCE_SIZE)
	{
		uint8_t zero[QSC_AES_BLOCK_SIZE] = { 0U };

		/* initialize AES-128 - the only difference from GCM-256 */
		ctx->encrypt = encryption;
		qsc_aes_initialize(&ctx->cstate, keyparams, true, qsc_aes_cipher_128);

		/* compute hash subkey: H = AES(K, 0^128) */
		qsc_aes_ecb_encrypt_block(&ctx->cstate, ctx->H, zero);

		/* derive pre-counter block J0 from the nonce */
		if (keyparams->noncelen == 12U)
		{
			/* standard 96-bit nonce: append 0x00000001 */
			qsc_memutils_copy(ctx->J0, keyparams->nonce, keyparams->noncelen);
			qsc_memutils_clear(ctx->J0 + keyparams->noncelen, QSC_AES_BLOCK_SIZE - keyparams->noncelen);
			ctx->J0[QSC_AES_BLOCK_SIZE - 1U] = 0x01U;
		}
		else
		{
			/* non-standard nonce length: derive J0 via GHASH */
			uint64_t ivbits;
			size_t   numblk;
			size_t   buflen;
			uint8_t  ivbuf[3U * QSC_AES_BLOCK_SIZE] = { 0U };

			if (keyparams->noncelen <= QSC_GCM_MAX_NONCE_SIZE)
			{
				numblk = ((keyparams->noncelen + QSC_AES_BLOCK_SIZE - 1U) / QSC_AES_BLOCK_SIZE);
				buflen = (numblk + 1U) * QSC_AES_BLOCK_SIZE;
				qsc_memutils_copy(ivbuf, keyparams->nonce, keyparams->noncelen);

				ivbits = keyparams->noncelen * GCM_BITS_PER_BYTE;

				for (size_t i = 0U; i < GCM_BITS_PER_BYTE; ++i)
				{
					ivbuf[buflen - GCM_BITS_PER_BYTE + i] = (uint8_t)(ivbits >> (56U - GCM_BITS_PER_BYTE * i));
				}

				qsc_memutils_clear(ctx->J0, QSC_AES_BLOCK_SIZE);

				for (size_t i = 0U; i < buflen; i += QSC_AES_BLOCK_SIZE)
				{
					ghash_update(ctx->J0, ivbuf + i, ctx->H);
				}

				qsc_memutils_clear(ivbuf, sizeof(ivbuf));
			}
		}

		qsc_memutils_secure_erase(ctx->S, QSC_AES_BLOCK_SIZE);
		ctx->aadlen = 0U;
		ctx->ctlen = 0U;

		/* C = inc32(J0) - first counter block for GCTR */
		qsc_memutils_copy(ctx->C, ctx->J0, QSC_AES_BLOCK_SIZE);
		gcm_increment(ctx->C);
	}
}

void qsc_aes_gcm128_set_associated(qsc_aes_gcm128_state* ctx, const uint8_t* data, size_t datalen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(data != NULL || datalen == 0U);

    if (ctx != NULL && ctx->cstate.roundkeylen != 0U && (data != NULL || datalen == 0U) &&
        datalen <= QSC_GCM_MAXAAD_SIZE && ctx->ctlen == 0U &&
        (uint64_t)datalen <= (UINT64_MAX - ctx->aadlen) / 8U)
    {
        if (datalen != 0U)
        {
            gcm_public_append_aad(ctx->S, ctx->C, ctx->H, &ctx->aadlen, data, datalen);
        }
    }
}
bool qsc_aes_gcm128_transform(qsc_aes_gcm128_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	
	bool res;

	res = false;

	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && input != NULL && output != NULL &&
        ctx->ctlen == 0U && gcm_public_length_valid(ctx->ctlen, length) == true)
	{
		if (ctx->encrypt == true)
		{
			if (length <= SIZE_MAX - QSC_GCM128_MAC_SIZE)
			{
				qsc_aes_gcm128_encrypt(ctx, output, input, length);
				res = true;
			}
		}
		else
		{
			res = length <= SIZE_MAX - QSC_GCM128_MAC_SIZE &&
                qsc_aes_gcm128_decrypt(ctx, output, input, length + QSC_GCM128_MAC_SIZE);
		}
	}

	return res;
}

static void aes_gcm256_finalize(qsc_aes_gcm256_state* ctx, uint8_t* tag)
{
    uint8_t lblock[QSC_AES_BLOCK_SIZE] = { 0U };
	uint8_t tblock[QSC_AES_BLOCK_SIZE] = { 0U };

    for (size_t i = 0U; i < GCM_BITS_PER_BYTE; ++i)
	{
        lblock[i] = (uint8_t)(ctx->aadlen >> (56U - GCM_BITS_PER_BYTE * i));
        lblock[GCM_BITS_PER_BYTE + i] = (uint8_t)(ctx->ctlen  >> (56U - GCM_BITS_PER_BYTE * i));
    }

    ghash_update(ctx->S, lblock, ctx->H);
    qsc_aes_ecb_encrypt_block(&ctx->cstate, tblock, ctx->J0);

    for (size_t i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
	{
        tag[i] = tblock[i] ^ ctx->S[i];
    }

	qsc_memutils_secure_erase(lblock, sizeof(lblock));
	qsc_memutils_secure_erase(tblock, sizeof(tblock));
}

bool qsc_aes_gcm256_decrypt(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	
	bool res;

	res = false;

	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && input != NULL && output != NULL &&
        length >= QSC_GCM256_MAC_SIZE &&
        gcm_public_length_valid(ctx->ctlen, length - QSC_GCM256_MAC_SIZE) == true)
	{
		uint8_t ctag[QSC_AES_BLOCK_SIZE] = { 0U };
		uint8_t kstream[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t i;
		size_t clen;

		clen = length - QSC_GCM256_MAC_SIZE;
		gcm_public_finish_aad(ctx->S, ctx->C, ctx->J0, ctx->H, ctx->aadlen);

		i = 0U;
#if defined(QSC_AES_GCM_PUBLIC_INTRINSICS_ACTIVE)
        if (clen >= 4096U)
        {
            size_t bulk;

            bulk = clen & ~(size_t)15U;
            if (gcm_public_fused(&ctx->cstate, ctx->C, ctx->S, output, input, bulk, true) == true)
            {
                i = bulk;
            }
        }
#endif
        for (; i + QSC_AES_BLOCK_SIZE <= clen; i += QSC_AES_BLOCK_SIZE)
		{
			ghash_update(ctx->S, input + i, ctx->H);
			qsc_aes_ecb_encrypt_block(&ctx->cstate, kstream, ctx->C);

			for (size_t j = 0U; j < QSC_AES_BLOCK_SIZE; ++j)
			{
				output[i + j] = input[i + j] ^ kstream[j];
			}

			gcm_increment(ctx->C);
		}

		if (i < clen)
		{
			uint8_t block[QSC_AES_BLOCK_SIZE] = { 0U };
			size_t rem;

			rem = clen - i;
			qsc_memutils_copy(block, input + i, rem);
			ghash_update(ctx->S, block, ctx->H);
			qsc_aes_ecb_encrypt_block(&ctx->cstate, kstream, ctx->C);

			for (size_t j = 0U; j < rem; j++)
			{
				output[i + j] = block[j] ^ kstream[j];
			}

			gcm_increment(ctx->C);
		}

		ctx->ctlen += ((uint64_t)clen) * GCM_BITS_PER_BYTE;

		aes_gcm256_finalize(ctx, ctag);
		res = (qsc_intutils_verify(ctag, input + clen, QSC_GCM256_MAC_SIZE) == 0U);

		if (res == false && clen != 0U)
		{
			qsc_memutils_secure_erase(output, clen);
		}

		qsc_memutils_secure_erase(ctag, sizeof(ctag));
		qsc_memutils_secure_erase(kstream, sizeof(kstream));

		if (clen == 0U)
		{
			ctx->ctlen = GCM_PUBLIC_EMPTY_FINALIZED;
		}
	}

    return res;
}

void qsc_aes_gcm256_dispose(qsc_aes_gcm256_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_aes_dispose(&ctx->cstate);
		qsc_memutils_secure_erase(ctx->C, sizeof(ctx->C));
		qsc_memutils_secure_erase(ctx->H, sizeof(ctx->H));
		qsc_memutils_secure_erase(ctx->J0, sizeof(ctx->J0));
		qsc_memutils_secure_erase(ctx->S, sizeof(ctx->S));
		ctx->aadlen = 0U;
		ctx->ctlen = 0U;
		ctx->encrypt = false;
	}
}

void qsc_aes_gcm256_encrypt(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	
	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && output != NULL && input != NULL &&
        (ctx->ctlen == 0U && gcm_public_length_valid(ctx->ctlen, length)) == true &&
        length <= SIZE_MAX - QSC_GCM256_MAC_SIZE)
	{
		uint8_t keystream[QSC_AES_BLOCK_SIZE] = { 0U };
		size_t i;
		gcm_public_finish_aad(ctx->S, ctx->C, ctx->J0, ctx->H, ctx->aadlen);

		i = 0U;
#if defined(QSC_AES_GCM_PUBLIC_INTRINSICS_ACTIVE)
        if (length >= 1024U)
        {
            size_t bulk;

            bulk = length & ~(size_t)15U;

            if (gcm_public_fused(&ctx->cstate, ctx->C, ctx->S, output, input, bulk, false) == true)
            {
                i = bulk;
            }
        }
#endif
        for (; i + QSC_AES_BLOCK_SIZE <= length; i += QSC_AES_BLOCK_SIZE)
		{
			qsc_aes_ecb_encrypt_block(&ctx->cstate, keystream, ctx->C);

			for (size_t j = 0U; j < QSC_AES_BLOCK_SIZE; ++j)
			{
				output[i + j] = input[i + j] ^ keystream[j];
			}

			ghash_update(ctx->S, output + i, ctx->H);
			gcm_increment(ctx->C);
		}

		if (i < length)
		{
			uint8_t block[QSC_AES_BLOCK_SIZE] = { 0U };
			size_t rem;

			rem = length - i;
			qsc_memutils_secure_erase(keystream, QSC_AES_BLOCK_SIZE);
			qsc_aes_ecb_encrypt_block(&ctx->cstate, keystream, ctx->C);

			for (size_t j = 0U; j < rem; ++j)
			{
				block[j] = input[i + j] ^ keystream[j];
				output[i + j] = block[j];
			}

			ghash_update(ctx->S, block, ctx->H);
			gcm_increment(ctx->C);
		}

		ctx->ctlen += ((uint64_t)length) * GCM_BITS_PER_BYTE;

		aes_gcm256_finalize(ctx, output + length);
		qsc_memutils_secure_erase(keystream, sizeof(keystream));

		if (length == 0U)
		{
			ctx->ctlen = GCM_PUBLIC_EMPTY_FINALIZED;
		}
	}
}

void qsc_aes_gcm256_initialize(qsc_aes_gcm256_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	if (ctx != NULL)
	{
		qsc_aes_gcm256_dispose(ctx);
	}

	if (ctx != NULL && keyparams != NULL && keyparams->key != NULL &&
		keyparams->keylen == QSC_AES256_KEY_SIZE && keyparams->nonce != NULL &&
		keyparams->noncelen >= 1U && keyparams->noncelen <= QSC_GCM_MAX_NONCE_SIZE)
	{
		uint8_t zero[QSC_AES_BLOCK_SIZE] = { 0U };

		/* initialize AES */
		ctx->encrypt = encryption;
		qsc_aes_initialize(&ctx->cstate, keyparams, true, qsc_aes_cipher_256);

		/* compute hash subkey: H = AES(K, 0U^128) */
		qsc_aes_ecb_encrypt_block(&ctx->cstate, ctx->H, zero);

		/* compute pre-counter block J0 based on IV length */
		if (keyparams->noncelen == 12U)
		{
			qsc_memutils_copy(ctx->J0, keyparams->nonce, keyparams->noncelen);
			qsc_memutils_clear(ctx->J0 + keyparams->noncelen, QSC_AES_BLOCK_SIZE - keyparams->noncelen);
			ctx->J0[QSC_AES_BLOCK_SIZE - 1U] = 0x01U;
		}
		else
		{
			uint64_t ivbits;
			size_t numblk;
			size_t buflen;
			uint8_t ivbuf[3U * QSC_AES_BLOCK_SIZE] = { 0U };

			if (keyparams->noncelen <= QSC_GCM_MAX_NONCE_SIZE)
			{
				/* initialize the buffer */
				numblk = ((keyparams->noncelen + QSC_AES_BLOCK_SIZE - 1U) / QSC_AES_BLOCK_SIZE);
				buflen = (numblk + 1U) * QSC_AES_BLOCK_SIZE;
				qsc_memutils_copy(ivbuf, keyparams->nonce, keyparams->noncelen);

				ivbits = keyparams->noncelen * GCM_BITS_PER_BYTE;

				for (size_t i = 0U; i < GCM_BITS_PER_BYTE; ++i)
				{
					ivbuf[buflen - GCM_BITS_PER_BYTE + i] = (uint8_t)(ivbits >> (56U - GCM_BITS_PER_BYTE * i));
				}

				qsc_memutils_secure_erase(ctx->J0, QSC_AES_BLOCK_SIZE);

				for (size_t i = 0U; i < buflen; i += QSC_AES_BLOCK_SIZE)
				{
					ghash_update(ctx->J0, ivbuf + i, ctx->H);
				}

				qsc_memutils_secure_erase(ivbuf, sizeof(ivbuf));
			}
		}

		qsc_memutils_secure_erase(ctx->S, QSC_AES_BLOCK_SIZE);
		ctx->aadlen = 0U;
		ctx->ctlen = 0U;

		/* set counter = inc(J0) */
		qsc_memutils_copy(ctx->C, ctx->J0, QSC_AES_BLOCK_SIZE);
		gcm_increment(ctx->C);
	}
}

void qsc_aes_gcm256_set_associated(qsc_aes_gcm256_state* ctx, const uint8_t* data, size_t datalen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(data != NULL || datalen == 0U);

    if (ctx != NULL && ctx->cstate.roundkeylen != 0U && (data != NULL || datalen == 0U) &&
        datalen <= QSC_GCM_MAXAAD_SIZE && ctx->ctlen == 0U &&
        (uint64_t)datalen <= (UINT64_MAX - ctx->aadlen) / 8U)
    {
        if (datalen != 0U)
        {
            gcm_public_append_aad(ctx->S, ctx->C, ctx->H, &ctx->aadlen, data, datalen);
        }
    }
}
bool qsc_aes_gcm256_transform(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	
	bool res;

	res = false;

	if (ctx != NULL && ctx->cstate.roundkeylen != 0U && input != NULL && output != NULL &&
        ctx->ctlen == 0U && gcm_public_length_valid(ctx->ctlen, length) == true)
	{
		if (ctx->encrypt == true)
		{
			if (length <= SIZE_MAX - QSC_GCM256_MAC_SIZE)
			{
				qsc_aes_gcm256_encrypt(ctx, output, input, length);
				res = true;
			}
		}
		else
		{
			res = length <= SIZE_MAX - QSC_GCM256_MAC_SIZE &&
                qsc_aes_gcm256_decrypt(ctx, output, input, length + QSC_GCM256_MAC_SIZE);
		}
	}

	return res;
}
