#include "aes.h"
#include "intutils.h"
#include "memutils.h"

/*!
\def AES128_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-128.
*/
#define AES128_ROUND_COUNT 10ULL

/*!
\def AES256_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-256.
*/
#define AES256_ROUND_COUNT 14ULL

/*!
\def ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
#if defined(QSC_SYSTEM_AESNI_ENABLED)
#	define ROUNDKEY_ELEMENT_SIZE 16
#else
#	define ROUNDKEY_ELEMENT_SIZE 4
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
#define AES128_ROUNDKEY_SIZE ((AES128_ROUND_COUNT + 1) * (QSC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def AES256_ROUNDKEY_SIZE
* The size of the AES-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_aes_state struct.
*/
#define AES256_ROUNDKEY_SIZE ((AES256_ROUND_COUNT + 1) * (QSC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/* AVX512 */

/*!
\def AVX512_BLOCK_SIZE
* The size byte size of an AVX512 block
*/
#define AVX512_BLOCK_SIZE (4 * QSC_AES_BLOCK_SIZE)

/* HBA */

/*!
\def HBA_INFO_SIZE
* The HBA version information array length.
*/
#define HBA_INFO_SIZE 16ULL

/*!
\def HBA256_MKEY_SIZE
* The size of the hba-256 mac key array
*/
#define HBA256_MKEY_SIZE 32ULL

/*!
\def HBA512_MKEY_SIZE
* The size of the hba-512 mac key array
*/
#define HBA512_MKEY_SIZE 64ULL

/*!
\def HBA_NAME_SIZE
* The HBA implementation specific name array length.
*/
#if defined(QSC_HBA_KMAC_EXTENSION)
#	define HBA_NAME_SIZE 29ULL
#else
#	define HBA_NAME_SIZE 33ULL
#endif

/* aes-ni and table-based fallback functions */

#if defined(QSC_SYSTEM_AESNI_ENABLED)

static void aes_beincrement_x128(__m128i* counter)
{
	__m128i tmp;
	qsc_intutils_reverse_bytes_x128(counter, &tmp);
	tmp = _mm_add_epi64(tmp, _mm_set_epi64x(0, 1));
	qsc_intutils_reverse_bytes_x128(&tmp, counter);
}

static void aes_decrypt_block(const qsc_aes_state* ctx, __m128i* output, const __m128i* input)
{
	const size_t RNDCNT = ctx->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
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
	const size_t RNDCNT = ctx->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
	*output = _mm_xor_si128(*input, ctx->roundkeys[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm_aesenc_si128(*output, ctx->roundkeys[keyctr]);
	}

	++keyctr;
	*output = _mm_aesenclast_si128(*output, ctx->roundkeys[keyctr]);
}

#if defined(QSC_SYSTEM_HAS_AVX512)
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
	const size_t RNDCNT = ctx->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
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
	const size_t RNDCNT = ctx->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
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
	key[index] = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(key[index - 1], 0x0), 0xAA);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	key[index] = _mm_xor_si128(pkb, key[index]);
}

static void aes_standard_expand(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams)
{
	size_t kwords;

	/* key in 32-bit words */
	kwords = keyparams->keylen / 4;

	if (kwords == 8)
	{
		ctx->roundkeys[0] = _mm_loadu_si128((const __m128i*)keyparams->key);
		ctx->roundkeys[1] = _mm_loadu_si128((const __m128i*)(keyparams->key + 16));
		ctx->roundkeys[2] = _mm_aeskeygenassist_si128(ctx->roundkeys[1], 0x01);
		aes_expand_rot(ctx->roundkeys, 2, 2);
		aes_expand_sub(ctx->roundkeys, 3, 2);
		ctx->roundkeys[4] = _mm_aeskeygenassist_si128(ctx->roundkeys[3], 0x02);
		aes_expand_rot(ctx->roundkeys, 4, 2);
		aes_expand_sub(ctx->roundkeys, 5, 2);
		ctx->roundkeys[6] = _mm_aeskeygenassist_si128(ctx->roundkeys[5], 0x04);
		aes_expand_rot(ctx->roundkeys, 6, 2);
		aes_expand_sub(ctx->roundkeys, 7, 2);
		ctx->roundkeys[8] = _mm_aeskeygenassist_si128(ctx->roundkeys[7], 0x08);
		aes_expand_rot(ctx->roundkeys, 8, 2);
		aes_expand_sub(ctx->roundkeys, 9, 2);
		ctx->roundkeys[10] = _mm_aeskeygenassist_si128(ctx->roundkeys[9], 0x10);
		aes_expand_rot(ctx->roundkeys, 10, 2);
		aes_expand_sub(ctx->roundkeys, 11, 2);
		ctx->roundkeys[12] = _mm_aeskeygenassist_si128(ctx->roundkeys[11], 0x20);
		aes_expand_rot(ctx->roundkeys, 12, 2);
		aes_expand_sub(ctx->roundkeys, 13, 2);
		ctx->roundkeys[14] = _mm_aeskeygenassist_si128(ctx->roundkeys[13], 0x40);
		aes_expand_rot(ctx->roundkeys, 14, 2);
	}
	else
	{
		ctx->roundkeys[0] = _mm_loadu_si128((const __m128i*)keyparams->key);
		ctx->roundkeys[1] = _mm_aeskeygenassist_si128(ctx->roundkeys[0], 0x01);
		aes_expand_rot(ctx->roundkeys, 1, 1);
		ctx->roundkeys[2] = _mm_aeskeygenassist_si128(ctx->roundkeys[1], 0x02);
		aes_expand_rot(ctx->roundkeys, 2, 1);
		ctx->roundkeys[3] = _mm_aeskeygenassist_si128(ctx->roundkeys[2], 0x04);
		aes_expand_rot(ctx->roundkeys, 3, 1);
		ctx->roundkeys[4] = _mm_aeskeygenassist_si128(ctx->roundkeys[3], 0x08);
		aes_expand_rot(ctx->roundkeys, 4, 1);
		ctx->roundkeys[5] = _mm_aeskeygenassist_si128(ctx->roundkeys[4], 0x10);
		aes_expand_rot(ctx->roundkeys, 5, 1);
		ctx->roundkeys[6] = _mm_aeskeygenassist_si128(ctx->roundkeys[5], 0x20);
		aes_expand_rot(ctx->roundkeys, 6, 1);
		ctx->roundkeys[7] = _mm_aeskeygenassist_si128(ctx->roundkeys[6], 0x40);
		aes_expand_rot(ctx->roundkeys, 7, 1);
		ctx->roundkeys[8] = _mm_aeskeygenassist_si128(ctx->roundkeys[7], 0x80);
		aes_expand_rot(ctx->roundkeys, 8, 1);
		ctx->roundkeys[9] = _mm_aeskeygenassist_si128(ctx->roundkeys[8], 0x1B);
		aes_expand_rot(ctx->roundkeys, 9, 1);
		ctx->roundkeys[10] = _mm_aeskeygenassist_si128(ctx->roundkeys[9], 0x36);
		aes_expand_rot(ctx->roundkeys, 10, 1);
	}
}

void qsc_aes_initialize(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption, qsc_aes_cipher_type ctype)
{
	assert(ctx != NULL);
	assert(keyparams != NULL);

	if (keyparams->nonce != NULL)
	{
		ctx->nonce = keyparams->nonce;
	}

	qsc_memutils_clear((uint8_t*)ctx->roundkeys, sizeof(ctx->roundkeys));

	if (ctype == qsc_aes_cipher_256)
	{
		ctx->roundkeylen = AES256_ROUNDKEY_SIZE;
		ctx->rounds = 14;
		aes_standard_expand(ctx, keyparams);
	}
	else if (ctype == qsc_aes_cipher_128)
	{
		ctx->roundkeylen = AES128_ROUNDKEY_SIZE;
		ctx->rounds = 10;
		aes_standard_expand(ctx, keyparams);
	}
	else
	{
		ctx->roundkeylen = 0;
	}

	/* inverse cipher */
	if (encryption == false && ctx->roundkeylen != 0)
	{
		__m128i tmp;
		size_t i;
		size_t j;

		tmp = ctx->roundkeys[0];
		ctx->roundkeys[0] = ctx->roundkeys[ctx->roundkeylen - 1];
		ctx->roundkeys[ctx->roundkeylen - 1] = tmp;

		for (i = 1, j = ctx->roundkeylen - 2; i < j; ++i, --j)
		{
			tmp = _mm_aesimc_si128(ctx->roundkeys[i]);
			ctx->roundkeys[i] = _mm_aesimc_si128(ctx->roundkeys[j]);
			ctx->roundkeys[j] = tmp;
		}

		ctx->roundkeys[i] = _mm_aesimc_si128(ctx->roundkeys[i]);
	}

#if defined(QSC_SYSTEM_HAS_AVX512)
	size_t i;

	qsc_memutils_clear((uint8_t*)ctx->roundkeysw, sizeof(ctx->roundkeysw));

	for (i = 0; i < ctx->rounds + 1; ++i)
	{
		aes_load128to512(&ctx->roundkeys[i], &ctx->roundkeysw[i]);
	}
#endif

}

/* cbc mode */

void qsc_aes_cbc_decrypt(qsc_aes_state* ctx, uint8_t* output, size_t *outputlen, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i ivt;
	__m128i otp;
	size_t len;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length > AVX512_BLOCK_SIZE)
	{
		__m512i inpw;
		__m512i ivtw;
		__m512i otpw;
		uint8_t ivtb[AVX512_BLOCK_SIZE] = { 0 };

		/* assemble the first block in the chain */
		qsc_memutils_copy(ivtb, ctx->nonce, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(ivtb + QSC_AES_BLOCK_SIZE), input, 3 * QSC_AES_BLOCK_SIZE);
		ivtw = _mm512_loadu_si512((const __m512i*)ivtb);

		/* process the first block */
		inpw = _mm512_loadu_si512((const __m512i*)input);
		aes_decrypt_blockw(ctx, &otpw, &inpw);
		otpw = _mm512_xor_si512(otpw, ivtw);

		/* store to output */
		_mm512_storeu_si512((__m512i*)output, otpw);
		length -= AVX512_BLOCK_SIZE;
		oft += AVX512_BLOCK_SIZE;

		/* process remaining blocks */
		while (length > AVX512_BLOCK_SIZE)
		{
			qsc_memutils_copy(ivtb, (uint8_t*)(input + (oft - QSC_AES_BLOCK_SIZE)), AVX512_BLOCK_SIZE);
			ivtw = _mm512_loadu_si512((const __m512i*)ivtb);
			inpw = _mm512_loadu_si512((const __m512i*)((uint8_t*)(input + oft)));

			aes_decrypt_blockw(ctx, &otpw, &inpw);
			otpw = _mm512_xor_si512(otpw, ivtw);

			_mm512_storeu_si512((__m512i*)(uint8_t*)(output + oft), otpw);
			length -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;
		}

		qsc_memutils_copy(ctx->nonce, (uint8_t*)(input + (oft - QSC_AES_BLOCK_SIZE)), QSC_AES_BLOCK_SIZE);
	}

#endif

	if (length > QSC_AES_BLOCK_SIZE)
	{
		ivt = _mm_loadu_si128((const __m128i*)ctx->nonce);
		inp = _mm_setzero_si128();

		while (length > QSC_AES_BLOCK_SIZE)
		{
			inp = _mm_loadu_si128((const __m128i*)(input + oft));

			aes_decrypt_block(ctx, &otp, &inp);
			otp = _mm_xor_si128(otp, ivt);

			_mm_storeu_si128(&ivt, inp);
			_mm_storeu_si128((__m128i*)(output + oft), otp);

			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		_mm_storeu_si128((__m128i*)ctx->nonce, inp);
	}

	uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };
	qsc_aes_cbc_decrypt_block(ctx, tmpb, (input + oft));
	len = qsc_pkcs7_padding_length(tmpb);
	qsc_memutils_copy((output + oft), tmpb, QSC_AES_BLOCK_SIZE - len);
	*outputlen = oft + (QSC_AES_BLOCK_SIZE - len);
}

void qsc_aes_cbc_encrypt(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i ivt;
	__m128i otp;
	size_t oft;

	oft = 0;

	while (length > QSC_AES_BLOCK_SIZE)
	{
		inp = _mm_loadu_si128((const __m128i*)(input + oft));
		ivt = _mm_loadu_si128((const __m128i*)ctx->nonce);

		ivt = _mm_xor_si128(ivt, inp);
		aes_encrypt_block(ctx, &otp, &ivt);

		_mm_storeu_si128((__m128i*)ctx->nonce, otp);
		_mm_storeu_si128((__m128i*)(output + oft), otp);

		length -= QSC_AES_BLOCK_SIZE;
		oft += QSC_AES_BLOCK_SIZE;
	}

	if (length != 0)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };
		qsc_memutils_copy(tmpb, (input + oft), length);

		if (length < QSC_AES_BLOCK_SIZE)
		{
			qsc_pkcs7_add_padding(tmpb, QSC_AES_BLOCK_SIZE - length);
		}

		qsc_aes_cbc_encrypt_block(ctx, (output + oft), tmpb);
	}
}

void qsc_aes_cbc_decrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

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

void qsc_aes_cbc_encrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

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

/* ctr mode */


void qsc_aes_ctrbe_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i nce;
	__m128i otp;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= AVX512_BLOCK_SIZE)
	{
		__m512i inpw;
		__m512i ncew;
		__m512i otpw;
		__m512i tmpn;
		uint8_t nceb[AVX512_BLOCK_SIZE];

		/* load the ctr nonce block */
		qsc_memutils_copy(nceb, ctx->nonce, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 16), ctx->nonce, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 32), ctx->nonce, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 48), ctx->nonce, QSC_AES_BLOCK_SIZE);

		ncew = _mm512_loadu_si512((const __m512i*)nceb);

		qsc_intutils_reverse_bytes_x512(&ncew, &tmpn);
		tmpn = _mm512_add_epi64(tmpn, _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0));
		qsc_intutils_reverse_bytes_x512(&tmpn, &ncew);

		while (length >= AVX512_BLOCK_SIZE)
		{
			/* encrypt the nonce block */
			aes_encrypt_blockw(ctx, &otpw, &ncew);
			inpw = _mm512_loadu_si512((const __m512i*)((uint8_t*)input + oft));
			/* xor encrypted nonce with the ctx */
			otpw = _mm512_xor_si512(otpw, inpw);
			/* store in output */
			_mm512_storeu_si512((__m512i*)((uint8_t*)output + oft), otpw);

			length -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;

			/* increment the low 64 bits across 4 blocks */
			aes_beincrement_x512(&ncew);
		}

		/* store the nonce */
		_mm512_storeu_si512((__m512i*)nceb, ncew);
		qsc_memutils_copy(ctx->nonce, nceb, QSC_AES_BLOCK_SIZE);
	}

#endif

	if (length >= QSC_AES_BLOCK_SIZE)
	{
		nce = _mm_loadu_si128((const __m128i*)ctx->nonce);

		while (length >= QSC_AES_BLOCK_SIZE)
		{
			aes_encrypt_block(ctx, &otp, &nce);
			inp = _mm_loadu_si128((const __m128i*)(input + oft));
			otp = _mm_xor_si128(inp, otp);
			_mm_storeu_si128((__m128i*)(output + oft), otp);
			aes_beincrement_x128(&nce);

			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		_mm_storeu_si128((__m128i*)ctx->nonce, nce);
	}

	if (length != 0)
	{
		QSC_ALIGN(16) uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };

		nce = _mm_loadu_si128((const __m128i*)ctx->nonce);
		qsc_intutils_be8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);

		aes_encrypt_block(ctx, &otp, &nce);
		inp = _mm_loadu_si128((const __m128i*)(input + oft));
		otp = _mm_xor_si128(inp, otp);

		_mm_storeu_si128((__m128i*)tmpb, otp);
		qsc_memutils_copy((output + oft), tmpb, length);
	}
}

void qsc_aes_ctrle_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i nce;
	__m128i otp;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= AVX512_BLOCK_SIZE)
	{
		__m512i inpw;
		__m512i ncew;
		__m512i otpw;
		uint8_t nceb[AVX512_BLOCK_SIZE] = { 0 };

		/* load the ctr nonce block */
		qsc_memutils_copy(nceb, ctx->nonce, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 16), ctx->nonce, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 32), ctx->nonce, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 48), ctx->nonce, QSC_AES_BLOCK_SIZE);

		ncew = _mm512_loadu_si512((const __m512i*)nceb);
		ncew = _mm512_add_epi64(ncew, _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0));

		while (length >= AVX512_BLOCK_SIZE)
		{
			/* encrypt the nonce block */
			aes_encrypt_blockw(ctx, &otpw, &ncew);
			inpw = _mm512_loadu_si512((const __m512i*)(uint8_t*)(input + oft));
			/* xor encrypted nonce with the ctx */
			otpw = _mm512_xor_si512(otpw, inpw);
			/* store in output */
			_mm512_storeu_si512((__m512i*)(uint8_t*)(output + oft), otpw);

			length -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;

			/* increment the low 64 bits across 4 blocks */
			qsc_intutils_leincrement_x512(&ncew);
		}

		/* store the nonce */
		_mm512_storeu_si512((__m512i*)nceb, ncew);
		qsc_memutils_copy(ctx->nonce, nceb, QSC_AES_BLOCK_SIZE);
	}

#endif

	if (length >= QSC_AES_BLOCK_SIZE)
	{
		nce = _mm_loadu_si128((const __m128i*)ctx->nonce);

		while (length >= QSC_AES_BLOCK_SIZE)
		{
			aes_encrypt_block(ctx, &otp, &nce);
			inp = _mm_loadu_si128((const __m128i*)(input + oft));
			otp = _mm_xor_si128(inp, otp);
			_mm_storeu_si128((__m128i*)(output + oft), otp);
			qsc_intutils_leincrement_x128(&nce);

			length -= QSC_AES_BLOCK_SIZE;
			oft += QSC_AES_BLOCK_SIZE;
		}

		_mm_storeu_si128((__m128i*)ctx->nonce, nce);
	}

	if (length != 0)
	{
		QSC_ALIGN(16) uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };

		nce = _mm_loadu_si128((const __m128i*)ctx->nonce);
		qsc_intutils_le8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);

		aes_encrypt_block(ctx, &otp, &nce);
		inp = _mm_loadu_si128((const __m128i*)(input + oft));
		otp = _mm_xor_si128(inp, otp);

		_mm_storeu_si128((__m128i*)tmpb, otp);
		qsc_memutils_copy((output + oft), tmpb, length);
	}
}

/* ecb mode */

void qsc_aes_ecb_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i otp;

	inp = _mm_loadu_si128((const __m128i*)input);
	aes_decrypt_block(ctx, &otp, &inp);
	_mm_storeu_si128((__m128i*)output, otp);
}

void qsc_aes_ecb_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i otp;

	inp = _mm_loadu_si128((const __m128i*)input);
	aes_encrypt_block(ctx, &otp, &inp);
	_mm_storeu_si128((__m128i*)output, otp);
}

void qsc_aes_dispose(qsc_aes_state* ctx)
{
	assert(ctx != NULL);

	/* erase the ctx members */

	if (ctx != NULL)
	{
		qsc_memutils_clear((uint8_t*)ctx->roundkeys, sizeof(ctx->roundkeys));

#if defined(QSC_SYSTEM_HAS_AVX512)
		qsc_memutils_clear((uint8_t*)ctx->roundkeysw, sizeof(ctx->roundkeysw));
#endif
		ctx->roundkeylen = 0;
	}
}

#else

/* rijndael rcon, and s-box constant tables */

static const uint32_t rcon[30] =
{
	0x00000000UL, 0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL, 0x20000000UL, 0x40000000UL,
	0x80000000UL, 0x1B000000UL, 0x36000000UL, 0x6C000000UL, 0xD8000000UL, 0xAB000000UL, 0x4D000000UL, 0x9A000000UL,
	0x2F000000UL, 0x5E000000UL, 0xBC000000UL, 0x63000000UL, 0xC6000000UL, 0x97000000UL, 0x35000000UL, 0x6A000000UL,
	0xD4000000UL, 0xB3000000UL, 0x7D000000UL, 0xFA000000UL, 0xEF000000UL, 0xC5000000UL
};

static inline void aes_swapn(uint32_t cl, uint32_t ch, uint32_t s, uint32_t* x, uint32_t* y)
{
	uint32_t a = *x;
	uint32_t b = *y;
	*x = (a & cl) | ((b & cl) << s);
	*y = ((a & ch) >> s) | (b & ch);
}
  
static inline void aes_swap2(uint32_t* x, uint32_t* y)
{
	/* 0101… / 1010…  (1-bit lanes) */
	aes_swapn(0x55555555U, 0xAAAAAAAAU, 1, x, y);
}

static inline void aes_swap4(uint32_t* x, uint32_t* y)
{
	/* 0011… / 1100…  (2-bit lanes) */
	aes_swapn(0x33333333U, 0xCCCCCCCCU, 2, x, y);
}

static inline void aes_swap8(uint32_t* x, uint32_t* y)
{
	/* 0000 1111… / 1111 0000…  (4-bit lanes) */
	aes_swapn(0x0F0F0F0FU, 0xF0F0F0F0U, 4, x, y);
}

static void aes_ct_ortho(uint32_t* q)
{
	aes_swap2(&q[0], &q[1]);
	aes_swap2(&q[2], &q[3]);
	aes_swap2(&q[4], &q[5]);
	aes_swap2(&q[6], &q[7]);

	aes_swap4(&q[0], &q[2]);
	aes_swap4(&q[1], &q[3]);
	aes_swap4(&q[4], &q[6]);
	aes_swap4(&q[5], &q[7]);

	aes_swap8(&q[0], &q[4]);
	aes_swap8(&q[1], &q[5]);
	aes_swap8(&q[2], &q[6]);
	aes_swap8(&q[3], &q[7]);
}

static void aes_ct_sbox(uint32_t* q)
{
	/*
	 * adapted from bearssl, author Thomas Pourin
	 * This S-box implementation is a straightforward translation of
	 * the circuit described by Boyar and Peralta in "A new
	 * combinational logic minimization technique with applications
	 * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	 *
	 * Note that variables x* (input) and s* (output) are numbered
	 * in "reverse" order (x0 is the high bit, x7 is the low bit).
	 */

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

	x0 = q[7];
	x1 = q[6];
	x2 = q[5];
	x3 = q[4];
	x4 = q[3];
	x5 = q[2];
	x6 = q[1];
	x7 = q[0];

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

	q[7] = s0;
	q[6] = s1;
	q[5] = s2;
	q[4] = s3;
	q[3] = s4;
	q[2] = s5;
	q[1] = s6;
	q[0] = s7;
}

static uint32_t sub_word(uint32_t x)
{
	uint32_t q[8] = { 0 };

	q[0] = x;
	aes_ct_ortho(q);
	aes_ct_sbox(q);
	aes_ct_ortho(q);

	return q[0];
}

static void aes_ct_isbox(uint32_t* q)
{
	/*
	 * adapted from bearssl, author Thomas Pourin
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

	q0 = ~q[0];
	q1 = ~q[1];
	q2 = q[2];
	q3 = q[3];
	q4 = q[4];
	q5 = ~q[5];
	q6 = ~q[6];
	q7 = q[7];

	q[7] = q1 ^ q4 ^ q6;
	q[6] = q0 ^ q3 ^ q5;
	q[5] = q7 ^ q2 ^ q4;
	q[4] = q6 ^ q1 ^ q3;
	q[3] = q5 ^ q0 ^ q2;
	q[2] = q4 ^ q7 ^ q1;
	q[1] = q3 ^ q6 ^ q0;
	q[0] = q2 ^ q5 ^ q7;

	aes_ct_sbox(q);

	q0 = ~q[0];
	q1 = ~q[1];
	q2 = q[2];
	q3 = q[3];
	q4 = q[4];
	q5 = ~q[5];
	q6 = ~q[6];
	q7 = q[7];

	q[7] = q1 ^ q4 ^ q6;
	q[6] = q0 ^ q3 ^ q5;
	q[5] = q7 ^ q2 ^ q4;
	q[4] = q6 ^ q1 ^ q3;
	q[3] = q5 ^ q0 ^ q2;
	q[2] = q4 ^ q7 ^ q1;
	q[1] = q3 ^ q6 ^ q0;
	q[0] = q2 ^ q5 ^ q7;
}

static uint32_t sub_iword(uint32_t x)
{
	uint32_t q[8] = { 0 };

	q[0] = x;
	aes_ct_ortho(q);
	aes_ct_isbox(q);
	aes_ct_ortho(q);

	return q[0];
}

static void aes_sub_bytes(uint8_t* ctx)
{
	uint32_t q[8] = { 0 };

	q[0] = ctx[0];
	q[1] = ctx[1];
	q[2] = ctx[2];
	q[3] = ctx[3];
	q[4] = ctx[4];
	q[5] = ctx[5];
	q[6] = ctx[6];
	q[7] = ctx[7];

	aes_ct_ortho(q);
	aes_ct_sbox(q);
	aes_ct_ortho(q);

	ctx[0] = (uint8_t)q[0];
	ctx[1] = (uint8_t)q[1];
	ctx[2] = (uint8_t)q[2];
	ctx[3] = (uint8_t)q[3];
	ctx[4] = (uint8_t)q[4];
	ctx[5] = (uint8_t)q[5];
	ctx[6] = (uint8_t)q[6];
	ctx[7] = (uint8_t)q[7];

	q[0] = ctx[8];
	q[1] = ctx[9];
	q[2] = ctx[10];
	q[3] = ctx[11];
	q[4] = ctx[12];
	q[5] = ctx[13];
	q[6] = ctx[14];
	q[7] = ctx[15];

	aes_ct_ortho(q);
	aes_ct_sbox(q);
	aes_ct_ortho(q);

	ctx[8] = (uint8_t)q[0];
	ctx[9] = (uint8_t)q[1];
	ctx[10] = (uint8_t)q[2];
	ctx[11] = (uint8_t)q[3];
	ctx[12] = (uint8_t)q[4];
	ctx[13] = (uint8_t)q[5];
	ctx[14] = (uint8_t)q[6];
	ctx[15] = (uint8_t)q[7];
}

static uint32_t aes_substitution(uint32_t rot)
{
	uint32_t val;
	uint32_t res;

	val = rot & 0xFFU;
	res = (uint8_t)sub_word(val);
	val = (rot >> 8) & 0xFFU;
	res |= ((uint32_t)(uint8_t)sub_word(val) << 8);
	val = (rot >> 16) & 0xFFU;
	res |= ((uint32_t)(uint8_t)sub_word(val) << 16);
	val = (rot >> 24) & 0xFFU;

	return res | ((uint32_t)((uint8_t)sub_word(val)) << 24);
}

static void aes_invsub_bytes(uint8_t* ctx)
{
	uint32_t q[8] = { 0 };

	q[0] = ctx[0];
	q[1] = ctx[1];
	q[2] = ctx[2];
	q[3] = ctx[3];
	q[4] = ctx[4];
	q[5] = ctx[5];
	q[6] = ctx[6];
	q[7] = ctx[7];

	aes_ct_ortho(q);
	aes_ct_isbox(q);
	aes_ct_ortho(q);

	ctx[0] = (uint8_t)q[0];
	ctx[1] = (uint8_t)q[1];
	ctx[2] = (uint8_t)q[2];
	ctx[3] = (uint8_t)q[3];
	ctx[4] = (uint8_t)q[4];
	ctx[5] = (uint8_t)q[5];
	ctx[6] = (uint8_t)q[6];
	ctx[7] = (uint8_t)q[7];

	q[0] = ctx[8];
	q[1] = ctx[9];
	q[2] = ctx[10];
	q[3] = ctx[11];
	q[4] = ctx[12];
	q[5] = ctx[13];
	q[6] = ctx[14];
	q[7] = ctx[15];

	aes_ct_ortho(q);
	aes_ct_isbox(q);
	aes_ct_ortho(q);

	ctx[8] = (uint8_t)q[0];
	ctx[9] = (uint8_t)q[1];
	ctx[10] = (uint8_t)q[2];
	ctx[11] = (uint8_t)q[3];
	ctx[12] = (uint8_t)q[4];
	ctx[13] = (uint8_t)q[5];
	ctx[14] = (uint8_t)q[6];
	ctx[15] = (uint8_t)q[7];
}

static void aes_add_roundkey(uint8_t* ctx, const uint32_t *skeys)
{
	uint32_t k;

	for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		k = *skeys;
		ctx[i] ^= (uint8_t)(k >> 24);
		ctx[i + 1] ^= (uint8_t)(k >> 16) & 0xFFU;
		ctx[i + 2] ^= (uint8_t)(k >> 8) & 0xFFU;
		ctx[i + 3] ^= (uint8_t)k & 0xFFU;
		++skeys;
	}
}

static uint8_t aes_gf256_reduce(uint32_t x)
{
	uint32_t y;

	y = x >> 8;

	return (x ^ y ^ (y << 1) ^ (y << 3) ^ (y << 4)) & 0xFFU;
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

	for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = ctx[i];
		s1 = ctx[i + 1];
		s2 = ctx[i + 2];
		s3 = ctx[i + 3];

		t0 = (s0 << 1) ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 1) ^ (s1 << 3)
			^ s2 ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 3);

		t1 = s0 ^ (s0 << 3) ^ (s1 << 1) ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 1) ^ (s2 << 3) ^ s3 ^ (s3 << 2) ^ (s3 << 3);

		t2 = s0 ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 3)
			^ (s2 << 1) ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 1) ^ (s3 << 3);

		t3 = s0 ^ (s0 << 1) ^ (s0 << 3) ^ s1 ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 3) ^ (s3 << 1) ^ (s3 << 2) ^ (s3 << 3);

		ctx[i] = aes_gf256_reduce(t0);
		ctx[i + 1] = aes_gf256_reduce(t1);
		ctx[i + 2] = aes_gf256_reduce(t2);
		ctx[i + 3] = aes_gf256_reduce(t3);
	}
}

static void aes_invshift_rows(uint8_t* ctx)
{
	uint8_t tmp;

	tmp = ctx[13];
	ctx[13] = ctx[9];
	ctx[9] = ctx[5];
	ctx[5] = ctx[1];
	ctx[1] = tmp;

	tmp = ctx[2];
	ctx[2] = ctx[10];
	ctx[10] = tmp;
	tmp = ctx[6];
	ctx[6] = ctx[14];
	ctx[14] = tmp;

	tmp = ctx[3];
	ctx[3] = ctx[7];
	ctx[7] = ctx[11];
	ctx[11] = ctx[15];
	ctx[15] = tmp;
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

	for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = ctx[i];
		s1 = ctx[i + 1];
		s2 = ctx[i + 2];
		s3 = ctx[i + 3];

		t0 = (s0 << 1) ^ s1 ^ (s1 << 1) ^ s2 ^ s3;
		t1 = s0 ^ (s1 << 1) ^ s2 ^ (s2 << 1) ^ s3;
		t2 = s0 ^ s1 ^ (s2 << 1) ^ s3 ^ (s3 << 1);
		t3 = s0 ^ (s0 << 1) ^ s1 ^ s2 ^ (s3 << 1);

		ctx[i] = (uint8_t)(t0 ^ ((~(t0 >> 8) + 1) & 0x0000011BUL));
		ctx[i + 1] = (uint8_t)(t1 ^ ((~(t1 >> 8) + 1) & 0x0000011BUL));
		ctx[i + 2] = (uint8_t)(t2 ^ ((~(t2 >> 8) + 1) & 0x0000011BUL));
		ctx[i + 3] = (uint8_t)(t3 ^ ((~(t3 >> 8) + 1) & 0x0000011BUL));
	}
}

static void aes_shift_rows(uint8_t* ctx)
{
	uint8_t tmp;

	tmp = ctx[1];
	ctx[1] = ctx[5];
	ctx[5] = ctx[9];
	ctx[9] = ctx[13];
	ctx[13] = tmp;

	tmp = ctx[2];
	ctx[2] = ctx[10];
	ctx[10] = tmp;
	tmp = ctx[6];
	ctx[6] = ctx[14];
	ctx[14] = tmp;

	tmp = ctx[15];
	ctx[15] = ctx[11];
	ctx[11] = ctx[7];
	ctx[7] = ctx[3];
	ctx[3] = tmp;
}

static void aes_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	const uint8_t* buf;
	uint8_t s[16];

	buf = input;
	qsc_memutils_copy(s, buf, QSC_AES_BLOCK_SIZE);
	aes_add_roundkey(s, ctx->roundkeys + (ctx->rounds << 2));

	for (size_t i = ctx->rounds - 1; i > 0; i--)
	{
		aes_invshift_rows(s);
		aes_invsub_bytes(s);
		aes_add_roundkey(s, ctx->roundkeys + (i << 2));
		aes_invmix_columns(s);
	}

	aes_invshift_rows(s);
	aes_invsub_bytes(s);
	aes_add_roundkey(s, ctx->roundkeys);
	qsc_memutils_copy(output, s, QSC_AES_BLOCK_SIZE);
}

static void aes_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	uint8_t buf[QSC_AES_BLOCK_SIZE] = { 0 };

	qsc_memutils_copy(buf, input, QSC_AES_BLOCK_SIZE);
	aes_add_roundkey(buf, ctx->roundkeys);

	for (size_t i = 1; i < ctx->rounds; ++i)
	{
		aes_sub_bytes(buf);
		aes_shift_rows(buf);
		aes_mix_columns(buf);
		aes_add_roundkey(buf, ctx->roundkeys + (i << 2));
	}

	aes_sub_bytes(buf);
	aes_shift_rows(buf);
	aes_add_roundkey(buf, ctx->roundkeys + (ctx->rounds << 2));
	qsc_memutils_copy(output, buf, QSC_AES_BLOCK_SIZE);
}

static void aes_expand_rot(uint32_t* key, uint32_t keyindex, uint32_t keyoffset, uint32_t rconindex)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = key[subkey] ^ aes_substitution((key[keyindex - 1] << 8) | ((key[keyindex - 1] >> 24) & 0xFFU)) ^ rcon[rconindex];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
}

static void aes_expand_sub(uint32_t* key, uint32_t keyindex, uint32_t keyoffset)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = aes_substitution(key[keyindex - 1]) ^ key[subkey];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
	++keyindex;
	++subkey;
	key[keyindex] = key[subkey] ^ key[keyindex - 1];
}

static void aes_standard_expand(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams)
{
	/* key in 32 bit words */
	size_t kwords;

	kwords = keyparams->keylen / sizeof(uint32_t);

	if (kwords == 8)
	{
		ctx->roundkeys[0] = qsc_intutils_be8to32(keyparams->key);
		ctx->roundkeys[1] = qsc_intutils_be8to32(keyparams->key + 4);
		ctx->roundkeys[2] = qsc_intutils_be8to32(keyparams->key + 8);
		ctx->roundkeys[3] = qsc_intutils_be8to32(keyparams->key + 12);
		ctx->roundkeys[4] = qsc_intutils_be8to32(keyparams->key + 16);
		ctx->roundkeys[5] = qsc_intutils_be8to32(keyparams->key + 20);
		ctx->roundkeys[6] = qsc_intutils_be8to32(keyparams->key + 24);
		ctx->roundkeys[7] = qsc_intutils_be8to32(keyparams->key + 28);

		/* k256 r: 8,16,24,32,40,48,56 s: 12,20,28,36,44,52 */
		aes_expand_rot(ctx->roundkeys, 8, 8, 1);
		aes_expand_sub(ctx->roundkeys, 12, 8);
		aes_expand_rot(ctx->roundkeys, 16, 8, 2);
		aes_expand_sub(ctx->roundkeys, 20, 8);
		aes_expand_rot(ctx->roundkeys, 24, 8, 3);
		aes_expand_sub(ctx->roundkeys, 28, 8);
		aes_expand_rot(ctx->roundkeys, 32, 8, 4);
		aes_expand_sub(ctx->roundkeys, 36, 8);
		aes_expand_rot(ctx->roundkeys, 40, 8, 5);
		aes_expand_sub(ctx->roundkeys, 44, 8);
		aes_expand_rot(ctx->roundkeys, 48, 8, 6);
		aes_expand_sub(ctx->roundkeys, 52, 8);
		aes_expand_rot(ctx->roundkeys, 56, 8, 7);
	}
	else
	{
		ctx->roundkeys[0] = qsc_intutils_be8to32(keyparams->key);
		ctx->roundkeys[1] = qsc_intutils_be8to32(keyparams->key + 4);
		ctx->roundkeys[2] = qsc_intutils_be8to32(keyparams->key + 8);
		ctx->roundkeys[3] = qsc_intutils_be8to32(keyparams->key + 12);

		/* k128 r: 4,8,12,16,20,24,28,32,36,40 */
		aes_expand_rot(ctx->roundkeys, 4, 4, 1);
		aes_expand_rot(ctx->roundkeys, 8, 4, 2);
		aes_expand_rot(ctx->roundkeys, 12, 4, 3);
		aes_expand_rot(ctx->roundkeys, 16, 4, 4);
		aes_expand_rot(ctx->roundkeys, 20, 4, 5);
		aes_expand_rot(ctx->roundkeys, 24, 4, 6);
		aes_expand_rot(ctx->roundkeys, 28, 4, 7);
		aes_expand_rot(ctx->roundkeys, 32, 4, 8);
		aes_expand_rot(ctx->roundkeys, 36, 4, 9);
		aes_expand_rot(ctx->roundkeys, 40, 4, 10);
	}
}

void qsc_aes_initialize(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption, qsc_aes_cipher_type ctype)
{
	assert(ctx != NULL);
	assert(keyparams != NULL);

	if (keyparams->nonce != NULL)
	{
		ctx->nonce = keyparams->nonce;
	}

	qsc_memutils_clear((uint8_t*)ctx->roundkeys, sizeof(ctx->roundkeys));

	if (ctype == qsc_aes_cipher_256)
	{
		ctx->roundkeylen = AES256_ROUNDKEY_SIZE;
		ctx->rounds = 14;
		aes_standard_expand(ctx, keyparams);
	}
	else if (ctype == qsc_aes_cipher_128)
	{
		ctx->roundkeylen = AES128_ROUNDKEY_SIZE;
		ctx->rounds = 10;
		aes_standard_expand(ctx, keyparams);
	}
	else
	{
		ctx->rounds = 0;
		ctx->roundkeylen = 0;
	}
}

/* cbc mode */

void qsc_aes_cbc_decrypt(qsc_aes_state* ctx, uint8_t* output, size_t *outputlen, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t nlen;
	size_t oft;

	oft = 0;

	while (length > QSC_AES_BLOCK_SIZE)
	{
		qsc_aes_cbc_decrypt_block(ctx, output + oft, input + oft);
		length -= QSC_AES_BLOCK_SIZE;
		oft += QSC_AES_BLOCK_SIZE;
	}

	qsc_aes_cbc_decrypt_block(ctx, tmpb, input + oft);
	nlen = qsc_pkcs7_padding_length(tmpb);
	qsc_memutils_copy(output + oft, tmpb, QSC_AES_BLOCK_SIZE - nlen);
	*outputlen = oft + (QSC_AES_BLOCK_SIZE - nlen);
}

void qsc_aes_cbc_encrypt(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t oft;

	oft = 0;

	while (length > QSC_AES_BLOCK_SIZE)
	{
		qsc_aes_cbc_encrypt_block(ctx, output + oft, input + oft);
		length -= QSC_AES_BLOCK_SIZE;
		oft += QSC_AES_BLOCK_SIZE;
	}

	if (length != 0)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };
		qsc_memutils_copy(tmpb, input + oft, length);

		if (length < QSC_AES_BLOCK_SIZE)
		{
			qsc_pkcs7_add_padding(tmpb, QSC_AES_BLOCK_SIZE - length);
		}

		qsc_aes_cbc_encrypt_block(ctx, output + oft, tmpb);
	}
}

void qsc_aes_cbc_decrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t tmpv[QSC_AES_BLOCK_SIZE] = { 0 };

	qsc_memutils_copy(tmpv, input, QSC_AES_BLOCK_SIZE);
	aes_decrypt_block(ctx, output, input);

	for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; ++i)
	{
		output[i] ^= ctx->nonce[i];
	}

	qsc_memutils_copy(ctx->nonce, tmpv, QSC_AES_BLOCK_SIZE);
}

void qsc_aes_cbc_encrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; ++i)
	{
		ctx->nonce[i] ^= input[i];
	}

	aes_encrypt_block(ctx, output, ctx->nonce);
	qsc_memutils_copy(ctx->nonce, output, QSC_AES_BLOCK_SIZE);
}

/* ctr mode */

void qsc_aes_ctrbe_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	size_t oft;

	oft = 0;

	while (length >= QSC_AES_BLOCK_SIZE)
	{
		aes_encrypt_block(ctx, output + oft, ctx->nonce);

		for (i = 0; i < QSC_AES_BLOCK_SIZE; ++i)
		{
			output[oft + i] ^= input[oft + i];
		}

		qsc_intutils_be8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);

		length -= QSC_AES_BLOCK_SIZE;
		oft += QSC_AES_BLOCK_SIZE;
	}

	if (length != 0)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };

		aes_encrypt_block(ctx, tmpb, ctx->nonce);

		for (i = 0; i < length; ++i)
		{
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_be8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);
	}
}

void qsc_aes_ctrle_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	size_t oft;

	oft = 0;

	while (length >= QSC_AES_BLOCK_SIZE)
	{
		aes_encrypt_block(ctx, output + oft, ctx->nonce);

		for (i = 0; i < QSC_AES_BLOCK_SIZE; ++i)
		{
			output[oft + i] ^= input[oft + i];
		}

		qsc_intutils_le8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);

		length -= QSC_AES_BLOCK_SIZE;
		oft += QSC_AES_BLOCK_SIZE;
	}

	if (length != 0)
	{
		uint8_t tmpb[QSC_AES_BLOCK_SIZE] = { 0 };

		aes_encrypt_block(ctx, tmpb, ctx->nonce);

		for (i = 0; i < length; ++i)
		{
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_le8increment(ctx->nonce, QSC_AES_BLOCK_SIZE);
	}
}

/* ecb mode */

void qsc_aes_ecb_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	aes_decrypt_block(ctx, output, input);
}

void qsc_aes_ecb_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	aes_encrypt_block(ctx, output, input);
}

void qsc_aes_dispose(qsc_aes_state* ctx)
{
	/* erase the ctx members */

	if (ctx != NULL)
	{
		qsc_memutils_clear((uint8_t*)ctx->roundkeys, sizeof(ctx->roundkeys));
		ctx->roundkeylen = 0;
	}
}

#endif

/* pkcs7 padding */

void qsc_pkcs7_add_padding(uint8_t* input, size_t length)
{
	assert(input != NULL);

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

size_t qsc_pkcs7_padding_length(const uint8_t* input)
{
	assert(input != NULL);

	size_t count;

	count = (size_t)input[QSC_AES_BLOCK_SIZE - 1];
	count = (count < QSC_AES_BLOCK_SIZE) ? count : 0;

	if (count != 0)
	{
		for (size_t i = 2; i <= count; ++i)
		{
			if (input[QSC_AES_BLOCK_SIZE - i] != count)
			{
				count = 0;
				break;
			}
		}
	}

	return count;
}


/* Block-cipher counter mode with Hash Based Authentication, -HBA- AEAD authenticated mode */

/* aes-hba256 */

#if defined(QSC_HBA_KMAC_AUTH)
static const uint8_t aes_hba256_name[HBA_NAME_SIZE] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48,
	0x58, 0x53, 0x32, 0x35, 0x36, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x32, 0x35, 0x36
};
#else
static const uint8_t aes_hba256_name[HBA_NAME_SIZE] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48,
	0x58, 0x48, 0x32, 0x35, 0x36, 0x2D, 0x48, 0x4D, 0x41, 0x43, 0x53, 0x48, 0x41, 0x32, 0x32, 0x35, 0x36
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
	uint8_t mkey[HBA256_MKEY_SIZE] = { 0 };
	uint8_t pctr[sizeof(uint64_t)] = { 0 };
	uint8_t tmpn[HBA_NAME_SIZE] = { 0 };
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
	qsc_kmac_initialize(&ctx->kstate, QSC_KECCAK_256_RATE, ctx->mkey, HBA256_MKEY_SIZE, NULL, 0);
#else
	/* extract the HKDF key from the ctx mac-key and salt */
	qsc_hkdf256_extract(mkey, HBA256_MKEY_SIZE, ctx->mkey, sizeof(ctx->mkey), tmpn, HBA_NAME_SIZE);
	/* key HKDF Expand and generate the next mac-key to ctx */
	qsc_hkdf256_expand(ctx->mkey, sizeof(ctx->mkey), mkey, HBA256_MKEY_SIZE, ctx->cust, ctx->custlen);
#endif
}

static void aes_hba256_genkeys(const qsc_aes_keyparams* keyparams, uint8_t* cprk, uint8_t* mack)
{
#if defined(QSC_HBA_KMAC_EXTENSION)

	qsc_keccak_state kstate = { 0 };
	uint8_t sbuf[QSC_KECCAK_256_RATE] = { 0 };

	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

	/* initialize an instance of cSHAKE */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, keyparams->key, keyparams->keylen, aes_hba256_name, HBA_NAME_SIZE, keyparams->info, keyparams->infolen);

	/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1);
	qsc_memutils_copy(cprk, sbuf, keyparams->keylen);
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, sbuf, 1);
	qsc_memutils_copy(mack, sbuf, HBA256_MKEY_SIZE);
	/* clear the shake buffer */
	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

#else

	uint8_t kbuf[QSC_AES256_KEY_SIZE + HBA256_MKEY_SIZE] = { 0 };
	uint8_t genk[QSC_HMAC_256_MAC_SIZE] = { 0 };

	/* extract the HKDF key from the user-key and salt */
	qsc_hkdf256_extract(genk, sizeof(genk), keyparams->key, keyparams->keylen, aes_hba256_name, HBA_NAME_SIZE);

	/* key HKDF Expand and generate the key buffer */
	qsc_hkdf256_expand(kbuf, sizeof(kbuf), genk, sizeof(genk), keyparams->info, keyparams->infolen);

	/* copy the cipher and mac keys from the buffer */
	qsc_memutils_copy(cprk, kbuf, QSC_AES256_KEY_SIZE);
	qsc_memutils_copy(mack, kbuf + QSC_AES256_KEY_SIZE, HBA256_MKEY_SIZE);

	/* clear the buffer */
	qsc_memutils_clear(kbuf, sizeof(kbuf));

#endif
}

void qsc_aes_hba256_dispose(qsc_aes_hba256_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
#if defined(QSC_HBA_KMAC_EXTENSION)
		qsc_keccak_dispose(&ctx->kstate);
#else
		qsc_hmac256_dispose(&ctx->kstate);
#endif

		qsc_aes_dispose(&ctx->cstate);
		qsc_memutils_clear(ctx->cust, sizeof(ctx->cust));
		qsc_memutils_clear(ctx->mkey, sizeof(ctx->mkey));

		ctx->counter = 0;
		ctx->custlen = 0;
		ctx->encrypt = false;
	}
}

void qsc_aes_hba256_initialize(qsc_aes_hba256_state* ctx, const qsc_aes_keyparams* keyparams, bool encrypt)
{
	assert(ctx != NULL);
	assert(keyparams != NULL);

	uint8_t cprk[QSC_AES256_KEY_SIZE] = { 0 };

	ctx->custlen = qsc_intutils_min(keyparams->infolen, sizeof(ctx->cust));

	if (ctx->custlen != 0)
	{
		qsc_memutils_clear(ctx->cust, sizeof(ctx->cust));
		qsc_memutils_copy(ctx->cust, keyparams->info, ctx->custlen);
	}

	qsc_intutils_clear8(ctx->mkey, sizeof(ctx->mkey));

	/* generate the cipher and mac keys */
	aes_hba256_genkeys(keyparams, cprk, ctx->mkey);

	/* initialize the mac ctx */
#if defined(QSC_HBA_KMAC_EXTENSION)
	qsc_kmac_initialize(&ctx->kstate, QSC_KECCAK_256_RATE, ctx->mkey, HBA256_MKEY_SIZE, NULL, 0);
#else
	qsc_hmac256_initialize(&ctx->kstate, ctx->mkey, HBA256_MKEY_SIZE);
#endif

	/* initialize the key parameters struct, info is optional */
	qsc_aes_keyparams kp = { .key = cprk, .keylen = QSC_AES256_KEY_SIZE, .nonce = keyparams->nonce, .noncelen = keyparams->noncelen };
	/* initialize the cipher ctx */
	qsc_aes_initialize(&ctx->cstate, &kp, true, qsc_aes_cipher_256);

	/* populate the hba ctx structure with mac-key and counter */
	/* the ctx counter always initializes at 1 */
	ctx->counter = 1;
	ctx->encrypt = encrypt;
}

void qsc_aes_hba256_set_associated(qsc_aes_hba256_state* ctx, const uint8_t* data, size_t datalen)
{
	assert(ctx != NULL);
	assert(data != NULL);

	/* process the additional data */
	if (datalen != 0)
	{
		uint8_t actr[sizeof(uint32_t)] = { 0 };

		/* add the additional data to the mac */
		aes_hba256_update(ctx, data, datalen);
		/* 1.1a encode with the ad size */
		qsc_intutils_le32to8(actr, (uint32_t)datalen);
		aes_hba256_update(ctx, actr, sizeof(actr));
	}
}

bool qsc_aes_hba256_transform(qsc_aes_hba256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(input != NULL);

	bool res;

	res = false;

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
		uint8_t code[QSC_HBA256_MAC_SIZE] = { 0 };

		/* update the mac with the nonce */
		aes_hba256_update(ctx, ctx->cstate.nonce, QSC_AES_BLOCK_SIZE);
		/* update the mac with the cipher-text */
		aes_hba256_update(ctx, input, length);
		/* mac the cipher-text to the mac */
		aes_hba256_finalize(ctx, code);

		/* test the mac for equality, bypassing the transform if the mac check fails */
		if (qsc_intutils_verify(code, (input + length), QSC_HBA256_MAC_SIZE) == 0)
		{
			/* use aes counter-mode to decrypt the array */
			qsc_aes_ctrle_transform(&ctx->cstate, output, input, length);
			res = true;
		}
	}

	return res;
}

/* aes-gcm */

#if defined(QSC_SYSTEM_AVX_INTRINSICS)

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
	__m128i a = { 0 };
	__m128i b = { 0 };
	__m128i c = { 0 };
	__m128i d = { 0 };

    for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; i++)
	{
        ((uint8_t*)&a)[i] = x[15 - i];
        ((uint8_t*)&b)[i] = y[15 - i];
    }

    gcm_clmul(a, b, &c, &d);
    gcm_shift(&c, &d);

    __m128i dx = gcm_reduce(c);
    __m128i xh = gcm_mix(dx);

    c = _mm_xor_si128(xh, d);

    for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; i++)
	{
        result[i] = ((uint8_t*)&c)[15 - i];
    }
}

#else

static void gcm_mult(const uint8_t* x, const uint8_t* y, uint8_t* result)
{
	uint8_t v[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t z[QSC_AES_BLOCK_SIZE] = { 0 };
	int32_t lsb;

	qsc_memutils_copy(v, y, QSC_AES_BLOCK_SIZE);

	for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; ++i)
	{
		for (int32_t bit = 7; bit >= 0; bit--)
		{
			if ((x[i] >> bit) & 1)
			{
				for (int32_t j = 0; j < QSC_AES_BLOCK_SIZE; j++)
				{
					z[j] ^= v[j];
				}
			}

			lsb = v[QSC_AES_BLOCK_SIZE - 1] & 1;

			for (size_t j = QSC_AES_BLOCK_SIZE - 1; j > 0; j--)
			{
				v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
			}

			v[0] >>= 1;

			if (lsb)
			{
				v[0] ^= 0xe1;
			}
		}
	}

	qsc_memutils_copy(result, z, QSC_AES_BLOCK_SIZE);
}

#endif

static void ghash_update(uint8_t* s, const uint8_t* block, const uint8_t* h)
{
    uint8_t tmp[QSC_AES_BLOCK_SIZE] = { 0 };

	qsc_memutils_xor(s, block, QSC_AES_BLOCK_SIZE);
    gcm_mult(s, h, tmp);
    qsc_memutils_copy(s, tmp, QSC_AES_BLOCK_SIZE);
}

static void aes_gcm256_finalize(qsc_aes_gcm256_state* ctx, uint8_t* tag)
{
    uint8_t lblock[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t tblock[QSC_AES_BLOCK_SIZE] = { 0 };

    for (size_t i = 0; i < sizeof(uint64_t); ++i)
	{
        lblock[i] = (uint8_t)(ctx->aadlen >> (56 - sizeof(uint64_t) * i));
        lblock[sizeof(uint64_t) + i] = (uint8_t)(ctx->ctlen  >> (56 - sizeof(uint64_t) * i));
    }

    ghash_update(ctx->S, lblock, ctx->H);
    qsc_aes_ecb_encrypt_block(&ctx->cstate, tblock, ctx->J0);

    for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; ++i)
	{
        tag[i] = tblock[i] ^ ctx->S[i];
    }
}

bool qsc_aes_gcm256_decrypt(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(input != NULL);

    uint8_t ctag[QSC_AES_BLOCK_SIZE] = { 0 };
    uint8_t kstream[QSC_AES_BLOCK_SIZE] = { 0 };
	uint8_t lblock[QSC_AES_BLOCK_SIZE] = { 0 };
    uint8_t tblock[QSC_AES_BLOCK_SIZE] = { 0 };
	size_t i;
	size_t clen;
	bool res;

	clen = length - QSC_GCM256_MAC_SIZE;

    for (i = 0; i + QSC_AES_BLOCK_SIZE <= clen; i += QSC_AES_BLOCK_SIZE)
	{
        ghash_update(ctx->S, input + i, ctx->H);
        qsc_aes_ecb_encrypt_block(&ctx->cstate, kstream, ctx->C);

        for (size_t j = 0; j < QSC_AES_BLOCK_SIZE; ++j)
		{
            output[i + j] = input[i + j] ^ kstream[j];
        }

        qsc_intutils_be8increment(ctx->C, QSC_AES_BLOCK_SIZE);
    }

    if (i < clen)
	{
        uint8_t block[QSC_AES_BLOCK_SIZE] = { 0 };
        size_t rem;

		rem = clen - i;
        qsc_memutils_copy(block, input + i, rem);
        ghash_update(ctx->S, block, ctx->H);
        qsc_aes_ecb_encrypt_block(&ctx->cstate, kstream, ctx->C);

        for (size_t j = 0; j < rem; j++) 
		{
            output[i + j] = block[j] ^ kstream[j];
        }

        qsc_intutils_be8increment(ctx->C, QSC_AES_BLOCK_SIZE);
    }

    ctx->ctlen += ((uint64_t)clen) * sizeof(uint64_t);

    for (size_t i = 0; i < sizeof(uint64_t); i++)
	{
        lblock[i] = (uint8_t)(ctx->aadlen >> (56 - sizeof(uint64_t) * i));
        lblock[sizeof(uint64_t) + i] = (uint8_t)(ctx->ctlen  >> (56 - sizeof(uint64_t) * i));
    }

    ghash_update(ctx->S, lblock, ctx->H);
    qsc_aes_ecb_encrypt_block(&ctx->cstate, tblock, ctx->J0);

    for (size_t i = 0; i < QSC_AES_BLOCK_SIZE; ++i) 
	{
        ctag[i] = tblock[i] ^ ctx->S[i];
    }

	res = (qsc_intutils_verify(ctag, input + clen, QSC_GCM256_MAC_SIZE) == 0);

    return res;
}

void qsc_aes_gcm256_dispose(qsc_aes_gcm256_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_aes_dispose(&ctx->cstate);
		qsc_memutils_clear(ctx->C, sizeof(ctx->C));
		qsc_memutils_clear(ctx->H, sizeof(ctx->H));
		qsc_memutils_clear(ctx->J0, sizeof(ctx->J0));
		qsc_memutils_clear(ctx->S, sizeof(ctx->S));
		ctx->aadlen = 0;
		ctx->ctlen = 0;
	}
}

void qsc_aes_gcm256_encrypt(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(input != NULL);

    uint8_t keystream[QSC_AES_BLOCK_SIZE] = { 0 };
    size_t i;

    for (i = 0; i + QSC_AES_BLOCK_SIZE <= length; i += QSC_AES_BLOCK_SIZE)
	{
        qsc_aes_ecb_encrypt_block(&ctx->cstate, keystream, ctx->C);

        for (size_t j = 0; j < QSC_AES_BLOCK_SIZE; ++j)
		{
            output[i + j] = input[i + j] ^ keystream[j];
        }

        ghash_update(ctx->S, output + i, ctx->H);
        qsc_intutils_be8increment(ctx->C, QSC_AES_BLOCK_SIZE);
    }

    if (i < length)
	{
        uint8_t block[QSC_AES_BLOCK_SIZE] = { 0 };
        size_t rem;

		rem = length - i;
        qsc_memutils_clear(keystream, QSC_AES_BLOCK_SIZE);
        qsc_aes_ecb_encrypt_block(&ctx->cstate, keystream, ctx->C);

        for (size_t j = 0; j < rem; ++j)
		{
            block[j] = input[i + j] ^ keystream[j];
            output[i + j] = block[j];
        }

        ghash_update(ctx->S, block, ctx->H);
        qsc_intutils_be8increment(ctx->C, QSC_AES_BLOCK_SIZE);
    }

    ctx->ctlen += ((uint64_t)length) * sizeof(uint64_t);

	aes_gcm256_finalize(ctx, output + length);
}

void qsc_aes_gcm256_initialize(qsc_aes_gcm256_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption)
{
	assert(ctx != NULL);
	assert(keyparams != NULL);

    uint8_t zero[QSC_AES_BLOCK_SIZE] = { 0 };

	/* initialize AES */
	ctx->encrypt = encryption;
    qsc_aes_initialize(&ctx->cstate, keyparams, true, qsc_aes_cipher_256);

    /* compute hash subkey: H = AES(K, 0^128) */
    qsc_aes_ecb_encrypt_block(&ctx->cstate, ctx->H, zero);

    /* compute pre–counter block J0 based on IV length */
    if (keyparams->noncelen == 12) 
	{
        qsc_memutils_copy(ctx->J0, keyparams->nonce, keyparams->noncelen);
        qsc_memutils_clear(ctx->J0 + keyparams->noncelen, QSC_AES_BLOCK_SIZE - keyparams->noncelen);
        ctx->J0[QSC_AES_BLOCK_SIZE - 1] = 0x01;
    } 
	else
	{
		uint8_t* buf;
		uint64_t ivbits;
		size_t numblk;
		size_t buflen;

		/* initialize the buffer */
		numblk = ((keyparams->noncelen + QSC_AES_BLOCK_SIZE - 1) / QSC_AES_BLOCK_SIZE);
		buflen = (numblk + 1) * QSC_AES_BLOCK_SIZE;
		buf = (uint8_t*)qsc_memutils_malloc(buflen);

		if (buf != NULL)
		{
			qsc_memutils_clear(buf, buflen);
			qsc_memutils_copy(buf, keyparams->nonce, keyparams->noncelen);

			ivbits = keyparams->noncelen * sizeof(uint64_t);

			for (size_t i = 0; i < sizeof(uint64_t); ++i)
			{
				buf[buflen - sizeof(uint64_t) + i] = (uint8_t)(ivbits >> (56 - sizeof(uint64_t) * i));
			}

			qsc_memutils_clear(ctx->J0, QSC_AES_BLOCK_SIZE);

			for (size_t i = 0; i < buflen; i += QSC_AES_BLOCK_SIZE)
			{
				ghash_update(ctx->J0, buf + i, ctx->H);
			}

			qsc_memutils_alloc_free(buf);
		}
    }

    qsc_memutils_clear(ctx->S, QSC_AES_BLOCK_SIZE);
    ctx->aadlen = 0;
    ctx->ctlen  = 0;

    /* set counter = inc(J0) */
    qsc_memutils_copy(ctx->C, ctx->J0, QSC_AES_BLOCK_SIZE);
    qsc_intutils_be8increment(ctx->C, QSC_AES_BLOCK_SIZE);
}

void qsc_aes_gcm256_set_associated(qsc_aes_gcm256_state* ctx, const uint8_t* data, size_t datalen)
{
	assert(ctx != NULL);
	assert(data != NULL);

    size_t i;

    for (i = 0; i + QSC_AES_BLOCK_SIZE <= datalen; i += QSC_AES_BLOCK_SIZE) 
	{
        ghash_update(ctx->S, data + i, ctx->H);
    }

    if (i < datalen) 
	{
        uint8_t block[QSC_AES_BLOCK_SIZE] = { 0 };

        qsc_memutils_copy(block, data + i, datalen - i);
        ghash_update(ctx->S, block, ctx->H);
    }

    ctx->aadlen += ((uint64_t)datalen) * sizeof(uint64_t);
}

bool qsc_aes_gcm256_transform(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	bool res;

	if (ctx->encrypt == true)
	{
		qsc_aes_gcm256_encrypt(ctx, output, input, length);
		res = true;
	}
	else
	{
		res = qsc_aes_gcm256_decrypt(ctx, output, input, length + QSC_GCM256_MAC_SIZE);
	}

	return res;
}
