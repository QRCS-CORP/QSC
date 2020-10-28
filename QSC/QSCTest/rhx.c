#include "rhx.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"

/*!
\def AES128_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-128.
*/
#define AES128_ROUND_COUNT 10

/*!
\def AES256_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-256.
*/
#define AES256_ROUND_COUNT 14

/*!
\def RHX256_ROUND_COUNT
* The number of Rijndael mixing rounds used by RHX-256.
*/
#define RHX256_ROUND_COUNT 22

/*!
\def RHX512_ROUND_COUNT
* The number of Rijndael ming rounds used by RHX-512.
*/
#define RHX512_ROUND_COUNT 30

/*!
\def ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
#if defined(QSC_SYSTEM_AESNI_ENABLED)
#	define ROUNDKEY_ELEMENT_SIZE 16
#else
#	define ROUNDKEY_ELEMENT_SIZE 4
#	define RHX_PREFETCH_TABLES
#endif

/*!
\def RHX_NONCE_SIZE
* The size byte size of the CTR nonce and CBC initialization vector.
*/
#define RHX_NONCE_SIZE QSC_RHX_BLOCK_SIZE

/*!
\def AES128_ROUNDKEY_SIZE
* The size of the AES-128 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rhx_state struct.
*/
#define AES128_ROUNDKEY_SIZE ((AES128_ROUND_COUNT + 1) * (QSC_RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def AES256_ROUNDKEY_SIZE
* The size of the AES-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rhx_state struct.
*/
#define AES256_ROUNDKEY_SIZE ((AES256_ROUND_COUNT + 1) * (QSC_RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RHX256_ROUNDKEY_SIZE
* The size of the RHX-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rhx_state struct.
*/
#define RHX256_ROUNDKEY_SIZE ((RHX256_ROUND_COUNT + 1) * (QSC_RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RHX512_ROUNDKEY_SIZE
* The size of the RHX-512 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rhx_state struct.
*/
#define RHX512_ROUNDKEY_SIZE ((RHX512_ROUND_COUNT + 1) * (QSC_RHX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RHX_INFO_DEFLEN
* The size in bytes of the internal default information string.
*/
#define RHX_INFO_DEFLEN 9

/* AVX512 */

/*!
\def AVX512_BLOCK_SIZE
* The size byte size of an AVX512 block
*/
#define AVX512_BLOCK_SIZE (4 * QSC_RHX_BLOCK_SIZE)

/* HBA */

/*!
\def HBA_INFO_LENGTH
* The HBA version information array length.
*/
#define HBA_INFO_LENGTH 16

/*!
\def HBA256_MKEY_LENGTH
* The size of the hba-rhx256 mac key array
*/
#define HBA256_MKEY_LENGTH 32

/*!
\def HBA512_MKEY_LENGTH
* The size of the hba-rhx512 mac key array
*/
#define HBA512_MKEY_LENGTH 64

/*!
\def HBA_NAME_LENGTH
* The HBA implementation specific name array length.
*/
#if defined(QSC_RHX_SHAKE_EXTENSION)
#	define HBA_NAME_LENGTH 29
#else
#	define HBA_NAME_LENGTH 33
#endif

/* default info parameter string literals */
#if defined(QSC_RHX_SHAKE_EXTENSION)
/* RHXS256 */
static const uint8_t RHX_CSHAKE256_INFO[7] = { 82, 72, 88, 83, 50, 53, 54 };
/* RHXS512 */
static const uint8_t RHX_CSHAKE512_INFO[7] = { 82, 72, 88, 83, 53, 49, 50 };
#else
/* RHXH256 */
static const uint8_t RHX_HKDF256_INFO[7] = { 82, 72, 88, 72, 50, 53, 54 };
/* RHXH512 */
static const uint8_t RHX_HKDF512_INFO[7] = { 82, 72, 88, 72, 53, 49, 50 };
#endif

/* aes-ni and table-based fallback functions */

#if defined(QSC_SYSTEM_AESNI_ENABLED)

static void rhx_beincrement_x128(__m128i* counter)
{
	__m128i tmp;
	qsc_intutils_reverse_bytes_x128(counter, &tmp);
	tmp = _mm_add_epi64(tmp, _mm_set_epi64x(0, 1));
	qsc_intutils_reverse_bytes_x128(&tmp, counter);
}

static void rhx_decrypt_block(qsc_rhx_state* state, __m128i* output, const __m128i* input)
{
	const size_t RNDCNT = state->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
	*output = _mm_xor_si128(*input, state->roundkeys[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm_aesdec_si128(*output, state->roundkeys[keyctr]);
	}

	++keyctr;
	*output = _mm_aesdeclast_si128(*output, state->roundkeys[keyctr]);
}

static void rhx_encrypt_block(qsc_rhx_state* state, __m128i* output, const __m128i* input)
{
	const size_t RNDCNT = state->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
	*output = _mm_xor_si128(*input, state->roundkeys[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm_aesenc_si128(*output, state->roundkeys[keyctr]);
	}

	++keyctr;
	*output = _mm_aesenclast_si128(*output, state->roundkeys[keyctr]);
}

static void rhx_le128to8(uint8_t* input, size_t inplen, __m128i* output, size_t outlen)
{
	size_t i;
	uint32_t tmpk;

	// swap endianess
	for (i = 0; i < inplen; i += sizeof(uint32_t))
	{
		tmpk = qsc_intutils_be8to32((uint8_t*)(input + i));
		qsc_intutils_le32to8((uint8_t*)(input + i), tmpk);
	}

	for (i = 0; i < outlen; ++i)
	{
		output[i] = _mm_loadu_si128((__m128i*)(uint8_t*)(input + (i * ROUNDKEY_ELEMENT_SIZE)));
	}
}

#if defined(QSC_SYSTEM_HAS_AVX512)
static void rhx_beincrement_x512(__m512i* counter)
{
	__m512i tmp;
	qsc_intutils_reverse_bytes_x512(counter, &tmp);
	tmp = _mm512_add_epi64(tmp, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4));
	qsc_intutils_reverse_bytes_x512(&tmp, counter);
}

static void rhx_load128to512(__m128i* input, __m512i* output)
{
	*output = _mm512_setzero_si512();
	*output = _mm512_inserti32x4(*output, *input, 0);
	*output = _mm512_inserti32x4(*output, *input, 1);
	*output = _mm512_inserti32x4(*output, *input, 2);
	*output = _mm512_inserti32x4(*output, *input, 3);
}

static void rhx_decrypt_blockw(qsc_rhx_state* state, __m512i* output, const __m512i* input)
{
	const size_t RNDCNT = state->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
	*output = _mm512_xor_si512(*input, state->roundkeysw[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm512_aesdec_epi128(*output, state->roundkeysw[keyctr]);
	}

	++keyctr;
	*output = _mm512_aesdeclast_epi128(*output, state->roundkeysw[keyctr]);
}

static void rhx_encrypt_blockw(qsc_rhx_state* state, __m512i* output, const __m512i* input)
{
	const size_t RNDCNT = state->roundkeylen - 2;
	size_t keyctr;

	keyctr = 0;
	*output = _mm512_xor_si512(*input, state->roundkeysw[keyctr]);

	while (keyctr != RNDCNT)
	{
		++keyctr;
		*output = _mm512_aesenc_epi128(*output, state->roundkeysw[keyctr]);
	}

	++keyctr;
	*output = _mm512_aesenclast_epi128(*output, state->roundkeysw[keyctr]);
}
#endif

static void rhx_expand_rot(__m128i* Key, size_t Index, size_t Offset)
{
	__m128i pkb;

	pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(Key[Index], 0xFF);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

static void rhx_expand_sub(__m128i* Key, size_t Index, size_t Offset)
{
	__m128i pkb;

	pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(Key[Index - 1], 0x0), 0xAA);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x04));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

static void rhx_secure_expand(qsc_rhx_state* state, const qsc_rhx_keyparams* keyparams)
{
	uint8_t tmpi[256] = { 0 };
	uint16_t kblen;
	size_t inlen;

	qsc_memutils_clear(tmpi, RHX_INFO_DEFLEN + keyparams->infolen);

	/* add the ciphers string literal name */
	if (keyparams->keylen == QSC_RHX256_KEY_SIZE)
	{
#if defined(QSC_RHX_SHAKE_EXTENSION)
		/* RHXS256 */
		qsc_memutils_copy(tmpi, RHX_CSHAKE256_INFO, sizeof(RHX_CSHAKE256_INFO));
#else
		/* RHXH256 */
		qsc_memutils_copy(tmpi, RHX_HKDF256_INFO, sizeof(RHX_HKDF256_INFO));
#endif
	}
	else
	{
#if defined(QSC_RHX_SHAKE_EXTENSION)
		/* RHXS512 */
		qsc_memutils_copy(tmpi, RHX_CSHAKE512_INFO, sizeof(RHX_CSHAKE512_INFO));
#else
		/* RHXH512 */
		qsc_memutils_copy(tmpi, RHX_HKDF512_INFO, sizeof(RHX_HKDF512_INFO));
#endif
	}

	/* add the key size in bits to info array as a little endian ordered 16-bit integer */
	kblen = (uint16_t)(keyparams->keylen * 8);
	tmpi[7] = (uint8_t)kblen;
	tmpi[8] = (uint8_t)(kblen >> 8);

	/* copy user-defined tweak to the info array */
	if (keyparams->infolen != 0)
	{
		inlen = qsc_intutils_min(keyparams->infolen, sizeof(tmpi) - RHX_INFO_DEFLEN);
		qsc_memutils_copy((uint8_t*)(tmpi + RHX_INFO_DEFLEN), keyparams->info, inlen);
	}

#if defined(QSC_RHX_SHAKE_EXTENSION)
	if (keyparams->keylen == QSC_RHX256_KEY_SIZE)
	{
		uint8_t rk[(RHX256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE)] = { 0 };

		/* generate the round-key buffer with cSHAKE-256 */
		qsc_cshake256_compute(rk, sizeof(rk), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
		/* convert the bytes to little endian encoded 128-bit integers */
		rhx_le128to8(rk, sizeof(rk), state->roundkeys, state->roundkeylen);
	}
	else
	{
		uint8_t rk[(RHX512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE)] = { 0 };

		/* generate the round-key buffer with cSHAKE-512 */
		qsc_cshake512_compute(rk, sizeof(rk), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
		/* convert the bytes to little endian encoded 128-bit integers */
		rhx_le128to8(rk, sizeof(rk), state->roundkeys, state->roundkeylen);
	}
#else
	if (keyparams->keylen == QSC_RHX256_KEY_SIZE)
	{
		uint8_t rk[RHX256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE] = { 0 };

		/* generate the round-key buffer with HKDF(HMAC(SHA2-256)) */
		qsc_hkdf256_expand(rk, sizeof(rk), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
		/* convert the bytes to little endian encoded 128-bit integers */
		rhx_le128to8(rk, sizeof(rk), state->roundkeys, state->roundkeylen);
	}
	else
	{
		uint8_t rk[(RHX512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE)] = { 0 };

		/* generate the round-key buffer with HKDF(HMAC(SHA2-512)) */
		qsc_hkdf512_expand(rk, sizeof(rk), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
		/* convert the bytes to little endian encoded 128-bit integers */
		rhx_le128to8(rk, sizeof(rk), state->roundkeys, state->roundkeylen);
	}
#endif

}

static void rhx_standard_expand(qsc_rhx_state* state, const qsc_rhx_keyparams* keyparams)
{
	size_t kwords;

	/* key in 32-bit words */
	kwords = keyparams->keylen / 4;

	if (kwords == 8)
	{
		state->roundkeys[0] = _mm_loadu_si128((__m128i*)keyparams->key);
		state->roundkeys[1] = _mm_loadu_si128((__m128i*)(uint8_t*)(keyparams->key + 16));
		state->roundkeys[2] = _mm_aeskeygenassist_si128(state->roundkeys[1], 0x01);
		rhx_expand_rot(state->roundkeys, 2, 2);
		rhx_expand_sub(state->roundkeys, 3, 2);
		state->roundkeys[4] = _mm_aeskeygenassist_si128(state->roundkeys[3], 0x02);
		rhx_expand_rot(state->roundkeys, 4, 2);
		rhx_expand_sub(state->roundkeys, 5, 2);
		state->roundkeys[6] = _mm_aeskeygenassist_si128(state->roundkeys[5], 0x04);
		rhx_expand_rot(state->roundkeys, 6, 2);
		rhx_expand_sub(state->roundkeys, 7, 2);
		state->roundkeys[8] = _mm_aeskeygenassist_si128(state->roundkeys[7], 0x08);
		rhx_expand_rot(state->roundkeys, 8, 2);
		rhx_expand_sub(state->roundkeys, 9, 2);
		state->roundkeys[10] = _mm_aeskeygenassist_si128(state->roundkeys[9], 0x10);
		rhx_expand_rot(state->roundkeys, 10, 2);
		rhx_expand_sub(state->roundkeys, 11, 2);
		state->roundkeys[12] = _mm_aeskeygenassist_si128(state->roundkeys[11], 0x20);
		rhx_expand_rot(state->roundkeys, 12, 2);
		rhx_expand_sub(state->roundkeys, 13, 2);
		state->roundkeys[14] = _mm_aeskeygenassist_si128(state->roundkeys[13], 0x40);
		rhx_expand_rot(state->roundkeys, 14, 2);
	}
	else
	{
		state->roundkeys[0] = _mm_loadu_si128((__m128i*)keyparams->key);
		state->roundkeys[1] = _mm_aeskeygenassist_si128(state->roundkeys[0], 0x01);
		rhx_expand_rot(state->roundkeys, 1, 1);
		state->roundkeys[2] = _mm_aeskeygenassist_si128(state->roundkeys[1], 0x02);
		rhx_expand_rot(state->roundkeys, 2, 1);
		state->roundkeys[3] = _mm_aeskeygenassist_si128(state->roundkeys[2], 0x04);
		rhx_expand_rot(state->roundkeys, 3, 1);
		state->roundkeys[4] = _mm_aeskeygenassist_si128(state->roundkeys[3], 0x08);
		rhx_expand_rot(state->roundkeys, 4, 1);
		state->roundkeys[5] = _mm_aeskeygenassist_si128(state->roundkeys[4], 0x10);
		rhx_expand_rot(state->roundkeys, 5, 1);
		state->roundkeys[6] = _mm_aeskeygenassist_si128(state->roundkeys[5], 0x20);
		rhx_expand_rot(state->roundkeys, 6, 1);
		state->roundkeys[7] = _mm_aeskeygenassist_si128(state->roundkeys[6], 0x40);
		rhx_expand_rot(state->roundkeys, 7, 1);
		state->roundkeys[8] = _mm_aeskeygenassist_si128(state->roundkeys[7], 0x80);
		rhx_expand_rot(state->roundkeys, 8, 1);
		state->roundkeys[9] = _mm_aeskeygenassist_si128(state->roundkeys[8], 0x1B);
		rhx_expand_rot(state->roundkeys, 9, 1);
		state->roundkeys[10] = _mm_aeskeygenassist_si128(state->roundkeys[9], 0x36);
		rhx_expand_rot(state->roundkeys, 10, 1);
	}
}

void qsc_rhx_initialize(qsc_rhx_state* state, const qsc_rhx_keyparams* keyparams, bool encryption, qsc_rhx_cipher_type ctype)
{
	if (keyparams->nonce != NULL)
	{
		state->nonce = keyparams->nonce;
	}

	qsc_memutils_clear((uint8_t*)state->roundkeys, sizeof(state->roundkeys));

	if (ctype == RHX256)
	{
		state->roundkeylen = RHX256_ROUNDKEY_SIZE;
		state->rounds = 22;
		rhx_secure_expand(state, keyparams);
	}
	else if (ctype == RHX512)
	{
		state->roundkeylen = RHX512_ROUNDKEY_SIZE;
		state->rounds = 30;
		rhx_secure_expand(state, keyparams);
	}
	else if (ctype == AES256)
	{
		state->roundkeylen = AES256_ROUNDKEY_SIZE;
		state->rounds = 14;
		rhx_standard_expand(state, keyparams);
	}
	else if (ctype == AES128)
	{
		state->roundkeylen = AES128_ROUNDKEY_SIZE;
		state->rounds = 10;
		rhx_standard_expand(state, keyparams);
	}
	else
	{
		state->roundkeylen = 0;
	}

	/* inverse cipher */
	if (encryption == false)
	{
		__m128i tmp;
		size_t i;
		size_t j;

		tmp = state->roundkeys[0];
		state->roundkeys[0] = state->roundkeys[state->roundkeylen - 1];
		state->roundkeys[state->roundkeylen - 1] = tmp;

		for (i = 1, j = state->roundkeylen - 2; i < j; ++i, --j)
		{
			tmp = _mm_aesimc_si128(state->roundkeys[i]);
			state->roundkeys[i] = _mm_aesimc_si128(state->roundkeys[j]);
			state->roundkeys[j] = tmp;
		}

		state->roundkeys[i] = _mm_aesimc_si128(state->roundkeys[i]);
	}

#if defined(QSC_SYSTEM_HAS_AVX512)
	size_t i;

	qsc_memutils_clear((uint8_t*)state->roundkeysw, sizeof(state->roundkeysw));

	for (i = 0; i < state->rounds + 1; ++i)
	{
		rhx_load128to512(&state->roundkeys[i], &state->roundkeysw[i]);
	}
#endif

}

/* cbc mode */

void qsc_rhx_cbc_decrypt(qsc_rhx_state* state, uint8_t* output, size_t *outputlen, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i ivt;
	__m128i otp;
	size_t len;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (inputlen > AVX512_BLOCK_SIZE)
	{
		__m512i inpw;
		__m512i ivtw;
		__m512i otpw;
		uint8_t ivtb[AVX512_BLOCK_SIZE];

		/* assemble the first block in the chain */
		qsc_memutils_copy(ivtb, state->nonce, QSC_RHX_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(ivtb + QSC_RHX_BLOCK_SIZE), input, 3 * QSC_RHX_BLOCK_SIZE);
		ivtw = _mm512_loadu_si512((const __m512i*)ivtb);

		/* process the first block */
		inpw = _mm512_loadu_si512((const __m512i*)input);
		rhx_decrypt_blockw(state, &otpw, &inpw);
		otpw = _mm512_xor_si512(otpw, ivtw);

		/* store to output */
		_mm512_storeu_si512((__m512i*)output, otpw);
		inputlen -= AVX512_BLOCK_SIZE;
		oft += AVX512_BLOCK_SIZE;

		/* process remaining blocks */
		while (inputlen > AVX512_BLOCK_SIZE)
		{
			qsc_memutils_copy(ivtb, (uint8_t*)(input + (oft - QSC_RHX_BLOCK_SIZE)), AVX512_BLOCK_SIZE);
			ivtw = _mm512_loadu_si512((const __m512i*)ivtb);
			inpw = _mm512_loadu_si512((const __m512i*)((uint8_t*)(input + oft)));

			rhx_decrypt_blockw(state, &otpw, &inpw);
			otpw = _mm512_xor_si512(otpw, ivtw);

			_mm512_storeu_si512((__m512i*)(uint8_t*)(output + oft), otpw);
			inputlen -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;
		}

		qsc_memutils_copy(state->nonce, (uint8_t*)(input + (oft - QSC_RHX_BLOCK_SIZE)), QSC_RHX_BLOCK_SIZE);
	}

#endif

	if (inputlen > QSC_RHX_BLOCK_SIZE)
	{
		ivt = _mm_loadu_si128((const __m128i*)state->nonce);
		inp = _mm_setzero_si128();

		while (inputlen > QSC_RHX_BLOCK_SIZE)
		{
			inp = _mm_loadu_si128((const __m128i*)(uint8_t*)(input + oft));

			rhx_decrypt_block(state, &otp, &inp);
			otp = _mm_xor_si128(otp, ivt);

			_mm_storeu_si128((__m128i*) & ivt, inp);
			_mm_storeu_si128((__m128i*)(uint8_t*)(output + oft), otp);

			inputlen -= QSC_RHX_BLOCK_SIZE;
			oft += QSC_RHX_BLOCK_SIZE;
		}

		_mm_storeu_si128((__m128i*)state->nonce, inp);
	}

	uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_cbc_decrypt_block(state, tmpb, (uint8_t*)(input + oft));
	len = qsc_pkcs7_padding_length(tmpb);
	qsc_memutils_copy((uint8_t*)(output + oft), tmpb, QSC_RHX_BLOCK_SIZE - len);
	*outputlen = oft + (QSC_RHX_BLOCK_SIZE - len);
}

void qsc_rhx_cbc_encrypt(qsc_rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i ivt;
	__m128i otp;
	size_t oft;

	oft = 0;

	while (inputlen > QSC_RHX_BLOCK_SIZE)
	{
		inp = _mm_loadu_si128((const __m128i*)(uint8_t*)(input + oft));
		ivt = _mm_loadu_si128((const __m128i*)state->nonce);

		ivt = _mm_xor_si128(ivt, inp);
		rhx_encrypt_block(state, &otp, &ivt);

		_mm_storeu_si128((__m128i*)state->nonce, otp);
		_mm_storeu_si128((__m128i*)(output + oft), otp);

		inputlen -= QSC_RHX_BLOCK_SIZE;
		oft += QSC_RHX_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };
		qsc_memutils_copy(tmpb, (uint8_t*)(input + oft), inputlen);

		if (inputlen < QSC_RHX_BLOCK_SIZE)
		{
			qsc_pkcs7_add_padding(tmpb, QSC_RHX_BLOCK_SIZE - inputlen);
		}

		qsc_rhx_cbc_encrypt_block(state, (uint8_t*)(output + oft), tmpb);
	}
}

void qsc_rhx_cbc_decrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i ivt;
	__m128i otp;

	inp = _mm_loadu_si128((const __m128i*)input);
	ivt = _mm_loadu_si128((const __m128i*)state->nonce);

	rhx_decrypt_block(state, &otp, &inp);
	otp = _mm_xor_si128(otp, ivt);

	_mm_storeu_si128((__m128i*)state->nonce, inp);
	_mm_storeu_si128((__m128i*)output, otp);
}

void qsc_rhx_cbc_encrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i ivt;
	__m128i otp;

	inp = _mm_loadu_si128((const __m128i*)input);
	ivt = _mm_loadu_si128((const __m128i*)state->nonce);

	ivt = _mm_xor_si128(ivt, inp);
	rhx_encrypt_block(state, &otp, &ivt);

	_mm_storeu_si128((__m128i*)state->nonce, otp);
	_mm_storeu_si128((__m128i*)output, otp);
}

/* ctr mode */
static void encryption_test()
{
	uint8_t msg[AVX512_BLOCK_SIZE] = { 0 };
	uint8_t ncel[AVX512_BLOCK_SIZE] = { 0 };
	uint8_t ncea[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t nces[QSC_RHX_BLOCK_SIZE] = { 0 };
	uint8_t otpa[AVX512_BLOCK_SIZE] = { 0 };
	uint8_t otpb[AVX512_BLOCK_SIZE] = { 0 };
	__m128i inp;
	__m128i nce;
	__m128i otp;
	__m512i ncew;
	size_t i;
	size_t oft;

	oft = 0;

	for (i = 0; i < 4; ++i)
	{
		nce = _mm_loadu_si128((const __m128i*)nces);
		inp = _mm_loadu_si128((const __m128i*)(uint8_t*)(msg + oft));
		// encrypt
		_mm_storeu_si128((__m128i*)(uint8_t*)(otpa + oft), otp);
		qsc_intutils_leincrement_x128(&nce);
	}

	/* load the ctr nonce block */
	qsc_memutils_copy(ncel, ncea, QSC_RHX_BLOCK_SIZE);
	qsc_intutils_le8increment(ncea, QSC_RHX_BLOCK_SIZE);
	qsc_memutils_copy((uint8_t*)(ncel + 16), ncea, QSC_RHX_BLOCK_SIZE);
	qsc_intutils_le8increment(ncea, QSC_RHX_BLOCK_SIZE);
	qsc_memutils_copy((uint8_t*)(ncel + 32), ncea, QSC_RHX_BLOCK_SIZE);
	qsc_intutils_le8increment(ncea, QSC_RHX_BLOCK_SIZE);
	qsc_memutils_copy((uint8_t*)(ncel + 48), ncea, QSC_RHX_BLOCK_SIZE);
	ncew = _mm512_loadu_si512((const __m512i*)ncel);
}

void qsc_rhx_ctrbe_transform(qsc_rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i nce;
	__m128i otp;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (inputlen >= AVX512_BLOCK_SIZE)
	{
		__m512i inpw;
		__m512i ncew;
		__m512i otpw;
		__m512i tmpn;
		uint8_t nceb[AVX512_BLOCK_SIZE];

		/* load the ctr nonce block */
		qsc_memutils_copy(nceb, state->nonce, QSC_RHX_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 16), state->nonce, QSC_RHX_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 32), state->nonce, QSC_RHX_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 48), state->nonce, QSC_RHX_BLOCK_SIZE);

		ncew = _mm512_loadu_si512((const __m512i*)nceb);

		qsc_intutils_reverse_bytes_x512(&ncew, &tmpn);
		tmpn = _mm512_add_epi64(tmpn, _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0));
		qsc_intutils_reverse_bytes_x512(&tmpn, &ncew);

		while (inputlen >= AVX512_BLOCK_SIZE)
		{
			/* encrypt the nonce block */
			rhx_encrypt_blockw(state, &otpw, &ncew);
			inpw = _mm512_loadu_si512((const __m512i*)((uint8_t*)input + oft));
			/* xor encrypted nonce with the state */
			otpw = _mm512_xor_si512(otpw, inpw);
			/* store in output */
			_mm512_storeu_si512((__m512i*)((uint8_t*)output + oft), otpw);

			inputlen -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;

			/* increment the low 64 bits across 4 blocks */
			rhx_beincrement_x512(&ncew);
		}

		/* store the nonce */
		_mm512_storeu_si512((__m512i*)nceb, ncew);
		qsc_memutils_copy(state->nonce, nceb, QSC_RHX_BLOCK_SIZE);
	}

#endif

	if (inputlen >= QSC_RHX_BLOCK_SIZE)
	{
		nce = _mm_loadu_si128((const __m128i*)state->nonce);

		while (inputlen >= QSC_RHX_BLOCK_SIZE)
		{
			rhx_encrypt_block(state, &otp, &nce);
			inp = _mm_loadu_si128((const __m128i*)((uint8_t*)input + oft));
			otp = _mm_xor_si128(inp, otp);
			_mm_storeu_si128((__m128i*)((uint8_t*)output + oft), otp);
			rhx_beincrement_x128(&nce);

			inputlen -= QSC_RHX_BLOCK_SIZE;
			oft += QSC_RHX_BLOCK_SIZE;
		}

		_mm_storeu_si128((__m128i*)state->nonce, nce);
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };

		nce = _mm_loadu_si128((const __m128i*)state->nonce);
		qsc_intutils_be8increment(state->nonce, QSC_RHX_BLOCK_SIZE);

		rhx_encrypt_block(state, &otp, &nce);
		inp = _mm_loadu_si128((const __m128i*)((uint8_t*)input + oft));
		otp = _mm_xor_si128(inp, otp);

		_mm_storeu_si128((__m128i*)tmpb, otp);
		qsc_memutils_copy(((uint8_t*)output + oft), tmpb, inputlen);
	}
}

void qsc_rhx_ctrle_transform(qsc_rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i nce;
	__m128i otp;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (inputlen >= AVX512_BLOCK_SIZE)
	{
		__m512i inpw;
		__m512i ncew;
		__m512i otpw;
		uint8_t nceb[AVX512_BLOCK_SIZE];

		/* load the ctr nonce block */
		qsc_memutils_copy(nceb, state->nonce, QSC_RHX_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 16), state->nonce, QSC_RHX_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 32), state->nonce, QSC_RHX_BLOCK_SIZE);
		qsc_memutils_copy((uint8_t*)(nceb + 48), state->nonce, QSC_RHX_BLOCK_SIZE);

		ncew = _mm512_loadu_si512((const __m512i*)nceb);
		ncew = _mm512_add_epi64(ncew, _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0));

		while (inputlen >= AVX512_BLOCK_SIZE)
		{
			/* encrypt the nonce block */
			rhx_encrypt_blockw(state, &otpw, &ncew);
			inpw = _mm512_loadu_si512((const __m512i*)(uint8_t*)(input + oft));
			/* xor encrypted nonce with the state */
			otpw = _mm512_xor_si512(otpw, inpw);
			/* store in output */
			_mm512_storeu_si512((__m512i*)(uint8_t*)(output + oft), otpw);

			inputlen -= AVX512_BLOCK_SIZE;
			oft += AVX512_BLOCK_SIZE;

			/* increment the low 64 bits across 4 blocks */
			qsc_intutils_leincrement_x512(&ncew);
		}

		/* store the nonce */
		_mm512_storeu_si512((__m512i*)nceb, ncew);
		qsc_memutils_copy(state->nonce, nceb, QSC_RHX_BLOCK_SIZE);
	}

#endif

	if (inputlen >= QSC_RHX_BLOCK_SIZE)
	{
		nce = _mm_loadu_si128((const __m128i*)state->nonce);

		while (inputlen >= QSC_RHX_BLOCK_SIZE)
		{
			rhx_encrypt_block(state, &otp, &nce);
			inp = _mm_loadu_si128((const __m128i*)(uint8_t*)(input + oft));
			otp = _mm_xor_si128(inp, otp);
			_mm_storeu_si128((__m128i*)(uint8_t*)(output + oft), otp);
			qsc_intutils_leincrement_x128(&nce);

			inputlen -= QSC_RHX_BLOCK_SIZE;
			oft += QSC_RHX_BLOCK_SIZE;
		}

		_mm_storeu_si128((__m128i*)state->nonce, nce);
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };

		nce = _mm_loadu_si128((const __m128i*)state->nonce);
		qsc_intutils_le8increment(state->nonce, QSC_RHX_BLOCK_SIZE);

		rhx_encrypt_block(state, &otp, &nce);
		inp = _mm_loadu_si128((const __m128i*)(uint8_t*)(input + oft));
		otp = _mm_xor_si128(inp, otp);

		_mm_storeu_si128((__m128i*)tmpb, otp);
		qsc_memutils_copy((uint8_t*)(output + oft), tmpb, inputlen);
	}
}

/* ecb mode */

void qsc_rhx_ecb_decrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i otp;

	inp = _mm_loadu_si128((const __m128i*)input);
	rhx_decrypt_block(state, &otp, &inp);
	_mm_storeu_si128((__m128i*)output, otp);
}

void qsc_rhx_ecb_encrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	__m128i inp;
	__m128i otp;

	inp = _mm_loadu_si128((const __m128i*)input);
	rhx_encrypt_block(state, &otp, &inp);
	_mm_storeu_si128((__m128i*)output, otp);
}

void qsc_rhx_dispose(qsc_rhx_state* state)
{
	/* erase the state members */

	if (state != NULL)
	{
		if (state->roundkeys != NULL)
		{
			qsc_memutils_clear((uint8_t*)state->roundkeys, sizeof(state->roundkeys));
		}

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (state->roundkeysw != NULL)
		{
			qsc_memutils_clear((uint8_t*)state->roundkeysw, sizeof(state->roundkeysw));
		}
#endif
		state->roundkeylen = 0;
	}
}

#else

/* rijndael rcon, and s-box constant tables */

static const uint8_t s_box[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t is_box[256] =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const uint32_t rcon[30] =
{
	0x00000000UL, 0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL, 0x20000000UL, 0x40000000UL,
	0x80000000UL, 0x1B000000UL, 0x36000000UL, 0x6C000000UL, 0xD8000000UL, 0xAB000000UL, 0x4D000000UL, 0x9A000000UL,
	0x2F000000UL, 0x5E000000UL, 0xBC000000UL, 0x63000000UL, 0xC6000000UL, 0x97000000UL, 0x35000000UL, 0x6A000000UL,
	0xD4000000UL, 0xB3000000UL, 0x7D000000UL, 0xFA000000UL, 0xEF000000UL, 0xC5000000UL
};

static void rhx_add_roundkey(uint8_t* state, const uint32_t *skeys)
{
	size_t i;
	uint32_t k;

	for (i = 0; i < QSC_RHX_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		k = *skeys;
		state[i] ^= (uint8_t)(k >> 24);
		state[i + 1] ^= (uint8_t)(k >> 16) & 0xFFU;
		state[i + 2] ^= (uint8_t)(k >> 8) & 0xFFU;
		state[i + 3] ^= (uint8_t)k & 0xFFU;
		++skeys;
	}
}

static uint8_t rhx_gf256_reduce(uint32_t x)
{
	uint32_t y;

	y = x >> 8;

	return (x ^ y ^ (y << 1) ^ (y << 3) ^ (y << 4)) & 0xFFU;
}

static void rhx_invmix_columns(uint8_t* state)
{
	size_t i;
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;

	for (i = 0; i < QSC_RHX_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = state[i];
		s1 = state[i + 1];
		s2 = state[i + 2];
		s3 = state[i + 3];

		t0 = (s0 << 1) ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 1) ^ (s1 << 3)
			^ s2 ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 3);

		t1 = s0 ^ (s0 << 3) ^ (s1 << 1) ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 1) ^ (s2 << 3) ^ s3 ^ (s3 << 2) ^ (s3 << 3);

		t2 = s0 ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 3)
			^ (s2 << 1) ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 1) ^ (s3 << 3);

		t3 = s0 ^ (s0 << 1) ^ (s0 << 3) ^ s1 ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 3) ^ (s3 << 1) ^ (s3 << 2) ^ (s3 << 3);

		state[i] = rhx_gf256_reduce(t0);
		state[i + 1] = rhx_gf256_reduce(t1);
		state[i + 2] = rhx_gf256_reduce(t2);
		state[i + 3] = rhx_gf256_reduce(t3);
	}
}

static void rhx_invshift_rows(uint8_t* state)
{
	uint8_t tmp;

	tmp = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = state[1];
	state[1] = tmp;

	tmp = state[2];
	state[2] = state[10];
	state[10] = tmp;
	tmp = state[6];
	state[6] = state[14];
	state[14] = tmp;

	tmp = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = tmp;
}

static void rhx_invsub_bytes(uint8_t* state)
{
	size_t i;

	for (i = 0; i < QSC_RHX_BLOCK_SIZE; ++i)
	{
		state[i] = is_box[state[i]];
	}
}

static void rhx_mix_columns(uint8_t* state)
{
	size_t i;
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;

	for (i = 0; i < QSC_RHX_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = state[i + 0];
		s1 = state[i + 1];
		s2 = state[i + 2];
		s3 = state[i + 3];

		t0 = (s0 << 1) ^ s1 ^ (s1 << 1) ^ s2 ^ s3;
		t1 = s0 ^ (s1 << 1) ^ s2 ^ (s2 << 1) ^ s3;
		t2 = s0 ^ s1 ^ (s2 << 1) ^ s3 ^ (s3 << 1);
		t3 = s0 ^ (s0 << 1) ^ s1 ^ s2 ^ (s3 << 1);

		state[i + 0] = (uint8_t)(t0 ^ ((~(t0 >> 8) + 1) & 0x0000011BUL));
		state[i + 1] = (uint8_t)(t1 ^ ((~(t1 >> 8) + 1) & 0x0000011BUL));
		state[i + 2] = (uint8_t)(t2 ^ ((~(t2 >> 8) + 1) & 0x0000011BUL));
		state[i + 3] = (uint8_t)(t3 ^ ((~(t3 >> 8) + 1) & 0x0000011BUL));
	}
}

static void rhx_shift_rows(uint8_t* state)
{
	uint8_t tmp;

	tmp = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = tmp;

	tmp = state[2];
	state[2] = state[10];
	state[10] = tmp;
	tmp = state[6];
	state[6] = state[14];
	state[14] = tmp;

	tmp = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = tmp;
}

static void rhx_sub_bytes(uint8_t* state, const uint8_t* sbox)
{
	size_t i;

	for (i = 0; i < QSC_RHX_BLOCK_SIZE; ++i)
	{
		state[i] = sbox[state[i]];
	}
}

static uint32_t rhx_substitution(uint32_t rot)
{
	uint32_t val;
	uint32_t res;

	val = rot & 0xFFU;
	res = s_box[val];
	val = (rot >> 8) & 0xFFU;
	res |= ((uint32_t)s_box[val] << 8);
	val = (rot >> 16) & 0xFFU;
	res |= ((uint32_t)s_box[val] << 16);
	val = (rot >> 24) & 0xFFU;

	return res | ((uint32_t)(s_box[val]) << 24);
}

static void rhx_decrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	const uint8_t* buf;
	uint8_t s[16];
	size_t i;

	buf = input;
	qsc_memutils_copy(s, buf, QSC_RHX_BLOCK_SIZE);
	rhx_add_roundkey(s, (uint32_t*)(state->roundkeys + (state->rounds << 2)));

	for (i = state->rounds - 1; i > 0; i--)
	{
		rhx_invshift_rows(s);
		rhx_invsub_bytes(s);
		rhx_add_roundkey(s, (uint32_t*)(state->roundkeys + (i << 2)));
		rhx_invmix_columns(s);
	}

	rhx_invshift_rows(s);
	rhx_invsub_bytes(s);
	rhx_add_roundkey(s, state->roundkeys);
	qsc_memutils_copy(output, s, QSC_RHX_BLOCK_SIZE);
}

static void rhx_encrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	uint8_t buf[QSC_RHX_BLOCK_SIZE];
	size_t i;

	qsc_memutils_copy(buf, input, QSC_RHX_BLOCK_SIZE);
	rhx_add_roundkey(buf, state->roundkeys);

	for (i = 1; i < state->rounds; ++i)
	{
		rhx_sub_bytes(buf, s_box);
		rhx_shift_rows(buf);
		rhx_mix_columns(buf);
		rhx_add_roundkey(buf, (uint32_t*)(state->roundkeys + (i << 2)));
	}

	rhx_sub_bytes(buf, s_box);
	rhx_shift_rows(buf);
	rhx_add_roundkey(buf, (uint32_t*)(state->roundkeys + (state->rounds << 2)));
	qsc_memutils_copy(output, buf, QSC_RHX_BLOCK_SIZE);
}

static void rhx_expand_rot(uint32_t* key, uint32_t keyindex, uint32_t keyoffset, uint32_t rconindex)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = key[subkey] ^ rhx_substitution((uint32_t)(key[keyindex - 1] << 8) | (uint32_t)(key[keyindex - 1] >> 24) & 0xFFU) ^ rcon[rconindex];
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

static void rhx_expand_sub(uint32_t* key, uint32_t keyindex, uint32_t keyoffset)
{
	uint32_t subkey;

	subkey = keyindex - keyoffset;
	key[keyindex] = rhx_substitution(key[keyindex - 1]) ^ key[subkey];
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

static void rhx_prefetch_sbox(bool encryption)
{
	size_t i;
	volatile uint32_t dmy;

	dmy = 0;

	if (encryption)
	{
		for (i = 0; i < 256; ++i)
		{
			dmy += s_box[i];
		}
	}
	else
	{
		for (i = 0; i < 256; ++i)
		{
			dmy += is_box[i];
		}
	}
}

static void rhx_secure_expand(qsc_rhx_state* state, const qsc_rhx_keyparams* keyparams)
{
	uint8_t tmpi[256] = { 0 };
	uint16_t kblen;
	size_t inlen;

	/* add the ciphers string literal name */
	if (keyparams->keylen == QSC_RHX256_KEY_SIZE)
	{
#if defined(QSC_RHX_SHAKE_EXTENSION)
		/* RHXS256 */
		qsc_memutils_copy(tmpi, RHX_CSHAKE256_INFO, sizeof(RHX_CSHAKE256_INFO));
#else
		/* RHXH256 */
		qsc_memutils_copy(tmpi, RHX_HKDF256_INFO, sizeof(RHX_HKDF256_INFO));
#endif
	}
	else
	{
#if defined(QSC_RHX_SHAKE_EXTENSION)
		/* RHXS512 */
		qsc_memutils_copy(tmpi, RHX_CSHAKE512_INFO, sizeof(RHX_CSHAKE512_INFO));
#else
		/* RHXH512 */
		qsc_memutils_copy(tmpi, RHX_HKDF512_INFO, sizeof(RHX_HKDF512_INFO));
#endif
	}

	/* add the key size in bits to info array as a little endian ordered 16-bit integer */
	kblen = (uint16_t)(keyparams->keylen * 8);
	tmpi[7] = (uint8_t)kblen;
	tmpi[8] = (uint8_t)(kblen >> 8);

	/* copy in user supplied tweak to info array */
	if (keyparams->infolen != 0)
	{
		inlen = qsc_intutils_min(keyparams->infolen, sizeof(tmpi) - RHX_INFO_DEFLEN);
		qsc_memutils_copy(tmpi + RHX_INFO_DEFLEN, keyparams->info, inlen);
	}

	/* seed the rng and generate the round key array */
#if defined(QSC_RHX_SHAKE_EXTENSION)
	if (keyparams->keylen == QSC_RHX256_KEY_SIZE)
	{
		/* info is used as cSHAKE name parameter */
		qsc_cshake256_compute((uint8_t*)state->roundkeys, state->roundkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
	}
	else
	{
		qsc_cshake512_compute((uint8_t*)state->roundkeys, state->roundkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen, NULL, 0);
	}
#else
	if (keyparams->keylen == QSC_RHX256_KEY_SIZE)
	{
		/* info is HKDF Expand info parameter */
		qsc_hkdf256_expand((uint8_t*)state->roundkeys, state->roundkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
	}
	else
	{
		qsc_hkdf512_expand((uint8_t*)state->roundkeys, state->roundkeylen * sizeof(uint32_t), keyparams->key, keyparams->keylen, tmpi, RHX_INFO_DEFLEN + keyparams->infolen);
	}
#endif
}

static void rhx_standard_expand(qsc_rhx_state* state, const qsc_rhx_keyparams* keyparams)
{
	/* key in 32 bit words */
	size_t kwords;

	kwords = keyparams->keylen / sizeof(uint32_t);

	if (kwords == 8)
	{
		state->roundkeys[0] = qsc_intutils_be8to32(keyparams->key);
		state->roundkeys[1] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 4));
		state->roundkeys[2] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 8));
		state->roundkeys[3] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 12));
		state->roundkeys[4] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 16));
		state->roundkeys[5] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 20));
		state->roundkeys[6] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 24));
		state->roundkeys[7] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 28));

		/* k256 r: 8,16,24,32,40,48,56 s: 12,20,28,36,44,52 */
		rhx_expand_rot(state->roundkeys, 8, 8, 1);
		rhx_expand_sub(state->roundkeys, 12, 8);
		rhx_expand_rot(state->roundkeys, 16, 8, 2);
		rhx_expand_sub(state->roundkeys, 20, 8);
		rhx_expand_rot(state->roundkeys, 24, 8, 3);
		rhx_expand_sub(state->roundkeys, 28, 8);
		rhx_expand_rot(state->roundkeys, 32, 8, 4);
		rhx_expand_sub(state->roundkeys, 36, 8);
		rhx_expand_rot(state->roundkeys, 40, 8, 5);
		rhx_expand_sub(state->roundkeys, 44, 8);
		rhx_expand_rot(state->roundkeys, 48, 8, 6);
		rhx_expand_sub(state->roundkeys, 52, 8);
		rhx_expand_rot(state->roundkeys, 56, 8, 7);
	}
	else
	{
		state->roundkeys[0] = qsc_intutils_be8to32(keyparams->key);
		state->roundkeys[1] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 4));
		state->roundkeys[2] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 8));
		state->roundkeys[3] = qsc_intutils_be8to32((uint8_t*)(keyparams->key + 12));

		/* k128 r: 4,8,12,16,20,24,28,32,36,40 */
		rhx_expand_rot(state->roundkeys, 4, 4, 1);
		rhx_expand_rot(state->roundkeys, 8, 4, 2);
		rhx_expand_rot(state->roundkeys, 12, 4, 3);
		rhx_expand_rot(state->roundkeys, 16, 4, 4);
		rhx_expand_rot(state->roundkeys, 20, 4, 5);
		rhx_expand_rot(state->roundkeys, 24, 4, 6);
		rhx_expand_rot(state->roundkeys, 28, 4, 7);
		rhx_expand_rot(state->roundkeys, 32, 4, 8);
		rhx_expand_rot(state->roundkeys, 36, 4, 9);
		rhx_expand_rot(state->roundkeys, 40, 4, 10);
	}
}

void qsc_rhx_initialize(qsc_rhx_state* state, const qsc_rhx_keyparams* keyparams, bool encryption, qsc_rhx_cipher_type ctype)
{
	if (keyparams->nonce != NULL)
	{
		state->nonce = keyparams->nonce;
	}

	qsc_memutils_clear((uint8_t*)state->roundkeys, sizeof(state->roundkeys));

	if (ctype == RHX256)
	{
		state->roundkeylen = RHX256_ROUNDKEY_SIZE;
		state->rounds = 22;
		rhx_secure_expand(state, keyparams);
	}
	else if (ctype == RHX512)
	{
		state->roundkeylen = RHX512_ROUNDKEY_SIZE;
		state->rounds = 30;
		rhx_secure_expand(state, keyparams);
	}
	else if (ctype == AES256)
	{
		state->roundkeylen = AES256_ROUNDKEY_SIZE;
		state->rounds = 14;
		rhx_standard_expand(state, keyparams);
	}
	else if (ctype == AES128)
	{
		state->roundkeylen = AES128_ROUNDKEY_SIZE;
		state->rounds = 10;
		rhx_standard_expand(state, keyparams);
	}
	else
	{
		state->rounds = 0;
		state->roundkeylen = 0;
	}
}

/* cbc mode */

void qsc_rhx_cbc_decrypt(qsc_rhx_state* state, uint8_t* output, size_t *outputlen, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };
	size_t nlen;
	size_t oft;

	nlen = 0;
	oft = 0;

	while (inputlen > QSC_RHX_BLOCK_SIZE)
	{
		qsc_rhx_cbc_decrypt_block(state, (uint8_t*)(output + oft), (uint8_t*)(input + oft));
		inputlen -= QSC_RHX_BLOCK_SIZE;
		oft += QSC_RHX_BLOCK_SIZE;
	}

	qsc_rhx_cbc_decrypt_block(state, tmpb, (uint8_t*)(input + oft));
	nlen = qsc_pkcs7_padding_length(tmpb);
	qsc_memutils_copy((uint8_t*)(output + oft), tmpb, QSC_RHX_BLOCK_SIZE - nlen);
	*outputlen = oft + (QSC_RHX_BLOCK_SIZE - nlen);
}

void qsc_rhx_cbc_encrypt(qsc_rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t oft;

	oft = 0;

	while (inputlen > QSC_RHX_BLOCK_SIZE)
	{
		qsc_rhx_cbc_encrypt_block(state, (uint8_t*)(output + oft), (uint8_t*)(input + oft));
		inputlen -= QSC_RHX_BLOCK_SIZE;
		oft += QSC_RHX_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };
		qsc_memutils_copy(tmpb, (uint8_t*)(input + oft), inputlen);

		if (inputlen < QSC_RHX_BLOCK_SIZE)
		{
			qsc_pkcs7_add_padding(tmpb, QSC_RHX_BLOCK_SIZE - inputlen);
		}

		qsc_rhx_cbc_encrypt_block(state, (uint8_t*)(output + oft), tmpb);
	}
}

void qsc_rhx_cbc_decrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	uint8_t tmpv[QSC_RHX_BLOCK_SIZE] = { 0 };

	qsc_memutils_copy(tmpv, input, QSC_RHX_BLOCK_SIZE);
	rhx_decrypt_block(state, output, input);

	for (i = 0; i < QSC_RHX_BLOCK_SIZE; ++i)
	{
		output[i] ^= state->nonce[i];
	}

	qsc_memutils_copy(state->nonce, tmpv, QSC_RHX_BLOCK_SIZE);
}

void qsc_rhx_cbc_encrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;

	for (i = 0; i < QSC_RHX_BLOCK_SIZE; ++i)
	{
		state->nonce[i] ^= input[i];
	}

	rhx_encrypt_block(state, output, state->nonce);
	qsc_memutils_copy(state->nonce, output, QSC_RHX_BLOCK_SIZE);
}

/* ctr mode */

void qsc_rhx_ctrbe_transform(qsc_rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	size_t oft;

	oft = 0;

	while (inputlen >= QSC_RHX_BLOCK_SIZE)
	{
		rhx_encrypt_block(state, (uint8_t*)(output + oft), state->nonce);

		for (i = 0; i < QSC_RHX_BLOCK_SIZE; ++i)
		{
			output[oft + i] ^= input[oft + i];
		}

		qsc_intutils_be8increment(state->nonce, QSC_RHX_BLOCK_SIZE);

		inputlen -= QSC_RHX_BLOCK_SIZE;
		oft += QSC_RHX_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };

		rhx_encrypt_block(state, tmpb, state->nonce);

		for (i = 0; i < inputlen; ++i)
		{
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_be8increment(state->nonce, QSC_RHX_BLOCK_SIZE);
	}
}

void qsc_rhx_ctrle_transform(qsc_rhx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	size_t oft;

	oft = 0;

	while (inputlen >= QSC_RHX_BLOCK_SIZE)
	{
		rhx_encrypt_block(state, (uint8_t*)(output + oft), state->nonce);

		for (i = 0; i < QSC_RHX_BLOCK_SIZE; ++i)
		{
			output[oft + i] ^= input[oft + i];
		}

		qsc_intutils_le8increment(state->nonce, QSC_RHX_BLOCK_SIZE);

		inputlen -= QSC_RHX_BLOCK_SIZE;
		oft += QSC_RHX_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[QSC_RHX_BLOCK_SIZE] = { 0 };

		rhx_encrypt_block(state, tmpb, state->nonce);

		for (i = 0; i < inputlen; ++i)
		{
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_le8increment(state->nonce, QSC_RHX_BLOCK_SIZE);
	}
}

/* ecb mode */

void qsc_rhx_ecb_decrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	rhx_decrypt_block(state, output, input);
}

void qsc_rhx_ecb_encrypt_block(qsc_rhx_state* state, uint8_t* output, const uint8_t* input)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(output != NULL);

	rhx_encrypt_block(state, output, input);
}

void qsc_rhx_dispose(qsc_rhx_state* state)
{
	/* erase the state members */

	if (state != NULL)
	{
		if (state->roundkeys != NULL)
		{
			qsc_memutils_clear((uint8_t*)state->roundkeys, sizeof(state->roundkeys));
		}

		state->roundkeylen = 0;
	}
}

#endif

/* pkcs7 padding */

void qsc_pkcs7_add_padding(uint8_t* input, size_t length)
{
	assert(input != NULL);

	const size_t PADOFT = QSC_RHX_BLOCK_SIZE - length;
	size_t ctr;
	uint8_t code;

	code = (uint8_t)length;
	ctr = PADOFT;

	while (ctr != QSC_RHX_BLOCK_SIZE)
	{
		input[ctr] = code;
		++ctr;
	}
}

size_t qsc_pkcs7_padding_length(const uint8_t* input)
{
	assert(input != NULL);

	size_t count;
	size_t i;

	count = (size_t)input[QSC_RHX_BLOCK_SIZE - 1];
	count = (count < QSC_RHX_BLOCK_SIZE) ? count : 0;

	if (count != 0)
	{
		for (i = 2; i <= count; ++i)
		{
			if (input[QSC_RHX_BLOCK_SIZE - i] != count)
			{
				count = 0;
				break;
			}
		}
	}

	return count;
}

/* Block-cipher counter mode with Hash Based Authentication, -HBA- AEAD authenticated mode */

/* rhx-hba256 */

#if defined(QSC_HBA_KMAC_AUTH)
static const uint8_t rhx_hba256_name[HBA_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48,
	0x58, 0x53, 0x32, 0x35, 0x36, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x32, 0x35, 0x36
};
#else
static const uint8_t rhx_hba256_name[HBA_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48,
	0x58, 0x48, 0x32, 0x35, 0x36, 0x2D, 0x48, 0x4D, 0x41, 0x43, 0x53, 0x48, 0x41, 0x32, 0x32, 0x35, 0x36
};
#endif

static void rhx_hba256_update(qsc_rhx_hba256_state* state, const uint8_t* input, size_t inputlen)
{
#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsc_kmac_update(&state->kstate, QSC_KECCAK_256_RATE, input, inputlen);
#else
	qsc_hmac256_update(&state->kstate, input, inputlen);
#endif
}

static void rhx_hba256_finalize(qsc_rhx_hba256_state* state, uint8_t* output)
{
	uint8_t mkey[HBA256_MKEY_LENGTH] = { 0 };
	uint8_t pctr[sizeof(uint64_t)];
	uint8_t tmpn[HBA_NAME_LENGTH];
	uint64_t mctr;

	/* add the nonce, input, and aad sizes to the counter */
	mctr = QSC_RHX_BLOCK_SIZE + state->counter + state->aadlen + sizeof(uint64_t);
	/* add the additional data to the mac */
	rhx_hba256_update(state, state->aad, state->aadlen);
	/* add the total bytes being processed by the mac  */
	qsc_intutils_le64to8(pctr, mctr);
	rhx_hba256_update(state, pctr, sizeof(pctr));

#if defined(QSC_HBA_KMAC_AUTH)
	/* mac the data and add the code to the end of the cipher-text output array */
	qsc_kmac_finalize(&state->kstate, QSC_KECCAK_256_RATE, output, QSC_HBA256_MAC_LENGTH);
#else
	/* mac the data and add the code to the end of the cipher-text output array */
	qsc_hmac256_finalize(&state->kstate, output);
#endif

	/* generate the new mac key */
	qsc_memutils_copy(tmpn, rhx_hba256_name, HBA_NAME_LENGTH);
	/* add 1 + the nonce, and last input size */
	/* append the counter to the end of the mac input array */
	qsc_intutils_le64to8(tmpn, state->counter);

#if defined(QSC_HBA_KMAC_AUTH)
	qsc_cshake256_compute(mkey, HBA256_MKEY_LENGTH, state->mkey, sizeof(state->mkey), tmpn, HBA_NAME_LENGTH, state->cust, state->custlen);
	qsc_memutils_copy(state->mkey, mkey, HBA256_MKEY_LENGTH);
	qsc_kmac_initialize(&state->kstate, QSC_KECCAK_256_RATE, state->mkey, HBA256_MKEY_LENGTH, NULL, 0);
#else
	/* extract the HKDF key from the state mac-key and salt */
	qsc_hkdf256_extract(mkey, HBA256_MKEY_LENGTH, state->mkey, sizeof(state->mkey), tmpn, HBA_NAME_LENGTH);
	/* key HKDF Expand and generate the next mac-key to state */
	qsc_hkdf256_expand(state->mkey, sizeof(state->mkey), mkey, HBA256_MKEY_LENGTH, state->cust, state->custlen);
#endif
}

static void rhx_hba256_genkeys(const qsc_rhx_keyparams* keyparams, uint8_t* cprk, uint8_t* mack)
{
#if defined(QSC_RHX_SHAKE_EXTENSION)

	qsc_keccak_state kstate;
	uint8_t sbuf[QSC_KECCAK_256_RATE] = { 0 };

	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

	/* initialize an instance of cSHAKE */
	qsc_cshake_initialize(&kstate, keccak_rate_256, keyparams->key, keyparams->keylen, rhx_hba256_name, HBA_NAME_LENGTH, keyparams->info, keyparams->infolen);

	/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
	qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, sbuf, 1);
	qsc_memutils_copy(cprk, sbuf, keyparams->keylen);
	qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, sbuf, 1);
	qsc_memutils_copy(mack, sbuf, HBA256_MKEY_LENGTH);
	/* clear the shake buffer */
	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

#else

	uint8_t kbuf[QSC_RHX256_KEY_SIZE + HBA256_MKEY_LENGTH] = { 0 };
	uint8_t genk[QSC_HMAC_256_MAC_SIZE] = { 0 };

	/* extract the HKDF key from the user-key and salt */
	qsc_hkdf256_extract(genk, sizeof(genk), keyparams->key, keyparams->keylen, rhx_hba256_name, HBA_NAME_LENGTH);

	/* key HKDF Expand and generate the key buffer */
	qsc_hkdf256_expand(kbuf, sizeof(kbuf), genk, sizeof(genk), keyparams->info, keyparams->infolen);

	/* copy the cipher and mac keys from the buffer */
	qsc_memutils_copy(cprk, kbuf, QSC_RHX256_KEY_SIZE);
	qsc_memutils_copy(mack, kbuf + QSC_RHX256_KEY_SIZE, HBA256_MKEY_LENGTH);

	/* clear the buffer */
	qsc_memutils_clear(kbuf, sizeof(kbuf));

#endif
}

void qsc_rhx_hba256_dispose(qsc_rhx_hba256_state* state)
{
	if (state != NULL)
	{
		if (&state->kstate != NULL)
		{
#if defined(QSC_RHX_SHAKE_EXTENSION)
			qsc_keccak_dispose(&state->kstate);
#else
			qsc_hmac256_dispose(&state->kstate);
#endif
		}

		if (&state->cstate != NULL)
		{
			qsc_rhx_dispose(&state->cstate);
		}

		if (state->aad != NULL)
		{
			qsc_memutils_clear(state->aad, sizeof(state->aad));
		}

		if (state->cust != NULL)
		{
			qsc_memutils_clear(state->cust, sizeof(state->cust));
		}

		if (state->mkey != NULL)
		{
			qsc_memutils_clear(state->mkey, sizeof(state->mkey));
		}

		state->aadlen = 0;
		state->counter = 0;
		state->custlen = 0;
		state->encrypt = false;
	}
}

void qsc_rhx_hba256_initialize(qsc_rhx_hba256_state* state, const qsc_rhx_keyparams* keyparams, bool encrypt)
{
	uint8_t cprk[QSC_RHX256_KEY_SIZE] = { 0 };

	state->custlen = qsc_intutils_min(keyparams->infolen, sizeof(state->cust));

	if (state->custlen != 0)
	{
		qsc_memutils_clear(state->cust, sizeof(state->cust));
		qsc_memutils_copy(state->cust, keyparams->info, state->custlen);
	}

	qsc_intutils_clear8(state->mkey, sizeof(state->mkey));

	/* generate the cipher and mac keys */
	rhx_hba256_genkeys(keyparams, cprk, state->mkey);

	/* initialize the mac state */
#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsc_kmac_initialize(&state->kstate, QSC_KECCAK_256_RATE, state->mkey, HBA256_MKEY_LENGTH, NULL, 0);
#else
	qsc_hmac256_initialize(&state->kstate, state->mkey, HBA256_MKEY_LENGTH);
#endif

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { cprk, QSC_RHX256_KEY_SIZE, keyparams->nonce, keyparams->info, keyparams->infolen };
	/* initialize the cipher state */
	qsc_rhx_initialize(&state->cstate, &kp, true, RHX256);

	/* populate the hba state structure with mac-key and counter */
	/* the state counter always initializes at 1 */
	state->counter = 1;
	state->encrypt = encrypt;
	state->aadlen = 0;
}

void qsc_rhx_hba256_set_associated(qsc_rhx_hba256_state* state, const uint8_t* data, size_t datalen)
{
	state->aadlen = qsc_intutils_min(datalen, sizeof(state->aad));

	if (state->aadlen != 0)
	{
		qsc_memutils_clear(state->aad, sizeof(state->aad));
		qsc_memutils_copy(state->aad, data, state->aadlen);
	}
}

bool qsc_rhx_hba256_transform(qsc_rhx_hba256_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	bool res;

	res = false;

	/* update the processed bytes counter */
	state->counter += inputlen;

	if (state->encrypt)
	{
		/* update the mac with the nonce */
		rhx_hba256_update(state, state->cstate.nonce, QSC_RHX_BLOCK_SIZE);
		/* use rhx counter-mode to encrypt the array */
		qsc_rhx_ctrle_transform(&state->cstate, output, input, inputlen);
		/* update the mac with the cipher-text */
		rhx_hba256_update(state, output, inputlen);
		/* mac the cipher-text appending the code to the end of the array */
		rhx_hba256_finalize(state, (uint8_t*)(output + inputlen));
		res = true;
	}
	else
	{
		uint8_t code[QSC_HBA256_MAC_LENGTH] = { 0 };

		/* update the mac with the nonce */
		rhx_hba256_update(state, state->cstate.nonce, QSC_RHX_BLOCK_SIZE);
		/* update the mac with the cipher-text */
		rhx_hba256_update(state, input, inputlen);
		/* mac the cipher-text to the mac */
		rhx_hba256_finalize(state, code);

		/* test the mac for equality, bypassing the transform if the mac check fails */
		if (qsc_intutils_verify(code, (uint8_t*)(input + inputlen), QSC_HBA256_MAC_LENGTH) == 0)
		{
			/* use rhx counter-mode to decrypt the array */
			qsc_rhx_ctrle_transform(&state->cstate, output, input, inputlen);
			res = true;
		}
	}

	return res;
}

/* rhx-hba512 */

#if defined(QSC_HBA_KMAC_AUTH)
static const uint8_t rhx_hba512_name[HBA_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48,
	0x58, 0x53, 0x35, 0x31, 0x32, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x35, 0x31, 0x32
};
#else
static const uint8_t rhx_hba512_name[HBA_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48,
	0x58, 0x48, 0x35, 0x31, 0x32, 0x2D, 0x48, 0x4D, 0x41, 0x43, 0x53, 0x48, 0x41, 0x32, 0x35, 0x31, 0x32
};
#endif

static void rhx_hba512_update(qsc_rhx_hba512_state* state, uint8_t* input, size_t inputlen)
{
#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsc_kmac_update(&state->kstate, QSC_KECCAK_512_RATE, input, inputlen);
#else
	qsc_hmac512_update(&state->kstate, input, inputlen);
#endif
}

static void rhx_hba512_finalize(qsc_rhx_hba512_state* state, uint8_t* output)
{
	uint8_t mkey[HBA512_MKEY_LENGTH] = { 0 };
	uint8_t pctr[sizeof(uint64_t)];
	uint8_t tmpn[HBA_NAME_LENGTH];
	uint64_t mctr;

	/* add the nonce, input, and aad sizes to the counter */
	mctr = QSC_RHX_BLOCK_SIZE + state->counter + state->aadlen + sizeof(uint64_t);
	/* add the additional data to the mac */
	rhx_hba512_update(state, state->aad, state->aadlen);
	/* add the total bytes being processed by the mac  */
	qsc_intutils_le64to8(pctr, mctr);
	rhx_hba512_update(state, pctr, sizeof(pctr));

#if defined(QSC_HBA_KMAC_AUTH)
	/* mac the data and add the code to the end of the cipher-text output array */
	qsc_kmac_finalize(&state->kstate, QSC_KECCAK_512_RATE, output, QSC_HBA512_MAC_LENGTH);
#else
	/* mac the data and add the code to the end of the cipher-text output array */
	qsc_hmac512_finalize(&state->kstate, output);
#endif

	/* generate the new mac key */
	qsc_memutils_copy(tmpn, rhx_hba512_name, HBA_NAME_LENGTH);
	/* add 1 + the nonce, and last input size */
	/* append the counter to the end of the mac input array */
	qsc_intutils_le64to8(tmpn, state->counter);

#if defined(QSC_HBA_KMAC_AUTH)
	qsc_cshake512_compute(mkey, HBA512_MKEY_LENGTH, state->mkey, sizeof(state->mkey), tmpn, HBA_NAME_LENGTH, state->cust, state->custlen);
	qsc_memutils_copy(state->mkey, mkey, HBA512_MKEY_LENGTH);
	qsc_kmac_initialize(&state->kstate, QSC_KECCAK_512_RATE, state->mkey, HBA512_MKEY_LENGTH, NULL, 0);
#else
	/* extract the HKDF key from the state mac-key and salt */
	qsc_hkdf512_extract(mkey, HBA512_MKEY_LENGTH, state->mkey, sizeof(state->mkey), tmpn, HBA_NAME_LENGTH);
	/* key HKDF Expand and generate the next mac-key to state */
	qsc_hkdf512_expand(state->mkey, sizeof(state->mkey), mkey, HBA512_MKEY_LENGTH, state->cust, state->custlen);
#endif
}

static void rhx_hba512_genkeys(const qsc_rhx_keyparams* keyparams, uint8_t* cprk, uint8_t* mack)
{
#if defined(QSC_RHX_SHAKE_EXTENSION)

	uint8_t sbuf[QSC_KECCAK_512_RATE] = { 0 };
	qsc_keccak_state kstate;

	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

	/* initialize an instance of cSHAKE */
	qsc_cshake_initialize(&kstate, keccak_rate_512, keyparams->key, keyparams->keylen, rhx_hba512_name, HBA_NAME_LENGTH, keyparams->info, keyparams->infolen);
	/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
	qsc_cshake_squeezeblocks(&kstate, keccak_rate_512, sbuf, 1);
	qsc_memutils_copy(cprk, sbuf, keyparams->keylen);

	qsc_cshake_squeezeblocks(&kstate, keccak_rate_512, sbuf, 1);
	qsc_memutils_copy(mack, sbuf, HBA512_MKEY_LENGTH);

	/* clear the shake buffer */
	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

#else

	uint8_t kbuf[QSC_RHX512_KEY_SIZE + HBA512_MKEY_LENGTH] = { 0 };
	uint8_t genk[QSC_HMAC_512_MAC_SIZE] = { 0 };

	/* extract the HKDF key from the user-key and salt */
	qsc_hkdf512_extract(genk, sizeof(genk), keyparams->key, keyparams->keylen, rhx_hba512_name, HBA_NAME_LENGTH);

	/* key HKDF Expand and generate the key buffer */
	qsc_hkdf512_expand(kbuf, sizeof(kbuf), genk, sizeof(genk), keyparams->info, keyparams->infolen);

	/* copy the cipher and mac keys from the buffer */
	qsc_memutils_copy(cprk, kbuf, QSC_RHX512_KEY_SIZE);
	qsc_memutils_copy(mack, (uint8_t*)(kbuf + QSC_RHX512_KEY_SIZE), HBA512_MKEY_LENGTH);

	/* clear the buffer */
	qsc_memutils_clear(kbuf, sizeof(kbuf));
#endif

}

void qsc_rhx_hba512_dispose(qsc_rhx_hba512_state* state)
{
	if (state != NULL)
	{
		if (&state->kstate != NULL)
		{
#if defined(QSC_RHX_SHAKE_EXTENSION)
			qsc_keccak_dispose(&state->kstate);
#else
			qsc_hmac512_dispose(&state->kstate);
#endif
		}

		if (&state->cstate != NULL)
		{
			qsc_rhx_dispose(&state->cstate);
		}

		if (state->aad != NULL)
		{
			qsc_memutils_clear(state->aad, sizeof(state->aad));
		}

		if (state->cust != NULL)
		{
			qsc_memutils_clear(state->cust, sizeof(state->cust));
		}

		if (state->mkey != NULL)
		{
			qsc_memutils_clear(state->mkey, sizeof(state->mkey));
		}

		state->aadlen = 0;
		state->counter = 0;
		state->custlen = 0;
		state->encrypt = false;
	}
}

void qsc_rhx_hba512_initialize(qsc_rhx_hba512_state* state, const qsc_rhx_keyparams* keyparams, bool encrypt)
{
	uint8_t cprk[QSC_RHX512_KEY_SIZE] = { 0 };

	state->custlen = qsc_intutils_min(keyparams->infolen, sizeof(state->cust));

	if (state->custlen != 0)
	{
		qsc_memutils_clear(state->cust, sizeof(state->cust));
		qsc_memutils_copy(state->cust, keyparams->info, state->custlen);
	}

	qsc_intutils_clear8(state->mkey, sizeof(state->mkey));

	/* generate the cipher and mac keys */
	rhx_hba512_genkeys(keyparams, cprk, state->mkey);

	/* initialize the mac state */
#if defined(QSC_RHX_SHAKE_EXTENSION)
	qsc_kmac_initialize(&state->kstate, QSC_KECCAK_512_RATE, state->mkey, HBA512_MKEY_LENGTH, NULL, 0);
#else
	qsc_hmac512_initialize(&state->kstate, state->mkey, HBA512_MKEY_LENGTH);
#endif

	/* initialize the key parameters struct, info is optional */
	qsc_rhx_keyparams kp = { cprk, QSC_RHX512_KEY_SIZE, keyparams->nonce, keyparams->info, keyparams->infolen };
	/* initialize the cipher state */
	qsc_rhx_initialize(&state->cstate, &kp, true, RHX512);

	/* populate the hba state structure with mac-key and counter */
	/* the state counter always initializes at 1 */
	state->counter = 1;
	state->encrypt = encrypt;
	state->aadlen = 0;
}

void qsc_rhx_hba512_set_associated(qsc_rhx_hba512_state* state, const uint8_t* data, size_t datalen)
{
	state->aadlen = qsc_intutils_min(datalen, sizeof(state->aad));

	if (state->aadlen != 0)
	{
		qsc_memutils_clear(state->aad, sizeof(state->aad));
		qsc_memutils_copy(state->aad, data, state->aadlen);
	}
}

bool qsc_rhx_hba512_transform(qsc_rhx_hba512_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	bool res;

	res = false;

	/* update the processed bytes counter */
	state->counter += inputlen;

	if (state->encrypt)
	{
		/* update the mac with the nonce */
		rhx_hba512_update(state, state->cstate.nonce, QSC_RHX_BLOCK_SIZE);
		/* use rhx counter-mode to encrypt the array */
		qsc_rhx_ctrle_transform(&state->cstate, output, input, inputlen);
		/* update the mac with the cipher-text */
		rhx_hba512_update(state, output, inputlen);
		/* mac the cipher-text appending the code to the end of the array */
		rhx_hba512_finalize(state, (uint8_t*)(output + inputlen));
		res = true;
	}
	else
	{
		uint8_t code[QSC_HBA512_MAC_LENGTH] = { 0 };

		/* update the mac with the nonce */
		rhx_hba512_update(state, state->cstate.nonce, QSC_RHX_BLOCK_SIZE);
		/* update the mac with the cipher-text */
		rhx_hba512_update(state, (uint8_t*)input, inputlen);
		/* mac the cipher-text to the mac */
		rhx_hba512_finalize(state, code);

		/* test the mac for equality, bypassing the transform if the mac check fails */
		if (qsc_intutils_verify(code, (uint8_t*)(input + inputlen), QSC_HBA512_MAC_LENGTH) == 0)
		{
			/* use rhx counter-mode to decrypt the array */
			qsc_rhx_ctrle_transform(&state->cstate, output, input, inputlen);
			res = true;
		}
	}

	return res;
}
