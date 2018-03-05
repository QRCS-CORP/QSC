#include "kem.h"
#include "common.h"
#include "hide.h"
#include "modq.h"
#include "params.h"
#include "randomweightw.h"
#include "rq.h"
#include "small.h"
#include "sysrand.h"
#include <string.h>

static int32_t verify(const uint8_t* x, const uint8_t* y)
{
	uint32_t differentbits = 0;
	size_t i;

	for (i = 0; i < NTRU_CIPHERTEXTBYTES; ++i)
	{
		differentbits |= x[i] ^ y[i];
	}

	return (1 & ((differentbits - 1) >> 8)) - 1;
}

qcc_status crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	int8_t a[NTRU_P];
	int16_t B[NTRU_P];
	int16_t aB[NTRU_P];
	int16_t C[256];
	uint8_t r[32];
	uint8_t checkcstr[NTRU_CIPHERTEXTBYTES];
	uint8_t maybek[32];
	size_t i;
	uint32_t result;

	small_decode(a, sk);
	sk += NTRU_SMALLENCODE_LEN;
	rq_decoderounded(B, ct + 32);
	rq_mult(aB, B, a);

	for (i = 0; i < 128; ++i)
	{
		uint32_t x = ct[32 + NTRU_RQENCODEROUNDED_LEN + i];
		C[2 * i] = (x & 15) * 287 - 2007;
		C[2 * i + 1] = (x >> 4) * 287 - 2007;
	}

	for (i = 0; i < 256; ++i)
	{
		C[i] = -(modq_freeze(C[i] - aB[i] + 4 * NTRU_W + 1) >> 14);
	}

	for (i = 0; i < 32; ++i)
	{
		r[i] = 0;
	}

	for (i = 0; i < 256; ++i)
	{
		r[i / 8] |= (C[i] << (i & 7));
	}

	hide(checkcstr, maybek, sk, r);
	result = verify(ct, checkcstr);

	for (i = 0; i < 32; ++i)
	{
		ss[i] = maybek[i] & ~result;
	}

	return (result == 0) ? QCC_STATUS_SUCCESS : QCC_STATUS_FAILURE;
}

qcc_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	uint8_t r[32];
	qcc_status ret;

	ret = sysrand_getbytes(r, 32);
	hide(ct, ss, pk, r);

	return ret;
}

qcc_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	uint8_t K[32];
	int16_t G[NTRU_P];
	int8_t a[NTRU_P];
	int16_t A[NTRU_P];
	qcc_status ret;

	ret = sysrand_getbytes(K, 32);
	rq_fromseed(G, K);

	small_random_weightw(a);

	rq_mult(A, G, a);
	rq_round3(A, A);

	memcpy(pk, K, 32);
	rq_encoderounded(pk + 32, A);

	small_encode(sk, a);
	memcpy(sk + NTRU_SMALLENCODE_LEN, pk, NTRU_PUBLICKEYBYTES);

	return ret;
}