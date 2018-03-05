#include "hide.h"
#include "kem.h"
#include "modq.h"
#include "params.h"
#include "randomweightw.h"
#include "rq.h"
#include "sha3.h"
#include <string.h>

void hide(uint8_t* cstr, uint8_t* k, const uint8_t* pk, const uint8_t* r)
{
	int16_t G[NTRU_P];
	int16_t A[NTRU_P];
	int16_t B[NTRU_P];
	int16_t C[NTRU_P];
	int8_t b[NTRU_P];
	uint8_t k12[64];
	uint8_t k34[64];
	size_t i;
	int16_t x;

	rq_fromseed(G, pk);
	rq_decoderounded(A, pk + 32);

	sha3_compute512(k12, r, 32);
	small_seeded_weightw(b, k12);
	sha3_compute512(k34, k12 + 32, 32);

	rq_mult(B, G, b);
	rq_round3(B, B);
	rq_mult(C, A, b);

	for (i = 0; i < 256; ++i)
	{
		x = C[i];
		x = modq_sum(x, 2295 * (1 & (r[i / 8] >> (i & 7))));
		x = (((x + 2156) * 114) + 16384) >> 15;
		C[i] = x; /* between 0 and 15 */
	}

	memcpy(cstr, k34, 32); 
	cstr += 32;
	memcpy(k, k34 + 32, 32);
	rq_encoderounded(cstr, B); 
	cstr += NTRU_RQENCODEROUNDED_LEN;

	for (i = 0; i < 128; ++i)
	{
		*cstr++ = C[2 * i] + (C[(2 * i) + 1] << 4);
	}
}
