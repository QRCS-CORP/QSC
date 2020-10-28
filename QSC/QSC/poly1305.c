#include "poly1305.h"
#include "intutils.h"

void qsc_poly1305_blockupdate(qsc_poly1305_state* ctx, const uint8_t* message)
{
	assert(ctx != NULL);
	assert(message != NULL);

	const uint32_t HIBIT = (ctx->fnl != 0) ? 0UL : (1UL << 24);
	uint64_t b;
	uint64_t t0;
	uint64_t t1;
	uint64_t t2;
	uint64_t t3;
	uint64_t tp0;
	uint64_t tp1;
	uint64_t tp2;
	uint64_t tp3;
	uint64_t tp4;

	t0 = qsc_intutils_le8to32(message);
	t1 = qsc_intutils_le8to32(message + 4);
	t2 = qsc_intutils_le8to32(message + 8);
	t3 = qsc_intutils_le8to32(message + 12);

	ctx->h[0] += (uint32_t)(t0 & 0x3FFFFFFUL);
	ctx->h[1] += (uint32_t)((((t1 << 32) | t0) >> 26) & 0x3FFFFFFUL);
	ctx->h[2] += (uint32_t)((((t2 << 32) | t1) >> 20) & 0x3FFFFFFUL);
	ctx->h[3] += (uint32_t)((((t3 << 32) | t2) >> 14) & 0x3FFFFFFUL);
	ctx->h[4] += (uint32_t)(t3 >> 8) | HIBIT;

	tp0 = ((uint64_t)ctx->h[0] * ctx->r[0]) + ((uint64_t)ctx->h[1] * ctx->s[3]) + ((uint64_t)ctx->h[2] * ctx->s[2]) + ((uint64_t)ctx->h[3] * ctx->s[1]) + ((uint64_t)ctx->h[4] * ctx->s[0]);
	tp1 = ((uint64_t)ctx->h[0] * ctx->r[1]) + ((uint64_t)ctx->h[1] * ctx->r[0]) + ((uint64_t)ctx->h[2] * ctx->s[3]) + ((uint64_t)ctx->h[3] * ctx->s[2]) + ((uint64_t)ctx->h[4] * ctx->s[1]);
	tp2 = ((uint64_t)ctx->h[0] * ctx->r[2]) + ((uint64_t)ctx->h[1] * ctx->r[1]) + ((uint64_t)ctx->h[2] * ctx->r[0]) + ((uint64_t)ctx->h[3] * ctx->s[3]) + ((uint64_t)ctx->h[4] * ctx->s[2]);
	tp3 = ((uint64_t)ctx->h[0] * ctx->r[3]) + ((uint64_t)ctx->h[1] * ctx->r[2]) + ((uint64_t)ctx->h[2] * ctx->r[1]) + ((uint64_t)ctx->h[3] * ctx->r[0]) + ((uint64_t)ctx->h[4] * ctx->s[3]);
	tp4 = ((uint64_t)ctx->h[0] * ctx->r[4]) + ((uint64_t)ctx->h[1] * ctx->r[3]) + ((uint64_t)ctx->h[2] * ctx->r[2]) + ((uint64_t)ctx->h[3] * ctx->r[1]) + ((uint64_t)ctx->h[4] * ctx->r[0]);

	ctx->h[0] = (uint32_t)(tp0 & 0x3FFFFFFUL);
	b = (tp0 >> 26);
	tp1 += b;
	ctx->h[1] = (uint32_t)(tp1 & 0x3FFFFFFUL);
	b = (tp1 >> 26);
	tp2 += b;
	ctx->h[2] = (uint32_t)(tp2 & 0x3FFFFFFUL);
	b = (tp2 >> 26);
	tp3 += b;
	ctx->h[3] = (uint32_t)(tp3 & 0x3FFFFFFUL);
	b = (tp3 >> 26);
	tp4 += b;
	ctx->h[4] = (uint32_t)(tp4 & 0x3FFFFFFUL);
	b = (tp4 >> 26);
	ctx->h[0] += (uint32_t)(b * 5);
}

void qsc_poly1305_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	qsc_poly1305_state ctx;

	qsc_poly1305_initialize(&ctx, key);
	qsc_poly1305_update(&ctx, message, msglen);
	qsc_poly1305_finalize(&ctx, output);
}

void qsc_poly1305_finalize(qsc_poly1305_state* ctx, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	uint64_t f0;
	uint64_t f1;
	uint64_t f2;
	uint64_t f3;
	size_t i;
	uint32_t b;
	uint32_t g0;
	uint32_t g1;
	uint32_t g2;
	uint32_t g3;
	uint32_t g4;
	uint32_t nb;

	if (ctx->rmd)
	{
		ctx->buf[ctx->rmd] = 1;

		for (i = ctx->rmd + 1; i < QSC_POLY1305_BLOCK_SIZE; i++)
		{
			ctx->buf[i] = 0;
		}

		ctx->fnl = 1;
		qsc_poly1305_blockupdate(ctx, ctx->buf);
	}

	b = ctx->h[0] >> 26;
	ctx->h[0] = ctx->h[0] & 0x3FFFFFFUL;
	ctx->h[1] += b;
	b = ctx->h[1] >> 26;
	ctx->h[1] = ctx->h[1] & 0x3FFFFFFUL;
	ctx->h[2] += b;
	b = ctx->h[2] >> 26;
	ctx->h[2] = ctx->h[2] & 0x3FFFFFFUL;
	ctx->h[3] += b;
	b = ctx->h[3] >> 26;
	ctx->h[3] = ctx->h[3] & 0x3FFFFFFUL;
	ctx->h[4] += b;
	b = ctx->h[4] >> 26;
	ctx->h[4] = ctx->h[4] & 0x3FFFFFFUL;
	ctx->h[0] += b * 5;

	g0 = ctx->h[0] + 5;
	b = g0 >> 26;
	g0 &= 0x3FFFFFFUL;
	g1 = ctx->h[1] + b;
	b = g1 >> 26;
	g1 &= 0x3FFFFFFUL;
	g2 = ctx->h[2] + b;
	b = g2 >> 26;
	g2 &= 0x3FFFFFFUL;
	g3 = ctx->h[3] + b;
	b = g3 >> 26;
	g3 &= 0x3FFFFFFUL;
	g4 = ctx->h[4] + b - (1UL << 26);

	b = (g4 >> 31) - 1;
	nb = ~b;
	ctx->h[0] = (ctx->h[0] & nb) | (g0 & b);
	ctx->h[1] = (ctx->h[1] & nb) | (g1 & b);
	ctx->h[2] = (ctx->h[2] & nb) | (g2 & b);
	ctx->h[3] = (ctx->h[3] & nb) | (g3 & b);
	ctx->h[4] = (ctx->h[4] & nb) | (g4 & b);

	/* jgu: checked */
	/*lint -save -e647 */
	f0 = (ctx->h[0] | (ctx->h[1] << 26)) + (uint64_t)ctx->k[0];
	f1 = ((ctx->h[1] >> 6) | (ctx->h[2] << 20)) + (uint64_t)ctx->k[1];
	f2 = ((ctx->h[2] >> 12) | (ctx->h[3] << 14)) + (uint64_t)ctx->k[2];
	f3 = ((ctx->h[3] >> 18) | (ctx->h[4] << 8)) + (uint64_t)ctx->k[3];
	/*lint -restore */

	qsc_intutils_le32to8(output + 0, (uint32_t)f0);
	f1 += (f0 >> 32);
	qsc_intutils_le32to8(output + 4, (uint32_t)f1);
	f2 += (f1 >> 32);
	qsc_intutils_le32to8(output + 8, (uint32_t)f2);
	f3 += (f2 >> 32);
	qsc_intutils_le32to8(output + 12, (uint32_t)f3);

	qsc_poly1305_reset(ctx);
}

void qsc_poly1305_initialize(qsc_poly1305_state* ctx, const uint8_t* key)
{
	assert(ctx != NULL);
	assert(key != NULL);

	ctx->r[0] = (qsc_intutils_le8to32(&key[0])) & 0x3FFFFFFUL;
	ctx->r[1] = (qsc_intutils_le8to32(&key[3]) >> 2) & 0x3FFFF03UL;
	ctx->r[2] = (qsc_intutils_le8to32(&key[6]) >> 4) & 0x3FFC0FFUL;
	ctx->r[3] = (qsc_intutils_le8to32(&key[9]) >> 6) & 0x3F03FFFUL;
	ctx->r[4] = (qsc_intutils_le8to32(&key[12]) >> 8) & 0x00FFFFFUL;
	ctx->s[0] = ctx->r[1] * 5;
	ctx->s[1] = ctx->r[2] * 5;
	ctx->s[2] = ctx->r[3] * 5;
	ctx->s[3] = ctx->r[4] * 5;
	ctx->h[0] = 0;
	ctx->h[1] = 0;
	ctx->h[2] = 0;
	ctx->h[3] = 0;
	ctx->h[4] = 0;
	ctx->k[0] = qsc_intutils_le8to32(&key[16]);
	ctx->k[1] = qsc_intutils_le8to32(&key[20]);
	ctx->k[2] = qsc_intutils_le8to32(&key[24]);
	ctx->k[3] = qsc_intutils_le8to32(&key[28]);
	ctx->fnl = 0;
	ctx->rmd = 0;
}

void qsc_poly1305_reset(qsc_poly1305_state* ctx)
{
	assert(ctx != NULL);

	qsc_intutils_clear32(ctx->h, 5);
	qsc_intutils_clear32(ctx->k, 4);
	qsc_intutils_clear32(ctx->r, 5);
	qsc_intutils_clear32(ctx->s, 4);
	qsc_intutils_clear8(ctx->buf, QSC_POLY1305_BLOCK_SIZE);
	ctx->rmd = 0;
	ctx->fnl = 0;
}

void qsc_poly1305_update(qsc_poly1305_state* ctx, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	size_t i;
	size_t rmd;

	if (ctx->rmd)
	{
		rmd = (QSC_POLY1305_BLOCK_SIZE - ctx->rmd);

		if (rmd > msglen)
		{
			rmd = msglen;
		}

		for (i = 0; i < rmd; ++i)
		{
			ctx->buf[ctx->rmd + i] = message[i];
		}

		msglen -= rmd;
		message += rmd;
		ctx->rmd += rmd;

		if (ctx->rmd == QSC_POLY1305_BLOCK_SIZE)
		{
			qsc_poly1305_blockupdate(ctx, ctx->buf);
			ctx->rmd = 0;
		}
	}

	while (msglen >= QSC_POLY1305_BLOCK_SIZE)
	{
		qsc_poly1305_blockupdate(ctx, message);
		message += QSC_POLY1305_BLOCK_SIZE;
		msglen -= QSC_POLY1305_BLOCK_SIZE;
	}

	if (msglen)
	{
		for (i = 0; i < msglen; ++i)
		{
			ctx->buf[ctx->rmd + i] = message[i];
		}

		ctx->rmd += msglen;
	}
}

int qsc_poly1305_verify(const uint8_t* mac, const uint8_t* message, size_t msglen, const uint8_t* key)
{
	assert(mac != NULL);
	assert(message != NULL);
	assert(key != NULL);

	uint8_t hash[QSC_POLY1305_MAC_SIZE] = { 0 };

	qsc_poly1305_compute(hash, message, msglen, key);

	return qsc_intutils_verify(mac, hash, QSC_POLY1305_MAC_SIZE);
}

