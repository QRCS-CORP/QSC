#include "poly1305.h"
#include "intutils.h"
#include "memutils.h"

void qsc_poly1305_blockupdate(qsc_poly1305_state* ctx, const uint8_t* message)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	if (ctx != NULL && message != NULL)
	{
		const uint32_t HIBIT = (ctx->fnl != 0U) ? 0UL : (1UL << 24);
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
		t1 = qsc_intutils_le8to32(message + 4U);
		t2 = qsc_intutils_le8to32(message + 8U);
		t3 = qsc_intutils_le8to32(message + 12U);

		ctx->h[0U] += (uint32_t)(t0 & 0x3FFFFFFUL);
		ctx->h[1U] += (uint32_t)((((t1 << 32) | t0) >> 26) & 0x3FFFFFFUL);
		ctx->h[2U] += (uint32_t)((((t2 << 32) | t1) >> 20) & 0x3FFFFFFUL);
		ctx->h[3U] += (uint32_t)((((t3 << 32) | t2) >> 14) & 0x3FFFFFFUL);
		ctx->h[4U] += (uint32_t)(t3 >> 8) | HIBIT;

		tp0 = ((uint64_t)ctx->h[0U] * ctx->r[0U]) + ((uint64_t)ctx->h[1U] * ctx->s[3U]) + ((uint64_t)ctx->h[2U] * ctx->s[2U]) + ((uint64_t)ctx->h[3U] * ctx->s[1U]) + ((uint64_t)ctx->h[4U] * ctx->s[0U]);
		tp1 = ((uint64_t)ctx->h[0U] * ctx->r[1U]) + ((uint64_t)ctx->h[1U] * ctx->r[0U]) + ((uint64_t)ctx->h[2U] * ctx->s[3U]) + ((uint64_t)ctx->h[3U] * ctx->s[2U]) + ((uint64_t)ctx->h[4U] * ctx->s[1U]);
		tp2 = ((uint64_t)ctx->h[0U] * ctx->r[2U]) + ((uint64_t)ctx->h[1U] * ctx->r[1U]) + ((uint64_t)ctx->h[2U] * ctx->r[0U]) + ((uint64_t)ctx->h[3U] * ctx->s[3U]) + ((uint64_t)ctx->h[4U] * ctx->s[2U]);
		tp3 = ((uint64_t)ctx->h[0U] * ctx->r[3U]) + ((uint64_t)ctx->h[1U] * ctx->r[2U]) + ((uint64_t)ctx->h[2U] * ctx->r[1U]) + ((uint64_t)ctx->h[3U] * ctx->r[0U]) + ((uint64_t)ctx->h[4U] * ctx->s[3U]);
		tp4 = ((uint64_t)ctx->h[0U] * ctx->r[4U]) + ((uint64_t)ctx->h[1U] * ctx->r[3U]) + ((uint64_t)ctx->h[2U] * ctx->r[2U]) + ((uint64_t)ctx->h[3U] * ctx->r[1U]) + ((uint64_t)ctx->h[4U] * ctx->r[0U]);

		ctx->h[0U] = (uint32_t)(tp0 & 0x3FFFFFFUL);
		b = (tp0 >> 26);
		tp1 += b;
		ctx->h[1U] = (uint32_t)(tp1 & 0x3FFFFFFUL);
		b = (tp1 >> 26);
		tp2 += b;
		ctx->h[2U] = (uint32_t)(tp2 & 0x3FFFFFFUL);
		b = (tp2 >> 26);
		tp3 += b;
		ctx->h[3U] = (uint32_t)(tp3 & 0x3FFFFFFUL);
		b = (tp3 >> 26);
		tp4 += b;
		ctx->h[4U] = (uint32_t)(tp4 & 0x3FFFFFFUL);
		b = (tp4 >> 26);
		ctx->h[0U] += (uint32_t)(b * 5U);
	}
}

void qsc_poly1305_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(key != NULL);

	if (output != NULL && message != NULL && key != NULL)
	{
		qsc_poly1305_state ctx;

		qsc_poly1305_initialize(&ctx, key);
		qsc_poly1305_update(&ctx, message, msglen);
		qsc_poly1305_finalize(&ctx, output);
	}
}

void qsc_poly1305_dispose(qsc_poly1305_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->h, sizeof(ctx->h));
		qsc_memutils_clear(ctx->r, sizeof(ctx->r));
		qsc_memutils_clear(ctx->s, sizeof(ctx->s));
		qsc_memutils_clear(ctx->buf, sizeof(ctx->buf));
		ctx->fnl = 0U;
		ctx->rmd = 0U;
	}
}

void qsc_poly1305_finalize(qsc_poly1305_state* ctx, uint8_t* output)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && output != NULL)
	{
		uint64_t f0;
		uint64_t f1;
		uint64_t f2;
		uint64_t f3;
		uint32_t b;
		uint32_t g0;
		uint32_t g1;
		uint32_t g2;
		uint32_t g3;
		uint32_t g4;
		uint32_t nb;

		if (ctx->rmd != 0U)
		{
			ctx->buf[ctx->rmd] = 1U;

			for (size_t i = ctx->rmd + 1U; i < QSC_POLY1305_BLOCK_SIZE; i++)
			{
				ctx->buf[i] = 0U;
			}

			ctx->fnl = 1U;
			qsc_poly1305_blockupdate(ctx, ctx->buf);
		}

		b = ctx->h[0U] >> 26;
		ctx->h[0U] = ctx->h[0U] & 0x3FFFFFFUL;
		ctx->h[1U] += b;
		b = ctx->h[1U] >> 26;
		ctx->h[1U] = ctx->h[1U] & 0x3FFFFFFUL;
		ctx->h[2U] += b;
		b = ctx->h[2U] >> 26;
		ctx->h[2U] = ctx->h[2U] & 0x3FFFFFFUL;
		ctx->h[3U] += b;
		b = ctx->h[3U] >> 26;
		ctx->h[3U] = ctx->h[3U] & 0x3FFFFFFUL;
		ctx->h[4U] += b;
		b = ctx->h[4U] >> 26;
		ctx->h[4U] = ctx->h[4U] & 0x3FFFFFFUL;
		ctx->h[0U] += b * 5U;

		g0 = ctx->h[0U] + 5U;
		b = g0 >> 26;
		g0 &= 0x3FFFFFFUL;
		g1 = ctx->h[1U] + b;
		b = g1 >> 26;
		g1 &= 0x3FFFFFFUL;
		g2 = ctx->h[2U] + b;
		b = g2 >> 26;
		g2 &= 0x3FFFFFFUL;
		g3 = ctx->h[3U] + b;
		b = g3 >> 26;
		g3 &= 0x3FFFFFFUL;
		g4 = ctx->h[4U] + b - (1UL << 26);

		b = (g4 >> 31) - 1U;
		nb = ~b;

		ctx->h[0U] = (ctx->h[0U] & nb) | (g0 & b);
		ctx->h[1U] = (ctx->h[1U] & nb) | (g1 & b);
		ctx->h[2U] = (ctx->h[2U] & nb) | (g2 & b);
		ctx->h[3U] = (ctx->h[3U] & nb) | (g3 & b);
		ctx->h[4U] = (ctx->h[4U] & nb) | (g4 & b);

		/* jgu: checked */
		/*lint -save -e647 */
		f0 = (ctx->h[0U] | (ctx->h[1U] << 26)) + (uint64_t)ctx->k[0U];
		f1 = ((ctx->h[1U] >> 6) | (ctx->h[2U] << 20)) + (uint64_t)ctx->k[1U];
		f2 = ((ctx->h[2U] >> 12) | (ctx->h[3U] << 14)) + (uint64_t)ctx->k[2U];
		f3 = ((ctx->h[3U] >> 18) | (ctx->h[4U] << 8)) + (uint64_t)ctx->k[3U];
		/*lint -restore */

		qsc_intutils_le32to8(output, (uint32_t)f0);
		f1 += (f0 >> 32);
		qsc_intutils_le32to8(output + 4U, (uint32_t)f1);
		f2 += (f1 >> 32);
		qsc_intutils_le32to8(output + 8U, (uint32_t)f2);
		f3 += (f2 >> 32);
		qsc_intutils_le32to8(output + 12U, (uint32_t)f3);

		qsc_poly1305_reset(ctx);
	}
}

void qsc_poly1305_initialize(qsc_poly1305_state* ctx, const uint8_t* key)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	if (ctx != NULL && key != NULL)
	{
		ctx->r[0U] = (qsc_intutils_le8to32(&key[0U])) & 0x3FFFFFFUL;
		ctx->r[1U] = (qsc_intutils_le8to32(&key[3U]) >> 2) & 0x3FFFF03UL;
		ctx->r[2U] = (qsc_intutils_le8to32(&key[6U]) >> 4) & 0x3FFC0FFUL;
		ctx->r[3U] = (qsc_intutils_le8to32(&key[9U]) >> 6) & 0x3F03FFFUL;
		ctx->r[4U] = (qsc_intutils_le8to32(&key[12U]) >> 8) & 0x00FFFFFUL;
		ctx->s[0U] = ctx->r[1U] * 5U;
		ctx->s[1U] = ctx->r[2U] * 5U;
		ctx->s[2U] = ctx->r[3U] * 5U;
		ctx->s[3U] = ctx->r[4U] * 5U;
		ctx->h[0U] = 0U;
		ctx->h[1U] = 0U;
		ctx->h[2U] = 0U;
		ctx->h[3U] = 0U;
		ctx->h[4U] = 0U;
		ctx->k[0U] = qsc_intutils_le8to32(&key[16U]);
		ctx->k[1U] = qsc_intutils_le8to32(&key[20U]);
		ctx->k[2U] = qsc_intutils_le8to32(&key[24U]);
		ctx->k[3U] = qsc_intutils_le8to32(&key[28U]);
		ctx->fnl = 0U;
		ctx->rmd = 0U;
	}
}

void qsc_poly1305_reset(qsc_poly1305_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_intutils_clear32(ctx->h, 5U);
		qsc_intutils_clear32(ctx->k, 4U);
		qsc_intutils_clear32(ctx->r, 5U);
		qsc_intutils_clear32(ctx->s, 4U);
		qsc_intutils_clear8(ctx->buf, QSC_POLY1305_BLOCK_SIZE);
		ctx->rmd = 0U;
		ctx->fnl = 0U;
	}
}

void qsc_poly1305_update(qsc_poly1305_state* ctx, const uint8_t* message, size_t msglen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	if (ctx != NULL && message != NULL)
	{
		size_t i;
		size_t rmd;

		if (ctx->rmd != 0U)
		{
			rmd = (QSC_POLY1305_BLOCK_SIZE - ctx->rmd);

			if (rmd > msglen)
			{
				rmd = msglen;
			}

			for (i = 0U; i < rmd; ++i)
			{
				ctx->buf[ctx->rmd + i] = message[i];
			}

			msglen -= rmd;
			message += rmd;
			ctx->rmd += rmd;

			if (ctx->rmd == QSC_POLY1305_BLOCK_SIZE)
			{
				qsc_poly1305_blockupdate(ctx, ctx->buf);
				ctx->rmd = 0U;
			}
		}

		while (msglen >= QSC_POLY1305_BLOCK_SIZE)
		{
			qsc_poly1305_blockupdate(ctx, message);
			message += QSC_POLY1305_BLOCK_SIZE;
			msglen -= QSC_POLY1305_BLOCK_SIZE;
		}

		if (msglen != 0U)
		{
			for (i = 0; i < msglen; ++i)
			{
				ctx->buf[ctx->rmd + i] = message[i];
			}

			ctx->rmd += msglen;
		}
	}
}

int32_t qsc_poly1305_verify(const uint8_t* code, const uint8_t* message, size_t msglen, const uint8_t* key)
{
	QSC_ASSERT(code != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(key != NULL);

	int32_t res;

	res = -1;

	if (code != NULL && message != NULL && key != NULL)
	{
		uint8_t hash[QSC_POLY1305_MAC_SIZE] = { 0U };

		qsc_poly1305_compute(hash, message, msglen, key);
		res = qsc_intutils_verify(code, hash, QSC_POLY1305_MAC_SIZE);
	}

	return res;
}

