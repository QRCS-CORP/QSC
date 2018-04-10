#include "poly1305.h"
#include "util.h"

void poly1305_blockupdate(poly1305_state* state, const uint8_t* message)
{
	const uint32_t HIBIT = (state->fnl) ? 0UL : (1UL << 24);
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

	t0 = le8to32(message);
	t1 = le8to32(message + 4);
	t2 = le8to32(message + 8);
	t3 = le8to32(message + 12);

	state->h[0] += (uint32_t)(t0 & 0x3FFFFFFUL);
	state->h[1] += (uint32_t)((((t1 << 32) | t0) >> 26) & 0x3FFFFFFUL);
	state->h[2] += (uint32_t)((((t2 << 32) | t1) >> 20) & 0x3FFFFFFUL);
	state->h[3] += (uint32_t)((((t3 << 32) | t2) >> 14) & 0x3FFFFFFUL);
	state->h[4] += (uint32_t)(t3 >> 8) | HIBIT;

	tp0 = ((uint64_t)state->h[0] * state->r[0]) + ((uint64_t)state->h[1] * state->s[3]) + ((uint64_t)state->h[2] * state->s[2]) + ((uint64_t)state->h[3] * state->s[1]) + ((uint64_t)state->h[4] * state->s[0]);
	tp1 = ((uint64_t)state->h[0] * state->r[1]) + ((uint64_t)state->h[1] * state->r[0]) + ((uint64_t)state->h[2] * state->s[3]) + ((uint64_t)state->h[3] * state->s[2]) + ((uint64_t)state->h[4] * state->s[1]);
	tp2 = ((uint64_t)state->h[0] * state->r[2]) + ((uint64_t)state->h[1] * state->r[1]) + ((uint64_t)state->h[2] * state->r[0]) + ((uint64_t)state->h[3] * state->s[3]) + ((uint64_t)state->h[4] * state->s[2]);
	tp3 = ((uint64_t)state->h[0] * state->r[3]) + ((uint64_t)state->h[1] * state->r[2]) + ((uint64_t)state->h[2] * state->r[1]) + ((uint64_t)state->h[3] * state->r[0]) + ((uint64_t)state->h[4] * state->s[3]);
	tp4 = ((uint64_t)state->h[0] * state->r[4]) + ((uint64_t)state->h[1] * state->r[3]) + ((uint64_t)state->h[2] * state->r[2]) + ((uint64_t)state->h[3] * state->r[1]) + ((uint64_t)state->h[4] * state->r[0]);

	state->h[0] = (uint32_t)(tp0 & 0x3FFFFFFUL);
	b = (tp0 >> 26);
	tp1 += b;
	state->h[1] = (uint32_t)(tp1 & 0x3FFFFFFUL);
	b = (tp1 >> 26);
	tp2 += b;
	state->h[2] = (uint32_t)(tp2 & 0x3FFFFFFUL);
	b = (tp2 >> 26);
	tp3 += b;
	state->h[3] = (uint32_t)(tp3 & 0x3FFFFFFUL);
	b = (tp3 >> 26);
	tp4 += b;
	state->h[4] = (uint32_t)(tp4 & 0x3FFFFFFUL);
	b = (tp4 >> 26);
	state->h[0] += (uint32_t)(b * 5);
}

void poly1305_compute(uint8_t mac[POLY1305_MAC_SIZE], const uint8_t* message, size_t msglen, const uint8_t key[POLY1305_KEY_SIZE])
{
	poly1305_state state;

	poly1305_initialize(&state, key);
	poly1305_update(&state, message, msglen);
	poly1305_finalize(&state, mac);
}

void poly1305_finalize(poly1305_state* state, uint8_t mac[POLY1305_MAC_SIZE])
{
	uint32_t b;
	uint64_t f0;
	uint64_t f1;
	uint64_t f2;
	uint64_t f3;
	size_t i;
	uint32_t g0;
	uint32_t g1;
	uint32_t g2;
	uint32_t g3;
	uint32_t g4;
	uint32_t nb;

	if (state->rmd)
	{
		state->buf[state->rmd] = 1;

		for (i = state->rmd + 1; i < POLY1305_BLOCK_SIZE; i++)
		{
			state->buf[i] = 0;
		}

		state->fnl = 1;
		poly1305_blockupdate(state, state->buf);
	}

	b = state->h[0] >> 26;
	state->h[0] = state->h[0] & 0x3FFFFFFUL;
	state->h[1] += b;
	b = state->h[1] >> 26;
	state->h[1] = state->h[1] & 0x3FFFFFFUL;
	state->h[2] += b;
	b = state->h[2] >> 26;
	state->h[2] = state->h[2] & 0x3FFFFFFUL;
	state->h[3] += b;
	b = state->h[3] >> 26;
	state->h[3] = state->h[3] & 0x3FFFFFFUL;
	state->h[4] += b;
	b = state->h[4] >> 26;
	state->h[4] = state->h[4] & 0x3FFFFFFUL;
	state->h[0] += b * 5;

	g0 = state->h[0] + 5;
	b = g0 >> 26;
	g0 &= 0x3FFFFFFUL;
	g1 = state->h[1] + b;
	b = g1 >> 26;
	g1 &= 0x3FFFFFFUL;
	g2 = state->h[2] + b;
	b = g2 >> 26;
	g2 &= 0x3FFFFFFUL;
	g3 = state->h[3] + b;
	b = g3 >> 26;
	g3 &= 0x3FFFFFFUL;
	g4 = state->h[4] + b - (1 << 26);

	b = (g4 >> 31) - 1;
	nb = ~b;
	state->h[0] = (state->h[0] & nb) | (g0 & b);
	state->h[1] = (state->h[1] & nb) | (g1 & b);
	state->h[2] = (state->h[2] & nb) | (g2 & b);
	state->h[3] = (state->h[3] & nb) | (g3 & b);
	state->h[4] = (state->h[4] & nb) | (g4 & b);

	/* jgu: checked */
	/*lint -save -e647 */
	f0 = (state->h[0] | (state->h[1] << 26)) + (uint64_t)state->k[0];
	f1 = ((state->h[1] >> 6) | (state->h[2] << 20)) + (uint64_t)state->k[1];
	f2 = ((state->h[2] >> 12) | (state->h[3] << 14)) + (uint64_t)state->k[2];
	f3 = ((state->h[3] >> 18) | (state->h[4] << 8)) + (uint64_t)state->k[3];
	/*lint -restore */

	le32to8(mac + 0, (uint32_t)f0);
	f1 += (f0 >> 32);
	le32to8(mac + 4, (uint32_t)f1);
	f2 += (f1 >> 32);
	le32to8(mac + 8, (uint32_t)f2);
	f3 += (f2 >> 32);
	le32to8(mac + 12, (uint32_t)f3);

	poly1305_reset(state);
}

void poly1305_initialize(poly1305_state* state, const uint8_t key[POLY1305_KEY_SIZE])
{
	state->r[0] = (le8to32(&key[0])) & 0x3FFFFFFUL;
	state->r[1] = (le8to32(&key[3]) >> 2) & 0x3FFFF03UL;
	state->r[2] = (le8to32(&key[6]) >> 4) & 0x3FFC0FFUL;
	state->r[3] = (le8to32(&key[9]) >> 6) & 0x3F03FFFUL;
	state->r[4] = (le8to32(&key[12]) >> 8) & 0x00FFFFFUL;
	state->s[0] = state->r[1] * 5;
	state->s[1] = state->r[2] * 5;
	state->s[2] = state->r[3] * 5;
	state->s[3] = state->r[4] * 5;
	state->h[0] = 0;
	state->h[1] = 0;
	state->h[2] = 0;
	state->h[3] = 0;
	state->h[4] = 0;
	state->k[0] = le8to32(&key[16]);
	state->k[1] = le8to32(&key[20]);
	state->k[2] = le8to32(&key[24]);
	state->k[3] = le8to32(&key[28]);
	state->fnl = 0;
	state->rmd = 0;
}

void poly1305_reset(poly1305_state* state)
{
	clear32(state->h, 5);
	clear32(state->k, 4);
	clear32(state->r, 5);
	clear32(state->s, 4);
	clear8(state->buf, POLY1305_BLOCK_SIZE);
	state->rmd = 0;
	state->fnl = 0;
}

void poly1305_update(poly1305_state* state, const uint8_t* message, size_t msglen)
{
	size_t i;
	size_t rmd;

	if (state->rmd)
	{
		rmd = (POLY1305_BLOCK_SIZE - state->rmd);

		if (rmd > msglen)
		{
			rmd = msglen;
		}

		for (i = 0; i < rmd; ++i)
		{
			state->buf[state->rmd + i] = message[i];
		}

		msglen -= rmd;
		message += rmd;
		state->rmd += rmd;

		if (state->rmd == POLY1305_BLOCK_SIZE)
		{
			poly1305_blockupdate(state, state->buf);
			state->rmd = 0;
		}
	}

	while (msglen >= POLY1305_BLOCK_SIZE)
	{
		poly1305_blockupdate(state, message);
		message += POLY1305_BLOCK_SIZE;
		msglen -= POLY1305_BLOCK_SIZE;
	}

	if (msglen)
	{
		for (i = 0; i < msglen; ++i)
		{
			state->buf[state->rmd + i] = message[i];
		}

		state->rmd += msglen;
	}
}

mqc_status poly1305_verify(const uint8_t mac[POLY1305_MAC_SIZE], const uint8_t* message, size_t msglen, const uint8_t key[POLY1305_KEY_SIZE])
{
	uint8_t hash[POLY1305_MAC_SIZE];

	poly1305_compute(hash, message, msglen, key);

	return verify(mac, hash, POLY1305_MAC_SIZE) == 0 ? MQC_STATUS_SUCCESS : MQC_STATUS_FAILURE;
}

