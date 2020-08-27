#include "bcg.h"
#include "intutils.h"
#include "sha3.h"
#include "sysrand.h"

qsc_bcg_state bcg_state;

static bcg_fill_buffer()
{
	/* cache the block */
	if (bcg_state.rate == QSC_SHAKE_512_RATE)
	{
		//qsc_cshake512_squeezeblocks(&bcg_state.state, bcg_state.cache, 1);
	}
	else
	{
		//qsc_cshake256_squeezeblocks(&bcg_state.state, bcg_state.cache, 1);
	}

	/* reset cache counters */
	bcg_state.crmd = bcg_state.rate;
	bcg_state.cpos = 0;
}

static bcg_auto_reseed()
{
	if (bcg_state.pres && bcg_state.bctr >= QSC_BCG_RESEED_THRESHHOLD)
	{
		if (bcg_state.rate == QSC_SHAKE_512_RATE)
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_BCG512_SEED_SIZE];
			qsc_sysrand_getbytes(prand, sizeof(prand));

			qsc_cshake512_update(&bcg_state.state, prand, sizeof(prand));
		}
		else
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_BCG256_SEED_SIZE];
			qsc_sysrand_getbytes(prand, sizeof(prand));

			qsc_cshake256_update(&bcg_state.state, prand, sizeof(prand));
		}

		/* re-fill the buffer and reset counter */
		bcg_fill_buffer();
		bcg_state.bctr = 0;
	}
}

void qsc_bcg_initialize(const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predictive_resistance)
{
	assert(seedlen == QSC_BCG256_SEED_SIZE || seedlen == QSC_BCG512_SEED_SIZE);

	if (seedlen == QSC_BCG512_SEED_SIZE)
	{
		bcg_state.rate = QSC_SHAKE_512_RATE;
	}
	else if (seedlen == QSC_BCG256_SEED_SIZE)
	{
		bcg_state.rate = QSC_SHAKE_256_RATE;
	}

	qsc_clear8(bcg_state.cache, sizeof(bcg_state.cache));
	bcg_state.bctr = 0;
	bcg_state.cpos = 0;
	bcg_state.pres = predictive_resistance;
	qsc_clear64(&bcg_state.state, sizeof(bcg_state.state) / sizeof(uint64_t));

	if (bcg_state.rate == QSC_SHAKE_512_RATE)
	{
		if (bcg_state.pres)
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_BCG512_SEED_SIZE];
			qsc_sysrand_getbytes(prand, sizeof(prand));
			qsc_cshake512_initialize(&bcg_state.state, seed, seedlen, info, infolen, prand, sizeof(prand));
		}
		else
		{
			/* initialize with the seed and info */
			qsc_cshake512_initialize(&bcg_state.state, seed, seedlen, info, infolen, NULL, 0);
		}
	}
	else
	{
		if (bcg_state.pres)
		{
			uint8_t prand[QSC_BCG256_SEED_SIZE];
			qsc_sysrand_getbytes(prand, sizeof(prand));
			qsc_cshake256_initialize(&bcg_state.state, seed, seedlen, info, infolen, prand, sizeof(prand));
		}
		else
		{
			qsc_cshake256_initialize(&bcg_state.state, seed, seedlen, info, infolen, NULL, 0);
		}
	}

	/* cache the first block */
	bcg_fill_buffer();
}

void qsc_bcg_generate(uint8_t* output, size_t outlen)
{
	bcg_state.bctr += outlen;

	if (bcg_state.crmd < outlen)
	{
		size_t outpos;

		outpos = 0;

		/* copy remaining bytes from the cache */
		if (bcg_state.crmd != 0)
		{
			/* empty the state buffer */
			memcpy(output, bcg_state.cache + bcg_state.cpos, bcg_state.crmd);
			outpos += bcg_state.crmd;
			outlen -= bcg_state.crmd;
		}

		/* loop through the remainder */
		while (outlen != 0)
		{
			/* fill the buffer */
			bcg_fill_buffer();
			/* copy to output */
			const size_t RMDLEN = qsc_minu(bcg_state.crmd, outlen);
			memcpy(output + outpos, bcg_state.cache, RMDLEN);
			outlen -= RMDLEN;
			outpos += RMDLEN;
			bcg_state.crmd -= RMDLEN;
			bcg_state.cpos += RMDLEN;
		}
	}
	else
	{
		/* copy from the state buffer to output */
		const size_t RMDLEN = qsc_minu(bcg_state.crmd, outlen);
		memcpy(output, bcg_state.cache + bcg_state.cpos, RMDLEN);
		bcg_state.crmd -= RMDLEN;
		bcg_state.cpos += RMDLEN;
	}

	/* clear used bytes */
	if (bcg_state.crmd != 0)
	{
		memset(bcg_state.cache, 0x00, bcg_state.cpos);
	}

	/* reseed check */
	bcg_auto_reseed();
}

void qsc_bcg_update(const uint8_t* seed, size_t seedlen)
{
	/* absorb and permute */

	if (bcg_state.rate == QSC_SHAKE_512_RATE)
	{
		//qsc_cshake512_update(&bcg_state.state, seed, seedlen);
	}
	else
	{
		//qsc_cshake256_update(&bcg_state.state, seed, seedlen);
	}

	/* re-fill the buffer */
	bcg_fill_buffer();
}