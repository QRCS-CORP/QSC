#include "csg.h"
#include "intutils.h"
#include "memutils.h"
#include "csp.h"

qsc_csg_state csg_state;

static csg_fill_buffer()
{
	/* cache the block */
	if (csg_state.rate == QSC_SHAKE_512_RATE)
	{
		qsc_cshake512_squeezeblocks(&csg_state.kstate, csg_state.cache, 1);
	}
	else
	{
		qsc_cshake256_squeezeblocks(&csg_state.kstate, csg_state.cache, 1);
	}

	/* reset cache counters */
	csg_state.crmd = csg_state.rate;
	csg_state.cpos = 0;
}

static csg_auto_reseed()
{
	if (csg_state.pres && csg_state.bctr >= QSC_CSG_RESEED_THRESHHOLD)
	{
		if (csg_state.rate == QSC_SHAKE_512_RATE)
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_CSG512_SEED_SIZE];
			qsc_csp_generate(prand, sizeof(prand));

			qsc_cshake512_update(&csg_state.kstate, prand, sizeof(prand));
		}
		else
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_CSG256_SEED_SIZE];
			qsc_csp_generate(prand, sizeof(prand));

			qsc_cshake256_update(&csg_state.kstate, prand, sizeof(prand));
		}

		/* re-fill the buffer and reset counter */
		csg_fill_buffer();
		csg_state.bctr = 0;
	}
}

void qsc_csg_initialize(const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predictive_resistance)
{
	assert(seed != NULL);
	assert(seedlen == QSC_CSG256_SEED_SIZE || seedlen == QSC_CSG512_SEED_SIZE);

	if (seedlen == QSC_CSG512_SEED_SIZE)
	{
		csg_state.rate = QSC_SHAKE_512_RATE;
	}
	else if (seedlen == QSC_CSG256_SEED_SIZE)
	{
		csg_state.rate = QSC_SHAKE_256_RATE;
	}

	qsc_intutils_clear8(csg_state.cache, sizeof(csg_state.cache));
	csg_state.bctr = 0;
	csg_state.cpos = 0;
	csg_state.pres = predictive_resistance;
	qsc_intutils_clear64(csg_state.kstate.state, sizeof(csg_state.kstate.state) / sizeof(uint64_t));

	if (csg_state.rate == QSC_SHAKE_512_RATE)
	{
		if (csg_state.pres)
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_CSG512_SEED_SIZE];
			qsc_csp_generate(prand, sizeof(prand));
			qsc_cshake512_initialize(&csg_state.kstate, seed, seedlen, info, infolen, prand, sizeof(prand));
		}
		else
		{
			/* initialize with the seed and info */
			qsc_cshake512_initialize(&csg_state.kstate, seed, seedlen, info, infolen, NULL, 0);
		}
	}
	else
	{
		if (csg_state.pres)
		{
			uint8_t prand[QSC_CSG256_SEED_SIZE];
			qsc_csp_generate(prand, sizeof(prand));
			qsc_cshake256_initialize(&csg_state.kstate, seed, seedlen, info, infolen, prand, sizeof(prand));
		}
		else
		{
			qsc_cshake256_initialize(&csg_state.kstate, seed, seedlen, info, infolen, NULL, 0);
		}
	}

	/* cache the first block */
	csg_fill_buffer();
}

void qsc_csg_generate(uint8_t* output, size_t outlen)
{
	assert(output != NULL);

	csg_state.bctr += outlen;

	if (csg_state.crmd < outlen)
	{
		size_t outpos;

		outpos = 0;

		/* copy remaining bytes from the cache */
		if (csg_state.crmd != 0)
		{
			/* empty the state buffer */
			qsc_memutils_copy(output, csg_state.cache + csg_state.cpos, csg_state.crmd);
			outpos += csg_state.crmd;
			outlen -= csg_state.crmd;
		}

		/* loop through the remainder */
		while (outlen != 0)
		{
			/* fill the buffer */
			csg_fill_buffer();
			/* copy to output */
			const size_t RMDLEN = qsc_intutils_min(csg_state.crmd, outlen);
			qsc_memutils_copy(output + outpos, csg_state.cache, RMDLEN);
			outlen -= RMDLEN;
			outpos += RMDLEN;
			csg_state.crmd -= RMDLEN;
			csg_state.cpos += RMDLEN;
		}
	}
	else
	{
		/* copy from the state buffer to output */
		const size_t RMDLEN = qsc_intutils_min(csg_state.crmd, outlen);
		qsc_memutils_copy(output, csg_state.cache + csg_state.cpos, RMDLEN);
		csg_state.crmd -= RMDLEN;
		csg_state.cpos += RMDLEN;
	}

	/* clear used bytes */
	if (csg_state.crmd != 0)
	{
		qsc_memutils_clear((uint8_t*)csg_state.cache, csg_state.cpos);
	}

	/* reseed check */
	csg_auto_reseed();
}

void qsc_csg_update(const uint8_t* seed, size_t seedlen)
{
	assert(seed != NULL);

	/* absorb and permute */

	if (csg_state.rate == QSC_SHAKE_512_RATE)
	{
		qsc_cshake512_update(&csg_state.kstate, seed, seedlen);
	}
	else
	{
		qsc_cshake256_update(&csg_state.kstate, seed, seedlen);
	}

	/* re-fill the buffer */
	csg_fill_buffer();
}