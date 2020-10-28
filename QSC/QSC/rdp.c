#include "rdp.h"
#include "intutils.h"
#include "intrinsics.h"
#include "sysutils.h"

/* the number of times to read from the RDRAND/RDSEED RNGs; each read generates 32 bits of output */
#define RDP_RNG_POLLS 32
/* RDRAND is guaranteed to generate a random number within 10 retries on a working CPU */
#define RDP_RDR_RETRY 10
/* RDSEED is not guaranteed to generate a random number within a specific number of retries */
#define RDP_RDS_RETRY 1000
/* successful return of a rdrand step call */
#define RDP_RDR_SUCCESS 1

bool qsc_rdp_generate(uint8_t* output, size_t length)
{
	assert(output != 0);
	assert(length <= QSC_RDP_SEED_MAX);

	size_t fctr;
	size_t i;
	size_t poff;
	int fret;
	bool hasrand;
	bool hasseed;
	bool res;

	res = true;
	fctr = 0;
	poff = 0;
	fret = 0;
	hasrand = qsc_sysutils_rdrand_available();
	hasseed = qsc_sysutils_rdseed_available();

#if defined(QSC_SYSTEM_AVX_INTRINSICS)

#	if defined(QSC_SYSTEM_IS_X64)

	uint64_t rnd64;

	while (length != 0)
	{
		rnd64 = 0;

		if (hasseed)
		{
			fret = _rdseed64_step(&rnd64);
		}
		else if (hasrand)
		{
			fret = _rdrand64_step(&rnd64);
		}
		else
		{
			res = false;
			break;
		}

		if (fret == RDP_RDR_SUCCESS)
		{
			const size_t RMDLEN = qsc_intutils_min(sizeof(uint64_t), length);

			for (i = 0; i < RMDLEN; ++i)
			{
				output[poff + i] = (uint8_t)(rnd64 >> (i * 8));
			}

			poff += RMDLEN;
			length -= RMDLEN;
			fctr = 0;
		}
		else
		{
			++fctr;

			if (fctr > RDP_RDS_RETRY)
			{
				res = false;
				break;
			}
		}
	}

#	else

	uint32_t rnd32;

	while (length != 0)
	{
		rnd32 = 0;

		if (hasseed)
		{
			fret = _rdseed32_step(&rnd32);
		}
		else if (hasrand)
		{
			fret = _rdrand32_step(&rnd32);
		}
		else
		{
			res = false;
			break;
		}

		if (fret == RDP_RDR_SUCCESS)
		{
			const size_t RMDLEN = qsc_intutils_min(sizeof(uint32_t), length);

			for (i = 0; i < RMDLEN; ++i)
			{
				output[poff + i] = (uint8_t)(rnd32 >> (i * 8));
			}

			poff += RMDLEN;
			length -= RMDLEN;
			fctr = 0;
		}
		else
		{
			++fctr;

			if (fctr > RDP_RDS_RETRY)
			{
				res = false;
				break;
			}
		}
	}
#	endif

#else
	res = false;
#endif

	return res;
}