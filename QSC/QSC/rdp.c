#include "rdp.h"
#include "cpuidex.h"
#include "intrinsics.h"
#include "intutils.h"
#include "sysutils.h"

#include "consoleutils.h"

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

	bool res;

#if defined(QSC_RDRAND_COMPATIBLE)

	qsc_cpuidex_cpu_features cfeat;
	size_t ectr;
	size_t pos;
	int32_t fret;
	bool hrand;
	bool hfeat;

	ectr = 0;
	pos = 0;
	res = true;
	hfeat = qsc_cpuidex_features_set(&cfeat);
	hrand = cfeat.rdrand;

	if (hrand == true && hfeat == true)
	{
		while (length != 0)
		{
#	if defined(QSC_SYSTEM_IS_X64)
			uint64_t rnd64;

			fret = _rdrand64_step((unsigned long long*)&rnd64);

			if (fret == RDP_RDR_SUCCESS)
			{
				const size_t RMDLEN = qsc_intutils_min(sizeof(uint64_t), length);

				for (size_t i = 0; i < RMDLEN; ++i)
				{
					output[pos + i] = (uint8_t)(rnd64 >> (i * 8));
				}

				pos += RMDLEN;
				length -= RMDLEN;
				ectr = 0;
			}
			else
			{
				++ectr;

				if (ectr > RDP_RDS_RETRY)
				{
					res = false;
					break;
				}
			}
#	else
			uint32_t rnd32;

			fret = _rdrand32_step((unsigned int*)&rnd32);

			if (fret == RDP_RDR_SUCCESS)
			{
				const size_t RMDLEN = qsc_intutils_min(sizeof(uint32_t), length);

				for (size_t i = 0; i < RMDLEN; ++i)
				{
					output[pos + i] = (uint8_t)(rnd32 >> (i * 8));
				}

				pos += RMDLEN;
				length -= RMDLEN;
				ectr = 0;
			}
			else
			{
				++ectr;

				if (ectr > RDP_RDS_RETRY)
				{
					res = false;
					break;
				}
			}
#	endif
		}
	}

#else

	res = false;

#endif

	return res;
}
