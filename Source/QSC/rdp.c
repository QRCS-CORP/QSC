#include "rdp.h"
#include "cpuidex.h"
#include "intrinsics.h"
#include "intutils.h"
#include "sysutils.h"

#include "consoleutils.h"

/* the number of times to read from the RDRAND/RDSEED RNGs; each read generates 32 bits of output */
#define RDP_RNG_POLLS 32ULL
/* RDRAND is guaranteed to generate a random number within 10 retries on a working CPU */
#define RDP_RDR_RETRY 10ULL
/* RDSEED is not guaranteed to generate a random number within a specific number of retries */
#define RDP_RDS_RETRY 1000ULL
/* successful return of a rdrand step call */
#define RDP_RDR_SUCCESS 1ULL

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

			fret = _rdrand32_step((uint32_t*)&rnd32);

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

uint16_t qsc_rdp_uint16()
{
	uint8_t arr[sizeof(uint16_t)] = { 0 };
	uint16_t num;

	qsc_rdp_generate(arr, sizeof(arr));

	num = (((uint16_t)arr[1]) | 
		(uint16_t)((uint16_t)arr[0] << 8U));

	return num;
}

uint32_t qsc_rdp_uint32()
{
	uint8_t arr[sizeof(uint32_t)] = { 0 };
	uint32_t num;

	qsc_rdp_generate(arr, sizeof(arr));

	num = (uint32_t)(arr[3]) |
		(((uint32_t)(arr[2])) << 8) |
		(((uint32_t)(arr[1])) << 16) |
		(((uint32_t)(arr[0])) << 24);

	return num;
}

uint64_t qsc_rdp_uint64()
{
	uint8_t arr[sizeof(uint64_t)] = { 0 };
	uint64_t num;

	qsc_rdp_generate(arr, sizeof(arr));

	num = (uint64_t)(arr[7]) |
		(((uint64_t)(arr[6])) << 8) |
		(((uint64_t)(arr[5])) << 16) |
		(((uint64_t)(arr[4])) << 24) |
		(((uint64_t)(arr[3])) << 32) |
		(((uint64_t)(arr[2])) << 40) |
		(((uint64_t)(arr[1])) << 48) |
		(((uint64_t)(arr[0])) << 56);

	return num;
}
