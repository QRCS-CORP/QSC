#include "rdp.h"
#include "cpuidex.h"
#include "intrinsics.h"
#include "intutils.h"
#include "memutils.h"
#include "sysutils.h"

/* RDRAND is guaranteed to generate a random number within 10 retries on a working CPU */
#define RDP_RDR_RETRY 10U
/* successful return of a rdrand step call */
#define RDP_RDR_SUCCESS 1

bool qsc_rdp_generate(uint8_t* output, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);
	QSC_ASSERT(length <= QSC_RDP_SEED_MAX);

	bool res;

	res = false;

	if (output != NULL && length != 0U && length <= QSC_RDP_SEED_MAX)
	{
#if defined(QSC_RDRAND_COMPATIBLE)
		qsc_cpuidex_cpu_features cfeat;

		size_t ectr;
		size_t pos;
		size_t rmd;
		size_t rmdlen;
		int32_t fret;
		bool hrand;
		bool hfeat;
		hfeat = qsc_cpuidex_features_set(&cfeat);
		hrand = cfeat.rdrand;

		if (hrand && hfeat)
		{
			ectr = 0U;
			pos = 0U;
			rmd = length;
			res = true;

			while (rmd != 0U && ectr <= RDP_RDR_RETRY)
			{
#	if defined(QSC_SYSTEM_IS_X64)
				uint64_t rnd64;

				fret = _rdrand64_step((unsigned long long*) & rnd64);

				if (fret == RDP_RDR_SUCCESS)
				{
					rmdlen = qsc_intutils_min(sizeof(uint64_t), rmd);

					for (size_t i = 0U; i < rmdlen; ++i)
					{
						output[pos + i] = (uint8_t)(rnd64 >> (i * 8U));
					}

					pos += rmdlen;
					rmd -= rmdlen;
					ectr = 0U;
				}
				else
				{
					++ectr;

					if (ectr > RDP_RDR_RETRY)
					{
						res = false;
					}
				}
#	else
				uint32_t rnd32;

				fret = _rdrand32_step((uint32_t*)&rnd32);

				if (fret == RDP_RDR_SUCCESS)
				{
					rmdlen = qsc_intutils_min(sizeof(uint32_t), rmd);

					for (size_t i = 0U; i < rmdlen; ++i)
					{
						output[pos + i] = (uint8_t)(rnd32 >> (i * 8U));
					}

					pos += rmdlen;
					rmd -= rmdlen;
					ectr = 0U;
				}
				else
				{
					++ectr;

					if (ectr > RDP_RDR_RETRY)
					{
						res = false;
						break;
					}
				}
#	endif
			}
		}
		else
		{
			res = false;
		}
#else
		res = false;
#endif
	}

	if (!res)
	{
		qsc_memutils_clear(output, length);
	}

	return res;
}

uint16_t qsc_rdp_uint16()
{
	uint8_t arr[sizeof(uint16_t)] = { 0U };
	uint16_t num;

	num = 0U;

	if (qsc_rdp_generate(arr, sizeof(arr)))
	{
		num = (((uint16_t)arr[1]) |
			(uint16_t)((uint16_t)arr[0U] << 8U));
	}

	return num;
}

uint32_t qsc_rdp_uint32()
{
	uint8_t arr[sizeof(uint32_t)] = { 0U };
	uint32_t num;

	num = 0U;

	if (qsc_rdp_generate(arr, sizeof(arr)))
	{
		num = (uint32_t)(arr[3U]) |
			(((uint32_t)(arr[2U])) << 8) |
			(((uint32_t)(arr[1U])) << 16) |
			(((uint32_t)(arr[0U])) << 24);
	}

	return num;
}

uint64_t qsc_rdp_uint64()
{
	uint8_t arr[sizeof(uint64_t)] = { 0U };
	uint64_t num;

	num = 0U;

	if (qsc_rdp_generate(arr, sizeof(arr)))
	{
		num = (uint64_t)(arr[7U]) |
			(((uint64_t)(arr[6U])) << 8) |
			(((uint64_t)(arr[5U])) << 16) |
			(((uint64_t)(arr[4U])) << 24) |
			(((uint64_t)(arr[3U])) << 32) |
			(((uint64_t)(arr[2U])) << 40) |
			(((uint64_t)(arr[1U])) << 48) |
			(((uint64_t)(arr[0U])) << 56);
	}

	return num;
}
