#include "secrand.h"
#include "memutils.h"

qsc_secrand_state secrand_state;

int8_t qsc_secrand_next_char()
{
	uint8_t smp[sizeof(int8_t)] = { 0 };
	qsc_secrand_generate(smp, sizeof(smp));

	return (int8_t)smp[0];
}

uint8_t qsc_secrand_next_uchar()
{
	uint8_t smp[sizeof(uint8_t)] = { 0 };
	qsc_secrand_generate(smp, sizeof(smp));

	return smp[0];
}

double qsc_secrand_next_double()
{
	uint8_t smp[sizeof(double)] = { 0 };
	double res;

	res = 0;
	qsc_secrand_generate(smp, sizeof(smp));
	qsc_memutils_copy(&res, smp, sizeof(double));

	return res;
}

int16_t qsc_secrand_next_int16()
{
	uint8_t smp[sizeof(int16_t)] = { 0 };
	int16_t res;

	res = 0;
	qsc_secrand_generate(smp, sizeof(smp));
	qsc_memutils_copy(&res, smp, sizeof(int16_t));

	return res;
}

int16_t qsc_secrand_next_int16_max(int16_t maximum)
{
	assert(maximum != 0);

	const int16_t SMPMAX = (int16_t)(INT16_MAX - (INT16_MAX % maximum));
	int16_t x;
	int16_t ret;

	do
	{
		x = qsc_secrand_next_int16();
		ret = x % maximum;
	} while (x >= SMPMAX || ret < 0);

	return ret;
}

int16_t qsc_secrand_next_int16_maxmin(int16_t maximum, int16_t minimum)
{
	assert(maximum != 0);
	assert(maximum > minimum);

	const int16_t SMPTHR = (maximum - minimum + 1);
	const int16_t SMPMAX = (int16_t)(INT16_MAX - (INT16_MAX % SMPTHR));
	int16_t x;
	int16_t ret;

	do
	{
		x = qsc_secrand_next_int16();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || ret < 0);

	return minimum + ret;
}

uint16_t qsc_secrand_next_uint16()
{
	uint8_t smp[sizeof(uint16_t)] = { 0 };
	uint16_t res;

	res = 0;
	qsc_secrand_generate(smp, sizeof(smp));
	qsc_memutils_copy(&res, smp, sizeof(uint16_t));

	return res;
}

uint16_t qsc_secrand_next_uint16_max(uint16_t maximum)
{
	assert(maximum != 0);

	const uint16_t SMPMAX = (uint16_t)(UINT16_MAX - (UINT16_MAX % maximum));
	uint16_t x;
	uint16_t ret;

	do
	{
		x = qsc_secrand_next_uint16();
		ret = x % maximum;
	} while (x >= SMPMAX || ret == 0);

	return ret;
}

uint16_t qsc_secrand_next_uint16_maxmin(uint16_t maximum, uint16_t minimum)
{
	assert(maximum != 0);
	assert(maximum > minimum);

	const uint16_t SMPTHR = (maximum - minimum + 1);
	const uint16_t SMPMAX = (uint16_t)(UINT16_MAX - (UINT16_MAX % SMPTHR));
	uint16_t x;
	uint16_t ret;

	do
	{
		x = qsc_secrand_next_uint16();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || ret == 0);

	return minimum + ret;
}

int32_t qsc_secrand_next_int32()
{
	uint8_t smp[sizeof(int32_t)] = { 0 };
	int32_t res;

	res = 0;
	qsc_secrand_generate(smp, sizeof(smp));
	qsc_memutils_copy(&res, smp, sizeof(int32_t));

	return res;
}

int32_t qsc_secrand_next_int32_max(int32_t maximum)
{
	assert(maximum != 0);

	const int32_t SMPMAX = (INT32_MAX - (INT32_MAX % maximum));
	int32_t x;
	int32_t ret;

	do
	{
		x = qsc_secrand_next_int32();
		ret = x % maximum;
	} while (x >= SMPMAX || ret < 0);

	return ret;
}

int32_t qsc_secrand_next_int32_maxmin(int32_t maximum, int32_t minimum)
{
	assert(maximum != 0);
	assert(maximum > minimum);

	const int32_t SMPTHR = (maximum - minimum + 1);
	const int32_t SMPMAX = (INT32_MAX - (INT32_MAX % SMPTHR));
	int32_t x;
	int32_t ret;

	do
	{
		x = qsc_secrand_next_int32();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || ret < 0);

	return minimum + ret;
}

uint32_t qsc_secrand_next_uint32()
{
	uint8_t smp[sizeof(uint32_t)] = { 0 };
	uint32_t res;

	res = 0;
	qsc_secrand_generate(smp, sizeof(smp));
	qsc_memutils_copy(&res, smp, sizeof(uint32_t));

	return res;
}

uint32_t qsc_secrand_next_uint32_max(uint32_t maximum)
{
	assert(maximum != 0);

	const uint32_t SMPMAX = (UINT32_MAX - (UINT32_MAX % maximum));
	uint32_t x;
	uint32_t ret;

	do
	{
		x = qsc_secrand_next_uint32();
		ret = x % maximum;
	} while (x >= SMPMAX || ret == 0);

	return ret;
}

uint32_t qsc_secrand_next_uint32_maxmin(uint32_t maximum, uint32_t minimum)
{
	assert(maximum != 0);
	assert(maximum > minimum);

	const uint32_t SMPTHR = (maximum - minimum + 1);
	const uint32_t SMPMAX = (UINT32_MAX - (UINT32_MAX % SMPTHR));
	uint32_t x;
	uint32_t ret;

	do
	{
		x = qsc_secrand_next_uint32();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || ret == 0);

	return minimum + ret;
}

int64_t qsc_secrand_next_int64()
{
	uint8_t smp[sizeof(int64_t)] = { 0 };
	int64_t res;

	res = 0;
	qsc_secrand_generate(smp, sizeof(smp));
	qsc_memutils_copy(&res, smp, sizeof(int64_t));

	return res;
}

int64_t qsc_secrand_next_int64_max(int64_t maximum)
{
	assert(maximum != 0);

	const int64_t SMPMAX = (INT64_MAX - (INT64_MAX % maximum));
	int64_t x;
	int64_t ret;

	do
	{
		x = qsc_secrand_next_int64();
		ret = x % maximum;
	} while (x >= SMPMAX || ret < 0);

	return ret;
}

int64_t qsc_secrand_next_int64_maxmin(int64_t maximum, int64_t minimum)
{
	assert(maximum != 0);
	assert(maximum > minimum);

	const int64_t SMPTHR = (maximum - minimum + 1);
	const int64_t SMPMAX = (INT64_MAX - (INT64_MAX % SMPTHR));
	int64_t x;
	int64_t ret;

	do
	{
		x = qsc_secrand_next_int64();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || ret < 0);

	return minimum + ret;
}

uint64_t qsc_secrand_next_uint64()
{
	uint8_t smp[sizeof(uint64_t)] = { 0 };
	uint64_t res;

	res = 0;
	qsc_secrand_generate(smp, sizeof(smp));
	qsc_memutils_copy(&res, smp, sizeof(uint64_t));

	return res;
}

uint64_t qsc_secrand_next_uint64_max(uint64_t maximum)
{
	assert(maximum != 0);

	const uint64_t SMPMAX = (UINT64_MAX - (UINT64_MAX % maximum));
	uint64_t x;
	uint64_t ret;

	do
	{
		x = qsc_secrand_next_uint64();
		ret = x % maximum;
	} while (x >= SMPMAX || ret == 0);

	return ret;
}

uint64_t qsc_secrand_next_uint64_maxmin(uint64_t maximum, uint64_t minimum)
{
	assert(maximum != 0);
	assert(maximum > minimum);

	const uint64_t SMPTHR = (maximum - minimum + 1);
	const uint64_t SMPMAX = (UINT64_MAX - (UINT64_MAX % SMPTHR));
	uint64_t x;
	uint64_t ret;

	do
	{
		x = qsc_secrand_next_uint64();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || ret == 0);

	return minimum + ret;
}

void qsc_secrand_destroy()
{
	if (secrand_state.init == true)
	{
		qsc_memutils_clear(secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
		qsc_csg_dispose(&secrand_state.hstate);
		secrand_state.cpos = 0;
		secrand_state.init = false;
	}
}

void qsc_secrand_initialize(const uint8_t* seed, size_t seedlen, const uint8_t* custom, size_t custlen)
{
	assert(seed != NULL);
	assert(seedlen == QSC_CSG256_SEED_SIZE || seedlen == QSC_CSG512_SEED_SIZE);

	/* initialize the underlying generator */
	qsc_csg_initialize(&secrand_state.hstate, seed, seedlen, custom, custlen, true);

	/* pre-fill the cache */
	qsc_csg_generate(&secrand_state.hstate, secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
	secrand_state.cpos = 0;
	secrand_state.init = true;
}

bool qsc_secrand_generate(uint8_t* output, size_t length)
{
	assert(secrand_state.init == true);

	const size_t BUFLEN = QSC_SECRAND_CACHE_SIZE - secrand_state.cpos;
	size_t poft;
	bool res;

	res = false;

	if (secrand_state.init != true)
	{
		output = NULL;
		length = 0;
	}

	if (length != 0)
	{
		if (length > BUFLEN)
		{
			poft = 0;

			if (BUFLEN > 0)
			{
				qsc_memutils_copy(output, secrand_state.cache + secrand_state.cpos, BUFLEN);
				length -= BUFLEN;
				poft += BUFLEN;
				secrand_state.cpos = QSC_SECRAND_CACHE_SIZE;
			}

			while (length >= QSC_SECRAND_CACHE_SIZE)
			{
				qsc_csg_generate(&secrand_state.hstate, secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
				qsc_memutils_copy(output + poft, secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
				length -= QSC_SECRAND_CACHE_SIZE;
				poft += QSC_SECRAND_CACHE_SIZE;
			}

			if (length != 0)
			{
				qsc_csg_generate(&secrand_state.hstate, secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
				qsc_memutils_copy(output + poft, secrand_state.cache, length);
				secrand_state.cpos = length;
			}
		}
		else
		{
			qsc_memutils_copy(output, secrand_state.cache + secrand_state.cpos, length);
			secrand_state.cpos += length;
		}

		res = true;
	}

	if (secrand_state.cpos != 0)
	{
		qsc_memutils_clear((uint8_t*)secrand_state.cache, secrand_state.cpos);
	}

	return res;
}
