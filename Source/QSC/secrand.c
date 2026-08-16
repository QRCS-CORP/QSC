#include "secrand.h"
#include "memutils.h"

static qsc_secrand_state m_secrand_state;
static volatile int32_t m_secrand_users;
static volatile bool m_secrand_transition;

static void secrand_state_enter(void)
{
	bool entered;

	entered = false;

	while (entered == false)
	{
		while (qsc_async_atomic_bool_load(&m_secrand_transition) == true)
		{
			qsc_async_thread_sleep(1U);
		}

		qsc_async_atomic_int32_increment(&m_secrand_users);

		if (qsc_async_atomic_bool_load(&m_secrand_transition) == false)
		{
			entered = true;
		}
		else
		{
			qsc_async_atomic_int32_decrement(&m_secrand_users);
		}
	}
}

static void secrand_state_leave(void)
{
	qsc_async_atomic_int32_decrement(&m_secrand_users);
}

static void secrand_transition_lock(void)
{
	bool locked;

	locked = false;

	while (locked == false)
	{
		locked = qsc_async_atomic_bool_compare_exchange(&m_secrand_transition, false, true);

		if (locked == false)
		{
			qsc_async_thread_sleep(1U);
		}
	}

	while (qsc_async_atomic_int32_load(&m_secrand_users) != 0)
	{
		qsc_async_thread_sleep(1U);
	}
}

static void secrand_transition_unlock(void)
{
	qsc_async_atomic_bool_store(&m_secrand_transition, false);
}

int8_t qsc_secrand_next_char(void)
{
	uint8_t smp[sizeof(int8_t)] = { 0U };
	int8_t res;

	res = 0;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		res = (int8_t)smp[0U];
	}

	return res;
}

uint8_t qsc_secrand_next_uchar(void)
{
	uint8_t smp[sizeof(uint8_t)] = { 0U };
	uint8_t res;

	res = 0U;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		res = smp[0U];
	}

	return res;
}

double qsc_secrand_next_double(void)
{
	uint8_t smp[sizeof(uint64_t)] = { 0U };
	int64_t rnd;
	double res = 0.0;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		qsc_memutils_copy(&rnd, smp, sizeof(uint64_t));
		res = (double)(rnd >> 11U) * (1.0 / 9007199254740992.0);
		qsc_memutils_secure_erase(smp, sizeof(smp));
	}

	return res;
}

int16_t qsc_secrand_next_int16(void)
{
	uint8_t smp[sizeof(int16_t)] = { 0U };
	int16_t res;

	res = 0;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		qsc_memutils_copy(&res, smp, sizeof(int16_t));
	}

	return res;
}

int16_t qsc_secrand_next_int16_max(int16_t maximum)
{
	QSC_ASSERT(maximum > 0);

	const int16_t SMPMAX = (int16_t)(INT16_MAX - (INT16_MAX % maximum));
	int16_t x;
	int16_t ret;

	do
	{
		x = qsc_secrand_next_int16();
		ret = x % maximum;
	} while (x >= SMPMAX);

	return ret;
}

int16_t qsc_secrand_next_int16_maxmin(int16_t maximum, int16_t minimum)
{
	QSC_ASSERT(maximum != 0);
	QSC_ASSERT(maximum >= minimum);

	const int16_t SMPTHR = (maximum - minimum + 1);
	const int16_t SMPMAX = (int16_t)(INT16_MAX - (INT16_MAX % SMPTHR));
	int16_t x;
	int16_t ret;

	do
	{
		x = qsc_secrand_next_int16();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || x < minimum);

	return minimum + ret;
}

uint16_t qsc_secrand_next_uint16(void)
{
	uint8_t smp[sizeof(uint16_t)] = { 0U };
	uint16_t res;

	res = 0U;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		qsc_memutils_copy(&res, smp, sizeof(uint16_t));
	}

	return res;
}

uint16_t qsc_secrand_next_uint16_max(uint16_t maximum)
{
	QSC_ASSERT(maximum != 0U);

	const uint16_t SMPMAX = (uint16_t)(UINT16_MAX - (UINT16_MAX % maximum));
	uint16_t x;
	uint16_t ret;

	do
	{
		x = qsc_secrand_next_uint16();
		ret = x % maximum;
	} while (x >= SMPMAX);

	return ret;
}

uint16_t qsc_secrand_next_uint16_maxmin(uint16_t maximum, uint16_t minimum)
{
	QSC_ASSERT(maximum != 0U);
	QSC_ASSERT(maximum >= minimum);

	const uint16_t SMPTHR = (maximum - minimum + 1U);
	const uint16_t SMPMAX = (uint16_t)(UINT16_MAX - (UINT16_MAX % SMPTHR));
	uint16_t x;
	uint16_t ret;

	do
	{
		x = qsc_secrand_next_uint16();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || x < minimum);

	return minimum + ret;
}

int32_t qsc_secrand_next_int32(void)
{
	uint8_t smp[sizeof(int32_t)] = { 0U };
	int32_t res;

	res = 0;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		qsc_memutils_copy(&res, smp, sizeof(int32_t));
	}

	return res;
}

int32_t qsc_secrand_next_int32_max(int32_t maximum)
{
	QSC_ASSERT(maximum > 0);

	const int32_t SMPMAX = (INT32_MAX - (INT32_MAX % maximum));
	int32_t x;
	int32_t ret;

	do
	{
		x = qsc_secrand_next_int32();
		ret = x % maximum;
	} while (x >= SMPMAX);

	return ret;
}

int32_t qsc_secrand_next_int32_maxmin(int32_t maximum, int32_t minimum)
{
	QSC_ASSERT(maximum != 0);
	QSC_ASSERT(maximum >= minimum);

	const int32_t SMPTHR = (maximum - minimum + 1);
	const int32_t SMPMAX = (INT32_MAX - (INT32_MAX % SMPTHR));
	int32_t x;
	int32_t ret;

	do
	{
		x = qsc_secrand_next_int32();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || x < minimum);

	return minimum + ret;
}

uint32_t qsc_secrand_next_uint32(void)
{
	uint8_t smp[sizeof(uint32_t)] = { 0U };
	uint32_t res;

	res = 0U;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		qsc_memutils_copy(&res, smp, sizeof(uint32_t));
	}

	return res;
}

uint32_t qsc_secrand_next_uint32_max(uint32_t maximum)
{
	QSC_ASSERT(maximum != 0U);

	const uint32_t SMPMAX = (UINT32_MAX - (UINT32_MAX % maximum));
	uint32_t x;
	uint32_t ret;

	do
	{
		x = qsc_secrand_next_uint32();
		ret = x % maximum;
	} while (x >= SMPMAX);

	return ret;
}

uint32_t qsc_secrand_next_uint32_maxmin(uint32_t maximum, uint32_t minimum)
{
	QSC_ASSERT(maximum != 0U);
	QSC_ASSERT(maximum >= minimum);

	const uint32_t SMPTHR = (maximum - minimum + 1U);
	const uint32_t SMPMAX = (UINT32_MAX - (UINT32_MAX % SMPTHR));
	uint32_t x;
	uint32_t ret;

	do
	{
		x = qsc_secrand_next_uint32();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || x < minimum);

	return minimum + ret;
}

int64_t qsc_secrand_next_int64(void)
{
	uint8_t smp[sizeof(int64_t)] = { 0U };
	int64_t res;

	res = 0;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		qsc_memutils_copy(&res, smp, sizeof(int64_t));
	}

	return res;
}

int64_t qsc_secrand_next_int64_max(int64_t maximum)
{
	QSC_ASSERT(maximum > 0);

	const int64_t SMPMAX = (INT64_MAX - (INT64_MAX % maximum));
	int64_t x;
	int64_t ret;

	do
	{
		x = qsc_secrand_next_int64();
		ret = x % maximum;
	} while (x >= SMPMAX);

	return ret;
}

int64_t qsc_secrand_next_int64_maxmin(int64_t maximum, int64_t minimum)
{
	QSC_ASSERT(maximum != 0);
	QSC_ASSERT(maximum >= minimum);

	const int64_t SMPTHR = (maximum - minimum + 1);
	const int64_t SMPMAX = (INT64_MAX - (INT64_MAX % SMPTHR));
	int64_t x;
	int64_t ret;

	do
	{
		x = qsc_secrand_next_int64();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || x < minimum);

	return minimum + ret;
}

uint64_t qsc_secrand_next_uint64(void)
{
	uint8_t smp[sizeof(uint64_t)] = { 0U };
	uint64_t res;

	res = 0U;

	if (qsc_secrand_generate(smp, sizeof(smp)) == true)
	{
		qsc_memutils_copy(&res, smp, sizeof(uint64_t));
	}

	return res;
}

uint64_t qsc_secrand_next_uint64_max(uint64_t maximum)
{
	QSC_ASSERT(maximum != 0U);

	const uint64_t SMPMAX = (UINT64_MAX - (UINT64_MAX % maximum));
	uint64_t x;
	uint64_t ret;

	do
	{
		x = qsc_secrand_next_uint64();
		ret = x % maximum;
	} while (x >= SMPMAX);

	return ret;
}

uint64_t qsc_secrand_next_uint64_maxmin(uint64_t maximum, uint64_t minimum)
{
	QSC_ASSERT(maximum != 0U);
	QSC_ASSERT(maximum >= minimum);

	const uint64_t SMPTHR = (maximum - minimum + 1U);
	const uint64_t SMPMAX = (UINT64_MAX - (UINT64_MAX % SMPTHR));
	uint64_t x;
	uint64_t ret;

	do
	{
		x = qsc_secrand_next_uint64();
		ret = x % SMPTHR;
	} while (x >= SMPMAX || x < minimum);

	return minimum + ret;
}

void qsc_secrand_dispose(void)
{
	secrand_transition_lock();

	if (m_secrand_state.opmtx != NULL)
	{
		qsc_async_mutex_lock(m_secrand_state.opmtx);

		if (m_secrand_state.init == true)
		{
			qsc_memutils_secure_erase(m_secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
			qsc_csg_dispose(&m_secrand_state.hstate);
			m_secrand_state.cpos = 0U;
			m_secrand_state.init = false;
		}

		qsc_async_mutex_unlock(m_secrand_state.opmtx);
		qsc_async_mutex_destroy(m_secrand_state.opmtx);
		m_secrand_state.opmtx = NULL;
	}

	secrand_transition_unlock();
}

void qsc_secrand_initialize(const uint8_t* seed, size_t seedlen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(seedlen == QSC_CSG_256_SEED_SIZE || seedlen == QSC_CSG_512_SEED_SIZE);

	if (seed != NULL && (seedlen == QSC_CSG_256_SEED_SIZE || seedlen == QSC_CSG_512_SEED_SIZE))
	{
		secrand_transition_lock();

		if (m_secrand_state.opmtx == NULL)
		{
			m_secrand_state.opmtx = qsc_async_mutex_create();
		}

		if (m_secrand_state.opmtx != NULL)
		{
			qsc_async_mutex_lock(m_secrand_state.opmtx);

			if (m_secrand_state.init == true)
			{
				qsc_csg_dispose(&m_secrand_state.hstate);
				qsc_memutils_secure_erase(m_secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
			}

			/* initialize the underlying generator */
			qsc_csg_initialize(&m_secrand_state.hstate, seed, seedlen, custom, custlen, false);

			/* pre-fill the cache */
			qsc_csg_generate(&m_secrand_state.hstate, m_secrand_state.cache, QSC_SECRAND_CACHE_SIZE);

			m_secrand_state.cpos = 0U;
			m_secrand_state.init = true;

			qsc_async_mutex_unlock(m_secrand_state.opmtx);
		}

		secrand_transition_unlock();
	}
}

bool qsc_secrand_generate(uint8_t* output, size_t length)
{
	size_t buflen;
	size_t poft;
	bool res;

	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0);

	res = false;
	secrand_state_enter();

	if (m_secrand_state.opmtx != NULL)
	{
		qsc_async_mutex_lock(m_secrand_state.opmtx);

		if (output != NULL && length != 0 && m_secrand_state.init == true)
		{
			buflen = QSC_SECRAND_CACHE_SIZE - m_secrand_state.cpos;

			if (length > buflen)
			{
				poft = 0U;

				if (buflen > 0U)
				{
					qsc_memutils_copy(output, m_secrand_state.cache + m_secrand_state.cpos, buflen);
					length -= buflen;
					poft += buflen;
					m_secrand_state.cpos = QSC_SECRAND_CACHE_SIZE;
				}

				while (length >= QSC_SECRAND_CACHE_SIZE)
				{
					qsc_csg_generate(&m_secrand_state.hstate, m_secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
					qsc_memutils_copy(output + poft, m_secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
					qsc_memutils_secure_erase(m_secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
					length -= QSC_SECRAND_CACHE_SIZE;
					poft += QSC_SECRAND_CACHE_SIZE;
				}

				if (length != 0U)
				{
					qsc_csg_generate(&m_secrand_state.hstate, m_secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
					qsc_memutils_copy(output + poft, m_secrand_state.cache, length);
					m_secrand_state.cpos = length;
				}
			}
			else
			{
				qsc_memutils_copy(output, m_secrand_state.cache + m_secrand_state.cpos, length);
				m_secrand_state.cpos += length;
			}

			res = true;
		}

		if (m_secrand_state.cpos != 0U)
		{
			qsc_memutils_secure_erase(m_secrand_state.cache, m_secrand_state.cpos);
		}

		qsc_async_mutex_unlock(m_secrand_state.opmtx);
	}

	secrand_state_leave();

	return res;
}
