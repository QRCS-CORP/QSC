/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

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

/**
 * \brief Sample a bounded 16-bit unsigned integer without modulo bias.
 * \param output: [uint16_t*] Receives the result on success; unchanged on failure.
 * \param span: [uint16_t] Exclusive range size; zero selects the full 16-bit domain.
 * \return [bool] True on successful generation, false if the generator is unavailable.
 * \details Uses the initialized global generator, which serializes its own state.
 */
static bool secrand_bounded_uint16(uint16_t* output, uint16_t span)
{
	uint16_t candidate;
	uint16_t threshold;
	bool res;

	candidate = 0U;
	threshold = (span != 0U) ? (uint16_t)((uint16_t)(0U - span) % span) : 0U;

	do
	{
		res = qsc_secrand_generate((uint8_t*)&candidate, sizeof(candidate));
	} while (res == true && candidate < threshold);

	if (res == true)
	{
		*output = (span == 0U) ? candidate : (uint16_t)(candidate % span);
	}

	qsc_memutils_secure_erase(&candidate, sizeof(candidate));

	return res;
}

/**
 * \brief Sample a bounded 32-bit unsigned integer without modulo bias.
 * \param output: [uint32_t*] Receives the result on success; unchanged on failure.
 * \param span: [uint32_t] Exclusive range size; zero selects the full 32-bit domain.
 * \return [bool] True on successful generation, false if the generator is unavailable.
 * \details Uses the initialized global generator, which serializes its own state.
 */
static bool secrand_bounded_uint32(uint32_t* output, uint32_t span)
{
	uint32_t candidate;
	uint32_t threshold;
	bool res;

	candidate = 0U;
	threshold = (span != 0U) ? (uint32_t)(0U - span) % span : 0U;

	do
	{
		res = qsc_secrand_generate((uint8_t*)&candidate, sizeof(candidate));
	} while (res == true && candidate < threshold);

	if (res == true)
	{
		*output = (span == 0U) ? candidate : candidate % span;
	}

	qsc_memutils_secure_erase(&candidate, sizeof(candidate));

	return res;
}

/**
 * \brief Sample a bounded 64-bit unsigned integer without modulo bias.
 * \param output: [uint64_t*] Receives the result on success; unchanged on failure.
 * \param span: [uint64_t] Exclusive range size; zero selects the full 64-bit domain.
 * \return [bool] True on successful generation, false if the generator is unavailable.
 * \details Uses the initialized global generator, which serializes its own state.
 */
static bool secrand_bounded_uint64(uint64_t* output, uint64_t span)
{
	uint64_t candidate;
	uint64_t threshold;
	bool res;

	candidate = 0U;
	threshold = (span != 0U) ? (uint64_t)(0ULL - span) % span : 0U;

	do
	{
		res = qsc_secrand_generate((uint8_t*)&candidate, sizeof(candidate));
	} while (res == true && candidate < threshold);

	if (res == true)
	{
		*output = (span == 0U) ? candidate : candidate % span;
	}

	qsc_memutils_secure_erase(&candidate, sizeof(candidate));

	return res;
}

int16_t qsc_secrand_next_int16_max(int16_t maximum)
{
	QSC_ASSERT(maximum > 0);

	return (maximum > 0) ? qsc_secrand_next_int16_maxmin(maximum, (int16_t)(-maximum)) : 0;
}

int16_t qsc_secrand_next_int16_maxmin(int16_t maximum, int16_t minimum)
{
	QSC_ASSERT(maximum >= minimum);

	int16_t res;
	uint16_t sample;
	uint16_t span;

	res = 0;
	sample = 0U;

	if (maximum >= minimum)
	{
		span = (uint16_t)((int32_t)maximum - (int32_t)minimum + 1);

		if (secrand_bounded_uint16(&sample, span) == true)
		{
			res = (int16_t)((int32_t)minimum + (int32_t)sample);
		}
	}

	return res;
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
	return qsc_secrand_next_uint16_maxmin(maximum, 0U);
}

uint16_t qsc_secrand_next_uint16_maxmin(uint16_t maximum, uint16_t minimum)
{
	QSC_ASSERT(maximum >= minimum);

	uint16_t res;
	uint16_t sample;
	uint16_t span;

	res = 0;
	sample = 0U;

	if (maximum >= minimum)
	{
		span = (uint16_t)((uint32_t)maximum - (uint32_t)minimum + 1U);

		if (secrand_bounded_uint16(&sample, span) == true)
		{
			res = (uint16_t)(minimum + sample);
		}
	}

	return res;
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

	return (maximum > 0) ? qsc_secrand_next_int32_maxmin(maximum, (int32_t)(-maximum)) : 0;
}

int32_t qsc_secrand_next_int32_maxmin(int32_t maximum, int32_t minimum)
{
	QSC_ASSERT(maximum >= minimum);

	int32_t res;
	uint32_t sample;
	uint32_t span;

	res = 0;
	sample = 0U;

	if (maximum >= minimum)
	{
		span = (uint32_t)((int64_t)maximum - (int64_t)minimum + 1LL);

		if (secrand_bounded_uint32(&sample, span) == true)
		{
			res = (int32_t)((int64_t)minimum + (int64_t)sample);
		}
	}

	return res;
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
	return qsc_secrand_next_uint32_maxmin(maximum, 0U);
}

uint32_t qsc_secrand_next_uint32_maxmin(uint32_t maximum, uint32_t minimum)
{
	QSC_ASSERT(maximum >= minimum);

	uint32_t res;
	uint32_t sample;
	uint32_t span;

	res = 0;
	sample = 0U;

	if (maximum >= minimum)
	{
		span = (uint32_t)(maximum - minimum + 1U);

		if (secrand_bounded_uint32(&sample, span) == true)
		{
			res = (uint32_t)(minimum + sample);
		}
	}

	return res;
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

	return (maximum > 0) ? qsc_secrand_next_int64_maxmin(maximum, (int64_t)(-maximum)) : 0;
}

int64_t qsc_secrand_next_int64_maxmin(int64_t maximum, int64_t minimum)
{
	QSC_ASSERT(maximum >= minimum);

	int64_t res;
	uint64_t sample;
	uint64_t span;

	res = 0;
	sample = 0U;

	if (maximum >= minimum)
	{
		span = (uint64_t)((uint64_t)maximum - (uint64_t)minimum + 1ULL);

		if (secrand_bounded_uint64(&sample, span) == true)
		{
			uint64_t resultbits;

			resultbits = (uint64_t)minimum + sample;
			qsc_memutils_copy(&res, &resultbits, sizeof(res));
		}
	}

	return res;
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
	return qsc_secrand_next_uint64_maxmin(maximum, 0U);
}

uint64_t qsc_secrand_next_uint64_maxmin(uint64_t maximum, uint64_t minimum)
{
	QSC_ASSERT(maximum >= minimum);

	uint64_t res;
	uint64_t sample;
	uint64_t span;

	res = 0;
	sample = 0U;

	if (maximum >= minimum)
	{
		span = (uint64_t)(maximum - minimum + 1ULL);

		if (secrand_bounded_uint64(&sample, span) == true)
		{
			res = (uint64_t)(minimum + sample);
		}
	}

	return res;
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
