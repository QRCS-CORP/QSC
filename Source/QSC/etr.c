#include "etr.h"
#include "memutils.h"
#include "sha3.h"

#define ETR_SOURCE_MIN_SIZE 64U
#define ETR_SOURCE_MAX_SIZE 1024U

typedef struct
{
	qsc_etr_source_callback source;
	void* context;
} etr_provider_state;

static etr_provider_state m_etr_state = { NULL, NULL };

void qsc_etr_dispose(void)
{
	m_etr_state.source = NULL;
	m_etr_state.context = NULL;
}

bool qsc_etr_generate(uint8_t* output, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);
	QSC_ASSERT(length <= QSC_ETR_SEED_MAX);

	qsc_keccak_state kstate;
	uint8_t previous[ETR_SOURCE_MAX_SIZE] = { 0U };
	uint8_t source_buffer[ETR_SOURCE_MAX_SIZE] = { 0U };
	qsc_etr_source_callback source;
	void* context;
	size_t compare_length;
	size_t consumed;
	size_t previous_length;
	size_t remaining;
	size_t source_length;
	size_t written;
	bool source_result;
	bool source_zeroed;
	bool res;

	res = false;

	if (output != NULL && length != 0U && length <= QSC_ETR_SEED_MAX)
	{
		qsc_memutils_clear(output, length);
		source = m_etr_state.source;
		context = m_etr_state.context;

		if (source != NULL)
		{
			qsc_keccak_initialize_state(&kstate);
			previous_length = 0U;
			remaining = length;
			res = true;

			while (remaining != 0U && res == true)
			{
				source_length = (remaining > ETR_SOURCE_MAX_SIZE) ? ETR_SOURCE_MAX_SIZE : remaining;

				if (source_length < ETR_SOURCE_MIN_SIZE)
				{
					source_length = ETR_SOURCE_MIN_SIZE;
				}

				qsc_memutils_clear(source_buffer, sizeof(source_buffer));
				written = 0U;
				source_result = source(source_buffer, source_length, &written, context);
				source_zeroed = qsc_memutils_zeroed(source_buffer, source_length);

				if (source_result == false || written != source_length || source_zeroed == true)
				{
					res = false;
				}
				else if (qsc_memutils_array_uniform(source_buffer, source_length) == true)
				{
					res = false;
				}
				else if (previous_length != 0U)
				{
					compare_length = (previous_length < source_length) ? previous_length : source_length;

					if (qsc_memutils_are_equal(previous, source_buffer, compare_length) == true)
					{
						res = false;
					}
				}

				if (res == true)
				{
					qsc_keccak_incremental_absorb(&kstate, qsc_keccak_rate_512, source_buffer, source_length);
					qsc_memutils_clear(previous, sizeof(previous));
					qsc_memutils_copy(previous, source_buffer, source_length);
					previous_length = source_length;
					consumed = (remaining < source_length) ? remaining : source_length;
					remaining -= consumed;
				}

				qsc_memutils_secure_erase(source_buffer, sizeof(source_buffer));
			}

			if (res == true)
			{
				qsc_keccak_incremental_finalize(&kstate, qsc_keccak_rate_512, QSC_KECCAK_SHAKE_DOMAIN_ID);
				qsc_keccak_incremental_squeeze(&kstate, qsc_keccak_rate_512, output, length);
			}

			qsc_keccak_dispose(&kstate);
			qsc_memutils_secure_erase(previous, sizeof(previous));
			qsc_memutils_secure_erase(source_buffer, sizeof(source_buffer));
		}
	}

	if (res == false && output != NULL && length != 0U && length <= QSC_ETR_SEED_MAX)
	{
		qsc_memutils_secure_erase(output, length);
	}

	return res;
}

bool qsc_etr_initialize(qsc_etr_source_callback source, void* context)
{
	QSC_ASSERT(source != NULL);

	bool res;

	res = false;

	if (source != NULL && m_etr_state.source == NULL)
	{
		m_etr_state.source = source;
		m_etr_state.context = context;
		res = true;
	}

	return res;
}
