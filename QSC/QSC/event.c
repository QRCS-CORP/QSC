#include "event.h"
#include "memutils.h"
#include "stringutils.h"

typedef struct
{
	qsc_event_handler* listeners;
	size_t lcount;
} event_state;

event_state m_event_state;

int32_t qsc_event_register(const char name[QSC_EVENT_NAME_SIZE], qsc_event_callback callback)
{
	qsc_event_handler* hndr;
	size_t idx;
	int32_t res;

	res = -1;

	if (m_event_state.listeners == NULL)
	{
		m_event_state.lcount = 1;
		m_event_state.listeners = (qsc_event_handler*)qsc_memutils_malloc(sizeof(qsc_event_handler));
	}
	else
	{
		++m_event_state.lcount;
		m_event_state.listeners = (qsc_event_handler*)qsc_memutils_realloc(m_event_state.listeners, m_event_state.lcount * sizeof(qsc_event_handler));
	}

	idx = m_event_state.lcount - 1;
	hndr = &m_event_state.listeners[idx];

	if (m_event_state.listeners != NULL && hndr != NULL)
	{
		hndr->callback = callback;
		qsc_memutils_copy(hndr->name, name, QSC_EVENT_NAME_SIZE);
		res = 0;
	}

	return res;
}

void qsc_event_clear_listener(const char name[QSC_EVENT_NAME_SIZE])
{
	qsc_event_handler* hndr;

	for (size_t i = 0; i < m_event_state.lcount; ++i)
	{
		hndr = &m_event_state.listeners[i];

		if (hndr != NULL)
		{
			if (qsc_stringutils_compare_strings(name, hndr->name, QSC_EVENT_NAME_SIZE) == true)
			{
				qsc_memutils_clear(hndr, sizeof(qsc_event_handler));
				break;
			}
		}
	}
}

qsc_event_callback qsc_event_get_callback(const char name[QSC_EVENT_NAME_SIZE])
{
	qsc_event_handler* hndr;
	qsc_event_callback hres = { 0 };

	for (size_t i = 0; i < m_event_state.lcount; ++i)
	{
		hndr = &m_event_state.listeners[i];

		if (hndr != NULL)
		{
			if (qsc_stringutils_compare_strings(name, hndr->name, QSC_EVENT_NAME_SIZE) == true)
			{
				hres = hndr->callback;
				break;
			}
		}
	}

	return hres;
}

void qsc_event_destroy_listeners()
{
	if (m_event_state.listeners != NULL)
	{
		qsc_memutils_clear(m_event_state.listeners, m_event_state.lcount * sizeof(qsc_event_handler));
		m_event_state.lcount = 0;
	}

	qsc_memutils_alloc_free(m_event_state.listeners);
}
