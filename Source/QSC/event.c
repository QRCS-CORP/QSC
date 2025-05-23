#include "event.h"
#include "async.h"
#include "memutils.h"
#include "stringutils.h"

/*!
* \struct event_state
* \brief The internal event state
*/
typedef struct
{
	qsc_event_handler* listeners;	/*!< The event listeners  */
	size_t lcount;					/*!< The listener count  */
} event_state;

event_state m_event_state;

int32_t qsc_event_register(const char name[QSC_EVENT_NAME_SIZE], qsc_event_callback callback)
{
	QSC_ASSERT(name != NULL);
    QSC_ASSERT(callback != NULL);

	qsc_mutex mtx;
	qsc_event_handler* hndr;
	qsc_event_handler* tevh;
	size_t idx;
	int32_t res;

	res = -1;

	if (name != NULL && callback != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();
		tevh = NULL;

		if (m_event_state.listeners == NULL)
		{
			m_event_state.lcount = 1U;
			tevh = (qsc_event_handler*)qsc_memutils_malloc(sizeof(qsc_event_handler));
		}
		else
		{
			++m_event_state.lcount;
			tevh = (qsc_event_handler*)qsc_memutils_realloc(m_event_state.listeners, m_event_state.lcount * sizeof(qsc_event_handler));
		}

		if (tevh != NULL)
		{
			m_event_state.listeners = tevh;
			idx = m_event_state.lcount - 1U;
			hndr = &m_event_state.listeners[idx];

			if (m_event_state.listeners != NULL && hndr != NULL)
			{
				hndr->callback = callback;
				qsc_memutils_copy(hndr->name, name, QSC_EVENT_NAME_SIZE);
				res = 0;
			}
		}
		else
		{
			res = -1;
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

void qsc_event_clear_listener(const char name[QSC_EVENT_NAME_SIZE])
{
	QSC_ASSERT(name != NULL);
	QSC_ASSERT(m_event_state.lcount <= QSC_EVENT_MAX_LISTENERS);

	if (name != NULL && m_event_state.lcount <= QSC_EVENT_MAX_LISTENERS && 
		m_event_state.lcount != 0U && m_event_state.listeners != NULL)
	{
		qsc_event_handler* hndr;

		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < m_event_state.lcount; ++i)
		{
			hndr = &m_event_state.listeners[i];

			if (hndr != NULL)
			{
				if (qsc_stringutils_compare_strings(name, hndr->name, QSC_EVENT_NAME_SIZE))
				{
					qsc_memutils_clear(hndr, sizeof(qsc_event_handler));
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}
}

qsc_event_callback qsc_event_get_callback(const char name[QSC_EVENT_NAME_SIZE])
{
	QSC_ASSERT(name != NULL);
	QSC_ASSERT(m_event_state.lcount <= QSC_EVENT_MAX_LISTENERS);

	qsc_event_callback hres = { 0U };

	if (name != NULL && m_event_state.lcount <= QSC_EVENT_MAX_LISTENERS && 
		m_event_state.lcount != 0U && m_event_state.listeners != NULL)
	{
		qsc_event_handler* hndr;

		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < m_event_state.lcount; ++i)
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

		qsc_async_mutex_unlock_ex(mtx);
	}

	return hres;
}

void qsc_event_destroy_listeners()
{
	if (m_event_state.listeners != NULL)
	{
		qsc_memutils_clear(m_event_state.listeners, m_event_state.lcount * sizeof(qsc_event_handler));
		m_event_state.lcount = 0U;

		qsc_memutils_alloc_free(m_event_state.listeners);
		m_event_state.listeners = NULL;
	}
}
