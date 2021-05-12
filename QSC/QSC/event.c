#include "event.h"
#include <stdio.h>
#include <stdlib.h>

qsc_event_handlers* listeners[QSC_EVENT_LIST_LENGTH];

int32_t qsc_event_register(qsc_event_list event, qsc_event_callback callback)
{
	qsc_event_handlers* hndr;
	int32_t res;

	res = 0;
	hndr = listeners[event];

	if (hndr == NULL)
	{
		hndr = (qsc_event_handlers*)malloc(sizeof(qsc_event_handlers));

		if (hndr != NULL)
		{
			hndr->callback = callback;
			hndr->next = NULL;
			listeners[event] = hndr;
		}
		else
		{
			res = -1;
		}
	}
	else
	{
		while (hndr->next != NULL)
		{
			hndr = hndr->next;

			if (hndr->callback == callback)
			{
				res = -1;
				break;
			}
		}

		if (res == 0)
		{
			qsc_event_handlers* nhnd;

			nhnd = (qsc_event_handlers*)malloc(sizeof(qsc_event_handlers));

			if (nhnd != NULL)
			{
				nhnd->callback = callback;
				nhnd->next = NULL;
				hndr->next = nhnd;
			}
			else
			{
				res = -1;
			}
		}
	}

	return res;
}

void qsc_event_init_listeners(qsc_event_handlers* handlers[QSC_EVENT_LIST_LENGTH])
{
	size_t i;

	for (i = 0; i < QSC_EVENT_LIST_LENGTH; ++i)
	{
		handlers[i] = NULL;
	}
}

void qsc_event_destroy_listeners(qsc_event_handlers* handlers[QSC_EVENT_LIST_LENGTH])
{
	size_t i;
	qsc_event_handlers* dh;
	qsc_event_handlers* next;

	for (i = 0; i < QSC_EVENT_LIST_LENGTH; i++)
	{
		dh = handlers[i];

		while (dh)
		{
			next = dh->next;
			free(dh);
			dh = next;
		}
	}
}