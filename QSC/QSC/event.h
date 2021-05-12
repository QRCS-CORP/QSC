/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Written by John G. Underhill
* Updated on November 11, 2020
* Contact: develop@vtdev.com */

#ifndef QSC_EVENT_H
#define QSC_EVENT_H

#include "common.h"

#define QSC_EVENT_LIST_LENGTH 4

typedef void (*qsc_event_callback)(void*);

/*! \enum qsc_event_list
* \brief The event types enumeration
*/
typedef enum qsc_event_list
{
	qsc_event_receive_callback = 0,
	qsc_event_send_callback = 1,
	qsc_event_connection_request = 3,
	qsc_event_connection_shutdown = 4
} qsc_event_list;

/*! \struct qsc_event_handlers
* \brief The event handler structure
*/
QSC_EXPORT_API typedef struct qsc_event_handlers
{
	qsc_event_callback callback;
	struct qsc_event_handlers* next;
} qsc_event_handlers;

/**
* \brief Register an event and callback
*
* \param event: The event to register
* \param callback: The callback function
* \return Returns 0 for success
*/
QSC_EXPORT_API int32_t qsc_event_register(qsc_event_list event, qsc_event_callback callback);

/**
* \brief Initialize the event handler array
*
* \param handlers: The array of event handlers
*/
QSC_EXPORT_API void qsc_event_init_listeners(qsc_event_handlers* handlers[QSC_EVENT_LIST_LENGTH]);

/**
* \brief Destroy the event handler array
*
* \param handlers: The array of event handlers
*/
QSC_EXPORT_API void qsc_event_destroy_listeners(qsc_event_handlers* handlers[QSC_EVENT_LIST_LENGTH]);

#endif