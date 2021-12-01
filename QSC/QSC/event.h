/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef QSC_EVENT_H
#define QSC_EVENT_H

#include "common.h"
#include <stdarg.h>

/*
* \file event.h
* \brief Event function definitions
*/

/*!
* \def QSC_EVENT_NAME_SIZE
* \brief The character length of the event name
*/
#define QSC_EVENT_NAME_SIZE 32

/*! \typedef qsc_event_callback
* \brief The event callback variadic prototype.
* Takes the count number of arguments, and the argument array.
*/
typedef void (*qsc_event_callback)(size_t, ...);

/* alternative callback definition that complies with Misra
typedef void (*qsc_event_callback)(void*, size_t); */

/*! \struct qsc_event_handler
* \brief The event handler structure
*/
QSC_EXPORT_API typedef struct qsc_event_handler
{
	qsc_event_callback callback;		/*!< The callback function  */
	char name[QSC_EVENT_NAME_SIZE];		/*!< The event handler name  */
} qsc_event_handler;

/**
* \brief Register an event and callback
*
* \param name: The name of the event
* \param callback: The callback function
* \return Returns 0 for success
*/
QSC_EXPORT_API int32_t qsc_event_register(const char name[QSC_EVENT_NAME_SIZE], qsc_event_callback callback);

/**
* \brief Clear a listener
*
* \param name: The name of the event
*/
QSC_EXPORT_API void qsc_event_clear_listener(const char name[QSC_EVENT_NAME_SIZE]);

/**
* \brief Retrieve a callback by name
*
* \param name: The name of the event
*/
QSC_EXPORT_API qsc_event_callback qsc_event_get_callback(const char name[QSC_EVENT_NAME_SIZE]);

/**
* \brief Destroy the event handler state
*/
QSC_EXPORT_API void qsc_event_destroy_listeners();

#endif
