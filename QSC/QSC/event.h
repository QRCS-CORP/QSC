/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
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
