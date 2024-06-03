
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
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
