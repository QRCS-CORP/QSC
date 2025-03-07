/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_EVENT_H
#define QSC_EVENT_H

#include "common.h"
#include <stdarg.h>

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file event.h
 * \brief Event function definitions.
 * 
 * \details
 * This file defines the API for registering, retrieving, and clearing event callbacks.
 * It supports grouping events by name and provides search hints for advanced documentation
 * navigation. Functions in this module allow for dynamic management of event listeners,
 * making it easier to integrate event-driven programming features into applications.
 * 
 * \code
 * // Example usage:
 * // Register an event callback for "my_event"
 * qsc_event_register("my_event", my_callback_function);
 * \endcode
 * 
 * \section event_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/sync/event-objects">Microsoft Event Objects Documentation</a>
 * - <a href="https://man7.org/linux/man-pages/man7/epoll.7.html">Linux epoll Event Handling</a>
 */

/*!
 * \def QSC_EVENT_NAME_SIZE
 * \brief The character length of the event name.
 */
#define QSC_EVENT_NAME_SIZE 32ULL

/*!
 * \typedef qsc_event_callback
 * \brief The event callback variadic prototype.
 *
 * This callback function takes a size_t indicating the number of arguments,
 * followed by a variable list of arguments.
 *
 * \see qsc_event_handler
 */
typedef void (*qsc_event_callback)(size_t, ...);

/*!
 * \struct qsc_event_handler
 * \brief The event handler structure.
 *
 * This structure holds an event's callback function and its associated name.
 *
 * \see qsc_event_callback
 */
QSC_EXPORT_API typedef struct
{
    qsc_event_callback callback;	/*!< [qsc_event_callback] The callback function. */
    char name[QSC_EVENT_NAME_SIZE];	/*!< [char[]] The event handler name. */
} qsc_event_handler;

/**
 * \brief Register an event and its callback.
 *
 * Registers an event with the specified name and callback function.
 *
 * \param name:     [const char[QSC_EVENT_NAME_SIZE]] The name of the event.
 * \param callback: [qsc_event_callback] The callback function.
 * \return          [int32_t] Returns 0 for success.
 *
 * \see qsc_event_clear_listener(), qsc_event_get_callback()
 */
QSC_EXPORT_API int32_t qsc_event_register(const char name[QSC_EVENT_NAME_SIZE], qsc_event_callback callback);

/**
 * \brief Clear a listener for a specified event.
 *
 * Clears the listener associated with the specified event name.
 *
 * \param name:     [const char[QSC_EVENT_NAME_SIZE]] The name of the event.
 */
QSC_EXPORT_API void qsc_event_clear_listener(const char name[QSC_EVENT_NAME_SIZE]);

/**
 * \brief Retrieve a callback function by event name.
 *
 * Retrieves the callback function registered with the specified event name.
 *
 * \param name:     [const char[QSC_EVENT_NAME_SIZE]] The name of the event.
 * \return          [qsc_event_callback] Returns the callback function if found.
 *
 * \see qsc_event_register()
 */
QSC_EXPORT_API qsc_event_callback qsc_event_get_callback(const char name[QSC_EVENT_NAME_SIZE]);

/**
 * \brief Destroy all event listeners.
 *
 * Destroys the event handler state and frees all associated resources.
 */
QSC_EXPORT_API void qsc_event_destroy_listeners(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
