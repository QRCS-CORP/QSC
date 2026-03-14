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

#ifndef QSC_EVENT_H
#define QSC_EVENT_H

#include "qsccommon.h"
#include "async.h"
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
#define QSC_EVENT_NAME_SIZE 32UL

/*!
 * \def QSC_EVENT_MAX_LISTENERS
 * \brief The maximum number of event listeners.
 */
#define QSC_EVENT_MAX_LISTENERS 16384

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
QSC_EXPORT_API typedef struct qsc_event_handler
{
    qsc_event_callback callback;	/*!< [qsc_event_callback] The callback function. */
    char name[QSC_EVENT_NAME_SIZE];	/*!< [char[]] The event handler name. */
} qsc_event_handler;

/*!
* \struct event_state
* \brief The event state context
*/
QSC_EXPORT_API typedef struct event_state
{
	qsc_event_handler* listeners;	/*!< The event listeners  */
	size_t lcount;					/*!< The listener count  */
	qsc_mutex opmtx;				/*!< The operations mutex  */
	bool initialized;				/*!< The initialized flag  */
} event_state;

/**
 * \brief Clear a listener for a specified event.
 *
 * \details Clears the listener associated with the specified event name.
 *
 * \param ctx: The event handler context.
 * \param name: [const char[QSC_EVENT_NAME_SIZE]] The name of the event.
 */
QSC_EXPORT_API void qsc_event_clear_listener(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE]);

/**
 * \brief Retrieve a callback function by event name.
 *
 * \details Retrieves the callback function registered with the specified event name.
 *
 * \param ctx: The event handler context.
 * \param name: [const char[QSC_EVENT_NAME_SIZE]] The name of the event.
 * 
 * \return [qsc_event_callback] Returns the callback function if found.
 *
 * \see qsc_event_register()
 */
QSC_EXPORT_API qsc_event_callback qsc_event_get_callback(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE]);

/**
 * \brief Destroy all event listeners.
 *
 * Destroys the event handler state and frees all associated resources.
 */
QSC_EXPORT_API void qsc_event_dispose(event_state* ctx);

/**
 * \brief Initialize the event state.
 *
 * \details Destroys the event handler state and frees all associated resources.
 * 
 * \param ctx: [const] The event handler context.
 * \param name: The event handler string name.
 */
QSC_EXPORT_API bool qsc_event_listener_name_exists(const event_state* ctx, const char name[QSC_EVENT_NAME_SIZE]);

/**
 * \brief Initialize the event state.
 *
 * \details Destroys the event handler state and frees all associated resources.
 * 
 * \param ctx: The event handler context.
 */
QSC_EXPORT_API void qsc_event_initialize(event_state* ctx);

/**
 * \brief Register an event and its callback.
 *
 * \details Registers an event with the specified name and callback function.
 *
 * \param ctx: The event handler context.
 * \param name: [const char[QSC_EVENT_NAME_SIZE]] The name of the event.
 * \param callback: [qsc_event_callback] The callback function.
 * 
 * \return [int32_t] Returns 0 for success.
 *
 * \see qsc_event_clear_listener(), qsc_event_get_callback()
 */
QSC_EXPORT_API int32_t qsc_event_register(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE], qsc_event_callback callback);

QSC_CPLUSPLUS_ENABLED_END

#endif
