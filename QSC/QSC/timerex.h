
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

#ifndef QSC_TIMEREX_H
#define QSC_TIMEREX_H

#include "common.h"
#include <time.h>

/**
* \file timerex.h
* \brief This file contains common time measurement functions
*/

/*!
* \def QSC_TIMEREX_TIME_STAMP_MAX
* \brief The maximum time-stamp array size
*/
#define QSC_TIMEREX_TIMESTAMP_MAX 80

/**
* \brief Get the calendar date from the current locale
*
* \param output: The output date string
* \return 
*/
QSC_EXPORT_API void qsc_timerex_get_date(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Get the calendar date and time from the current locale
*
* \param output: The output time and date string
* \return
*/
QSC_EXPORT_API void qsc_timerex_get_datetime(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Get the local time
*
* \param output: The output time string
*/
QSC_EXPORT_API void qsc_timerex_get_time(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
QSC_EXPORT_API uint64_t qsc_timerex_stopwatch_start();

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The time difference in milliseconds
*/
QSC_EXPORT_API uint64_t qsc_timerex_stopwatch_elapsed(uint64_t start);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print timer function values
*/
QSC_EXPORT_API void qsc_timerex_print_values();
#endif

#endif
