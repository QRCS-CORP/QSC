/* 2025 Quantum Resistant Cryptographic Solutions Corporation
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


#ifndef QSC_TIMEREX_H
#define QSC_TIMEREX_H

#include "common.h"
#include <time.h>

/**
 * \file timerex.h
 * \brief System Time Measurement Functions
 *
 * \details
 * This header provides common time measurement functions for retrieving the current date,
 * time, and high-resolution timestamps from the system clock. It offers functions to obtain
 * the current calendar date, time, and to compute elapsed time intervals (in milliseconds)
 * using a stopwatch mechanism. These functions facilitate performance measurements and 
 * time-based operations in a cross-platform manner.
 *
 * \code
 * // Example: Retrieving and printing the current date and elapsed time.
 * #define TIMESTAMP_SIZE QSC_TIMEREX_TIMESTAMP_MAX
 * char date[TIMESTAMP_SIZE];
 * qsc_timerex_get_date(date);
 * printf("Current Date: %s\n", date);
 * 
 * uint64_t start = qsc_timerex_stopwatch_start();
 * // ... perform some operations ...
 * uint64_t elapsed = qsc_timerex_stopwatch_elapsed(start);
 * printf("Elapsed Time: %llu ms\n", (unsigned long long)elapsed);
 * \endcode
 * 
 * \section timerex_links Reference Links:
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/time.html">POSIX Time Functions</a>
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/sysinfo/acquiring-system-time">Windows System Time</a>
 */

/*!
* \def QSC_TIMEREX_TIMESTAMP_MAX
* \brief The maximum time-stamp array size
*/
#define QSC_TIMEREX_TIMESTAMP_MAX 80ULL

/**
* \brief Get the calendar date from the current locale
*
* \param output:	[char*] The output date string
*/
QSC_EXPORT_API void qsc_timerex_get_date(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Get the calendar date and time from the current locale
*
* \param output:	[char*] The output time and date string
*/
QSC_EXPORT_API void qsc_timerex_get_datetime(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Get the local time
*
* \param output:	[char*] The output time string
*/
QSC_EXPORT_API void qsc_timerex_get_time(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return			[uint64_t] The starting clock time
*/
QSC_EXPORT_API uint64_t qsc_timerex_stopwatch_start(void);

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return			[uint64_t] The time difference in milliseconds
*/
QSC_EXPORT_API uint64_t qsc_timerex_stopwatch_elapsed(uint64_t start);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print timer function values
*/
QSC_EXPORT_API void qsc_timerex_print_values(void);
#endif

#endif
