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

#ifndef QSC_TIMEREX_H
#define QSC_TIMEREX_H

#include "qsccommon.h"
#include <time.h>

QSC_CPLUSPLUS_ENABLED_START

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
* \param output: [char*] The output date string
*/
QSC_EXPORT_API void qsc_timerex_get_date(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Get the calendar date and time from the current locale
*
* \param output: [char*] The output time and date string
*/
QSC_EXPORT_API void qsc_timerex_get_datetime(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Get the local time
*
* \param output: [char*] The output time string
*/
QSC_EXPORT_API void qsc_timerex_get_time(char output[QSC_TIMEREX_TIMESTAMP_MAX]);

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return [uint64_t] The starting clock time
*/
QSC_EXPORT_API uint64_t qsc_timerex_stopwatch_start(void);

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return [uint64_t] The time difference in milliseconds
*/
QSC_EXPORT_API uint64_t qsc_timerex_stopwatch_elapsed(uint64_t start);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print timer function values
*/
QSC_EXPORT_API void qsc_timerex_print_values(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
