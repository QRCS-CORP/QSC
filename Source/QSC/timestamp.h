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

#ifndef QSC_TIMESTAMP_H
#define QSC_TIMESTAMP_H

#include "qsccommon.h"
#include <time.h>

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file timestamp.h
 * \brief Time-stamp utility functions.
 *
 * \details
 * This header provides a collection of functions for retrieving and formatting
 * time-stamp information from the system clock. It supports operations for
 * obtaining the current calendar date, current local time, and current date-time
 * in a formatted string ("YYYY-MM-DD HH-MM-SS"). In addition, it includes a stopwatch
 * functionality to measure elapsed time in milliseconds and functions to convert
 * between epoch time and human-readable date-time strings.
 *
 * \code
 * // Example usage:
 * #include "timestamp.h"
 * #include <stdio.h>
 *
 * int32_t main(void)
 * {
 *     char date[QSC_TIMESTAMP_STRING_SIZE];
 *     char datetime[QSC_TIMESTAMP_STRING_SIZE];
 *     char time_str[QSC_TIMESTAMP_STRING_SIZE];
 *
 *     // Retrieve current date, time, and full datetime strings.
 *     qsc_timestamp_current_date(date);
 *     qsc_timestamp_current_datetime(datetime);
 *     qsc_timestamp_current_time(time_str);
 *
 *     printf("Current Date: %s\n", date);
 *     printf("Current DateTime: %s\n", datetime);
 *     printf("Current Time: %s\n", time_str);
 *
 *     // Measure elapsed time using the stopwatch functions.
 *     uint64_t start = qsc_timestamp_epochtime_seconds();
 *     // ... perform some operations ...
 *     uint64_t elapsed = qsc_timestamp_stopwatch_elapsed(start);
 *     printf("Elapsed time: %llu ms\n", elapsed);
 *
 *     return 0;
 * }
 * \endcode
 *
 * \section timestamp_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/api/time.h">Microsoft Time Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/">POSIX Time Documentation</a>
 */

/*!
* \def QSC_TIMESTAMP_EPOCH_START
* \brief The year starting the epoch
*/
#define QSC_TIMESTAMP_EPOCH_START 1900ULL

/*!
* \def QSC_TIMESTAMP_SECONDS_PER_MINUTE
* \brief The number of seconds in a minute
*/
#define QSC_TIMESTAMP_SECONDS_PER_MINUTE 60U

/*!
* \def QSC_TIMESTAMP_SECONDS_PER_HOUR
* \brief The number of seconds in an hour
*/
#define QSC_TIMESTAMP_SECONDS_PER_HOUR (QSC_TIMESTAMP_SECONDS_PER_MINUTE * 60U)

/*!
* \def QSC_TIMESTAMP_SECONDS_PER_DAY
* \brief The number of seconds in a day
*/
#define QSC_TIMESTAMP_SECONDS_PER_DAY (QSC_TIMESTAMP_SECONDS_PER_HOUR * 24U)

/*!
* \def QSC_TIMESTAMP_STRING_SIZE
* \brief The size of the time-stamp string
*/
#define QSC_TIMESTAMP_STRING_SIZE 20U

/**
* \brief Get the calendar date from the current locale
*
* \param output:	[char*] The output date string
*/
QSC_EXPORT_API void qsc_timestamp_current_date(char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the calendar date and time from the current locale.
* Time-stamp string format is YYYY-MM-DD HH-MM-SS.
*
* \param output:	[char*] The output time and date string
*/
QSC_EXPORT_API void qsc_timestamp_current_datetime(char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the local time
*
* \param output:	[char*] The output time string
*/
QSC_EXPORT_API void qsc_timestamp_current_time(char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the date and time from the current locale in seconds from epoch
*
* \return			[uint64_t] Return the date/time in seconds from epoch
*/
QSC_EXPORT_API uint64_t qsc_timestamp_epochtime_seconds(void);

/**
* \brief Get the date and time from the current locale in milliseconds from epoch
*
* \return			[uint64_t] Return the date/time in seconds from epoch
*/
QSC_EXPORT_API uint64_t qsc_timestamp_epochtime_milliseconds(void);

/**
* \brief Get the date and time from the current locale in microseconds from epoch
*
* \return			[uint64_t] Return the date/time in seconds from epoch
*/
QSC_EXPORT_API uint64_t qsc_timestamp_epochtime_microseconds(void);

/**
* \brief Convert a time structure to a date and time string.
* Time-stamp string format is YYYY-MM-DD HH-MM-SS.
*
* \param output:	[char*] The output time and date string
* \param tstruct:	[const struct tm*] The populated time structure
*/
QSC_EXPORT_API void qsc_timestamp_time_struct_to_string(char output[QSC_TIMESTAMP_STRING_SIZE], const struct tm* tstruct);

/**
* \brief Convert a date and time string to a time structure.
* Time-stamp string format must be YYYY-MM-DD HH-MM-SS.
*
* \param tstruct:	[struct tm*] The time struct to be populated
* \param input:		[const char*] The input time and date string
*/
QSC_EXPORT_API void qsc_timestamp_string_to_time_struct(struct tm* tstruct, const char input[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Compare a base date-time with another future date-time string, and return the difference in seconds.
* if the comparison date is less than the base date, the return is zero.
* Time-stamp string format must be YYYY-MM-DD HH-MM-SS.
*
* \param basetime:	[const char*] The base time string
* \param comptime:	[const char*] The future time string
* 
* \return			[uint64_t] Returns the number of seconds remaining
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_seconds_remaining(const char basetime[QSC_TIMESTAMP_STRING_SIZE], const char comptime[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Convert the date-time string to a seconds from epoch unsigned 64-bit integer
*
* \param input:		[const char*] The input date-time string
* \return			[uint64_t] The number of seconds in the date-time string
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_to_seconds(const char input[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the calendar date and time for utc time.
*
* \return			[uint64_t] The number of seconds
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_utc(void);

/**
* \brief Convert a seconds count from epoch-time to a date-time string
*
* \param tsec:		[uint64_t] The number of seconds between the clock epoch time and now
* \param output:	[char*] The output time and date string
*/
QSC_EXPORT_API void qsc_timestamp_seconds_to_datetime(uint64_t tsec, char output[QSC_TIMESTAMP_STRING_SIZE]);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print time-stamp function values
*/
QSC_EXPORT_API void qsc_timestamp_print_values(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
