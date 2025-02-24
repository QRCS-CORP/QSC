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


#ifndef QSC_TIMESTAMP_H
#define QSC_TIMESTAMP_H

#include "common.h"
#include <time.h>

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
 * int main(void)
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
#define QSC_TIMESTAMP_SECONDS_PER_MINUTE 60ULL

/*!
* \def QSC_TIMESTAMP_SECONDS_PER_HOUR
* \brief The number of seconds in an hour
*/
#define QSC_TIMESTAMP_SECONDS_PER_HOUR (QSC_TIMESTAMP_SECONDS_PER_MINUTE * 60ULL)

/*!
* \def QSC_TIMESTAMP_SECONDS_PER_DAY
* \brief The number of seconds in a day
*/
#define QSC_TIMESTAMP_SECONDS_PER_DAY (QSC_TIMESTAMP_SECONDS_PER_HOUR * 24ULL)

/*!
* \def QSC_TIMESTAMP_STRING_SIZE
* \brief The size of the time-stamp string
*/
#define QSC_TIMESTAMP_STRING_SIZE 20ULL

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

#endif
