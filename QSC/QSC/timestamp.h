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

#ifndef QSC_TIMESTAMP_H
#define QSC_TIMESTAMP_H

#include "common.h"
#include <time.h>

/**
* \file timestamp.h
* \brief Time-stamp function definitions
*/

/*!
* \def QSC_TIMESTAMP_EPOCH_START
* \brief The year starting the epoch
*/
#define QSC_TIMESTAMP_EPOCH_START 1900

/*!
* \def QSC_TIMESTAMP_STRING_SIZE
* \brief The size of the time-stamp string
*/
#define QSC_TIMESTAMP_STRING_SIZE 20

/**
* \brief Get the calendar date from the current locale
*
* \param output: The output date string
* \return 
*/
QSC_EXPORT_API void qsc_timestamp_current_date(char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the calendar date and time from the current locale.
* Time-stamp string format is YYYY-MM-DD HH-MM-SS.
*
* \param output: The output time and date string
*/
QSC_EXPORT_API void qsc_timestamp_current_datetime(char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the local time
*
* \param output: The output time string
* \return
*/
QSC_EXPORT_API void qsc_timestamp_current_time(char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the date and time from the current locale in seconds from epoch
*
* \return the date/time in seconds from epoch
*/
QSC_EXPORT_API uint64_t qsc_timestamp_epochtime_seconds(void);

/**
* \brief Convert a time structure to a date and time string.
* Time-stamp string format is YYYY-MM-DD HH-MM-SS.
*
* \param output: The output time and date string
* \param tstruct: [const] The populated time structure
*/
QSC_EXPORT_API void qsc_timestamp_time_struct_to_string(char output[QSC_TIMESTAMP_STRING_SIZE], const struct tm* tstruct);

/**
* \brief Convert a date and time string to a time structure.
* Time-stamp string format must be YYYY-MM-DD HH-MM-SS.
*
* \param tstruct: The time struct to be populated
* \param input: [const] The input time and date string
*/
QSC_EXPORT_API void qsc_timestamp_string_to_time_struct(struct tm* tstruct, const char input[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Compare a base date-time with another future date-time string, and return the difference in seconds.
* if the comparison date is less than the base date, the return is zero.
* Time-stamp string format must be YYYY-MM-DD HH-MM-SS.
*
* \param basetime: [const] The base time string
* \param comptime: [const] The future time string
* \return Returns the number of seconds remaining
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_seconds_remaining(const char basetime[QSC_TIMESTAMP_STRING_SIZE], const char comptime[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Convert the date-time string to a seconds from epoch unsigned 64-bit integer
*
* \param input: [const] The input date-time string
* \return The number of seconds in the date-time string
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_to_seconds(const char input[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the calendar date and time for utc time.
*
* \return The number of seconds
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_utc();

/**
* \brief Convert a seconds count from epoch-time to a date-time string
*
* \param tsec: The number of seconds between the clock epoch time and now
* \param output: The output time and date string
*/
QSC_EXPORT_API void qsc_timestamp_seconds_to_datetime(uint64_t tsec, char output[QSC_TIMESTAMP_STRING_SIZE]);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print time-stamp function values
*/
QSC_EXPORT_API void qsc_timestamp_print_values();
#endif

#endif
