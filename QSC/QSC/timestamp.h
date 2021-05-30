/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/*
* \file timer.h
* \brief <b>Timing utilities</b> \n
* This file contains common time related functions
* February 18, 2021
*/

#ifndef QSC_TIMESTAMP_H
#define QSC_TIMESTAMP_H

#include "common.h"
#include <time.h>

#define QSC_TIMESTAMP_EPOCH_START 1900
#define QSC_TIMESTAMP_STRING_SIZE 20

/**
* \brief Get the calender date from the current locale
*
* \param output: The output date string
* \return 
*/
QSC_EXPORT_API void qsc_timestamp_current_date(char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Get the calender date and time from the current locale.
* Timestamp string format is YYYY-MM-DD HH-MM-SS.
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
* \brief Get the date and time from the current locale in seconds
*
* \return the date-time in seconds
*/
QSC_EXPORT_API uint64_t qsc_timestamp_epochtime_seconds();

/**
* \brief Convert a time steructure to a date and time string.
* Timestamp string format is YYYY-MM-DD HH-MM-SS.
*
* \param output: The output time and date string
* \param tstruct: The populated time structure
*/
QSC_EXPORT_API void qsc_timestamp_time_struct_to_string(char output[QSC_TIMESTAMP_STRING_SIZE], const struct tm* tstruct);

/**
* \brief Convert a date and time string to a time structure.
* Timestamp string format must be YYYY-MM-DD HH-MM-SS.
*
* \param tstruct: The time struct to be populated
* \param input: The input time and date string
*/
QSC_EXPORT_API void qsc_timestamp_string_to_time_struct(struct tm* tstruct, const char input[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Compare a base datetime with another future datetime string, and return the difference in seconds.
* if the comparison date is less than the base date, the return is zero.
* Timestamp string format must be YYYY-MM-DD HH-MM-SS.
*
* \param basetime: The base time string
* \param comptime: The future time string
* \return Returns the number of seconds remaining
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_seconds_remaining(const char basetime[QSC_TIMESTAMP_STRING_SIZE], const char comptime[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Convert the date-time string to a seconds from epoch unsigned 64-bit integer
*
* \param input: The input date-time string
* \return The number of seconds in the date-time string
*/
QSC_EXPORT_API uint64_t qsc_timestamp_datetime_to_seconds(const char input[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Convert a seconds count from epoch-time to a date-time string
*
* \param tsec: The number of seconds between the clock epoch time and now.
* \param output: The output time and date string
*/
QSC_EXPORT_API void qsc_timestamp_seconds_to_datetime(uint64_t tsec, char output[QSC_TIMESTAMP_STRING_SIZE]);

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
QSC_EXPORT_API clock_t qsc_timestamp_stopwatch_start();

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The timke difference in milliseconds
*/
QSC_EXPORT_API uint64_t qsc_timestamp_stopwatch_elapsed(clock_t start);

#endif