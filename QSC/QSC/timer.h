#ifndef QSC_TIMER_H
#define QSC_TIMER_H

/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* An implementation of supporting time based functions
* Written by John G. Underhill
* Updated on February 18, 2021
* Contact: develop@vtdev.com */

/*
* \file timer.h
* \brief <b>Timing utilities</b> \n
* This file contains common time related functions
* February 18, 2021
*/

#include "common.h"
#include <time.h>

#define QSC_TIMER_TIME_STAMP_MAX 80

/**
* \brief Get the calender date from the current locale
*
* \param output: The output date string
* \return 
*/
void qsc_timer_get_date(char output[QSC_TIMER_TIME_STAMP_MAX]);

/**
* \brief Get the calender date and time from the current locale
*
* \param output: The output time and date string
* \return
*/
void qsc_timer_get_datetime(char output[QSC_TIMER_TIME_STAMP_MAX]);

/**
* \brief Get the local time
*
* \param output: The output time string
* \return
*/
void qsc_timer_get_time(char output[QSC_TIMER_TIME_STAMP_MAX]);

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
clock_t qsc_timer_stopwatch_start();

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The timke difference in milliseconds
*/
uint64_t qsc_timer_stopwatch_elapsed(clock_t start);

#endif