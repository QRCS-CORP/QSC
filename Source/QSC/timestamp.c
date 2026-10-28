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

#include "timestamp.h"
#include "memutils.h"
#include <limits.h>
#include <string.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#   include <windows.h>
#endif
#if defined(QSC_DEBUG_MODE)
#   include "consoleutils.h"
#endif

/**
 * \brief Write an unsigned two-digit component to a non-terminated buffer.
 * \param output Writable buffer of at least two bytes; caller owns storage.
 * \param value Value between 0 and 99, verified by the caller.
 * \note No allocation or global state is used; thread safe.
 */
static void qsc_timestamp_write_two(char* output, uint32_t value)
{
	output[0U] = (char)('0' + (value / 10U));
	output[1U] = (char)('0' + (value % 10U));
}

/**
 * \brief Parse a decimal digit pair without reading past the supplied string.
 * \param input Buffer containing at least two characters; caller owns storage.
 * \return The decoded value, or UINT32_MAX on nondecimal input.
 * \note No allocation or global state is used; thread safe.
 */
static uint32_t qsc_timestamp_read_two(const char* input)
{
	uint32_t result;

	result = UINT32_MAX;

	if (input[0U] >= '0' && input[0U] <= '9' && input[1U] >= '0' && input[1U] <= '9')
	{
		result = ((uint32_t)(input[0U] - '0') * 10U) + (uint32_t)(input[1U] - '0');
	}

	return result;
}

/**
 * \brief Return the number of days in a Gregorian calendar month.
 * \param year Four-digit calendar year.
 * \param month One-based calendar month.
 * \return Days in the month, or zero for an invalid month.
 * \note No allocation or global state is used; thread safe.
 */
static uint32_t qsc_timestamp_month_days(uint32_t year, uint32_t month)
{
	static const uint8_t MDAYS[12U] = { 31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U };
	uint32_t days;

	days = 0U;

	if (month >= 1U && month <= 12U)
	{
		days = (uint32_t)MDAYS[month - 1U];

		if (month == 2U && (year % 4U == 0U) && ((year % 100U != 0U) || (year % 400U == 0U)))
		{
			days = 29U;
		}
	}

	return days;
}

/**
 * \brief Retrieve current local civil time using the platform's reentrant API.
 * \param output Destination for a complete tm structure; caller owns storage.
 * \return True on success; false on clock or conversion failure.
 * \note Uses only thread-safe C runtime time conversion functions.
 */
static bool qsc_timestamp_local_now(struct tm* output)
{
	bool result;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	__time64_t current;
#else
	time_t current;
#endif

	result = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	current = _time64(NULL);

	if (current != (__time64_t)-1)
	{
		result = (_localtime64_s(output, &current) == 0);
	}
#else
	current = time(NULL);

	if (current != (time_t)-1)
	{
		result = (localtime_r(&current, output) != NULL);
	}
#endif

	return result;
}

void qsc_timestamp_time_struct_to_string(char output[QSC_TIMESTAMP_STRING_SIZE], const struct tm* tstruct)
{
	int64_t year;

	QSC_ASSERT(output != NULL);
	QSC_ASSERT(tstruct != NULL);

	if (output != NULL)
	{
		output[0U] = '\0';

		if (tstruct != NULL)
		{
			year = (int64_t)tstruct->tm_year + (int64_t)QSC_TIMESTAMP_EPOCH_START;

			if (year >= 0 && year <= 9999 &&
				tstruct->tm_mon >= 0 && tstruct->tm_mon <= 11 &&
				tstruct->tm_mday >= 1 && tstruct->tm_mday <= (int32_t)qsc_timestamp_month_days((uint32_t)year, (uint32_t)tstruct->tm_mon + 1U) &&
				tstruct->tm_hour >= 0 && tstruct->tm_hour <= 23 &&
				tstruct->tm_min >= 0 && tstruct->tm_min <= 59 &&
				tstruct->tm_sec >= 0 && tstruct->tm_sec <= 60)
			{
				qsc_timestamp_write_two(output, (uint32_t)year / 100U);
				qsc_timestamp_write_two(output + 2U, (uint32_t)year % 100U);
				output[4U] = '-';
				qsc_timestamp_write_two(output + 5U, (uint32_t)tstruct->tm_mon + 1U);
				output[7U] = '-';
				qsc_timestamp_write_two(output + 8U, (uint32_t)tstruct->tm_mday);
				output[10U] = ' ';
				qsc_timestamp_write_two(output + 11U, (uint32_t)tstruct->tm_hour);
				output[13U] = '-';
				qsc_timestamp_write_two(output + 14U, (uint32_t)tstruct->tm_min);
				output[16U] = '-';
				qsc_timestamp_write_two(output + 17U, (uint32_t)tstruct->tm_sec);
				output[19U] = '\0';
			}
		}
	}
}

bool qsc_timestamp_string_to_time_struct_checked(struct tm* tstruct, const char input[QSC_TIMESTAMP_STRING_SIZE])
{
	bool result;
	uint32_t year;
	uint32_t yearlow;
	uint32_t month;
	uint32_t day;
	uint32_t hour;
	uint32_t minute;
	uint32_t second;
	size_t i;

	result = false;
	QSC_ASSERT(tstruct != NULL);
	QSC_ASSERT(input != NULL);

	if (tstruct != NULL)
	{
		qsc_memutils_clear(tstruct, sizeof(struct tm));

		if (input != NULL)
		{
			/* Scan exactly 19 characters and require an explicit terminator. */
			for (i = 0U; i < QSC_TIMESTAMP_STRING_SIZE; ++i)
			{
				if (input[i] == '\0')
				{
					break;
				}
			}

			if (i == QSC_TIMESTAMP_STRING_SIZE - 1U &&
				input[4U] == '-' && input[7U] == '-' && input[10U] == ' ' &&
				input[13U] == '-' && input[16U] == '-')
			{
				year = qsc_timestamp_read_two(input);
				month = qsc_timestamp_read_two(input + 5U);
				day = qsc_timestamp_read_two(input + 8U);
				hour = qsc_timestamp_read_two(input + 11U);
				minute = qsc_timestamp_read_two(input + 14U);
				second = qsc_timestamp_read_two(input + 17U);

				if (year != UINT32_MAX && month != UINT32_MAX && day != UINT32_MAX &&
					hour != UINT32_MAX && minute != UINT32_MAX && second != UINT32_MAX)
				{
					yearlow = qsc_timestamp_read_two(input + 2U);

					if (yearlow != UINT32_MAX)
					{
						year = (year * 100U) + yearlow;
					}

					if (yearlow != UINT32_MAX && year <= 9999U && month >= 1U && month <= 12U &&
						day >= 1U && day <= qsc_timestamp_month_days(year, month) &&
						hour <= 23U && minute <= 59U && second <= 60U)
					{
						tstruct->tm_year = (int32_t)year - (int32_t)QSC_TIMESTAMP_EPOCH_START;
						tstruct->tm_mon = (int32_t)month - 1;
						tstruct->tm_mday = (int32_t)day;
						tstruct->tm_hour = (int32_t)hour;
						tstruct->tm_min = (int32_t)minute;
						tstruct->tm_sec = (int32_t)second;
						tstruct->tm_isdst = -1;
						result = true;
					}
				}
			}
		}
	}

	return result;
}

void qsc_timestamp_string_to_time_struct(struct tm* tstruct, const char input[QSC_TIMESTAMP_STRING_SIZE])
{
	(void)qsc_timestamp_string_to_time_struct_checked(tstruct, input);
}

void qsc_timestamp_current_date(char output[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm local;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);

		if (qsc_timestamp_local_now(&local))
		{
			(void)strftime(output, QSC_TIMESTAMP_STRING_SIZE, "%Y-%m-%d", &local);
		}
	}
}

void qsc_timestamp_current_datetime(char output[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm local;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);

		if (qsc_timestamp_local_now(&local))
		{
			qsc_timestamp_time_struct_to_string(output, &local);
		}
	}
}

void qsc_timestamp_current_time(char output[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm local;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);

		if (qsc_timestamp_local_now(&local))
		{
			(void)strftime(output, QSC_TIMESTAMP_STRING_SIZE, "%H:%M:%S", &local);
		}
	}
}

uint64_t qsc_timestamp_datetime_seconds_remaining(const char basetime[QSC_TIMESTAMP_STRING_SIZE], const char comptime[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm base;
	struct tm comparison;
	time_t bsec;
	time_t csec;
	double difference;
	uint64_t result;

	result = 0U;

	QSC_ASSERT(basetime != NULL);
	QSC_ASSERT(comptime != NULL);

	if (qsc_timestamp_string_to_time_struct_checked(&base, basetime) &&
		qsc_timestamp_string_to_time_struct_checked(&comparison, comptime))
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		bsec = (time_t)_mktime64(&base);
		csec = (time_t)_mktime64(&comparison);
		difference = _difftime64(csec, bsec);
#else
		bsec = mktime(&base);
		csec = mktime(&comparison);
		difference = difftime(csec, bsec);
#endif

		if (bsec != (time_t)-1 && csec != (time_t)-1 && difference > 0.0)
		{
			result = (uint64_t)difference;
		}
	}

	return result;
}

uint64_t qsc_timestamp_datetime_to_seconds(const char input[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm parsed;
	uint64_t result;
	time_t epoch;

	result = 0U;

	QSC_ASSERT(input != NULL);

	if (qsc_timestamp_string_to_time_struct_checked(&parsed, input))
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		epoch = (time_t)_mktime64(&parsed);
#else
		epoch = mktime(&parsed);
#endif

		if (epoch != (time_t)-1 && epoch >= (time_t)0)
		{
			result = (uint64_t)epoch;
		}
	}

	return result;
}

uint64_t qsc_timestamp_datetime_utc(void)
{
	return qsc_timestamp_epochtime_seconds();
}

void qsc_timestamp_seconds_to_datetime(uint64_t tsec, char output[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm local;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);

		if (tsec <= (uint64_t)INT64_MAX)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			__time64_t epoch;

			epoch = (__time64_t)tsec;

			if (_localtime64_s(&local, &epoch) == 0)
			{
				qsc_timestamp_time_struct_to_string(output, &local);
			}
#else
			time_t epoch;

			epoch = (time_t)tsec;

			if ((uint64_t)epoch == tsec && localtime_r(&epoch, &local) != NULL)
			{
				qsc_timestamp_time_struct_to_string(output, &local);
			}
#endif
		}
	}
}

uint64_t qsc_timestamp_epochtime_seconds(void)
{
	time_t now;
	uint64_t result;

	result = 0U;
	now = time(NULL);

	if (now != (time_t)-1 && now >= (time_t)0)
	{
		result = (uint64_t)now;
	}

	return result;
}

/**
 * \brief Read current Unix epoch time in nanoseconds from the real-time clock.
 * \param seconds Output whole Unix seconds; caller owns storage.
 * \param nanoseconds Output fractional nanoseconds; caller owns storage.
 * \return True on success; false on unsupported or invalid clock readings.
 * \note The underlying clock can jump; not suitable for elapsed intervals.
 */
static bool qsc_timestamp_realtime(uint64_t* seconds, uint32_t* nanoseconds)
{
	bool result;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	FILETIME ft;
	uint64_t ticks;
#else
	struct timespec ts;
#endif

	result = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	GetSystemTimeAsFileTime(&ft);
	ticks = ((uint64_t)ft.dwHighDateTime << 32U) | (uint64_t)ft.dwLowDateTime;

	if (ticks >= 116444736000000000ULL)
	{
		ticks -= 116444736000000000ULL;
		*seconds = ticks / 10000000ULL;
		*nanoseconds = (uint32_t)((ticks % 10000000ULL) * 100U);
		result = true;
	}
#else
	if (clock_gettime(CLOCK_REALTIME, &ts) == 0 && ts.tv_sec >= 0 &&
		ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L)
	{
		*seconds = (uint64_t)ts.tv_sec;
		*nanoseconds = (uint32_t)ts.tv_nsec;
		result = true;
	}
#endif

	return result;
}

uint64_t qsc_timestamp_epochtime_milliseconds(void)
{
	uint64_t seconds;
	uint64_t result;
	uint32_t fraction;

	seconds = 0U;
	fraction = 0U;
	result = 0U;

	if (qsc_timestamp_realtime(&seconds, &fraction) &&
		(seconds < UINT64_MAX / 1000ULL ||
		(seconds == UINT64_MAX / 1000ULL && (uint64_t)(fraction / 1000000ULL) <= UINT64_MAX % 1000ULL)))
	{
		result = (seconds * 1000ULL) + ((uint64_t)fraction / 1000000ULL);
	}

	return result;
}

uint64_t qsc_timestamp_epochtime_microseconds(void)
{
	uint64_t seconds;
	uint64_t result;
	uint32_t fraction;

	seconds = 0U;
	fraction = 0U;
	result = 0U;

	if (qsc_timestamp_realtime(&seconds, &fraction) &&
		(seconds < UINT64_MAX / 1000000ULL ||
		(seconds == UINT64_MAX / 1000000ULL && (uint64_t)(fraction / 1000ULL) <= UINT64_MAX % 1000000ULL)))
	{
		result = (seconds * 1000000ULL) + ((uint64_t)fraction / 1000ULL);
	}

	return result;
}

#if defined(QSC_DEBUG_MODE)
void qsc_timestamp_print_values(void)
{
	char stpo[QSC_TIMESTAMP_STRING_SIZE] = { 0U };
	struct tm tstamp = { 0U };
	uint64_t tms;

	qsc_consoleutils_print_line("Time-stamp visual verification test");
	qsc_consoleutils_print_line("Printing output from time-stamp functions..");
	qsc_consoleutils_print_safe("Current date-stamp: ");
	qsc_timestamp_current_date(stpo);
	qsc_consoleutils_print_line(stpo);
	qsc_memutils_clear(stpo, sizeof(stpo));
	qsc_consoleutils_print_safe("Current time-stamp: ");
	qsc_timestamp_current_time(stpo);
	qsc_consoleutils_print_line(stpo);
	qsc_memutils_clear(stpo, sizeof(stpo));
	qsc_consoleutils_print_safe("After conversion: ");
	qsc_timestamp_current_datetime(stpo);
	qsc_timestamp_string_to_time_struct(&tstamp, stpo);
	qsc_timestamp_time_struct_to_string(stpo, &tstamp);
	qsc_consoleutils_print_line(stpo);
	tms = qsc_timestamp_epochtime_seconds();
	qsc_consoleutils_print_safe("Epoch seconds: ");
	qsc_consoleutils_print_ulong(tms);
	qsc_consoleutils_print_line("");
}
#endif
