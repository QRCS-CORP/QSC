#include "timerex.h"
#include "memutils.h"
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

/* \cond DOXYGEN_NO_DOCUMENT */

/**
 * \brief Read current local civil time with a reentrant platform conversion.
 * \param output Writable tm structure; caller owns storage.
 * \return True on success, false if the system time cannot be converted.
 * \note Thread safe; no heap allocations.
 */
static bool qsc_timerex_local_now(struct tm* output)
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

void qsc_timerex_get_date(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
	struct tm local;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);

		if (qsc_timerex_local_now(&local))
		{
			(void)strftime(output, QSC_TIMEREX_TIMESTAMP_MAX, "%Y-%m-%d", &local);
		}
	}
}

void qsc_timerex_get_datetime(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
	struct tm local;
	size_t len;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);

		if (qsc_timerex_local_now(&local))
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			if (asctime_s(output, QSC_TIMEREX_TIMESTAMP_MAX, &local) == 0)
#else
			if (asctime_r(&local, output) != NULL)
#endif
			{
				len = strlen(output);

				if (len != 0U && output[len - 1U] == '\n')
				{
					output[len - 1U] = '\0';
				}
			}
		}
	}
}

void qsc_timerex_get_time(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
	struct tm local;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);

		if (qsc_timerex_local_now(&local))
		{
			(void)strftime(output, QSC_TIMEREX_TIMESTAMP_MAX, "%H:%M:%S", &local);
		}
	}
}

/**
 * \brief Read an opaque high-resolution monotonic counter.
 * \return Monotonic nanoseconds on POSIX or QPC ticks on Windows; UINT64_MAX on failure.
 * \note Caller must pass this value only to the timerex elapsed functions.
 */
static uint64_t qsc_timerex_read_counter(void)
{
	uint64_t result;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	LARGE_INTEGER counter;
#else
	struct timespec now;
#endif

	result = UINT64_MAX;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (QueryPerformanceCounter(&counter) != 0 && counter.QuadPart >= 0)
	{
		result = (uint64_t)counter.QuadPart;
	}
#else
	if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec >= 0 &&
		now.tv_nsec >= 0 && now.tv_nsec < 1000000000L &&
		(uint64_t)now.tv_sec <= UINT64_MAX / 1000000000ULL)
	{
		result = ((uint64_t)now.tv_sec * 1000000000ULL) + (uint64_t)now.tv_nsec;
	}
#endif

	return result;
}

/**
 * \brief Convert elapsed counter ticks to the requested time unit.
 * \param start Opaque value from qsc_timerex_stopwatch_start.
 * \param units Number of output units per second (1000, 1000000, or 1000000000).
 * \return Elapsed units or zero if the clock fails or the counter goes backwards; saturates on overflow.
 * \note Thread safe; no heap allocations.
 */
static uint64_t qsc_timerex_elapsed_units(uint64_t start, uint64_t units)
{
	uint64_t current;
	uint64_t delta;
	uint64_t result;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	LARGE_INTEGER frequency;
	uint64_t freq;
	uint64_t seconds;
	uint64_t remainder;
	uint64_t fraction;
#endif

	result = 0U;
	current = qsc_timerex_read_counter();

	if (start != UINT64_MAX && current != UINT64_MAX && current >= start)
	{
		delta = current - start;

#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (QueryPerformanceFrequency(&frequency) != 0 && frequency.QuadPart > 0)
		{
			freq = (uint64_t)frequency.QuadPart;
			seconds = delta / freq;
			remainder = delta % freq;

			if (remainder <= UINT64_MAX / units)
			{
				fraction = (remainder * units) / freq;
			}
			else
			{
				fraction = (uint64_t)(((long double)remainder * (long double)units) / (long double)freq);
			}

			if (seconds > UINT64_MAX / units ||
				(seconds == UINT64_MAX / units && fraction > UINT64_MAX % units))
			{
				result = UINT64_MAX;
			}
			else
			{
				result = (seconds * units) + fraction;
			}
		}
#else
		result = delta / (1000000000ULL / units);
#endif
	}

	return result;
}

uint64_t qsc_timerex_stopwatch_start(void)
{
	return qsc_timerex_read_counter();
}

uint64_t qsc_timerex_stopwatch_elapsed(uint64_t start)
{
	return qsc_timerex_elapsed_units(start, 1000ULL);
}

uint64_t qsc_timerex_stopwatch_elapsed_microseconds(uint64_t start)
{
	return qsc_timerex_elapsed_units(start, 1000000ULL);
}

uint64_t qsc_timerex_stopwatch_elapsed_nanoseconds(uint64_t start)
{
	return qsc_timerex_elapsed_units(start, 1000000000ULL);
}

#if defined(QSC_DEBUG_MODE)
void qsc_timerex_print_values(void)
{
	char tmro[QSC_TIMEREX_TIMESTAMP_MAX] = { 0U };
	uint64_t elapsed;
	uint64_t start;

	start = qsc_timerex_stopwatch_start();
	qsc_consoleutils_print_line("Timer visual verification test");
	qsc_consoleutils_print_line("Printing output from timer functions..");
	qsc_consoleutils_print_safe("Date: ");
	qsc_timerex_get_date(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_consoleutils_print_safe("Date-time: ");
	qsc_timerex_get_datetime(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_consoleutils_print_safe("Time: ");
	qsc_timerex_get_time(tmro);
	qsc_consoleutils_print_line(tmro);
	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsc_consoleutils_print_safe("Elapsed: ");
	qsc_consoleutils_print_ulong(elapsed);
	qsc_consoleutils_print_line("");
}
#endif

/* \endcond DOXYGEN_NO_DOCUMENT */
