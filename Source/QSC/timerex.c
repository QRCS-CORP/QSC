#include "timerex.h"
#include "memutils.h"
#include <string.h>
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif

void qsc_timerex_get_date(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		struct tm nt = { 0U };
		char tbuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0U };
		__time64_t lt = { 0U };
		errno_t err;
		size_t len;

		lt = 0;
		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);

		_time64(&lt);
		err = _localtime64_s(&nt, &lt);

		if (err == 0)
		{
			len = strftime(tbuf, QSC_TIMEREX_TIMESTAMP_MAX, "%Y-%m-%d", &nt);

			if (len > 0U && len < QSC_TIMEREX_TIMESTAMP_MAX)
			{
				qsc_memutils_copy(output, tbuf, len);
				output[len] = '\0';
			}
		}
#else
		char abuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0 };
		time_t rt;
		struct tm* ti;
		struct tm tmr;
		size_t len;

		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);
		rt = time(NULL);
		ti = localtime_r(&rt, &tmr);

		if (ti != NULL)
		{
			len = strftime(abuf, QSC_TIMEREX_TIMESTAMP_MAX, "%F", ti);

			if (len > 0U && len < QSC_TIMEREX_TIMESTAMP_MAX)
			{
				qsc_memutils_copy(output, abuf, len);
				output[len] = '\0';
			}
		}
#endif
	}
}

void qsc_timerex_get_datetime(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		struct tm nt = { 0U };
		char tbuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0U };
		__time64_t lt;
		errno_t err;
		size_t len;

		lt = 0;
		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);

		_time64(&lt);
		err = _localtime64_s(&nt, &lt);

		if (err == 0)
		{
			err = asctime_s(tbuf, QSC_TIMEREX_TIMESTAMP_MAX, &nt);
			len = strlen(tbuf);

			if (err == 0 && len > 0U && len < QSC_TIMEREX_TIMESTAMP_MAX)
			{
				qsc_memutils_copy(output, tbuf, len);
				output[len] = '\0';
			}
		}
#else
		char abuf[26U] = { 0U };
		time_t rt;
		struct tm* ti;
		char* ct;
		struct tm tmr;
		size_t len;

		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);
		rt = time(NULL);
		ti = localtime_r(&rt, &tmr);

		if (ti != NULL) 
		{
			ct = asctime_r(ti, abuf);

			if (ct != NULL)
			{
				len = strlen(ct);

				if (len > 0U && ct[len - 1U] == '\n')
				{
					--len;
				}

				if (len > 0U && len < QSC_TIMEREX_TIMESTAMP_MAX)
				{
					qsc_memutils_copy(output, ct, len);
					output[len] = '\0';
				}
			}
		}
#endif
	}
}

void qsc_timerex_get_time(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		struct tm nt = { 0U };
		char tbuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0U };
		__time64_t lt;
		errno_t err;
		size_t len;

		lt = 0;
		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);

		_time64(&lt);
		err = _localtime64_s(&nt, &lt);

		if (err == 0)
		{
			len = strftime(tbuf, QSC_TIMEREX_TIMESTAMP_MAX, "%H:%M:%S", &nt);

			if (len > 0U && len < QSC_TIMEREX_TIMESTAMP_MAX)
			{
				qsc_memutils_copy(output, tbuf, len);
				output[len] = '\0';
			}
		}
#else
		char abuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0 };
		time_t rt;
		struct tm* ti;
		struct tm tmr;
		size_t len;

		qsc_memutils_clear(output, QSC_TIMEREX_TIMESTAMP_MAX);
		rt = time(NULL);
		ti = localtime_r(&rt, &tmr);

		if (ti != NULL)
		{
			len = strftime(abuf, QSC_TIMEREX_TIMESTAMP_MAX, "%T", ti);

			if (len > 0U && len < QSC_TIMEREX_TIMESTAMP_MAX)
			{
				qsc_memutils_copy(output, abuf, len);
				output[len] = '\0';
			}
		}
#endif
	}
}

uint64_t qsc_timerex_stopwatch_start(void)
{
	clock_t ct;
	uint64_t res;

	ct = clock();
	res = (ct == (clock_t)-1) ? UINT64_MAX : (uint64_t)ct;

	return res;
}

uint64_t qsc_timerex_stopwatch_elapsed(uint64_t start)
{
	clock_t ct;
	uint64_t diff;
	uint64_t now;
	uint64_t res;

	ct = clock();
	res = 0U;

	if (ct != (clock_t)-1 && start != UINT64_MAX)
	{
		now = (uint64_t)ct;
		diff = (now >= start) ? (now - start) : 0U;
		res = (diff / (uint64_t)CLOCKS_PER_SEC) * 1000U + ((diff % (uint64_t)CLOCKS_PER_SEC) * 1000U) / (uint64_t)CLOCKS_PER_SEC;
	}

	return res;
}

#if defined(QSC_DEBUG_MODE)
void qsc_timerex_print_values(void)
{
	char tmro[QSC_TIMEREX_TIMESTAMP_MAX] = { 0U };

	uint64_t elps;
	uint64_t tms;

	elps = qsc_timerex_stopwatch_start(void);

	qsc_consoleutils_print_line("Timer visual verification test");
	qsc_consoleutils_print_line("Printing output from timer functions..");

	qsc_consoleutils_print_safe("Date: ");
	qsc_timerex_get_date(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_memutils_clear(tmro, sizeof(tmro));

	qsc_consoleutils_print_safe("Date-time: ");
	qsc_timerex_get_datetime(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_memutils_clear(tmro, sizeof(tmro));

	qsc_consoleutils_print_safe("Time: ");
	qsc_timerex_get_time(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_memutils_clear(tmro, sizeof(tmro));

	qsc_consoleutils_print_safe("Elapsed: ");
	tms = qsc_timerex_stopwatch_elapsed(elps);
	qsc_consoleutils_print_ulong(tms);
	qsc_consoleutils_print_line("");
}
#endif
