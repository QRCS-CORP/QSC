#include "timer.h"

void qsc_timer_get_date(char output[QSC_TIMER_TIME_STAMP_MAX])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	struct tm nt;
	char tbuf[QSC_TIMER_TIME_STAMP_MAX] = { 0 };
	__time64_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	memset(output, 0x00, QSC_TIMER_TIME_STAMP_MAX);

	_time64(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMER_TIME_STAMP_MAX, "%F", &nt);

		if (len > 0 && len < QSC_TIMER_TIME_STAMP_MAX)
		{
			memcpy(output, tbuf, len);
		}
	}
#else
	time_t rt;
	struct tm* ti;
	char buf[QSC_TIMER_TIME_STAMP_MAX];
	size_t len;

	memset(output, 0x00, QSC_TIMER_TIME_STAMP_MAX);
	time(&rt);

	ti = localtime(&rt);
	strftime(buf, QSC_TIMER_TIME_STAMP_MAX, "%F", ti);

	len = strlen(buf);

	if (len > 0 && len < QSC_TIMER_TIME_STAMP_MAX)
	{
		memcpy(output, buf, len);
	}
#endif
}

void qsc_timer_get_datetime(char output[QSC_TIMER_TIME_STAMP_MAX])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	struct tm nt;
	char tbuf[QSC_TIMER_TIME_STAMP_MAX] = { 0 };
	__time64_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	memset(output, 0x00, QSC_TIMER_TIME_STAMP_MAX);

	_time64(&lt);
	err = _localtime64_s(&nt, &lt);

	if (err == 0)
	{
		err = asctime_s(tbuf, QSC_TIMER_TIME_STAMP_MAX, &nt);
		len = strlen(tbuf);

		if (err == 0 && len > 0 && len < QSC_TIMER_TIME_STAMP_MAX)
		{
			memcpy(output, tbuf, len);
		}
	}
#else
	time_t rt;
	struct tm* ti;
	char* ct;

	size_t len;

	memset(output, 0x00, QSC_TIMER_TIME_STAMP_MAX);
	rt = time(NULL);
	ti = localtime(rt);
	ct = asctime(ti);

	if (ct != NULL)
	{
		len = strlen(ct);
		memcpy(output, ct, len);
	}
#endif
}

void qsc_timer_get_time(char output[QSC_TIMER_TIME_STAMP_MAX])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	struct tm nt;
	char tbuf[QSC_TIMER_TIME_STAMP_MAX] = { 0 };
	__time64_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	memset(output, 0x00, QSC_TIMER_TIME_STAMP_MAX);

	_time64(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMER_TIME_STAMP_MAX, "%T", &nt);

		if (len > 0 && len < QSC_TIMER_TIME_STAMP_MAX)
		{
			memcpy(output, tbuf, len);
		}
	}
#else
	time_t rt;
	struct tm* ti;
	char buf[QSC_TIMER_TIME_STAMP_MAX];
	size_t len;

	memset(output, 0x00, QSC_TIMER_TIME_STAMP_MAX);
	time(&rt);
	ti = localtime(&rt);
	strftime(buf, QSC_TIMER_TIME_STAMP_MAX, "%T", ti);

	len = strlen(buf);

	if (len > 0 && len < QSC_TIMER_TIME_STAMP_MAX)
	{
		memcpy(output, buf, len);
	}
#endif
}

clock_t qsc_timer_stopwatch_start()
{
	clock_t start;

	start = clock();

	return start;
}

uint64_t qsc_timer_stopwatch_elapsed(clock_t start)
{
	clock_t diff;
	uint64_t msec;

	diff = clock() - start;
	msec = (diff * 1000) / CLOCKS_PER_SEC;

	return msec;
}