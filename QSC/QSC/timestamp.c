#include "timestamp.h"
#include "memutils.h"
#include "stringutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif
#include <locale.h>

void qsc_timestamp_time_struct_to_string(char output[QSC_TIMESTAMP_STRING_SIZE], const struct tm* tstruct)
{
	size_t pos;

	qsc_stringutils_int_to_string(tstruct->tm_year + QSC_TIMESTAMP_EPOCH_START, output, QSC_TIMESTAMP_STRING_SIZE);
	pos = 4;
	output[pos] = '-';
	++pos;

	if (tstruct->tm_mon < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_mon + 1, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_mon + 1, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		pos += 2;
	}

	output[pos] = '-';
	++pos;

	if (tstruct->tm_mday < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_mday, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_mday, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		pos += 2;
	}

	output[pos] = ' ';
	++pos;

	if (tstruct->tm_hour < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_hour, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_hour, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		pos += 2;
	}

	output[pos] = '-';
	++pos;

	if (tstruct->tm_min < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_min, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_min, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		pos += 2;
	}

	output[pos] = '-';
	++pos;

	if (tstruct->tm_sec < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_sec, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_sec, output + pos, QSC_TIMESTAMP_STRING_SIZE - pos);
		pos += 2;
	}

	qsc_memutils_clear(output + pos, 1);
}

void qsc_timestamp_string_to_time_struct(struct tm* tstruct, const char output[QSC_TIMESTAMP_STRING_SIZE])
{
	char tmp[5] = { 0 };

	qsc_memutils_clear(tstruct, sizeof(struct tm));

	qsc_memutils_copy(tmp, output, 4);
	tstruct->tm_year = qsc_stringutils_string_to_int(tmp) - QSC_TIMESTAMP_EPOCH_START;
	qsc_memutils_clear(tmp, sizeof(tmp));
	qsc_memutils_copy(tmp, output + 5, 2);
	tstruct->tm_mon = qsc_stringutils_string_to_int(tmp) - 1;
	qsc_memutils_copy(tmp, output + 8, 2);
	tstruct->tm_mday = qsc_stringutils_string_to_int(tmp);
	qsc_memutils_copy(tmp, output + 11, 2);
	tstruct->tm_hour = qsc_stringutils_string_to_int(tmp);
	qsc_memutils_copy(tmp, output + 14, 2);
	tstruct->tm_min = qsc_stringutils_string_to_int(tmp);
	qsc_memutils_copy(tmp, output + 17, 2);
	tstruct->tm_sec = qsc_stringutils_string_to_int(tmp);
	tstruct->tm_wday = 0;
	tstruct->tm_yday = 0;
	tstruct->tm_isdst = -1;
}

void qsc_timestamp_current_date(char output[QSC_TIMESTAMP_STRING_SIZE])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	char tbuf[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm nt;
	time_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMESTAMP_STRING_SIZE, "%F", &nt);

		if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
		{
			qsc_memutils_copy(output, tbuf, len);
		}
	}

#else

	char tbuf[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm* nt;
	time_t lt;
	size_t len;

	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	nt = localtime(&lt);
	strftime(tbuf, QSC_TIMESTAMP_STRING_SIZE, "%F", nt);

	len = strlen(tbuf);

	if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
	{
		qsc_memutils_copy(output, tbuf, len);
	}

#endif
}

void qsc_timestamp_current_datetime(char output[QSC_TIMESTAMP_STRING_SIZE])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	struct tm nt;
	time_t lt;
	errno_t err;

	lt = 0;
	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	err = _localtime64_s(&nt, &lt);

	if (err == 0)
	{
		qsc_timestamp_time_struct_to_string(output, &nt);
	}

#else

	time_t lt;
	struct tm* nt;

	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	lt = time(NULL);
	nt = localtime(&lt);
    qsc_timestamp_time_struct_to_string(output, nt);

#endif
}

void qsc_timestamp_current_time(char output[QSC_TIMESTAMP_STRING_SIZE])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	char tbuf[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm nt;
	time_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMESTAMP_STRING_SIZE, "%T", &nt);

		if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
		{
			qsc_memutils_copy(output, tbuf, len);
		}
	}

#else

	struct tm* nt;
	time_t lt;
	char buf[QSC_TIMESTAMP_STRING_SIZE];
	size_t len;

	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	nt = localtime(&lt);
	strftime(buf, QSC_TIMESTAMP_STRING_SIZE, "%T", nt);

	len = strlen(buf);

	if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
	{
		qsc_memutils_copy(output, buf, len);
	}

#endif
}

uint64_t qsc_timestamp_datetime_seconds_remaining(const char basetime[QSC_TIMESTAMP_STRING_SIZE], const char comptime[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm bt;
	struct tm ft;
	double dtmp;
	time_t bsec;
	time_t csec;

	qsc_timestamp_string_to_time_struct(&bt, basetime);
	qsc_timestamp_string_to_time_struct(&ft, comptime);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	bsec = _mktime64(&bt);
	csec = _mktime64(&ft);
	dtmp = _difftime64(csec, bsec);
#else
	bsec = mktime(&bt);
	csec = mktime(&ft);
	dtmp = difftime(csec, bsec);
#endif

	if (dtmp < 0 || bsec > csec)
	{
		dtmp = 0;
	}

	return (uint64_t)dtmp;
}

uint64_t qsc_timestamp_datetime_to_seconds(const char input[QSC_TIMESTAMP_STRING_SIZE])
{
	struct tm dt;
	time_t tsec;

	qsc_timestamp_string_to_time_struct(&dt, input);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	tsec = _mktime64(&dt);
#else
	tsec = mktime(&dt);
#endif

	return (uint64_t)tsec;
}

void qsc_timestamp_seconds_to_datetime(uint64_t dtsec, char output[QSC_TIMESTAMP_STRING_SIZE])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	struct tm nt;
	time_t lt;
	errno_t err;

	lt = (time_t)dtsec;
	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	nt.tm_isdst = -1;
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		qsc_timestamp_time_struct_to_string(output, &nt);
	}

#else

	struct tm* nt;
	time_t lt;

	qsc_memutils_clear(output, QSC_TIMESTAMP_STRING_SIZE);
	lt = (time_t)dtsec;
	nt = localtime(&lt);

	qsc_timestamp_time_struct_to_string(output, nt);

#endif
}

uint64_t qsc_timestamp_epochtime_seconds()
{
	uint64_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	time_t lt;

	lt = 0;
	time(&lt);
	res = (uint64_t)lt;

	return res;

#else

	time_t lt;

	lt = time(NULL);
	res = (uint64_t)lt;

	return res;

#endif
}

#if defined(QSC_DEBUG_MODE)
void qsc_timestamp_print_values()
{
	char stpo[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm tstamp = { 0 };
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
	qsc_memutils_clear(stpo, sizeof(stpo));

	qsc_consoleutils_print_safe("Epoch seconds: ");
	tms = qsc_timestamp_epochtime_seconds();
	qsc_consoleutils_print_ulong(tms);
	qsc_consoleutils_print_line("");
}
#endif
