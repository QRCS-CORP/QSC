#include "timestamp.h"
#include <locale.h>
#include "stringutils.h"

void qsc_timestamp_time_struct_to_string(char output[QSC_TIMESTAMP_STRING_SIZE], const struct tm* tstruct)
{
	size_t pos;

	qsc_stringutils_int_to_string(tstruct->tm_year + QSC_TIMESTAMP_EPOCH_START, output, 5);
	pos = 4;
	output[pos] = '-';
	++pos;

	if (tstruct->tm_mon < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_mon + 1, output + pos, 2);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_mon + 1, output + pos, 3);
		pos += 2;
	}

	output[pos] = '-';
	++pos;

	if (tstruct->tm_mday < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_mday, output + pos, 2);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_mday, output + pos, 3);
		pos += 2;
	}

	output[pos] = ' ';
	++pos;

	if (tstruct->tm_hour < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_hour, output + pos, 2);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_hour, output + pos, 3);
		pos += 2;
	}

	output[pos] = '-';
	++pos;

	if (tstruct->tm_min < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_min, output + pos, 2);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_min, output + pos, 3);
		pos += 2;
	}

	output[pos] = '-';
	++pos;

	if (tstruct->tm_sec < 10)
	{
		output[pos] = '0';
		++pos;
		qsc_stringutils_int_to_string(tstruct->tm_sec, output + pos, 2);
		++pos;
	}
	else
	{
		qsc_stringutils_int_to_string(tstruct->tm_sec, output + pos, 3);
		pos += 2;
	}

	memset(output + pos, 0x00, 1);
}

void qsc_timestamp_string_to_time_struct(struct tm* tstruct, const char output[QSC_TIMESTAMP_STRING_SIZE])
{
	char tmp[5] = { 0 };

	memset(tstruct, 0x00, sizeof(tstruct));

	memcpy(tmp, output, 4);
	tstruct->tm_year = qsc_stringutils_string_to_int(tmp) - QSC_TIMESTAMP_EPOCH_START;
	memset(tmp, 0x00, sizeof(tmp));
	memcpy(tmp, output + 5, 2);
	tstruct->tm_mon = qsc_stringutils_string_to_int(tmp) - 1;
	memcpy(tmp, output + 8, 2);
	tstruct->tm_mday = qsc_stringutils_string_to_int(tmp);
	memcpy(tmp, output + 11, 2);
	tstruct->tm_hour = qsc_stringutils_string_to_int(tmp);
	memcpy(tmp, output + 14, 2);
	tstruct->tm_min = qsc_stringutils_string_to_int(tmp);
	memcpy(tmp, output + 17, 2);
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
	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMESTAMP_STRING_SIZE, "%F", &nt);

		if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
		{
			memcpy(output, tbuf, len);
		}
	}

#else

	char tbuf[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm* nt;
	time_t lt;
	size_t len;

	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	nt = localtime(&lt);
	strftime(tbuf, QSC_TIMESTAMP_STRING_SIZE, "%F", nt);

	len = strlen(tbuf);

	if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
	{
		memcpy(output, tbuf, len);
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
	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	err = _localtime64_s(&nt, &lt);

	if (err == 0)
	{
		qsc_timestamp_time_struct_to_string(output, &nt);
	}

#else

	time_t lt;
	struct tm* nt;
	char* ct;

	size_t len;

	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
	lt = time(NULL);
	nt = localtime(lt);

	if (ct != NULL)
	{
		qsc_timestamp_time_struct_to_string(output, nt);
	}

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
	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMESTAMP_STRING_SIZE, "%T", &nt);

		if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
		{
			memcpy(output, tbuf, len);
		}
	}

#else

	struct tm* nt;
	time_t lt;
	char buf[QSC_TIMESTAMP_STRING_SIZE];
	size_t len;

	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
	time(&lt);
	nt = localtime(&lt);
	strftime(buf, QSC_TIMESTAMP_STRING_SIZE, "%T", nt);

	len = strlen(buf);

	if (len > 0 && len < QSC_TIMESTAMP_STRING_SIZE)
	{
		memcpy(output, buf, len);
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

	char tbuf[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm nt;
	time_t lt;
	errno_t err;

	lt = (time_t)dtsec;
	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
	nt.tm_isdst = -1;
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		qsc_timestamp_time_struct_to_string(output, &nt);
	}

#else

	char tbuf[QSC_TIMESTAMP_STRING_SIZE];
	struct tm* nt;
	time_t lt;

	memset(output, 0x00, QSC_TIMESTAMP_STRING_SIZE);
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

clock_t qsc_timestamp_stopwatch_start()
{
	clock_t start;

	start = clock();

	return start;
}

uint64_t qsc_timestamp_stopwatch_elapsed(clock_t start)
{
	clock_t diff;
	uint64_t msec;

	diff = clock() - start;
	msec = (diff * 1000) / CLOCKS_PER_SEC;

	return msec;
}