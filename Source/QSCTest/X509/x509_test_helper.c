#include "x509_test_helper.h"
#include "fileutils.h"
#include "memutils.h"
#include "timestamp.h"

char* qsctest_x509_read_text_file(const char* path, size_t* len)
{
	size_t flen;
	char* buf;

	buf = NULL;

	if (path != NULL && len != NULL)
	{
		flen = qsc_fileutils_get_size(path);

		if (flen > 0U)
		{
			buf = (char*)qsc_memutils_malloc(flen + 1U);

			if (buf != NULL)
			{
				if (qsc_fileutils_copy_file_to_stream(path, buf, flen) == flen)
				{
					buf[flen] = 0;
					*len = flen;
				}
				else
				{
					qsc_memutils_alloc_free(buf);
					buf = NULL;
				}
			}
		}
	}

	return buf;
}

uint8_t* qsctest_x509_read_binary_file(const char* path, size_t* len)
{
	size_t flen;
	uint8_t* buf;

	buf = NULL;

	if (path != NULL && len != NULL)
	{
		flen = qsc_fileutils_get_size(path);

		if (flen != 0U)
		{
			buf = (uint8_t*)qsc_memutils_malloc(flen);

			if (buf != NULL)
			{
				if (qsc_fileutils_copy_file_to_object(path, buf, flen) == flen)
				{
					*len = flen;
				}
				else
				{
					qsc_memutils_alloc_free(buf);
					buf = NULL;
				}
			}
		}
	}

	return buf;
}

void qsctest_x509_current_time(qsc_asn1_time* t)
{
	char dt[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm nt;

	if (t != NULL)
	{
		qsc_memutils_clear(t, sizeof(*t));
		qsc_memutils_clear(&nt, sizeof(nt));

		qsc_timestamp_seconds_to_datetime(qsc_timestamp_epochtime_seconds(), dt);
		qsc_timestamp_string_to_time_struct(&nt, dt);

		t->year = (uint16_t)(nt.tm_year + 1900);
		t->month = (uint8_t)(nt.tm_mon + 1);
		t->day = (uint8_t)nt.tm_mday;
		t->hour = (uint8_t)nt.tm_hour;
		t->minute = (uint8_t)nt.tm_min;
		t->second = (uint8_t)nt.tm_sec;
		t->generalized = (t->year >= 2050U);
	}
}
