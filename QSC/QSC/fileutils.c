#include "fileutils.h"
#include "memutils.h"
#include "stringutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <direct.h>
#	include <io.h>
#else
#	include <unistd.h>
#	include <stdlib.h>
#endif

bool qsc_filetools_working_directory(char* path)
{
	char buf[FILENAME_MAX] = { 0 };
	size_t len;
	char* res;
	bool ret;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _getcwd(buf, sizeof(buf));
#else

	res = getcwd(buf, sizeof(buf));
#endif

	if (res != NULL)
	{
		len = strlen(buf);
		ret = strlen(path) <= len;

		if (ret == true)
		{
			qsc_memutils_copy(path, buf, len);
		}
	}
	else
	{
		ret = false;
	}

	return ret;
}

bool qsc_filetools_file_exists(const char* path)
{
	int32_t err;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = _access(path, 0);
#else
	err = access(path, F_OK);
#endif

	return (err == 0);
}

size_t qsc_filetools_file_size(const char* path)
{
	FILE* fp;
	errno_t err;
	size_t res;

	res = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "rb");
#else
	fp = fopen(path, "rb");
	err = (fp != NULL) ? 0 : -1;
#endif

	if (fp != NULL && err == 0)
	{
		fseek(fp, 0L, SEEK_END);
		res = ftell(fp);
		fclose(fp);
	}

	return res;
}

FILE*  qsc_filetools_open_file(const char* path, const char* mode, errno_t* err)
{
    FILE* fp;

    fp = NULL;
    #if defined(QSC_SYSTEM_OS_WINDOWS)
	*err = fopen_s(&fp, path, mode);
#else
    fp = fopen(path, mode);
    *err = (fp == NULL) ? -1 : 0;
#endif

return fp;
}

int64_t qsc_filetools_getline(char** line, size_t* length, FILE* fp)
{
	char* tmpl;

	/* check if either line, length or fp are NULL pointers */
	if (line == NULL || length == NULL || fp == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	else
	{
		/* use a chunk array of 128 bytes as parameter for fgets */
		char chunk[128] = { 0 };

		/* allocate a block of memory for *line if it is NULL or smaller than the chunk array */
		if (*line == NULL || *length < sizeof(chunk))
		{
			*length = sizeof(chunk);

			if ((*line = malloc(*length)) == NULL)
			{
				errno = ENOMEM;
				return -1;
			}
		}

		(*line)[0] = '\0';

		while (fgets(chunk, sizeof(chunk), fp) != NULL)
		{
			/* resize the line buffer if necessary */
			size_t lenused = strlen(*line);
			size_t chunkused = strlen(chunk);

			if (*length - lenused < chunkused)
			{
				// Check for overflow
				if (*length > SIZE_MAX / 2)
				{
					errno = EOVERFLOW;
					return -1;
				}
				else
				{
					*length *= 2;
				}

				tmpl = realloc(*line, *length);

				if (tmpl != NULL)
				{
					*line = tmpl;
				}
				else
				{
					errno = ENOMEM;
					return -1;
				}
			}

			/* copy the chunk to the end of the line buffer */
			qsc_memutils_copy(*line + lenused, chunk, chunkused);
			lenused += chunkused;
			(*line)[lenused] = '\0';

			/* check if *line contains '\n', if yes, return the *line length */
			if ((*line)[lenused - 1] == '\n')
			{
				return lenused;
			}
		}

		return -1;
	}
}

bool qsc_filetools_append_to_file(const char* path, const char* stream, size_t length)
{
	FILE* fp;
	errno_t err;
	bool res;

	res = false;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "ab");
#else
	fp = fopen(path, "ab");
	err = (fp != NULL) ? 0 : -1;
#endif

	if (fp != NULL && err == 0)
	{
		fseek(fp, 0L, SEEK_END);
		res = (fwrite(stream, 1, length, fp) != 0);
		fclose(fp);
	}

	return res;
}

bool qsc_filetools_create_file(const char* path)
{
	FILE* fp;
	bool res;

	qsc_filetools_delete_file(path);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (fopen_s(&fp, path, "wb") == 0);
#else
	fp = fopen(path, "wb");
	res = (fp != NULL) ? true : false;
#endif

	if (fp != NULL)
	{
		fclose(fp);
	}

	return res;
}

size_t qsc_filetools_copy_file_to_object(const char* path, void* obj, size_t length)
{
	FILE* fp;
	errno_t err;
	size_t len;

	len = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "rb");
#else
	fp = fopen(path, "rb");
	err = (fp != NULL) ? 0 : -1;
#endif

	if (fp != NULL && err == 0)
	{
		len = fread(obj, 1, length, fp);
		fclose(fp);
	}

	return len;
}

size_t qsc_filetools_copy_file_to_stream(const char* path, char* stream, size_t length)
{
	FILE* fp;
	errno_t err;
	size_t len;

	len = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "rb");
#else
	fp = fopen(path, "rb");
	err = (fp != NULL) ? 0 : -1;
#endif

	if (fp != NULL && err == 0)
	{
		len = fread(stream, 1, length, fp);
		fclose(fp);
	}

	return len;
}

bool qsc_filetools_copy_stream_to_file(const char* path, const char* stream, size_t length)
{
	FILE* fp;
	errno_t err;
	bool res;

	res = false;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "wb");
#else
	fp = fopen(path, "wb");
	err = (fp != NULL) ? 0 : -1;
#endif

	if (fp != NULL && err == 0)
	{
		res = (fwrite(stream, 1, length, fp) != 0);
		fclose(fp);
	}

	return res;
}

bool qsc_filetools_copy_object_to_file(const char* path, const void* obj, size_t length)
{
	FILE* fp;
	errno_t err;
	bool res;

	res = false;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "wb");
#else
	fp = fopen(path, "wb");
	err = (fp != NULL) ? 0 : -1;
#endif

	if (fp != NULL && err == 0)
	{
		res = (fwrite(obj, 1, length, fp) != 0);
		fclose(fp);
	}

	return res;
}

bool qsc_filetools_delete_file(const char* path)
{
	bool res;

	res = (remove(path) == 0);

	return res;
}

bool qsc_filetools_erase_file(const char* path)
{
	FILE* fp;
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (fopen_s(&fp, path, "wb") == 0);
#else
	fp = fopen(path, "wb");
	res = (fp != NULL) ? true : false;
#endif

	if (fp != NULL)
	{
		fclose(fp);
	}

	return res;
}

size_t qsc_filetools_read_line(const char* path, char* buffer, size_t buflen, size_t linenum)
{
	FILE* fp;
	char* sbuf;
	errno_t err;
	int32_t pln;
	size_t ctr;
	size_t len;
	size_t pos;
	size_t res;

	ctr = 0;
	pos = 0;
	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "r");
#else
	fp = fopen(path, "r");
	err = (fp != NULL) ? 0 : -1;
#endif

	len = qsc_filetools_file_size(path);

	if (len > 0)
	{
		sbuf = (char*)qsc_memutils_malloc(len);

		if (sbuf != NULL && fp != NULL && err == 0)
		{
			len = fread(sbuf, 1, len, fp);

			if (len > 0)
			{
				do
				{
					pln = qsc_stringutils_find_string(sbuf + pos, "\n");
					pos += pln;
					++ctr;

					if (ctr == linenum)
					{
						res = qsc_stringutils_find_string(sbuf + pos, "\n");
						qsc_memutils_copy(buffer, sbuf, res <= buflen ? res : buflen);
						break;
					}
				} while (pln != -1);
			}

			fclose(fp);
			qsc_memutils_alloc_free(sbuf);
		}
	}

	return res;
}
