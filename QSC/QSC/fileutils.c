#include "fileutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#	include "csp.h"
#endif
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdlib.h>
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <direct.h>
#	include <io.h>
#else
#	include <unistd.h>
#endif

static bool file_has_access(const char* path, qsc_fileutils_access_rights level)
{
	int32_t err;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = _access(path, (int32_t)level);
#else
	err = access(path, (int32_t)level);
#endif

	return (err == 0);
}

bool qsc_fileutils_append_to_file(const char* path, const char* stream, size_t length)
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
		res = (fwrite(stream, sizeof(char), length, fp) != 0);
		fclose(fp);
	}

	return res;
}

void qsc_fileutils_close(FILE* fp)
{
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
}

size_t qsc_fileutils_copy_file_to_object(const char* path, void* obj, size_t length)
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
		len = fread(obj, sizeof(char), length, fp);
		fclose(fp);
	}

	return len;
}

size_t qsc_fileutils_copy_file_to_stream(const char* path, char* stream, size_t length)
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
		len = fread(stream, sizeof(char), length, fp);
		fclose(fp);
	}

	return len;
}

bool qsc_fileutils_copy_object_to_file(const char* path, const void* obj, size_t length)
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
		res = (fwrite(obj, sizeof(char), length, fp) != 0);
		fclose(fp);
	}

	return res;
}

bool qsc_fileutils_copy_stream_to_file(const char* path, const char* stream, size_t length)
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
		res = (fwrite(stream, sizeof(char), length, fp) != 0);
		fclose(fp);
	}

	return res;
}

bool qsc_fileutils_create(const char* path)
{
	FILE* fp;
	bool res;

	qsc_fileutils_delete(path);

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

bool qsc_fileutils_delete(const char* path)
{
	bool res;

	res = (remove(path) == 0);

	return res;
}

bool qsc_fileutils_erase(const char* path)
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

bool qsc_fileutils_exists(const char* path)
{
	FILE* fp;
	bool res;

	res = false;
	fp = NULL;

	fp = qsc_fileutils_open(path, qsc_fileutils_mode_read, true);

	if (fp != NULL)
	{
		qsc_fileutils_close(fp);
		res = true;
	}

	return res;
}

bool qsc_fileutils_get_access(const char* path, qsc_fileutils_access_rights level)
{
	bool res;

	res = false;

	if (qsc_fileutils_exists(path))
	{
		res = file_has_access(path, level);
	}

	return res;
}

size_t qsc_fileutils_get_directory(char* directory, size_t dirlen, const char* path)
{
	const char* pname;
	size_t pos;

	pos = 0;

	if (dirlen > 0)
	{
		qsc_memutils_clear(directory, dirlen);
		pname = qsc_stringutils_reverse_sub_string(path, QSC_FILEUTILS_DIRECTORY_SEPERATOR);

		if (pname != NULL)
		{
			pos = pname - path;

			if (pos > 0)
			{
				qsc_memutils_copy(directory, path, pos);
			}
		}
	}

	return pos;
}

size_t qsc_fileutils_get_extension(char* extension, size_t extlen, const char* path)
{
	const char* pname;
	size_t len;
	size_t pos;

	len = 0;
	pos = 0;

	if (extlen > 0)
	{
		qsc_memutils_clear(extension, extlen);
		pname = qsc_stringutils_reverse_sub_string(path, ".");

		if (pname != NULL)
		{
			pos = pname - path - 1;
			len = qsc_stringutils_string_size(path);

			if (pos > 0 && extlen >= (len - pos))
			{
				qsc_memutils_copy(extension, path + pos, len - pos);
			}
		}
	}

	return (len - pos);
}

size_t qsc_fileutils_get_name(char* name, size_t namelen, const char* path)
{
	const char* pname;
	size_t len;
	size_t pos;

	len = 0;
	pos = 0;

	if (namelen > 0)
	{
		qsc_memutils_clear(name, namelen);
		pname = qsc_stringutils_reverse_sub_string(path, QSC_FILEUTILS_DIRECTORY_SEPERATOR);

		if (pname != NULL)
		{
			pos = pname - path;
			len = qsc_stringutils_string_size(path);
			const char* pext = qsc_stringutils_reverse_sub_string(path, ".");

			if (pext != NULL)
			{
				size_t elen = (len - (pext - path)) + 1;

				if (pos > 0 && namelen >= (len - (pos + elen)))
				{
					qsc_memutils_copy(name, path + pos, len - (pos + elen));
				}
			}
		}
	}

	return (len - pos);
}

int64_t qsc_fileutils_get_line(char** line, size_t* length, FILE* fp)
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
			size_t lenused = qsc_stringutils_string_size(*line);
			size_t chunkused = qsc_stringutils_string_size(chunk);

			if (*length - lenused < chunkused)
			{
				/* Check for overflow */
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

size_t qsc_fileutils_get_size(const char* path)
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
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_fseeki64(fp, 0L, SEEK_END);
		res = (size_t)_ftelli64(fp);
#else
		fseeko(fp, 0L, SEEK_END);
		res = (size_t)ftello(fp);
#endif
		fclose(fp);
	}

	return res;
}

bool qsc_fileutils_get_working_directory(char* path)
{
	char buf[FILENAME_MAX] = { 0 };
	size_t len;
	const char* res;
	bool ret;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _getcwd(buf, sizeof(buf));
#else

	res = getcwd(buf, sizeof(buf));
#endif

	if (res != NULL)
	{
		len = qsc_stringutils_string_size(buf);
		ret = qsc_stringutils_string_size(path) <= len;

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

FILE* qsc_fileutils_open(const char* path, qsc_fileutils_mode mode, bool binary)
{
	char mstr[4] = { 0 };
    FILE* fp;

    if (mode == qsc_fileutils_mode_read)
    {
    	qsc_stringutils_copy_string(mstr, sizeof(mstr), "r");
    }
    else if (mode == qsc_fileutils_mode_read_update)
    {
    	qsc_stringutils_copy_string(mstr, sizeof(mstr), "r+");
    }
    else if (mode == qsc_fileutils_mode_write)
    {
    	qsc_stringutils_copy_string(mstr, sizeof(mstr), "w");
    }
    else if (mode == qsc_fileutils_mode_write_update)
	{
    	qsc_stringutils_copy_string(mstr, sizeof(mstr), "w+");
	}
    else if (mode == qsc_fileutils_mode_append)
	{
    	qsc_stringutils_copy_string(mstr, sizeof(mstr), "a");
	}
    else
	{
    	qsc_stringutils_copy_string(mstr, sizeof(mstr), "a+");
	}

	if (binary == true)
	{
		size_t plen = qsc_stringutils_string_size(mstr);
		qsc_stringutils_copy_string(mstr + plen, sizeof(mstr), "b");
	}

    fp = NULL;
 #if defined(QSC_SYSTEM_OS_WINDOWS)
    errno_t err;
	err = fopen_s(&fp, path, mstr);
#else
    fp = fopen(path, mstr);
#endif

return fp;
}

size_t qsc_fileutils_read(char* output, size_t outlen, size_t position, FILE* fp)
{
	size_t res;

	res = 0;

	if (fp != NULL)
	{
		if (qsc_fileutils_seekto(fp, position) == true)
		{
			res = fread(output, sizeof(char), outlen, fp);
		}
	}

	return res;
}

size_t qsc_fileutils_read_line(const char* path, char* buffer, size_t buflen, size_t linenum)
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

	len = qsc_fileutils_get_size(path);

	if (len > 0)
	{
		sbuf = (char*)qsc_memutils_malloc(len);

		if (sbuf != NULL && fp != NULL && err == 0)
		{
			len = fread(sbuf, sizeof(char), len, fp);

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

size_t qsc_fileutils_safe_read(const char* path, size_t position, char* output, size_t length)
{
	FILE* fp;
	size_t res;

	res = 0;
	fp = qsc_fileutils_open(path, qsc_fileutils_mode_read, true);

	if (fp != NULL)
	{
		if (qsc_fileutils_seekto(fp, position) == true)
		{
			res = fread(output, sizeof(char), length, fp);
		}
		
		fclose(fp);
	}

	return res;
}

size_t qsc_fileutils_safe_write(const char* path, size_t position, const char* input, size_t length)
{
	FILE* fp;
	size_t res;

	res = 0;
	fp = qsc_fileutils_open(path, qsc_fileutils_mode_write, true);

	if (fp != NULL)
	{
		if (qsc_fileutils_seekto(fp, position) == true)
		{
			res = fwrite(input, sizeof(char), length, fp);
			fflush(fp);
		}

		fclose(fp);
	}

	return res;
}

bool qsc_fileutils_seekto(FILE* fp, size_t position)
{
	int32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _fseeki64(fp, (long long)position, SEEK_SET);
#else
	res = fseeko(fp, (off_t)position, SEEK_SET);
#endif

	return (res == 0);
}

bool qsc_fileutils_truncate_file(FILE* fp, size_t length)
{
	size_t flen;
	bool res;

	res = false;

	if (fp != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_fseeki64(fp, 0L, SEEK_END);
		flen = (size_t)_ftelli64(fp);
#else
		fseeko(fp, 0L, SEEK_END);
		flen = (size_t)ftello(fp);
#endif
		
		if (length < flen)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			if (_chsize_s(_fileno(fp), length) == 0)
			{
				res = true;
			}
#else
			if (ftruncate(fileno(fp), length) == 0)
			{
				res = true;
			}
#endif
		}
	}

	return res;
}

bool qsc_fileutils_valid_path(const char* path)
{
	char dir[QSC_FILEUTILS_MAX_PATH] = { 0 };
	char ext[QSC_FILEUTILS_MAX_EXTENSION] = { 0 };
	char name[QSC_FILEUTILS_MAX_FILENAME] = { 0 };

	bool res;

	res = false;

	if (qsc_fileutils_get_directory(dir, sizeof(dir), path) > 0)
	{
		if (qsc_fileutils_get_name(name, sizeof(name), path) > 0)
		{
			if (qsc_fileutils_get_extension(ext, sizeof(ext), path) > 0)
			{
				res = true;
			}
		}
	}

	return res;
}

size_t qsc_fileutils_write(const char* input, size_t inlen, size_t position, FILE* fp)
{
	size_t res;

	res = 0;

	if (fp != NULL)
	{
		if (qsc_fileutils_seekto(fp, position) == true)
		{
			res = fwrite(input, 1, inlen, fp);
			fflush(fp);
		}
	}

	return res;
}

bool qsc_fileutils_write_line(const char* path, const char* input, size_t inlen)
{
	FILE* fp;
	errno_t err;
	bool res;

	res = false;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	err = fopen_s(&fp, path, "a");
#else
	fp = fopen(path, "a");
	err = (fp != NULL) ? 0 : -1;
#endif

	if (fp != NULL && err == 0)
	{
		fseek(fp, 0L, SEEK_END);
		res = (fwrite(input, sizeof(char), inlen, fp) != 0);

		if (res == true)
		{
			const char line[1] = { '\n' };
			res = (fwrite(line, sizeof(char), sizeof(line), fp) != 0);
		}

		fclose(fp);
	}

	return res;
}

#if defined(QSC_DEBUG_MODE)
void qsc_fileutils_test(const char* fpath)
{
	uint8_t rnd[1024] = { 0 };
	char smp[1024] = { 0 };
	size_t len;

	qsc_consoleutils_print_line("File verification test");
	qsc_consoleutils_print_line("Printing file function output..");

	if (qsc_fileutils_exists(fpath) == true)
	{
		qsc_fileutils_delete(fpath);
	}

	qsc_fileutils_create(fpath);

	if (qsc_fileutils_exists(fpath) == true)
	{
		qsc_csp_generate(rnd, sizeof(rnd));

		if (qsc_fileutils_copy_stream_to_file(fpath, (char*)rnd, sizeof(rnd)) == true)
		{
			qsc_consoleutils_print_line("Success: copied random sample to file.");

			len = qsc_fileutils_get_size(fpath);

			if (len == sizeof(rnd))
			{
				qsc_consoleutils_print_line("Success: copied file size is a match.");

				if (qsc_fileutils_copy_file_to_stream(fpath, smp, sizeof(smp)) == sizeof(rnd))
				{
					if (qsc_intutils_are_equal8((uint8_t*)smp, rnd, sizeof(rnd)) == true)
					{
						qsc_consoleutils_print_line("Success: read file matches random input.");
					}
					else
					{
						qsc_consoleutils_print_line("Failure: read random sample does not match.");
					}
				}
				else
				{
					qsc_consoleutils_print_line("Failure: could not copy data to file.");
				}
			}
			else
			{
				qsc_consoleutils_print_line("Failure: failed to write random data to file.");
			}
		}
		else
		{
			qsc_consoleutils_print_line("Failure: could not write to the test file.");
		}
	}
	else
	{
		qsc_consoleutils_print_line("Failure: the test file could not be created.");
	}

	if (qsc_fileutils_exists(fpath) == true)
	{
		qsc_fileutils_delete(fpath);
	}

	qsc_consoleutils_print_line("");
}
#endif
