#include "fileutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#	include "csp.h"
#endif
#include "stringutils.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdlib.h>
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <direct.h>
#	include <io.h>
#	include <stdio.h>
#	include <windows.h>
#else
#	include <stdio.h>
#	include <sys/types.h>
#	include <dirent.h>
#	include <unistd.h>
#endif

#if defined(QSC_SYSTEM_OS_WINDOWS)
typedef struct FileAttributeDescription
{
    DWORD attribute;
    const char* description;
} FileAttributeDescription;

static FileAttributeDescription fileutils_attribute_descriptions[] = 
{
    { FILE_ATTRIBUTE_READONLY, "readonly" },
    { FILE_ATTRIBUTE_HIDDEN, "hidden" },
    { FILE_ATTRIBUTE_SYSTEM, "system" },
    { FILE_ATTRIBUTE_DIRECTORY, "directory" },
    { FILE_ATTRIBUTE_ARCHIVE, "archive" },
    { FILE_ATTRIBUTE_DEVICE, "device" },
    { FILE_ATTRIBUTE_NORMAL, "normal" },
    { FILE_ATTRIBUTE_TEMPORARY, "temporary" },
    { FILE_ATTRIBUTE_SPARSE_FILE, "sparse_file" },
    { FILE_ATTRIBUTE_REPARSE_POINT, "reparse_point" },
    { FILE_ATTRIBUTE_COMPRESSED, "compressed" },
    { FILE_ATTRIBUTE_OFFLINE, "offline" },
    { FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "not_content_indexed" },
    { FILE_ATTRIBUTE_ENCRYPTED, "encrypted" },
    { FILE_ATTRIBUTE_INTEGRITY_STREAM, "integrity_stream" },
    { FILE_ATTRIBUTE_VIRTUAL, "virtual" },
    { FILE_ATTRIBUTE_NO_SCRUB_DATA, "no_scrub_data" },
    { FILE_ATTRIBUTE_EA, "ea" },
    { FILE_ATTRIBUTE_PINNED, "pinned" },
    { FILE_ATTRIBUTE_UNPINNED, "unpinned" },
    { FILE_ATTRIBUTE_RECALL_ON_OPEN, "recall_on_open" },
    { FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "recall_on_data_access" }
};

static const char* fileutils_file_get_attribute_string(DWORD attr)
{
    const char* satr;

    satr = NULL;

    for (size_t i = 0; i < sizeof(fileutils_attribute_descriptions) / sizeof(fileutils_attribute_descriptions[0]); ++i)
    {
        if (attr & fileutils_attribute_descriptions[i].attribute)
        {
            satr = fileutils_attribute_descriptions[i].description;
			break;
        }
    }

    return satr;
}
#endif

static bool file_has_access(const char* fpath, qsc_fileutils_access_rights level)
{
	assert(fpath != NULL);

	int32_t err;

	err = -1;

	if (fpath != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = _access(fpath, (int32_t)level);
#else
		err = access(fpath, (int32_t)level);
#endif
	}

	return (err == 0);
}

bool qsc_fileutils_append_to_file(const char* fpath, const char* stream, size_t length)
{
	assert(fpath != NULL);
	assert(stream != NULL);
	assert(length != 0);

	FILE* fp;
	errno_t err;
	bool res;

	res = false;

	if (fpath != NULL && stream != NULL && length != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "ab");
#else
		fp = fopen(fpath, "ab");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			fseek(fp, 0L, SEEK_END);
			res = (fwrite(stream, sizeof(char), length, fp) != 0);
			fclose(fp);
		}
	}

	return res;
}

void qsc_fileutils_close(FILE* fp)
{
	assert(fp != NULL);

	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
}

size_t qsc_fileutils_copy_file_to_object(const char* fpath, void* obj, size_t length)
{
	assert(fpath != NULL);
	assert(obj != NULL);
	assert(length != 0);

	FILE* fp;
	errno_t err;
	size_t len;

	len = 0;

	if (fpath != NULL && obj != NULL && length != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "rb");
#else
		fp = fopen(fpath, "rb");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			len = fread(obj, sizeof(char), length, fp);
			fclose(fp);
		}
	}

	return len;
}

size_t qsc_fileutils_copy_file_to_stream(const char* fpath, char* stream, size_t length)
{
	assert(fpath != NULL);
	assert(stream != NULL);
	assert(length != 0);

	FILE* fp;
	errno_t err;
	size_t len;

	len = 0;

	if (fpath != NULL && stream != NULL && length != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "rb");
#else
		fp = fopen(fpath, "rb");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			len = fread(stream, sizeof(char), length, fp);
			fclose(fp);
		}
	}

	return len;
}

bool qsc_fileutils_copy_object_to_file(const char* fpath, const void* obj, size_t length)
{
	assert(fpath != NULL);
	assert(obj != NULL);
	assert(length != 0);

	FILE* fp;
	errno_t err;
	bool res;

	res = false;

	if (fpath != NULL && obj != NULL && length != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "wb");
#else
		fp = fopen(fpath, "wb");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			res = (fwrite(obj, sizeof(char), length, fp) != 0);
			fclose(fp);
		}
	}

	return res;
}

bool qsc_fileutils_copy_stream_to_file(const char* fpath, const char* stream, size_t length)
{
	assert(fpath != NULL);
	assert(stream != NULL);
	assert(length != 0);

	FILE* fp;
	errno_t err;
	bool res;

	res = false;

	if (fpath != NULL && stream != NULL && length != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "wb");
#else
		fp = fopen(fpath, "wb");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			res = (fwrite(stream, sizeof(char), length, fp) != 0);
			fclose(fp);
		}
	}

	return res;
}

bool qsc_fileutils_create(const char* fpath)
{
	assert(fpath != NULL);

	FILE* fp;
	bool res;

	res = false;

	if (fpath != NULL)
	{
		qsc_fileutils_delete(fpath);

#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (fopen_s(&fp, fpath, "wb") == 0);
#else
		fp = fopen(fpath, "wb");
		res = (fp != NULL) ? true : false;
#endif


		if (fp != NULL)
		{
			fclose(fp);
		}
	}
	return res;
}

bool qsc_fileutils_delete(const char* fpath)
{
	assert(fpath != NULL);

	bool res;

	res = false;

	if (fpath != NULL)
	{
		res = (remove(fpath) == 0);
	}

	return res;
}

bool qsc_fileutils_erase(const char* fpath)
{
	assert(fpath != NULL);

	size_t flen;
	bool res;

	res = false;

	if (fpath != NULL)
	{
		flen = qsc_fileutils_get_size(fpath);

		if (flen > 0)
		{
			char* pbuff;

			pbuff = (char*)qsc_memutils_malloc(flen);

			if (pbuff != NULL)
			{
				/* overwrite with 4 passes, flushing to disk each time */
				qsc_memutils_set_value(pbuff, flen, 0xFF);
				qsc_fileutils_safe_write(fpath, 0, pbuff, flen);
				qsc_memutils_set_value(pbuff, flen, 0x00);
				qsc_fileutils_safe_write(fpath, 0, pbuff, flen);
				qsc_memutils_set_value(pbuff, flen, 0xFF);
				qsc_fileutils_safe_write(fpath, 0, pbuff, flen);
				qsc_memutils_set_value(pbuff, flen, 0x00);
				qsc_fileutils_safe_write(fpath, 0, pbuff, flen);

				qsc_memutils_alloc_free(pbuff);
				res = true;
			}

			qsc_fileutils_zeroise(fpath);
		}
	}

	return res;
}

bool qsc_fileutils_exists(const char* fpath)
{
	assert(fpath != NULL);

	FILE* fp;
	bool res;

	res = false;

	if (fpath != NULL)
	{
		fp = NULL;

		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);

		if (fp != NULL)
		{
			qsc_fileutils_close(fp);
			res = true;
		}
	}

	return res;
}

bool qsc_fileutils_file_copy(const char* inpath, const char* outpath)
{
	assert(inpath != NULL);
	assert(outpath != NULL);

	char* pfs;
	size_t len;

	if (inpath != NULL && outpath != NULL)
	{
		len = qsc_fileutils_get_size(inpath);

		if (len > 0)
		{
			pfs = (char*)qsc_memutils_malloc(len);

			if (pfs != NULL)
			{
				len = qsc_fileutils_copy_file_to_stream(inpath, pfs, len);

				if (len > 0)
				{
					if (qsc_fileutils_copy_stream_to_file(outpath, pfs, len) == false)
					{
						len = 0;
					}
				}

				qsc_memutils_alloc_free(pfs);
			}
		}
	}

	return (len != 0);
}

bool qsc_fileutils_get_access(const char* fpath, qsc_fileutils_access_rights level)
{
	assert(fpath != NULL);
	
	bool res;

	res = false;

	if (fpath != NULL)
	{
		if (qsc_fileutils_exists(fpath))
		{
			res = file_has_access(fpath, level);
		}
	}

	return res;
}

size_t qsc_fileutils_get_directory(char* directory, size_t dirlen, const char* fpath)
{
	assert(directory != NULL);
	assert(dirlen != 0);
	assert(fpath != NULL);

	const char* pname;
	size_t pos;

	pos = 0;

	if (dirlen > 0 && dirlen != 0 && fpath != NULL)
	{
		qsc_memutils_clear(directory, dirlen);
		pname = qsc_stringutils_reverse_sub_string(fpath, QSC_FILEUTILS_DIRECTORY_SEPERATOR);

		if (pname != NULL)
		{
			pos = pname - fpath;

			if (pos > 0)
			{
				qsc_memutils_copy(directory, fpath, pos);
			}
		}
	}

	return pos;
}

size_t qsc_fileutils_get_extension(char* extension, size_t extlen, const char* fpath)
{
	assert(extension != NULL);
	assert(extlen != 0);
	assert(fpath != NULL);

	const char* pname;
	size_t len;
	size_t pos;

	len = 0;
	pos = 0;

	if (extension != NULL && extlen > 0 && fpath != NULL)
	{
		qsc_memutils_clear(extension, extlen);
		pname = qsc_stringutils_reverse_sub_string(fpath, ".");

		if (pname != NULL)
		{
			pos = pname - fpath - 1;
			len = qsc_stringutils_string_size(fpath);

			if (pos > 0 && extlen >= (len - pos))
			{
				qsc_memutils_copy(extension, fpath + pos, len - pos);
			}
		}
	}

	return (len - pos);
}

size_t qsc_fileutils_get_name(char* name, size_t namelen, const char* fpath)
{
	assert(name != NULL);
	assert(namelen != 0);
	assert(fpath != NULL);

	const char* pname;
	size_t len;
	size_t pos;

	len = 0;
	pos = 0;

	if (name != NULL && namelen > 0 && fpath != NULL)
	{
		qsc_memutils_clear(name, namelen);
		pname = qsc_stringutils_reverse_sub_string(fpath, QSC_FILEUTILS_DIRECTORY_SEPERATOR);

		if (pname != NULL)
		{
			pos = pname - fpath;
			len = qsc_stringutils_string_size(fpath);
			const char* pext = qsc_stringutils_reverse_sub_string(fpath, ".");

			if (pext != NULL)
			{
				size_t elen = (len - (pext - fpath)) + 1;

				if (pos > 0 && namelen >= (len - (pos + elen)))
				{
					qsc_memutils_copy(name, fpath + pos, len - (pos + elen));
				}
			}
		}
	}

	return (len - pos);
}

int64_t qsc_fileutils_get_line(char** line, size_t* length, FILE* fp)
{
	assert(line != NULL);
	assert(length != 0);
	assert(fp != NULL);

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

size_t qsc_fileutils_get_size(const char* fpath)
{
	assert(fpath != NULL);
	
	FILE* fp;
	errno_t err;
	size_t res;

	res = 0;

	if (fpath != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "rb");
#else
		fp = fopen(fpath, "rb");
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
	}

	return res;
}

bool qsc_fileutils_get_working_directory(char* fpath)
{
	assert(fpath != NULL);

	char buf[FILENAME_MAX] = { 0 };
	const char* sdir;
	size_t len;
	bool res;

	res = false;

	if (fpath != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		sdir = _getcwd(buf, sizeof(buf));
#else

		sdir = getcwd(buf, sizeof(buf));
#endif

		if (sdir != NULL)
		{
			len = qsc_stringutils_string_size(buf);
			res = qsc_stringutils_string_size(fpath) <= len;

			if (res == true)
			{
				qsc_memutils_copy(fpath, buf, len);
			}
		}
		else
		{
			res = false;
		}
	}

	return res;
}

size_t qsc_fileutils_list_files(char* result, size_t reslen, const char* directory) 
{
	assert(result != NULL);
	assert(reslen != 0);
	assert(directory != NULL);

	size_t sctr;
	size_t slen;

	sctr = 0;

	if (result != NULL && reslen != 0 && directory != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)

		char sdir[QSC_FILEUTILS_MAX_FILENAME] = { 0 };
		WIN32_FIND_DATA wfd = { 0 };
		HANDLE hfind;
		size_t dlen;

		qsc_stringutils_copy_string(sdir, sizeof(sdir), directory);
		dlen = qsc_stringutils_string_size(sdir);

		if (sdir[dlen - 1] == '\\')
		{
			qsc_stringutils_concat_strings(sdir, sizeof(sdir), "*");
		}
		else
		{
			qsc_stringutils_concat_strings(sdir, sizeof(sdir), "\\*");
		}

		hfind = FindFirstFile(sdir, &wfd);
		
		if (hfind != INVALID_HANDLE_VALUE)
		{
			do
			{
				slen = qsc_stringutils_string_size(wfd.cFileName);

				if (slen > 0)
				{
					sctr += slen + 1;

					if (sctr <= reslen)
					{
						if (qsc_stringutils_strings_equal(wfd.cFileName, ".") == false &&
							qsc_stringutils_strings_equal(wfd.cFileName, "..") == false)
						{
							SYSTEMTIME atime = { 0 };
							SYSTEMTIME ctime = { 0 };
							const char* pattr;
							size_t lpos;

							qsc_stringutils_concat_strings(result, reslen, wfd.cFileName);
							lpos = qsc_stringutils_concat_strings(result, reslen, "\t");

							pattr = fileutils_file_get_attribute_string(wfd.dwFileAttributes);

							if (pattr != NULL)
							{
								qsc_stringutils_concat_strings(result, reslen, pattr);
								lpos = qsc_stringutils_concat_strings(result, reslen, "\t");
							}
							else
							{
								lpos = qsc_stringutils_concat_strings(result, reslen, "Unknown\t");
							}

							if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
							{
								lpos = qsc_stringutils_concat_strings(result, reslen, " \t");
							}
							else
							{
								LARGE_INTEGER fsize;

								fsize.LowPart = wfd.nFileSizeLow;
								fsize.HighPart = wfd.nFileSizeHigh;

								qsc_stringutils_uint64_to_string(fsize.QuadPart, result + lpos, reslen - lpos);
								lpos = qsc_stringutils_concat_strings(result, reslen, "\t");
							}

							FileTimeToSystemTime(&wfd.ftLastAccessTime, &atime);
							FileTimeToSystemTime(&wfd.ftCreationTime, &ctime);

							lpos += sprintf_s(result + lpos, reslen - lpos, "%02d-%02d-%d %02d:%02d:%02d\t",
								ctime.wMonth, ctime.wDay, ctime.wYear, ctime.wHour, ctime.wMinute, ctime.wSecond);

							sprintf_s(result + lpos, reslen - lpos, "%02d-%02d-%d %02d:%02d:%02d\n",
								atime.wMonth, atime.wDay, atime.wYear, atime.wHour, atime.wMinute, atime.wSecond);
						}
					}
					else
					{
						break;
					}
				}

			} while (FindNextFile(hfind, &wfd) != 0);

			FindClose(hfind);
		}

#else

		DIR* dp;
		struct dirent* ep;

		dp = opendir(directory);

		if (dp != NULL)
		{
			while (true)
			{
				ep = readdir(dp);

				if (ep == NULL)
				{
					break;
				}

				slen = qsc_stringutils_string_size(ep->d_name);

				if (slen > 0)
				{
					sctr += slen + 1;

					if (sctr <= reslen)
					{
						qsc_stringutils_concat_strings(result, reslen, ep->d_name);
						qsc_stringutils_concat_strings(result, reslen, "\n");
					}
					else
					{
						break;
					}
				}
			}

			closedir(dp);
		}
#endif
	}


	return sctr;
}

FILE* qsc_fileutils_open(const char* fpath, qsc_fileutils_mode mode, bool binary)
{
	assert(fpath != NULL);
	
	FILE* fp;

	fp = NULL;

	if (fpath != NULL)
	{
		char mstr[sizeof(uint32_t)] = {0};

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

#if defined(QSC_SYSTEM_OS_WINDOWS)
		errno_t err;
		err = fopen_s(&fp, fpath, mstr);
#else
		fp = fopen(fpath, mstr);
#endif
	}

return fp;
}

size_t qsc_fileutils_read(char* output, size_t otplen, size_t position, FILE* fp)
{
	assert(output != NULL);
	assert(otplen != 0);
	assert(fp != NULL);

	size_t res;

	res = 0;

	if (output != NULL && otplen != 0 && fp != NULL)
	{
		if (qsc_fileutils_seekto(fp, position) == true)
		{
			res = fread(output, sizeof(char), otplen, fp);
		}
	}

	return res;
}

int64_t qsc_fileutils_read_line(const char* fpath, char* buffer, size_t buflen, size_t linenum)
{
	assert(fpath != NULL);
	assert(buffer != NULL);
	assert(buflen != 0);

	int64_t pln;

	pln = 0;

	if (fpath != NULL && buffer != NULL && buflen != 0)
	{
		FILE* fp;
		char* sbuf;
		errno_t err;
		size_t ctr;
		size_t len;
		size_t pos;

		ctr = 0;
		pos = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "r");
#else
		fp = fopen(fpath, "r");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			len = qsc_fileutils_get_size(fpath);

			if (len > 0)
			{
				sbuf = (char*)qsc_memutils_malloc(len);
				qsc_memutils_clear(sbuf, len);

				if (sbuf != NULL)
				{
					len = fread(sbuf, sizeof(char), len, fp);

					if (len > 0)
					{
						while (true)
						{
							pln = qsc_stringutils_find_string(sbuf + pos, "\n");

							if (pln == QSC_STRINGUTILS_TOKEN_NOT_FOUND || ctr > linenum)
							{
								break;
							}

							if (ctr == linenum)
							{
								if (pln > 0)
								{
									qsc_memutils_copy(buffer, sbuf + pos, (size_t)pln <= buflen ? (size_t)pln : buflen);
								}

								break;
							}

							pos += pln + 1;
							++ctr;
						};
					}

					qsc_memutils_alloc_free(sbuf);
				}
			}

			fclose(fp);
		}
	}

	return pln;
}

size_t qsc_fileutils_safe_read(const char* fpath, size_t position, char* output, size_t length)
{
	assert(fpath != NULL);
	assert(output != NULL);
	assert(length != 0);

	size_t res;

	res = 0;

	if (fpath != NULL && output != NULL && length != 0)
	{
		FILE* fp;

		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);

		if (fp != NULL)
		{
			if (qsc_fileutils_seekto(fp, position) == true)
			{
				res = fread(output, sizeof(char), length, fp);
			}

			fclose(fp);
		}
	}

	return res;
}

size_t qsc_fileutils_safe_write(const char* fpath, size_t position, const char* input, size_t length)
{
	assert(fpath != NULL);
	assert(input != NULL);
	assert(length != 0);

	size_t res;

	res = 0;

	if (fpath != NULL && input != NULL && length != 0)
	{
		FILE* fp;

		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_write, true);

		if (fp != NULL)
		{
			if (qsc_fileutils_seekto(fp, position) == true)
			{
				res = fwrite(input, sizeof(char), length, fp);
				fflush(fp);
			}

			fclose(fp);
		}
	}

	return res;
}

bool qsc_fileutils_seekto(FILE* fp, size_t position)
{
	assert(fp != NULL);
	
	int32_t res;

	res = -1;

	if (fp != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = _fseeki64(fp, (long long)position, SEEK_SET);
#else
		res = fseeko(fp, (off_t)position, SEEK_SET);
#endif
	}

	return (res == 0);
}

bool qsc_fileutils_truncate_file(FILE* fp, size_t length)
{
	assert(fp != NULL);

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

bool qsc_fileutils_valid_path(const char* fpath)
{
	assert(fpath != NULL);

	bool res;

	res = false;

	if (fpath != NULL)
	{
		char dir[QSC_FILEUTILS_MAX_PATH] = { 0 };
		char ext[QSC_FILEUTILS_MAX_EXTENSION] = { 0 };
		char name[QSC_FILEUTILS_MAX_FILENAME] = { 0 };

		if (qsc_fileutils_get_directory(dir, sizeof(dir), fpath) > 0)
		{
			if (qsc_fileutils_get_name(name, sizeof(name), fpath) > 0)
			{
				if (qsc_fileutils_get_extension(ext, sizeof(ext), fpath) > 0)
				{
					res = true;
				}
			}
		}
	}

	return res;
}

size_t qsc_fileutils_write(const char* input, size_t inplen, size_t position, FILE* fp)
{
	assert(input != NULL);
	assert(inplen != 0);
	assert(fp != NULL);

	size_t res;

	res = 0;

	if (input != NULL && inplen != 0 && fp != NULL)
	{
		if (qsc_fileutils_seekto(fp, position) == true)
		{
			res = fwrite(input, 1, inplen, fp);
			fflush(fp);
		}
	}

	return res;
}

bool qsc_fileutils_write_line(const char* fpath, const char* input, size_t inplen)
{
	assert(fpath != NULL);
	assert(input != NULL);
	assert(inplen != 0);

	bool res;

	res = false;

	if (fpath != NULL && input != NULL && inplen != 0)
	{
		FILE* fp;
		errno_t err;

#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "a");
#else
		fp = fopen(fpath, "a");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			fseek(fp, 0L, SEEK_END);
			res = (fwrite(input, sizeof(char), inplen, fp) != 0);

			if (res == true)
			{
				const char line[1] = { '\n' };
				res = (fwrite(line, sizeof(char), sizeof(line), fp) != 0);
			}

			fclose(fp);
		}
	}

	return res;
}

void qsc_fileutils_zeroise(const char* fpath)
{
	assert(fpath != NULL);

	if (fpath != NULL)
	{
		FILE* fp;
		bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (fopen_s(&fp, fpath, "wb") == 0);
#else
		fp = fopen(fpath, "wb");
		res = (fp != NULL);
#endif

		if (res == true)
		{
			fclose(fp);
		}
	}
}

#if defined(QSC_DEBUG_MODE)
void qsc_fileutils_test(const char* fpath)
{
	assert(fpath != NULL);

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
