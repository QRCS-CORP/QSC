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

#if !defined(_WIN32) && !defined(_FILE_OFFSET_BITS)
#   define _FILE_OFFSET_BITS 64
#endif
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#   define _POSIX_C_SOURCE 200809L
#endif

#include "fileutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#  include <direct.h>
#  include <io.h>
#  include <stdio.h>
#  if !defined(WIN32_LEAN_AND_MEAN)
#    define WIN32_LEAN_AND_MEAN
#  endif
#  if !defined(NOMINMAX)
#    define NOMINMAX
#  endif
#  include <windows.h>
#elif defined(QSC_SYSTEM_OS_MAC)
#	if !defined(_LARGEFILE_SOURCE)
#		define _LARGEFILE_SOURCE
#	endif
#  include <unistd.h>
#  include <dirent.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <stdlib.h>
#elif defined(QSC_SYSTEM_OS_POSIX)
#	if !defined(_LARGEFILE_SOURCE)
#		define _LARGEFILE_SOURCE
#	endif
#  include <unistd.h>
#  include <dirent.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <stdlib.h>
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

	for (size_t i = 0U; i < sizeof(fileutils_attribute_descriptions) / sizeof(fileutils_attribute_descriptions[0U]); ++i)
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
	QSC_ASSERT(fpath != NULL);

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
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(stream != NULL);
	QSC_ASSERT(length != 0U);

	FILE* fp;
	errno_t err;
	bool res;

	res = false;

	if (fpath != NULL && stream != NULL && length != 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "ab");
#else
		fp = fopen(fpath, "ab");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			res = (fwrite(stream, sizeof(char), length, fp) == length);

			if (fflush(fp) != 0)
			{
				res = false;
			}

			if (fclose(fp) != 0)
			{
				res = false;
			}
		}
	}

	return res;
}

void qsc_fileutils_close(FILE* fp)
{
	QSC_ASSERT(fp != NULL);

	if (fp != NULL)
	{
		fclose(fp);
	}
}

size_t qsc_fileutils_copy_file_to_object(const char* fpath, void* obj, size_t length)
{
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(obj != NULL);
	QSC_ASSERT(length != 0U);

	FILE* fp;
	errno_t err;
	size_t len;

	len = 0U;

	if (fpath != NULL && obj != NULL && length != 0U)
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
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(stream != NULL);
	QSC_ASSERT(length != 0U);

	FILE* fp;
	errno_t err;
	size_t len;

	len = 0U;

	if (fpath != NULL && stream != NULL && length != 0U)
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
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(obj != NULL);
	QSC_ASSERT(length != 0U);

	FILE* fp;
	errno_t err;
	bool res;

	res = false;

	if (fpath != NULL && obj != NULL && length != 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "wb");
#else
		fp = fopen(fpath, "wb");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			res = (fwrite(obj, sizeof(char), length, fp) == length);

			if (fflush(fp) != 0)
			{
				res = false;
			}

			if (fclose(fp) != 0)
			{
				res = false;
			}
		}
	}

	return res;
}

bool qsc_fileutils_copy_stream_to_file(const char* fpath, const char* stream, size_t length)
{
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(stream != NULL);
	QSC_ASSERT(length != 0U);

	FILE* fp;
	errno_t err;
	bool res;

	res = false;

	if (fpath != NULL && stream != NULL && length != 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		err = fopen_s(&fp, fpath, "wb");
#else
		fp = fopen(fpath, "wb");
		err = (fp != NULL) ? 0 : -1;
#endif

		if (fp != NULL && err == 0)
		{
			res = (fwrite(stream, sizeof(char), length, fp) == length);

			if (fflush(fp) != 0)
			{
				res = false;
			}

			if (fclose(fp) != 0)
			{
				res = false;
			}
		}
	}

	return res;
}

bool qsc_fileutils_create(const char* fpath)
{
	QSC_ASSERT(fpath != NULL);

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
	QSC_ASSERT(fpath != NULL);

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
	QSC_ASSERT(fpath != NULL);

	size_t flen;
	bool res;

	res = false;

	if (fpath != NULL)
	{
		flen = qsc_fileutils_get_size(fpath);

		if (flen > 0U)
		{
			char* pbuff;

			pbuff = (char*)qsc_memutils_malloc(flen);

			if (pbuff != NULL)
			{
				/* overwrite with 4 passes, flushing to disk each time */
				qsc_memutils_set_value(pbuff, flen, 0xFFU);
				qsc_fileutils_safe_write(fpath, 0U, pbuff, flen);
				qsc_memutils_set_value(pbuff, flen, 0x00U);
				qsc_fileutils_safe_write(fpath, 0U, pbuff, flen);
				qsc_memutils_set_value(pbuff, flen, 0xFFU);
				qsc_fileutils_safe_write(fpath, 0U, pbuff, flen);
				qsc_memutils_set_value(pbuff, flen, 0x00U);
				qsc_fileutils_safe_write(fpath, 0U, pbuff, flen);

				qsc_memutils_alloc_free(pbuff);
				pbuff = NULL;
				res = true;
			}

			qsc_fileutils_zeroise(fpath);
		}
	}

	return res;
}

void qsc_fileutils_flush(FILE* fp)
{
	QSC_ASSERT(fp != NULL);

	if (fp != NULL)
	{
		fflush(fp);
	}
}

bool qsc_fileutils_exists(const char* fpath)
{
	QSC_ASSERT(fpath != NULL);

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
	QSC_ASSERT(inpath != NULL);
	QSC_ASSERT(outpath != NULL);

	FILE* src;
	FILE* dst;
	uint8_t buffer[32768U];
	size_t nread;
	bool res;

	src = NULL;
	dst = NULL;
	res = false;

	if (inpath != NULL && outpath != NULL && strcmp(inpath, outpath) != 0)
	{
		src = qsc_fileutils_open(inpath, qsc_fileutils_mode_read, true);

		if (src != NULL)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			BY_HANDLE_FILE_INFORMATION srcinfo;
			BY_HANDLE_FILE_INFORMATION dstinfo;
			HANDLE target;
			bool distinct;

			distinct = false;
			target = CreateFileA(outpath, FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

			if (target != INVALID_HANDLE_VALUE)
			{
				const intptr_t srcfd = _get_osfhandle(_fileno(src));
				if (srcfd != -1 &&
					GetFileInformationByHandle((HANDLE)srcfd, &srcinfo) != 0 &&
					GetFileInformationByHandle(target, &dstinfo) != 0)
				{
					distinct = (srcinfo.dwVolumeSerialNumber != dstinfo.dwVolumeSerialNumber ||
						srcinfo.nFileIndexHigh != dstinfo.nFileIndexHigh ||
						srcinfo.nFileIndexLow != dstinfo.nFileIndexLow);
				}
				CloseHandle(target);
			}
			else
			{
				const DWORD err = GetLastError();
				distinct = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND);
			}
#else
			struct stat inst;
			struct stat outst;
			bool distinct;

			distinct = (fstat(fileno(src), &inst) == 0);
			if (distinct == true && stat(outpath, &outst) == 0)
			{
				distinct = (inst.st_dev != outst.st_dev || inst.st_ino != outst.st_ino);
			}
#endif

			if (distinct == true)
			{
				dst = qsc_fileutils_open(outpath, qsc_fileutils_mode_write, true);

				if (dst != NULL)
				{
					res = true;

					do
					{
						nread = fread(buffer, 1U, sizeof(buffer), src);

						if (nread != 0U && fwrite(buffer, 1U, nread, dst) != nread)
						{
							res = false;
							break;
						}
					} while (nread == sizeof(buffer));

					if (ferror(src) != 0 || fflush(dst) != 0)
					{
						res = false;
					}

					if (fclose(dst) != 0)
					{
						res = false;
					}
				}
			}

			if (fclose(src) != 0)
			{
				res = false;
			}
		}
	}

	return res;
}



bool qsc_fileutils_get_access(const char* fpath, qsc_fileutils_access_rights level)
{
	QSC_ASSERT(fpath != NULL);

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
	QSC_ASSERT(directory != NULL);
	QSC_ASSERT(dirlen != 0U);
	QSC_ASSERT(fpath != NULL);

	const char* pname;
	size_t pos;

	pos = 0U;

	if (directory != NULL && dirlen > 0U && fpath != NULL)
	{
		qsc_memutils_clear(directory, dirlen);
		pname = qsc_stringutils_reverse_sub_string(fpath, QSC_FILEUTILS_DIRECTORY_SEPERATOR);

		if (pname != NULL)
		{
			pos = pname - fpath;

			if (pos > 0U)
			{
				qsc_memutils_copy(directory, fpath, pos);
			}
		}
	}

	return pos;
}

size_t qsc_fileutils_get_extension(char* extension, size_t extlen, const char* fpath)
{
	QSC_ASSERT(extension != NULL);
	QSC_ASSERT(extlen != 0U);
	QSC_ASSERT(fpath != NULL);

	const char* pname;
	size_t len;
	size_t pos;

	len = 0U;
	pos = 0U;

	if (extension != NULL && extlen > 0U && fpath != NULL)
	{
		qsc_memutils_clear(extension, extlen);
		pname = qsc_stringutils_reverse_sub_string(fpath, ".");

		if (pname != NULL)
		{
			pos = pname - fpath - 1U;
			len = qsc_stringutils_string_size(fpath);

			if (pos > 0U && extlen >= (len - pos))
			{
				qsc_memutils_copy(extension, fpath + pos, len - pos);
			}
		}
	}

	return (len - pos);
}

size_t qsc_fileutils_get_name(char* name, size_t namelen, const char* fpath)
{
	QSC_ASSERT(name != NULL);
	QSC_ASSERT(namelen != 0U);
	QSC_ASSERT(fpath != NULL);

	const char* pname;
	size_t len;
	size_t pos;

	len = 0U;
	pos = 0U;

	if (name != NULL && namelen > 0U && fpath != NULL)
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
				size_t elen = (len - (pext - fpath)) + 1U;

				if (pos > 0U && namelen >= (len - (pos + elen)))
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
	QSC_ASSERT(line != NULL);
	QSC_ASSERT(length != NULL);
	QSC_ASSERT(fp != NULL);

	char chunk[512U];
	char* data;
	char* replacement;
	size_t capacity;
	size_t count;
	size_t nread;
	size_t need;
	size_t ncopy;
	int64_t res;
	bool found;

	res = -1;
	if (line != NULL && length != NULL && fp != NULL)
	{
		*line = NULL;
		*length = 0U;
		capacity = sizeof(chunk);
		data = (char*)qsc_memutils_malloc(capacity);
		count = 0U;
		found = false;

		if (data != NULL)
		{
			while (fgets(chunk, (int32_t)sizeof(chunk), fp) != NULL)
			{
				const char* newline;

				nread = strlen(chunk);
				newline = (const char*)memchr(chunk, '\n', nread);
				ncopy = (newline != NULL) ? (size_t)(newline - chunk) : nread;

				if (ncopy > SIZE_MAX - count - 1U || ncopy > (size_t)INT64_MAX - count)
				{
					break;
				}

				need = count + ncopy + 1U;
				if (need > capacity)
				{
					size_t next;
					next = capacity;

					while (next < need && next <= SIZE_MAX / 2U)
					{
						next *= 2U;
					}

					if (next < need)
					{
						next = need;
					}

					replacement = (char*)qsc_memutils_realloc(data, next);
					if (replacement == NULL)
					{
						break;
					}

					data = replacement;
					capacity = next;
				}

				if (ncopy != 0U)
				{
					qsc_memutils_copy(data + count, chunk, ncopy);
					count += ncopy;
				}

				if (newline != NULL)
				{
					found = true;
					break;
				}
			}

			if (found == true || (feof(fp) != 0 && count != 0U))
			{
				data[count] = '\0';
				*line = data;
				*length = capacity;
				res = (int64_t)count + (found == true ? 1 : 0);
			}
			else
			{
				qsc_memutils_alloc_free(data);
			}
		}
	}

	return res;
}



size_t qsc_fileutils_get_size(const char* fpath)
{
	QSC_ASSERT(fpath != NULL);

	FILE* fp;
	size_t res;

	res = 0U;
	fp = NULL;

	if (fpath != NULL)
	{
		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);

		if (fp != NULL)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			if (_fseeki64(fp, 0, SEEK_END) == 0)
			{
				const __int64 pos = _ftelli64(fp);
				if (pos >= 0 && (uint64_t)pos <= (uint64_t)SIZE_MAX)
				{
					res = (size_t)pos;
				}
			}
#else
			if (fseeko(fp, (off_t)0, SEEK_END) == 0)
			{
				const off_t pos = ftello(fp);
				if (pos >= (off_t)0 && (uint64_t)pos <= (uint64_t)SIZE_MAX)
				{
					res = (size_t)pos;
				}
			}
#endif
			fclose(fp);
		}
	}

	return res;
}



bool qsc_fileutils_get_working_directory(char* fpath, size_t flen)
{
	QSC_ASSERT(fpath != NULL);

	bool res;
	res = false;

	if (fpath != NULL && flen != 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (_getcwd(fpath, (int32_t)((flen > (size_t)INT_MAX) ? (size_t)INT_MAX : flen)) != NULL);
#else
		res = (getcwd(fpath, flen) != NULL);
#endif
	}

	return res;
}



size_t qsc_fileutils_list_files(char* result, size_t reslen, const char* directory)
{
	QSC_ASSERT(result != NULL);
	QSC_ASSERT(reslen != 0U);
	QSC_ASSERT(directory != NULL);

	size_t sctr;
	size_t slen;

	sctr = 0U;

	if (result != NULL && reslen != 0U && directory != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)

		char sdir[QSC_FILEUTILS_MAX_FILENAME] = { 0U };
		WIN32_FIND_DATA wfd = { 0U };
		HANDLE hfind;
		size_t dlen;

		qsc_stringutils_copy_string(sdir, sizeof(sdir), directory);
		dlen = qsc_stringutils_string_size(sdir);

		if (sdir[dlen - 1U] == '\\')
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

				if (slen > 0U)
				{
					sctr += slen + 1;

					if (sctr <= reslen)
					{
						if (qsc_stringutils_strings_equal(wfd.cFileName, ".") == false &&
							qsc_stringutils_strings_equal(wfd.cFileName, "..") == false)
						{
							SYSTEMTIME atime = { 0U };
							SYSTEMTIME ctime = { 0U };
							const char* pattr;
							size_t lpos;

							qsc_stringutils_concat_strings(result, reslen, wfd.cFileName);
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

				if (slen > 0U)
				{
					sctr += slen + 1U;

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
	QSC_ASSERT(fpath != NULL);

	FILE* fp;

	fp = NULL;

	if (fpath != NULL)
	{
		char mstr[sizeof(uint32_t)] = { 0U };

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

		if (err != 0)
		{
			fp = NULL;
		}
#else
		fp = fopen(fpath, mstr);
#endif
	}

	return fp;
}

size_t qsc_fileutils_read(char* output, size_t otplen, size_t position, FILE* fp)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);
	QSC_ASSERT(fp != NULL);

	size_t res;

	res = 0U;

	if (output != NULL && otplen != 0U && fp != NULL)
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
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(buffer != NULL);
	QSC_ASSERT(buflen != 0U);

	FILE* fp;
	uint8_t chunk[8192U];
	const uint8_t* current;
	const uint8_t* newline;
	size_t lines;
	size_t copied;
	size_t count;
	size_t offset;
	size_t nread;
	size_t avail;
	size_t take;
	int64_t result;
	bool located;
	bool done;

	result = -1;
	if (fpath != NULL && buffer != NULL && buflen != 0U)
	{
		buffer[0] = '\0';
		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);
		if (fp != NULL)
		{
			lines = 0U;
			copied = 0U;
			count = 0U;
			located = false;
			done = false;
			result = -1;

			while (done == false && (nread = fread(chunk, 1U, sizeof(chunk), fp)) != 0U)
			{
				offset = 0U;

				while (offset < nread)
				{
					current = chunk + offset;
					newline = (const uint8_t*)memchr(current, '\n', nread - offset);
					take = (newline != NULL) ? (size_t)(newline - current) : nread - offset;

					if (lines == linenum)
					{
						located = true;
						if (take > (size_t)INT64_MAX - count)
						{
							result = -1;
							done = true;
							break;
						}

						count += take;
						avail = buflen - 1U - copied;
						if (avail > take)
						{
							avail = take;
						}

						if (avail != 0U)
						{
							qsc_memutils_copy(buffer + copied, current, avail);
							copied += avail;
						}
					}

					offset += take;
					if (newline != NULL)
					{
						if (lines == linenum)
						{
							result = (int64_t)count;
							done = true;
							break;
						}

						++offset;
						++lines;
					}
				}
			}

			if (done == false && located == true && ferror(fp) == 0)
			{
				result = (int64_t)count;
			}

			buffer[copied] = '\0';
			fclose(fp);
		}
	}

	return result;
}



bool qsc_fileutils_sync(FILE* fp)
{
	QSC_ASSERT(fp != NULL);

	int32_t fd;
	bool res;

	fd = -1;
	res = false;

	if (fp != NULL && fflush(fp) == 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		fd = _fileno(fp);

		if (fd >= 0)
		{
			res = (_commit(fd) == 0);
		}
#else
		fd = fileno(fp);

		if (fd >= 0)
		{
			res = (fsync(fd) == 0);
		}
#endif
	}

	return res;
}

size_t qsc_fileutils_safe_read(const char* fpath, size_t position, char* output, size_t length)
{
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);

	size_t res;

	res = 0U;

	if (fpath != NULL && output != NULL && length != 0U)
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
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	FILE* fp;
	size_t res;

	res = 0U;
	if (fpath != NULL && input != NULL && length != 0U)
	{
		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read_update, true);
		if (fp == NULL && errno == ENOENT)
		{
			/* Only create if the file genuinely does not exist. */
			fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_write_update, true);
		}

		if (fp != NULL)
		{
			if (qsc_fileutils_seekto(fp, position) == true)
			{
				res = fwrite(input, 1U, length, fp);
				if (fflush(fp) != 0)
				{
					res = 0U;
				}
			}

			if (fclose(fp) != 0)
			{
				res = 0U;
			}
		}
	}

	return res;
}



bool qsc_fileutils_seekto(FILE* fp, size_t position)
{
	QSC_ASSERT(fp != NULL);

	int32_t res;
	res = -1;
	if (fp != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (position <= (size_t)INT64_MAX)
		{
			res = _fseeki64(fp, (__int64)position, SEEK_SET);
		}
#else
		if ((uint64_t)position <= (uint64_t)INT64_MAX)
		{
			res = fseeko(fp, (off_t)position, SEEK_SET);
		}
#endif
	}

	return (res == 0);
}



bool qsc_fileutils_truncate_file(FILE* fp, size_t length)
{
	QSC_ASSERT(fp != NULL);

	bool res;
	res = false;
	if (fp != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (length <= (size_t)INT64_MAX && _fseeki64(fp, 0, SEEK_END) == 0)
		{
			const __int64 oldlen = _ftelli64(fp);
			if (oldlen >= 0 && length < (uint64_t)oldlen)
			{
				res = (_chsize_s(_fileno(fp), (uint64_t)length) == 0);
			}
		}
#else
		if ((uint64_t)length <= (uint64_t)INT64_MAX && fseeko(fp, (off_t)0, SEEK_END) == 0)
		{
			const off_t oldlen = ftello(fp);
			if (oldlen >= (off_t)0 && length < (uint64_t)oldlen)
			{
				res = (ftruncate(fileno(fp), (off_t)length) == 0);
			}
		}
#endif
	}
	return res;
}


bool qsc_fileutils_valid_path(const char* fpath)
{
	QSC_ASSERT(fpath != NULL);

	bool res;

	res = false;

	if (fpath != NULL)
	{
		char dir[QSC_FILEUTILS_MAX_PATH] = { 0U };
		char ext[QSC_FILEUTILS_MAX_EXTENSION] = { 0U };
		char name[QSC_FILEUTILS_MAX_FILENAME] = { 0U };

		if (qsc_fileutils_get_directory(dir, sizeof(dir), fpath) > 0U)
		{
			if (qsc_fileutils_get_name(name, sizeof(name), fpath) > 0U)
			{
				if (qsc_fileutils_get_extension(ext, sizeof(ext), fpath) > 0U)
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
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(inplen != 0U);
	QSC_ASSERT(fp != NULL);

	size_t res;

	res = 0U;

	if (input != NULL && inplen != 0U && fp != NULL)
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
	QSC_ASSERT(fpath != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(inplen != 0U);

	bool res;

	res = false;

	if (fpath != NULL && input != NULL && inplen != 0U)
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
			res = (fwrite(input, sizeof(char), inplen, fp) != 0U);

			if (res == true)
			{
				const char line[1U] = { '\n' };
				res = (fwrite(line, sizeof(char), sizeof(line), fp) != 0U);
			}

			fclose(fp);
		}
	}

	return res;
}

void qsc_fileutils_zeroise(const char* fpath)
{
	QSC_ASSERT(fpath != NULL);

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
#include "csp.h"
#include "consoleutils.h"
#include "intutils.h"

void qsc_fileutils_test(const char* fpath)
{
	QSC_ASSERT(fpath != NULL);

	uint8_t rnd[1024U] = { 0U };
	char smp[1024U] = { 0U };
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

		if (qsc_fileutils_copy_stream_to_file(fpath, (const char*)rnd, sizeof(rnd)) == true)
		{
			qsc_consoleutils_print_line("Success: copied random sample to file.");

			len = qsc_fileutils_get_size(fpath);

			if (len == sizeof(rnd))
			{
				qsc_consoleutils_print_line("Success: copied file size is a match.");

				if (qsc_fileutils_copy_file_to_stream(fpath, smp, sizeof(smp)) == sizeof(rnd))
				{
					if (qsc_memutils_are_equal((uint8_t*)smp, rnd, sizeof(rnd)) == true)
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
