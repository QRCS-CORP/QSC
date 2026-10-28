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

#	define _XOPEN_SOURCE 700
#	define _DARWIN_C_SOURCE
#	define _DEFAULT_SOURCE

#include "folderutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif
#include "memutils.h"
#include "stringutils.h"
#include <errno.h>
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	if !defined(WIN32_LEAN_AND_MEAN)
#		define WIN32_LEAN_AND_MEAN
#	endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#	include <direct.h>
#	include <initguid.h>
#	include <KnownFolders.h>
#	include <ShlObj.h>
#	include <Shlwapi.h>
#	include <stdio.h>
#	include <string.h>
#	include <tchar.h>
#	include <Windows.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma comment(lib, "Shlwapi.lib")
#   endif
#else
#	include <stdio.h>
#	include <string.h>
#	include <unistd.h>
#	include <dirent.h>
#	include <sys/stat.h>
#   include <stdlib.h>
#   include <sys/types.h>
#endif

#if !defined(QSC_SYSTEM_OS_WINDOWS)
/**
 * \brief Determine the file type of a POSIX directory entry without building an absolute path.
 * \param directory: An open enumeration handle, owned by the caller.
 * \param entry: Directory entry returned by readdir, valid until the next readdir call.
 * \return True for directories; false for other entries and failed stat operations.
 */
static bool folderutils_is_directory_entry(DIR* directory, const struct dirent* entry)
{
	bool res;
	res = (entry->d_type == DT_DIR);
	if (entry->d_type == DT_UNKNOWN || entry->d_type == DT_LNK)
	{
		struct stat st;
		res = (fstatat(dirfd(directory), entry->d_name, &st, 0) == 0 && S_ISDIR(st.st_mode));
	}
	return res;
}
#endif

void qsc_folderutils_append_delimiter(char path[QSC_SYSTEM_MAX_PATH])
{
	QSC_ASSERT(path != NULL);

	size_t len;
	if (path != NULL)
	{
		len = qsc_stringutils_string_size(path);
		if (len != 0U && len < QSC_SYSTEM_MAX_PATH - 1U && path[len - 1U] != QSC_FOLDERUTILS_DELIMITER)
		{
			path[len] = QSC_FOLDERUTILS_DELIMITER;
			path[len + 1U] = '\0';
		}
	}
}


bool qsc_folderutils_create_directory(const char path[QSC_SYSTEM_MAX_PATH])
{
	QSC_ASSERT(path != NULL);

	int32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _mkdir(path);
#else
	res = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
#endif

	return (res == 0);
}

bool qsc_folderutils_create_directory_tree(const char path[QSC_SYSTEM_MAX_PATH])
{
	char tmp[QSC_SYSTEM_MAX_PATH] = { 0U };
	size_t len;
	size_t pos;
	bool res;

	res = false;
	if (path != NULL)
	{
		len = 0U;
		while (len < sizeof(tmp) && path[len] != '\0')
		{
			++len;
		}
		if (len > 0U && len < sizeof(tmp))
		{
			qsc_memutils_copy(tmp, path, len + 1U);
			while (len > 1U && tmp[len - 1U] == QSC_FOLDERUTILS_DELIMITER)
			{
				tmp[--len] = '\0';
			}

			res = true;
			for (pos = 1U; pos < len && res == true; ++pos)
			{
				if (tmp[pos] == QSC_FOLDERUTILS_DELIMITER)
				{
					char saved;
					saved = tmp[pos];
					tmp[pos] = '\0';

#if defined(QSC_SYSTEM_OS_WINDOWS)
					/* Skip a drive-root prefix, which is not creatable. */
					if (!(pos == 2U && tmp[1U] == ':'))
#endif
					{
						if (qsc_folderutils_directory_exists(tmp) == false)
						{
							res = qsc_folderutils_create_directory(tmp);
							if (res == false && qsc_folderutils_directory_exists(tmp) == true)
							{
								res = true;
							}
						}
					}
					tmp[pos] = saved;
				}
			}

			if (res == true && qsc_folderutils_directory_exists(tmp) == false)
			{
				res = qsc_folderutils_create_directory(tmp);
				if (res == false && qsc_folderutils_directory_exists(tmp) == true)
				{
					res = true;
				}
			}
		}
	}
	return res;
}


bool qsc_folderutils_delete_directory(const char path[QSC_SYSTEM_MAX_PATH])
{
	QSC_ASSERT(path != NULL);

	int32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _rmdir(path);
#else
	res = rmdir(path);
#endif

	return (res == 0);
}

bool qsc_folderutils_directory_exists(const char path[QSC_SYSTEM_MAX_PATH])
{
	QSC_ASSERT(path != NULL);

	bool res;
	res = false;
	if (path != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		const DWORD attrs = GetFileAttributesA(path);
		res = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0U);
#else
		struct stat st;
		res = (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
	}
	return res;
}


size_t qsc_folderutils_directory_list(char* result, size_t reslen, const char* directory)
{
	QSC_ASSERT(result != NULL);
	QSC_ASSERT(reslen != 0U);
	QSC_ASSERT(directory != NULL);

	size_t used;
	used = 0U;

	if (result != NULL && reslen != 0U && directory != NULL)
	{
		result[0] = '\0';
#if defined(QSC_SYSTEM_OS_WINDOWS)
		WIN32_FIND_DATAA wfd;
		HANDLE find;
		char pattern[QSC_SYSTEM_MAX_PATH];
		int32_t pathlen;

		pathlen = snprintf(pattern, sizeof(pattern), "%s\\*", directory);
		if (pathlen > 0 && (size_t)pathlen < sizeof(pattern))
		{
			find = FindFirstFileA(pattern, &wfd);
			if (find != INVALID_HANDLE_VALUE)
			{
				do
				{
					if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U &&
						strcmp(wfd.cFileName, ".") != 0 && strcmp(wfd.cFileName, "..") != 0)
					{
						SYSTEMTIME created;
						SYSTEMTIME accessed;
						char record[QSC_SYSTEM_MAX_PATH + 90U];
						int32_t n;
						FileTimeToSystemTime(&wfd.ftCreationTime, &created);
						FileTimeToSystemTime(&wfd.ftLastAccessTime, &accessed);
						n = snprintf(record, sizeof(record), "%s\t%02u-%02u-%u %02u:%02u:%02u\t%02u-%02u-%u %02u:%02u:%02u\n",
							wfd.cFileName, created.wMonth, created.wDay, created.wYear,
							created.wHour, created.wMinute, created.wSecond,
							accessed.wMonth, accessed.wDay, accessed.wYear,
							accessed.wHour, accessed.wMinute, accessed.wSecond);
						if (n > 0 && (size_t)n < sizeof(record) && (size_t)n < reslen - used)
						{
							qsc_memutils_copy(result + used, record, (size_t)n);
							used += (size_t)n;
							result[used] = '\0';
						}
						else
						{
							break;
						}
					}
				} while (FindNextFileA(find, &wfd) != 0);
				FindClose(find);
			}
		}
#else
		DIR* dp;
		struct dirent* entry;

		dp = opendir(directory);
		if (dp != NULL)
		{
			while ((entry = readdir(dp)) != NULL)
			{
				bool isdir;
				size_t len;
				isdir = folderutils_is_directory_entry(dp, entry);

				if (isdir == true && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
				{
					len = strlen(entry->d_name);
					if (len < reslen - used - 1U)
					{
						qsc_memutils_copy(result + used, entry->d_name, len);
						used += len;
						result[used++] = '\n';
						result[used] = '\0';
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
	return used;
}


bool qsc_folderutils_enumerate(const char* directory, qsc_folderutils_entry_callback callback, void* context)
{
	QSC_ASSERT(directory != NULL);
	QSC_ASSERT(callback != NULL);

	bool res;
	res = false;
	if (directory != NULL && callback != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		WIN32_FIND_DATAA entry;
		HANDLE find;
		char pattern[QSC_SYSTEM_MAX_PATH];
		int32_t n;

		n = snprintf(pattern, sizeof(pattern), "%s\\*", directory);
		if (n > 0 && (size_t)n < sizeof(pattern))
		{
			find = FindFirstFileA(pattern, &entry);
			if (find != INVALID_HANDLE_VALUE)
			{
				res = true;
				do
				{
					if (strcmp(entry.cFileName, ".") != 0 && strcmp(entry.cFileName, "..") != 0)
					{
						if (callback(entry.cFileName,
							(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U, context) == false)
						{
							res = false;
							break;
						}
					}
				} while (FindNextFileA(find, &entry) != 0);
				if (res == true && GetLastError() != ERROR_NO_MORE_FILES)
				{
					res = false;
				}
				FindClose(find);
			}
		}
#else
		DIR* dp;
		struct dirent* entry;

		dp = opendir(directory);
		if (dp != NULL)
		{
			res = true;
			errno = 0;
			while ((entry = readdir(dp)) != NULL)
			{
				if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
				{
					if (callback(entry->d_name, folderutils_is_directory_entry(dp, entry), context) == false)
					{
						res = false;
						break;
					}
				}
				errno = 0;
			}
			if (res == true && errno != 0)
			{
				res = false;
			}
			if (closedir(dp) != 0)
			{
				res = false;
			}
		}
#endif
	}
	return res;
}

void qsc_folderutils_get_directory(qsc_folderutils_directories directory, char output[QSC_SYSTEM_MAX_PATH])
{
	QSC_ASSERT(output != NULL);

	qsc_memutils_clear(output, QSC_SYSTEM_MAX_PATH);

#if defined(QSC_SYSTEM_OS_WINDOWS)

	HRESULT hr;
	KNOWNFOLDERID id;
	PWSTR pstr;
	size_t len;

	if (directory == qsc_folderutils_directories_user_app_data)
	{
		id = FOLDERID_LocalAppData;
	}
	else if (directory == qsc_folderutils_directories_user_desktop)
	{
		id = FOLDERID_Desktop;
	}
	else if (directory == qsc_folderutils_directories_user_documents)
	{
		id = FOLDERID_LocalDocuments;
	}
	else if (directory == qsc_folderutils_directories_user_downloads)
	{
		id = FOLDERID_LocalDownloads;
	}
	else if (directory == qsc_folderutils_directories_user_favourites)
	{
		id = FOLDERID_Favorites;
	}
	else if (directory == qsc_folderutils_directories_user_music)
	{
		id = FOLDERID_LocalMusic;
	}
	else if (directory == qsc_folderutils_directories_user_pictures)
	{
		id = FOLDERID_LocalPictures;
	}
	else if (directory == qsc_folderutils_directories_user_programs)
	{
		id = FOLDERID_Programs;
	}
	else if (directory == qsc_folderutils_directories_user_shortcuts)
	{
		id = FOLDERID_ApplicationShortcuts;
	}
	else if (directory == qsc_folderutils_directories_user_videos)
	{
		id = FOLDERID_Videos;
	}
	else
	{
		id = FOLDERID_Documents;
	}

	hr = SHGetKnownFolderPath(&id, 0, NULL, &pstr);

	if (SUCCEEDED(hr) && pstr != NULL)
	{
        len = (size_t)WideCharToMultiByte(CP_ACP, 0, pstr, -1, NULL, 0, NULL, NULL);
        if (len != 0U && len <= QSC_SYSTEM_MAX_PATH)
        {
            WideCharToMultiByte(CP_ACP, 0, pstr, -1, output, (int32_t)len, NULL, NULL);
        }
		CoTaskMemFree(pstr);
	}

#else

	char* pstr;
	size_t len;

	qsc_stringutils_clear_string(output);
	pstr = getenv("HOME");

	if (pstr != NULL)
	{
		len = qsc_stringutils_string_size(pstr);

		if (len > 0U)
		{
			qsc_stringutils_copy_string(output, QSC_SYSTEM_MAX_PATH, pstr);
		}

		switch (directory)
		{
		case qsc_folderutils_directories_user_desktop:
		{
			qsc_stringutils_concat_strings(output, QSC_SYSTEM_MAX_PATH, "/Desktop");
			break;
		}
		case qsc_folderutils_directories_user_documents:
		{
			qsc_stringutils_concat_strings(output, QSC_SYSTEM_MAX_PATH, "/Documents");
			break;
		}
		case qsc_folderutils_directories_user_downloads:
		{
			qsc_stringutils_concat_strings(output, QSC_SYSTEM_MAX_PATH, "/Downloads");
			break;
		}
		case qsc_folderutils_directories_user_music:
		{
			qsc_stringutils_concat_strings(output, QSC_SYSTEM_MAX_PATH, "/Music");
			break;
		}
		case qsc_folderutils_directories_user_pictures:
		{
			qsc_stringutils_concat_strings(output, QSC_SYSTEM_MAX_PATH, "/Pictures");
			break;
		}
		case qsc_folderutils_directories_user_videos:
		{
			qsc_stringutils_concat_strings(output, QSC_SYSTEM_MAX_PATH, "/Videos");
			break;
		}
		default:
		{
			qsc_stringutils_concat_strings(output, QSC_SYSTEM_MAX_PATH, "/Documents");
		}
		}
	}
#endif
}

bool qsc_folderutils_directory_has_delimiter(const char path[QSC_SYSTEM_MAX_PATH])
{
	QSC_ASSERT(path != NULL);

	size_t len;
	bool res;

	res = false;
	len = qsc_stringutils_string_size(path);

	if (len > 0U)
	{
		res = (path[len - 1U] == QSC_FOLDERUTILS_DELIMITER);
	}

	return res;
}

#if defined(QSC_DEBUG_MODE)
void qsc_folderutils_test()
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0U };

	qsc_consoleutils_print_line("Folder verification test");
	qsc_consoleutils_print_line("Printing folder function output..");

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_desktop, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_downloads, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_favourites, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_music, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_pictures, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_programs, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_shortcuts, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_videos, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_consoleutils_print_line(fpath);

	qsc_stringutils_concat_strings(fpath, sizeof(fpath), "/test");
	qsc_folderutils_create_directory(fpath);

	if (qsc_folderutils_directory_exists(fpath) == true)
	{
		qsc_consoleutils_print_safe("Found path: ");
		qsc_consoleutils_print_line(fpath);

		qsc_folderutils_delete_directory(fpath);

		if (qsc_folderutils_directory_exists(fpath) == false)
		{
			qsc_consoleutils_print_safe("Deleted path: ");
			qsc_consoleutils_print_line(fpath);
		}
	}

	qsc_consoleutils_print_line("");
}
#endif

