#	define _XOPEN_SOURCE 700
#	define _DARWIN_C_SOURCE
#	define _DEFAULT_SOURCE

#include "folderutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif
#include "memutils.h"
#include "stringutils.h"
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	if !defined(WIN32_LEAN_AND_MEAN)
#		define WIN32_LEAN_AND_MEAN
#	endif
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

void qsc_folderutils_append_delimiter(char path[QSC_SYSTEM_MAX_PATH])
{
	QSC_ASSERT(path != NULL);

	size_t len;

	len = qsc_stringutils_string_size(path);

	if (len < QSC_SYSTEM_MAX_PATH - 1U)
	{
		path[len] = QSC_FOLDERUTILS_DELIMITER;
		++len;
		path[len] = '\0';
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
	char* p;
	char sch;
	bool res;

	res = false;

	if (path != NULL)
	{
		qsc_memutils_copy(tmp, path, QSC_SYSTEM_MAX_PATH - 1U);
		tmp[QSC_SYSTEM_MAX_PATH - 1U] = '\0';
		len = strlen(tmp);

		/* remove trailing delimiter if present */
		if (len > 0U && tmp[len - 1U] == QSC_FOLDERUTILS_DELIMITER)
		{
			tmp[len - 1U] = '\0';
		}

		res = true;

		/* iterate through path and create each component */
		for (p = tmp + 1; *p != '\0' && res; p++)
		{
			if (*p == QSC_FOLDERUTILS_DELIMITER)
			{
				sch = *p;
				*p = '\0';

				if (qsc_folderutils_directory_exists(tmp) == false)
				{
					res = qsc_folderutils_create_directory(tmp);

					if (res == false)
					{
						break;
					}
				}

				*p = sch;
			}
		}

		if (res == true)
		{
			if (qsc_folderutils_directory_exists(tmp) == false)
			{
				res = qsc_folderutils_create_directory(tmp);
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

#if defined(QSC_SYSTEM_OS_WINDOWS)

	LPCSTR lppath = TEXT(path);

	res = (PathFileExistsA(lppath) == TRUE);

#else

	res = false;

	DIR* dir = opendir(path);

	if (dir)
	{
		closedir(dir);
		res = true;
	}

#endif

	return res;
}

size_t qsc_folderutils_directory_list(char* result, size_t reslen, const char* directory)
{
	QSC_ASSERT(result != NULL);
	QSC_ASSERT(reslen != 0U);
	QSC_ASSERT(directory != NULL);

	size_t lctr;

	lctr = 0U;

	if (result != NULL && reslen != 0U && directory != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)

		WIN32_FIND_DATA wfd;
		HANDLE hFind;
		char spath[MAX_PATH] = { 0U };

		/* create the search path pattern */
		snprintf(spath, MAX_PATH, "%s\\*", directory);
		hFind = FindFirstFile(spath, &wfd);

		if (hFind != INVALID_HANDLE_VALUE)
		{
			do {
				/* check if the found item is a directory and not "." or ".." */
				if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
					strcmp(wfd.cFileName, ".") != 0 &&
					strcmp(wfd.cFileName, "..") != 0)
				{
					size_t ilen = strlen(wfd.cFileName);

					if (lctr + ilen + 1U <= reslen)
					{
						SYSTEMTIME atime;
						SYSTEMTIME ctime;
						size_t lpos;

						/* Append directory name to result buffer */
						strcat_s(result, reslen, wfd.cFileName);
						strcat_s(result, reslen, "\t");
						lpos = strlen(result);

						FileTimeToSystemTime(&wfd.ftLastAccessTime, &atime);
						FileTimeToSystemTime(&wfd.ftCreationTime, &ctime);

						lpos += sprintf_s(result + lpos, reslen - lpos, "%02d-%02d-%d %02d:%02d:%02d\t",
							ctime.wMonth, ctime.wDay, ctime.wYear, ctime.wHour, ctime.wMinute, ctime.wSecond);

						sprintf_s(result + lpos, reslen - lpos, "%02d-%02d-%d %02d:%02d:%02d\n",
							atime.wMonth, atime.wDay, atime.wYear, atime.wHour, atime.wMinute, atime.wSecond);

						lctr += ilen + 1U;
					}
					else
					{
						break;
					}
				}
			} while (FindNextFile(hFind, &wfd) != 0U);

			FindClose(hFind);
		}

#else

		DIR *dir;
		struct dirent *entry;

		dir = opendir(directory);

		if (dir)
		{
			while ((entry = readdir(dir)) != NULL)
			{
				bool isdir;

				if (entry->d_type == DT_UNKNOWN) 
				{
					struct stat st;
					char full[QSC_SYSTEM_MAX_PATH] = { 0U };

					snprintf(full, sizeof(full), "%s/%s", directory, entry->d_name);
					isdir = (stat(full, &st) == 0 && S_ISDIR(st.st_mode));
				}
				else
				{
					isdir = (entry->d_type == DT_DIR);
				}

				if (isdir && strcmp(entry->d_name, ".") != 0U && strcmp(entry->d_name, "..") != 0U)
				{
					size_t item_length = strlen(entry->d_name);

					if (lctr + item_length + 1 <= reslen)
					{
						strcat(result, entry->d_name);
						strcat(result, "\n");
						lctr += item_length + 1U;
					}
					else
					{
						break;
					}
				}
			}

			closedir(dir);
		}

#endif
	}

    return lctr;
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
		len = (size_t)WideCharToMultiByte(CP_ACP, 0, pstr, (int32_t)wcslen(pstr), NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_ACP, 0, pstr, (int32_t)wcslen(pstr), output, (int32_t)len, NULL, NULL);
		output[len] = '\0';
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

