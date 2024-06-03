#include "folderutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif
#include "memutils.h"
#include "stringutils.h"
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define WIN32_LEAN_AND_MEAN
#	include <direct.h>
#	include <initguid.h>
#	include <KnownFolders.h>
#	include <ShlObj.h>
#	include <Shlwapi.h>
#	include <tchar.h>
#	include <Windows.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma comment(lib, "Shlwapi.lib")
#   endif
#else
#   include <dirent.h>
#   include <sys/stat.h>
#   include <stdlib.h>
#   include <sys/types.h>
#   include <unistd.h>
#endif

void qsc_folderutils_append_delimiter(char path[QSC_SYSTEM_MAX_PATH])
{
	size_t len;

	len = qsc_stringutils_string_size(path);

	if (len < QSC_SYSTEM_MAX_PATH)
	{
		path[len] = QSC_FOLDERUTILS_DELIMITER;
		++len;
		path[len] = '\0';
	}
}

bool qsc_folderutils_create_directory(const char path[QSC_SYSTEM_MAX_PATH])
{
	int32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _mkdir(path);
#else
	res = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
#endif

	return (res == 0);
}

bool qsc_folderutils_delete_directory(const char path[QSC_SYSTEM_MAX_PATH])
{
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

void qsc_folderutils_get_directory(qsc_folderutils_directories directory, char output[QSC_SYSTEM_MAX_PATH])
{
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
	len = qsc_stringutils_string_size(pstr);

	if (len > 0)
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
#endif
}

bool qsc_folderutils_directory_has_delimiter(const char path[QSC_SYSTEM_MAX_PATH])
{
	size_t len;

	len = qsc_stringutils_string_size(path);

	return (path[len - 1] == '\\');
}

#if defined(QSC_DEBUG_MODE)
void qsc_folderutils_test()
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };

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

