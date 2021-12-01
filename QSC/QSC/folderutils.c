#include "folderutils.h"
#include "memutils.h"
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

	switch (directory)
	{
	case qsc_folderutils_directories_user_app_data:
	{
		pstr = getenv("PATH");
		break;
	}
	case qsc_folderutils_directories_user_desktop:
	case qsc_folderutils_directories_user_documents:
	case qsc_folderutils_directories_user_downloads:
	case qsc_folderutils_directories_user_favourites:
	case qsc_folderutils_directories_user_music:
	case qsc_folderutils_directories_user_pictures:
	case qsc_folderutils_directories_user_programs:
	case qsc_folderutils_directories_user_shortcuts:
	case qsc_folderutils_directories_user_videos:
	{
		pstr = getenv("HOME");
		break;
	}
	default:
	{
		pstr = getenv("HOME");
	}
	}

	len = strlen((char*)pstr);
	len = (len <= QSC_SYSTEM_MAX_PATH) ? len : QSC_SYSTEM_MAX_PATH;
	qsc_memutils_copy(output, pstr, len);

#endif
}
