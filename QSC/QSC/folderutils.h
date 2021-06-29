/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* An implementation of common string support functions
* Written by John G. Underhill
* Written on February 18, 2021
* Contact: support@vtdev.com 
*/

/*
* \file stringutils.h
* \brief <b>Folder utilities; common folder support functions</b> \n
* February 18, 2021
*/

#ifndef QSC_FOLDERUTILS_H
#define QSC_FOLDERUTILS_H

/* bogus winbase.h error */
#pragma warning(disable : 5105)

#include "common.h"

/*! \enum qsc_folderutils_directories
* \brief The system special folders enumeration
*/
QSC_EXPORT_API typedef enum qsc_folderutils_directories
{
	qsc_folderutils_directories_user_app_data,
	qsc_folderutils_directories_user_desktop,
	qsc_folderutils_directories_user_documents,
	qsc_folderutils_directories_user_downloads,
	qsc_folderutils_directories_user_favourites,
	qsc_folderutils_directories_user_music,
	qsc_folderutils_directories_user_pictures,
	qsc_folderutils_directories_user_programs,
	qsc_folderutils_directories_user_shortcuts,
	qsc_folderutils_directories_user_videos,
} qsc_folderutils_directories;

/**
* \brief Create a folder in an existing directory

*
* \param path: The full path including the new folder name
* \return Returns true if the folder is created
*/
QSC_EXPORT_API bool qsc_folderutils_create_directory(char path[QSC_SYSTEM_MAX_PATH]);

/**
* \brief Delete a folder in an existing directory

*
* \param path: The full path including the folder name
* \return Returns true if the folder is deleted
*/
QSC_EXPORT_API bool qsc_folderutils_delete_directory(const char path[QSC_SYSTEM_MAX_PATH]);

/**
* \brief Check if a folder exists

*
* \param path: The full path including the folder name
* \return Returns true if the folder is found
*/
QSC_EXPORT_API bool qsc_folderutils_directory_exists(const char path[QSC_SYSTEM_MAX_PATH]);

/**
* \brief Get the full path to a special system folder

*
* \param directory: The enum name of the system directory
* \param output: The output string containing the directory path
*/
QSC_EXPORT_API void qsc_folderutils_get_directory(qsc_folderutils_directories directory, char output[QSC_SYSTEM_MAX_PATH]);

#endif