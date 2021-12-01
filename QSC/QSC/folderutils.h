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
*/

#ifndef QSC_FOLDERUTILS_H
#define QSC_FOLDERUTILS_H

#include "common.h"

/*
* \file folderutils.h
* \brief Folder utilities, common folder support functions
*/

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*! \enum qsc_folderutils_directories
* \brief The system special folders enumeration
*/
typedef enum qsc_folderutils_directories
{
	qsc_folderutils_directories_user_app_data,		/*!< User App Data directory */
	qsc_folderutils_directories_user_desktop,		/*!< User Desktop directory */
	qsc_folderutils_directories_user_documents,		/*!< User Documents directory */
	qsc_folderutils_directories_user_downloads,		/*!< User Downloads directory */
	qsc_folderutils_directories_user_favourites,	/*!< User Favourites directory */
	qsc_folderutils_directories_user_music,			/*!< User Music directory */
	qsc_folderutils_directories_user_pictures,		/*!< User Pictures directory */
	qsc_folderutils_directories_user_programs,		/*!< User Programs directory */
	qsc_folderutils_directories_user_shortcuts,		/*!< User Shortcuts directory */
	qsc_folderutils_directories_user_videos,		/*!< User Video directory */
} qsc_folderutils_directories;

/**
* \brief Create a new folder

*
* \param path: [const] The full path including the new folder name
* \return Returns true if the folder is created
*/
QSC_EXPORT_API bool qsc_folderutils_create_directory(const char path[QSC_SYSTEM_MAX_PATH]);

/**
* \brief Delete a folder

*
* \param path: [const] The full path including the folder name
* \return Returns true if the folder is deleted
*/
QSC_EXPORT_API bool qsc_folderutils_delete_directory(const char path[QSC_SYSTEM_MAX_PATH]);

/**
* \brief Check if a folder exists

*
* \param path: [const] The full path including the folder name
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
