/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
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

#if defined(QSC_SYSTEM_OS_WINDOWS)
static const char QSC_FOLDERUTILS_DELIMITER = '\\';
#else
static const char QSC_FOLDERUTILS_DELIMITER = '/';
#endif

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
* \brief Append a folder path delimiter

*
* \param path: [const] The full path including the new folder name
* \return Returns true if the folder is created
*/
QSC_EXPORT_API void qsc_folderutils_append_delimiter(char path[QSC_SYSTEM_MAX_PATH]);

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

/**
* \brief Test the folder functions
*/
QSC_EXPORT_API void qsc_folderutils_test();

#endif
