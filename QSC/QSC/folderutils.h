
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
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
* \brief Check if the folder path ends in a delimter

*
* \param path: [const] The full path including the folder name
* \return Returns true if the folder ends in a delimter
*/
QSC_EXPORT_API bool qsc_folderutils_directory_has_delimiter(const char path[QSC_SYSTEM_MAX_PATH]);

/**
* \brief Test the folder functions
*/
QSC_EXPORT_API void qsc_folderutils_test();

#endif
