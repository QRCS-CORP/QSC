/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_FOLDERUTILS_H
#define QSC_FOLDERUTILS_H

#include "common.h"
#include <stdio.h>

QSC_CPLUSPLUS_ENABLED_START

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
 * \file folderutils.h
 * \brief Folder utilities: common folder support functions.
 *
 * \details
 * This file provides a suite of functions for performing operations on folders such as:
 * - Appending a folder delimiter to a path.
 * - Creating and deleting directories.
 * - Checking for the existence of a folder.
 * - Listing files within a directory.
 * - Retrieving the full path to a special system folder.
 *
 * \code
 * // Example: Creating a new directory
 * if (qsc_folder_create("C:\\NewFolder") == true) {
 *     // Folder successfully created.
 * }
 * \endcode
 *
 * \section folderutils_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/fileio/directory-functions">Microsoft Directory Functions</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/opendir.html">POSIX Directory Operations</a>
 */

#if defined(QSC_SYSTEM_OS_WINDOWS)
    static const char QSC_FOLDERUTILS_DELIMITER = '\\';
#else
    static const char QSC_FOLDERUTILS_DELIMITER = '/';
#endif

/*!
 * \enum qsc_folderutils_directories
 * \brief The system special folders enumeration.
 */
typedef enum
{
    qsc_folderutils_directories_user_app_data = 0x00U,      /*!< User App Data directory. */
    qsc_folderutils_directories_user_desktop = 0x01U,       /*!< User Desktop directory. */
    qsc_folderutils_directories_user_documents = 0x02U,     /*!< User Documents directory. */
    qsc_folderutils_directories_user_downloads = 0x03U,     /*!< User Downloads directory. */
    qsc_folderutils_directories_user_favourites = 0x04U,    /*!< User Favourites directory. */
    qsc_folderutils_directories_user_music = 0x05U,         /*!< User Music directory. */
    qsc_folderutils_directories_user_pictures = 0x06U,      /*!< User Pictures directory. */
    qsc_folderutils_directories_user_programs = 0x07U,      /*!< User Programs directory. */
    qsc_folderutils_directories_user_shortcuts = 0x08U,     /*!< User Shortcuts directory. */
    qsc_folderutils_directories_user_videos = 0x09U         /*!< User Video directory. */
} qsc_folderutils_directories;

/**
 * \brief Append a folder path delimiter.
 *
 * Appends a directory delimiter to the provided path string if it is not already present.
 *
 * \param path:         [char*] The full path including the new folder name.
 */
QSC_EXPORT_API void qsc_folderutils_append_delimiter(char path[QSC_SYSTEM_MAX_PATH]);

/**
 * \brief Create a new folder.
 *
 * Creates a directory at the specified path.
 *
 * \param path:         [const char*] The full path including the new folder name.
 * \return              [bool] Returns true if the folder is created.
 */
QSC_EXPORT_API bool qsc_folderutils_create_directory(const char path[QSC_SYSTEM_MAX_PATH]);

/**
 * \brief Delete a folder.
 *
 * Deletes the directory at the specified path.
 *
 * \param path:         [const char*] The full path including the folder name.
 * \return              [bool] Returns true if the folder is deleted.
 */
QSC_EXPORT_API bool qsc_folderutils_delete_directory(const char path[QSC_SYSTEM_MAX_PATH]);

/**
 * \brief Check if a folder exists.
 *
 * Checks whether the specified folder exists.
 *
 * \param path:         [const char*] The full path including the folder name.
 * \return              [bool] Returns true if the folder is found.
 */
QSC_EXPORT_API bool qsc_folderutils_directory_exists(const char path[QSC_SYSTEM_MAX_PATH]);

/**
 * \brief Write a list of directories to a string, delineated by newline characters.
 *
 * Constructs a string listing the directories within the specified starting directory.
 *
 * \param result:       [char*] The output result string.
 * \param reslen:       [size_t] The length of the output string buffer.
 * \param directory:    [const char*] The starting directory.
 * \return              [size_t] Returns the length of the output string.
 */
QSC_EXPORT_API size_t qsc_folderutils_directory_list(char* result, size_t reslen, const char* directory);

/**
 * \brief Get the full path to a special system folder.
 *
 * Retrieves the full directory path corresponding to the given special folder enumeration.
 *
 * \param directory:    [qsc_folderutils_directories] The enum value of the system folder.
 * \param output:       [char*] The output string containing the directory path.
 */
QSC_EXPORT_API void qsc_folderutils_get_directory(qsc_folderutils_directories directory, char output[QSC_SYSTEM_MAX_PATH]);

/**
 * \brief Check if the folder path ends in a delimiter.
 *
 * Determines whether the provided folder path string ends with a directory delimiter.
 *
 * \param path:         [const char*] The full path including the folder name.
 * \return              [bool] Returns true if the folder path ends with a delimiter.
 */
QSC_EXPORT_API bool qsc_folderutils_directory_has_delimiter(const char path[QSC_SYSTEM_MAX_PATH]);

#if defined(QSC_DEBUG_MODE)
/**
 * \brief Test the folder functions.
 *
 * Executes internal tests on folder utility functions.
 */
QSC_EXPORT_API void qsc_folderutils_test(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
