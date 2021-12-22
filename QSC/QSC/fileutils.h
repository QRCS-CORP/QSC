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

#ifndef QSC_FILEUTILS_H
#define QSC_FILEUTILS_H

#include "common.h"
#include <stdio.h>

/**
* \file fileutils.h
* \brief File utilities contains common file related functions
*/

/*! \enum qsc_fileutils_access_rights
* The access rights enumeration.
*/
typedef enum qsc_fileutils_access_rights
{
	qsc_fileutils_access_exists = 0,		/*!< No access right specified */
#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_fileutils_access_read = 1,			/*!< The read access right */
	qsc_fileutils_access_write = 2,			/*!< The write access right */
	qsc_fileutils_access_execute = 3,		/*!< The execute access right */
#else
	qsc_fileutils_access_read = 4,			/*!< The read access right */
	qsc_fileutils_access_write = 2,			/*!< The write access right */
	qsc_fileutils_access_execute = 6,		/*!< The execute access right */
#endif
} qsc_fileutils_access_rights;

/*! \enum qsc_fileutils_mode
* The file mode enumeration.
*/
typedef enum qsc_fileutils_mode
{
	qsc_fileutils_mode_none = 0,			/*!< No mode was specified */
	qsc_fileutils_mode_read = 1,			/*!< Open file for input operations */
	qsc_fileutils_mode_read_update = 2,		/*!< read/update: Open a file for update (both for input and output) */
	qsc_fileutils_mode_write = 3,			/*!< Create an empty file for output operations */
	qsc_fileutils_mode_write_update = 4,	/*!< write/update: Create an empty file and open it for update */
	qsc_fileutils_mode_append = 5,			/*!< Open file for output at the end of a file */
	qsc_fileutils_mode_append_update = 6,	/*!< append/update: Open a file for update (both for input and output) */

} qsc_fileutils_mode;

/**
* \brief Close a file
*
* \param fp: The file pointer
*/
QSC_EXPORT_API void qsc_filetools_file_close(FILE* fp);

/**
* \brief Open a file and return the handle
*
* \param path: The current director
* \param mode: The file access mode
* \return Returns the file handle, or NULL on failure
*/
QSC_EXPORT_API FILE* qsc_filetools_file_open(const char* path, qsc_fileutils_mode mode);

/**
* \brief Open a file for binary operations and return the handle
*
* \param path: The current director
* \param mode: The file access mode
* \return Returns the file handle, or NULL on failure
*/
QSC_EXPORT_API FILE* qsc_filetools_file_binary_open(const char* path, qsc_fileutils_mode mode);

/**
* \brief Get the working directory path
*
* \param path: The current directory
* \return Returns true if the path is found, false if the buffer is too small or path not found
*/
QSC_EXPORT_API bool qsc_filetools_working_directory(char* path);

/**
* \brief Test a users access right to a file
*
* \param path: [const] The fully qualified path to the file
* \param level: the access level to check
* \return Returns true if the access level is present
*/
QSC_EXPORT_API bool qsc_filetools_file_access(const char* path, qsc_fileutils_access_rights level);

/**
* \brief Test to see if a file exists
*
* \param path: [const] The fully qualified path to the file
* \return Returns true if the file exists
*/
QSC_EXPORT_API bool qsc_filetools_file_exists(const char* path);

/**
* \brief Read data to a binary file
*
* \param path: The file path
* \param position: The position to start reading from
* \param output: the output char stream
* \param length:the number of bytes to read
* \return Returns the number of characters read
*/
QSC_EXPORT_API size_t qsc_filetools_file_read(const char* path, size_t position, char* output, size_t length);

/**
* \brief Get the files size in bytes
*
* \param path: [const] The path to the file
* \return Returns the length of the file
*/
QSC_EXPORT_API size_t qsc_filetools_file_size(const char* path);

/**
* \brief Write data to a binary file
*
* \param path: The file path
* \param position: The position to start writing to
* \param input: the input character string
* \param length: the number of bytes to write
* \return Returns the number of characters written
*/
QSC_EXPORT_API size_t qsc_filetools_file_write(const char* path, size_t position, const char* input, size_t length);

/**
* \brief Reads a line of text from a formatted file.
*
* \warning line buffer must be freed after last call
*
* \param line: the line of text to read
* \param length: the buffer size
* \param fp: the file stream handle
* \return Returns the number of characters read
*/
QSC_EXPORT_API int64_t qsc_filetools_getline(char** line, size_t* length, FILE* fp);

/**
* \brief Append an array of characters to a file.
* Writes new data to the end of a binary file.
*
* \param path: [const] The path to the file
* \param stream: [const] The array to write to the file
* \param length: the stream size
* \return Returns true if the operation succeeded
*/
QSC_EXPORT_API bool qsc_filetools_append_to_file(const char* path, const char* stream, size_t length);

/**
* \brief Create a new file
*
* \param path: [const] The path to the file to be created
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_filetools_create_file(const char* path);

/**
* \brief Copy an object to a file.
*
* \param path: [const] The path to the file
* \param obj: [const] The object to write to the file
* \param length: The size of the object
* \return Returns true if the operation succeeded
*/
QSC_EXPORT_API bool qsc_filetools_copy_object_to_file(const char* path, const void* obj, size_t length);

/**
* \brief Copy the contents of a stream to a file.
*
* \param [const] path: The path to the file
* \param [const] stream: The array to write to the file
* \param length: The length of the array
* \return Returns true if the operation succeeded
*/
QSC_EXPORT_API bool qsc_filetools_copy_stream_to_file(const char* path, const char* stream, size_t length);

/**
* \brief Copy a file to an object.
*
* \param path: [const] The path to the file
* \param obj: The object to write to the file
* \param length: The size of the object
* \return Returns the number of characters written to the byte array
*/
QSC_EXPORT_API size_t qsc_filetools_copy_file_to_object(const char* path, void* obj, size_t length);

/**
* \brief Copy elements from a file to a byte array.
*
* \param path: [const] The path to the file
* \param stream: The array to write to the file
* \param length: The number of bytes to write to the file
* \return Returns the number of characters written to the byte array
*/
QSC_EXPORT_API size_t qsc_filetools_copy_file_to_stream(const char* path, char* stream, size_t length);

/**
* \brief Delete a file
*
* \param path: [const] The path to the file ro be deleted
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_filetools_delete_file(const char* path);

/**
* \brief Erase a files contents
*
* \param path: [const] The path to the file
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_filetools_erase_file(const char* path);

/**
* \brief Read a line of text from a file
*
* \param path: [const] The path to the file
* \param buffer: The string buffer
* \param buflen: The size of the string buffer
* \param linenum: The line number to read
* \return Returns the length of the line
*/
QSC_EXPORT_API size_t qsc_filetools_read_line(const char* path, char* buffer, size_t buflen, size_t linenum);

#endif
