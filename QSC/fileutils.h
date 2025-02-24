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

#ifndef QSC_FILEUTILS_H
#define QSC_FILEUTILS_H

#include "common.h"
#include <stdio.h>

/*!
 * \file fileutils.h
 * \brief Contains common file related functions.
 *
 * \details
 * Provides a suite of file utility functions for reading, writing, copying, and managing files and directories.
 * This includes operations such as appending to files, copying files to objects or streams, checking file existence
 * and access rights, retrieving file size, and listing files in a directory.
 *
 * \code
 * // Example: Reading a file into memory
 * uint8_t* data = qsc_file_read("example.txt", &filesize);
 * if (data != NULL) {
 *     // Process the file data as needed.
 *     qsc_file_free(data);
 * }
 * \endcode
 *
 * \section fileutils_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/fileio/file-management">Microsoft File Management API</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/">POSIX File Management</a>
 */

/*!
 * \def QSC_FILEUTILS_CHUNK_SIZE
 * \brief [size_t] The default file chunk size.
 */
#define QSC_FILEUTILS_CHUNK_SIZE 4096ULL

/*!
 * \def QSC_FILEUTILS_MAX_EXTENSION
 * \brief [size_t] The maximum file extension size.
 */
#define QSC_FILEUTILS_MAX_EXTENSION 16ULL

/*!
 * \def QSC_FILEUTILS_MAX_FILENAME
 * \brief [size_t] The maximum file name size.
 */
#define QSC_FILEUTILS_MAX_FILENAME QSC_SYSTEM_MAX_PATH

/*!
 * \def QSC_FILEUTILS_MAX_PATH
 * \brief [size_t] The maximum file path size.
 */
#define QSC_FILEUTILS_MAX_PATH QSC_SYSTEM_MAX_PATH

#if defined(QSC_SYSTEM_OS_WINDOWS)
    /*!
     * \brief [const char[]] The directory separator character for Windows.
     */
    static const char QSC_FILEUTILS_DIRECTORY_SEPERATOR[] = "\\";
#else
    /*!
     * \brief [const char[]] The directory separator character for POSIX systems.
     */
    static const char QSC_FILEUTILS_DIRECTORY_SEPERATOR[] = "/";
#endif

/*!
 * \enum qsc_fileutils_access_rights
 * \brief Enumerates the file access rights.
 */
typedef enum
{
    qsc_fileutils_access_exists  = 0x00U,       /*!< No access right specified. */
#if defined(QSC_SYSTEM_OS_WINDOWS)
    qsc_fileutils_access_read    = 0x01U,       /*!< The read access right. */
    qsc_fileutils_access_write   = 0x02U,       /*!< The write access right. */
    qsc_fileutils_access_execute = 0x03U,        /*!< The execute access right. */
#else
    qsc_fileutils_access_read    = 0x04U,       /*!< The read access right. */
    qsc_fileutils_access_write   = 0x02U,       /*!< The write access right. */
    qsc_fileutils_access_execute = 0x06U        /*!< The execute access right. */
#endif
} qsc_fileutils_access_rights;

/*!
 * \enum qsc_fileutils_mode
 * \brief Enumerates the file open modes.
 */
typedef enum
{
    qsc_fileutils_mode_none = 0x00U,            /*!< No mode was specified. */
    qsc_fileutils_mode_read = 0x01U,            /*!< Open file for input operations. */
    qsc_fileutils_mode_read_update = 0x02U,     /*!< Open file for update (input and output). */
    qsc_fileutils_mode_write = 0x03U,           /*!< Create an empty file for output operations. */
    qsc_fileutils_mode_write_update = 0x04U,    /*!< Create an empty file and open it for update. */
    qsc_fileutils_mode_append = 0x05U,          /*!< Open file for output at the end of the file. */
    qsc_fileutils_mode_append_update = 0x06U    /*!< Open file for update in append mode. */
} qsc_fileutils_mode;

/**
 * \brief Append an array of characters to a file.
 *
 * Writes new data to the end of a binary file.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \param stream:       [const char*] The array to write to the file.
 * \param length:       [size_t] The stream size.
 * \return              [bool] Returns true if the operation succeeded.
 */
QSC_EXPORT_API bool qsc_fileutils_append_to_file(const char* fpath, const char* stream, size_t length);

/**
 * \brief Copy a file to an object.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \param obj:          [void*] The object to write to.
 * \param length:       [size_t] The size of the object.
 * \return              [size_t] Returns the number of characters written to the object.
 */
QSC_EXPORT_API size_t qsc_fileutils_copy_file_to_object(const char* fpath, void* obj, size_t length);

/**
 * \brief Copy elements from a file to a byte array.
 *
 * \param fpath:        [const char*] The full fpath to the stream.
 * \param stream:       [char*] The stream receiving the file.
 * \param length:       [size_t] The number of bytes to write to the stream.
 * \return              [size_t] Returns the number of characters written to the stream.
 */
QSC_EXPORT_API size_t qsc_fileutils_copy_file_to_stream(const char* fpath, char* stream, size_t length);

/**
 * \brief Copy an object to a file.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \param obj:          [const void*] The object to write to the file.
 * \param length:       [size_t] The size of the object.
 * \return              [bool] Returns true if the operation succeeded.
 */
QSC_EXPORT_API bool qsc_fileutils_copy_object_to_file(const char* fpath, const void* obj, size_t length);

/**
 * \brief Copy the contents of a stream to a file.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \param stream:       [const char*] The array to write to the file.
 * \param length:       [size_t] The length of the array.
 * \return              [bool] Returns true if the operation succeeded.
 */
QSC_EXPORT_API bool qsc_fileutils_copy_stream_to_file(const char* fpath, const char* stream, size_t length);

/**
 * \brief Create a new file.
 *
 * \param fpath:        [const char*] The full fpath to the file to be created.
 * \return              [bool] Returns true for success.
 */
QSC_EXPORT_API bool qsc_fileutils_create(const char* fpath);

/**
 * \brief Delete a file.
 *
 * \param fpath:        [const char*] The full fpath to the file to be deleted.
 * \return              [bool] Returns true for success.
 */
QSC_EXPORT_API bool qsc_fileutils_delete(const char* fpath);

/**
 * \brief Erase a file's contents.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \return              [bool] Returns true for success.
 */
QSC_EXPORT_API bool qsc_fileutils_erase(const char* fpath);

/**
 * \brief Copy a file to a new location.
 *
 * \param inpath:       [const char*] The full fpath to the input file.
 * \param outpath:      [const char*] The full fpath to the output file.
 * \return              [bool] Returns true if the file was copied.
 */
QSC_EXPORT_API bool qsc_fileutils_file_copy(const char* inpath, const char* outpath);

/**
 * \brief Test a user's access right to a file.
 *
 * \param fpath:        [const char*] The fully qualified fpath to the file.
 * \param level:        [qsc_fileutils_access_rights] The access level to check.
 * \return              [bool] Returns true if the specified access level is present.
 */
QSC_EXPORT_API bool qsc_fileutils_get_access(const char* fpath, qsc_fileutils_access_rights level);

/**
 * \brief Get the file directory.
 *
 * \param directory:    [char*] The output directory buffer.
 * \param dirlen:       [size_t] The length of the directory buffer.
 * \param fpath:        [const char*] The full fpath to the file.
 * \return              [size_t] Returns the length of the directory string.
 */
QSC_EXPORT_API size_t qsc_fileutils_get_directory(char* directory, size_t dirlen, const char* fpath);

/**
 * \brief Get the file extension.
 *
 * \param extension:    [char*] The output extension buffer.
 * \param extlen:       [size_t] The length of the extension buffer.
 * \param fpath:        [const char*] The full fpath to the file.
 * \return              [size_t] Returns the length of the file extension.
 */
QSC_EXPORT_API size_t qsc_fileutils_get_extension(char* extension, size_t extlen, const char* fpath);

/**
 * \brief Get the file name.
 *
 * \param name:         [char*] The output file name buffer.
 * \param namelen:      [size_t] The length of the name buffer.
 * \param fpath:        [const char*] The full fpath to the file.
 * \return              [size_t] Returns the length of the file name.
 */
QSC_EXPORT_API size_t qsc_fileutils_get_name(char* name, size_t namelen, const char* fpath);

/**
 * \brief Reads a line of text from a formatted file.
 *
 * \warning The line buffer must be freed after the last call.
 *
 * \param line:         [char**] Pointer to the line buffer (dynamically allocated).
 * \param length:       [size_t*] Pointer to the buffer size.
 * \param fp:           [FILE*] The file stream handle.
 * \return              [int64_t] Returns the number of characters read.
 */
QSC_EXPORT_API int64_t qsc_fileutils_get_line(char** line, size_t* length, FILE* fp);

/**
 * \brief Get the file size in bytes.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \return              [size_t] Returns the size of the file in bytes.
 */
QSC_EXPORT_API size_t qsc_fileutils_get_size(const char* fpath);

/**
 * \brief Get the working directory fpath.
 *
 * \param fpath:        [char*] The output buffer for the current working directory.
 * \return              [bool] Returns true if the working directory was successfully retrieved.
 */
QSC_EXPORT_API bool qsc_fileutils_get_working_directory(char* fpath);

/**
 * \brief Get the filenames in a directory delineated with a newline.
 *
 * \param result:       [char*] The output result string.
 * \param reslen:       [size_t] The length of the output string.
 * \param directory:    [const char*] The starting directory.
 * \return              [size_t] Returns the length of the output string.
 */
QSC_EXPORT_API size_t qsc_fileutils_list_files(char* result, size_t reslen, const char* directory);

/**
 * \brief Close a file.
 *
 * \param fp:           [FILE*] The file pointer.
 */
QSC_EXPORT_API void qsc_fileutils_close(FILE* fp);

/**
 * \brief Test to see if a file exists.
 *
 * \param fpath:        [const char*] The fully qualified fpath to the file.
 * \return              [bool] Returns true if the file exists.
 */
QSC_EXPORT_API bool qsc_fileutils_exists(const char* fpath);

/**
 * \brief Open a file and return the handle.
 *
 * \param fpath:        [const char*] The fully qualified file fpath.
 * \param mode:         [qsc_fileutils_mode] The file access mode.
 * \param binary:       [bool] Open the file in binary mode (true) or ANSI mode (false).
 * \return              [FILE*] Returns the file handle, or NULL on failure.
 */
QSC_EXPORT_API FILE* qsc_fileutils_open(const char* fpath, qsc_fileutils_mode mode, bool binary);

/**
 * \brief Read data from a file into an output stream.
 *
 * \param output:       [char*] The output buffer.
 * \param otplen:       [size_t] The size of the output buffer.
 * \param position:     [size_t] The starting position within the file.
 * \param fp:           [FILE*] The file pointer.
 * \return              [size_t] Returns the number of bytes read.
 */
QSC_EXPORT_API size_t qsc_fileutils_read(char* output, size_t otplen, size_t position, FILE* fp);

/**
 * \brief Read data from a binary file.
 *
 * \param fpath:        [const char*] The file fpath.
 * \param position:     [size_t] The position to start reading from.
 * \param output:       [char*] The output character stream.
 * \param length:       [size_t] The number of bytes to read.
 * \return              [size_t] Returns the number of characters read.
 */
QSC_EXPORT_API size_t qsc_fileutils_safe_read(const char* fpath, size_t position, char* output, size_t length);

/**
 * \brief Write data to a binary file.
 *
 * \param fpath:        [const char*] The file fpath.
 * \param position:     [size_t] The position to start writing to.
 * \param input:        [const char*] The input character string.
 * \param length:       [size_t] The number of bytes to write.
 * \return              [size_t] Returns the number of characters written.
 */
QSC_EXPORT_API size_t qsc_fileutils_safe_write(const char* fpath, size_t position, const char* input, size_t length);

/**
 * \brief Set the file pointer position.
 *
 * \param fp:           [FILE*] The file pointer.
 * \param position:     [size_t] The position within the file.
 * \return              [bool] Returns true if the pointer has been moved.
 */
QSC_EXPORT_API bool qsc_fileutils_seekto(FILE* fp, size_t position);

/**
 * \brief Read a line of text from a file.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \param buffer:       [char*] The string buffer.
 * \param buflen:       [size_t] The size of the string buffer.
 * \param linenum:      [size_t] The line number to read.
 * \return              [int64_t] Returns the length of the line or -1 at EOF.
 */
QSC_EXPORT_API int64_t qsc_fileutils_read_line(const char* fpath, char* buffer, size_t buflen, size_t linenum);

/**
 * \brief Truncate a file to a specified byte size.
 *
 * \param fp:           [FILE*] The file pointer.
 * \param length:       [size_t] The new file size.
 * \return              [bool] Returns true if the file was successfully truncated.
 */
QSC_EXPORT_API bool qsc_fileutils_truncate_file(FILE* fp, size_t length);

/**
 * \brief Checks if the fpath is valid.
 *
 * \param fpath:        [const char*] The full fpath to the file.
 * \return              [bool] Returns true if the fpath is formed properly.
 */
QSC_EXPORT_API bool qsc_fileutils_valid_path(const char* fpath);

/**
 * \brief Write data to a file.
 *
 * \param input:        [const char*] The input buffer.
 * \param inplen:       [size_t] The size of the input buffer.
 * \param position:     [size_t] The starting position within the file.
 * \param fp:           [FILE*] The file pointer.
 * \return              [size_t] Returns the number of bytes written.
 */
QSC_EXPORT_API size_t qsc_fileutils_write(const char* input, size_t inplen, size_t position, FILE* fp);

/**
 * \brief Append a line of text to the end of a file.
 *
 * \param fpath:        [const char*] The file fpath.
 * \param input:        [const char*] The input buffer.
 * \param inplen:       [size_t] The size of the input buffer.
 * \return              [bool] Returns true if the operation succeeded.
 */
QSC_EXPORT_API bool qsc_fileutils_write_line(const char* fpath, const char* input, size_t inplen);

/**
 * \brief Truncate a file to zero bytes.
 *
 * \param fpath:        [const char*] The file fpath.
 */
QSC_EXPORT_API void qsc_fileutils_zeroise(const char* fpath);

/**
 * \brief Test the file functions.
 *
 * \param fpath:        [const char*] The file fpath.
 */
#if defined(QSC_DEBUG_MODE)
QSC_EXPORT_API void qsc_fileutils_test(const char* fpath);
#endif

#endif
