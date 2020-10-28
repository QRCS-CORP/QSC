#ifndef QSCTEST_FILE_TOOLS_H
#define QSCTEST_FILE_TOOLS_H

#include "common.h"
#include "../QSC/common.h"

/**
* \brief Convert a hexadecimal character string to a binary byte array
*
* \param filepath: The path to the test vector file
* \return Returns true if the file exists
*/
bool file_exists(const char* filepath);

#if defined(QSC_SYSTEM_COMPILER_MSC)
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
int64_t getline(char** line, size_t* length, FILE* fp);
#endif

#endif
