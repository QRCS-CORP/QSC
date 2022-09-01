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

#ifndef QSC_SYSUTILS_H
#define QSC_SYSUTILS_H

#include "common.h"

/**
* \file sysutils.h
* \brief System functions; provides system statistics, counters, and feature availability
*/

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
* \def QSC_SYSUTILS_SYSTEM_NAME_MAX
* \brief The system maximum name length
*/
#define QSC_SYSUTILS_SYSTEM_NAME_MAX 256

/**
* \brief Get the computer string name
*
* \param name: The array receiving the computer name string
* \return Returns the size of the computer name in characters
*/
QSC_EXPORT_API size_t qsc_sysutils_computer_name(char* name);

/*!
* \struct qsc_sysutils_drive_space_state
* \brief The drive_space state structure
*/
QSC_EXPORT_API typedef struct
{
	uint64_t free;		/*!< The free drive space */
	uint64_t total;		/*!< The total drive space */
	uint64_t avail;		/*!< The available drive space */
} 
qsc_sysutils_drive_space_state;

/**
* \brief Get the system drive space statistics
*
* \param drive: The drive letter
* \param state: The struct containing the statistics
*/
QSC_EXPORT_API void qsc_sysutils_drive_space(const char* drive, qsc_sysutils_drive_space_state* state);

/*!
* \struct qsc_sysutils_memory_statistics_state
* \brief The memory_statistics state structure
*/
QSC_EXPORT_API typedef struct
{
	uint64_t phystotal;		/*!< The total physical memory */
	uint64_t physavail;		/*!< The available physical memory */
	uint64_t virttotal;		/*!< The total virtual memory */
	uint64_t virtavail;		/*!< The available virtual memory */
}
qsc_sysutils_memory_statistics_state;

/**
* \brief Get the memory statistics from the system
*
* \param state: The struct containing the memory statistics
*/
QSC_EXPORT_API void qsc_sysutils_memory_statistics(qsc_sysutils_memory_statistics_state* state);

/**
* \brief Get the current process id
*
* \return Returns the process id
*/
QSC_EXPORT_API uint32_t qsc_sysutils_process_id(void);

/**
* \brief Get the RDTSC availability status
*
* \return Returns true if RDTSC is available
*/
QSC_EXPORT_API bool qsc_sysutils_rdtsc_available();

/**
* \brief Get the systems logged-on user name string
*
* \param name: The char array that holds the user name 
* \return Returns the size of the user name
*/
QSC_EXPORT_API size_t qsc_sysutils_user_name(char* name);

/**
* \brief Get the system up-time since boot
*
* \return Returns the system up-time
*/
QSC_EXPORT_API uint64_t qsc_sysutils_system_uptime(void);

/**
* \brief Get the current high-resolution time-stamp
*
* \return Returns the system time-stamp
*/
QSC_EXPORT_API uint64_t qsc_sysutils_system_timestamp(void);

/**
* \brief Get the users identity string
*
* \param name: The char array that holds the user name
* \param id: The output array containing the id string
*/
QSC_EXPORT_API void qsc_sysutils_user_identity(const char* name, char* id);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print the output of system function calls
*/
QSC_EXPORT_API void qsc_system_values_print();
#endif

#endif
