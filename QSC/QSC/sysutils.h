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
