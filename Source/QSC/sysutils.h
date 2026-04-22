/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_SYSUTILS_H
#define QSC_SYSUTILS_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file sysutils.h
 * \brief System functions; provides system statistics, counters, and feature availability.
 *
 * \details
 * This header provides functions for retrieving system-level information including computer name,
 * drive space, memory statistics, process identifiers, and high-resolution time-stamps. It also
 * provides functions to query the current user's identity and the system's up-time since boot.
 *
 * \code
 * // Example: Retrieve and print system memory statistics.
 * qsc_sysutils_memory_statistics_state mem_stats;
 * qsc_sysutils_memory_statistics(&mem_stats);
 * printf("Total Physical Memory: %llu bytes\n", mem_stats.phystotal);
 * \endcode
 *
 * \section sysutils_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/sysinfo/system-information">Microsoft System Information</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/009695399/functions/sysinfo.html">POSIX sysinfo Documentation </a>
 */

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
* \def QSC_SYSUTILS_SYSTEM_NAME_MAX
* \brief The system maximum name length
*/
#define QSC_SYSUTILS_SYSTEM_NAME_MAX 256ULL

/*!
* \def QSC_USERNAME_SYSTEM_NAME_MAX
* \brief The maximum user name length
*/
#define QSC_USERNAME_SYSTEM_NAME_MAX 256ULL

/**
* \brief Get the computer string name
*
* \param name: The array receiving the computer name string
* \return Returns the size of the computer name in characters
*/
QSC_EXPORT_API size_t qsc_sysutils_computer_name(char* name);

/**
* \brief Get the CPU count
*
* \return Returns the number of cpus on the system
*/
QSC_EXPORT_API size_t qsc_sysutils_cpu_count(void);

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
* \param state:	[qsc_sysutils_memory_statistics_state*] The struct containing the memory statistics
*/
QSC_EXPORT_API void qsc_sysutils_memory_statistics(qsc_sysutils_memory_statistics_state* state);

/**
* \brief On Windows returns the drive letter containing the OS, on macOS/BSD/Linux returns '/'
*
* \return [char] 'A'..'Z' on success (Windows), '/' on *nix, or \0
*/
QSC_EXPORT_API char qsc_sysutils_get_os_drive_letter(void);

/**
* \brief Get the current process id
*
* \return [uint32_t] Returns the process id
*/
QSC_EXPORT_API uint32_t qsc_sysutils_process_id(void);

/**
* \brief Get the RDTSC availability status
*
* \return [bool] Returns true if RDTSC is available
*/
QSC_EXPORT_API bool qsc_sysutils_rdtsc_available(void);

/**
* \brief Get the systems logged-on user name string
*
* \param name: [char*] The char array that holds the user name 
* 
* \return [size_t] Returns the size of the user name
*/
QSC_EXPORT_API size_t qsc_sysutils_user_name(char* name);

/**
* \brief Get the system up-time since boot
*
* \return [uint64_t] Returns the system up-time
*/
QSC_EXPORT_API uint64_t qsc_sysutils_system_uptime(void);

/**
* \brief Get the current high-resolution time-stamp
*
* \return [uint64_t] Returns the system time-stamp
*/
QSC_EXPORT_API uint64_t qsc_sysutils_system_timestamp(void);

/**
* \brief Get the users identity string
*
* \param name: [const char*] The char array that holds the user name
* \param id: [char*] The output array containing the id string
*/
QSC_EXPORT_API void qsc_sysutils_user_identity(const char* name, char* id);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print the output of system function calls
*/
QSC_EXPORT_API void qsc_system_values_print(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
