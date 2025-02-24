/* 2025 Quantum Resistant Cryptographic Solutions Corporation
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


#ifndef QSC_WINUTILLS_H
#define QSC_WINUTILLS_H

#include "common.h"

/**
 * \file winutils.h
 * \brief Windows utility functions.
 *
 * \details
 * This header defines utility functions for various Windows-specific operations, including file attribute management,
 * process management, registry operations, service management, and executing applications with elevated privileges.
 * The functions provide an abstraction layer over the Windows API, enabling applications to perform common system-level tasks.
 *
 * \code
 * // Example: Retrieve file attributes for a given file path.
 * char attributes[QSC_WINTOOLS_ATTRIBUTES_BUFFER_SIZE];
 * size_t attr_len = qsc_winutils_file_get_attributes(attributes, QSC_WINTOOLS_ATTRIBUTES_BUFFER_SIZE, "C:\\example.txt");
 * printf("File attributes: %s\n", attributes);
 * \endcode
 */

/*!
* \def QSC_WINTOOLS_ATTRIBUTES_BUFFER_SIZE
* \brief The file attributes buffer size 
*/
#define QSC_WINTOOLS_ATTRIBUTES_BUFFER_SIZE 256ULL

/*!
* \def QSC_WINTOOLS_NETSTAT_BUFFER_SIZE
* \brief The network statistics buffer size 
*/
#define QSC_WINTOOLS_NETSTAT_BUFFER_SIZE 1024ULL

/*!
* \def QSC_WINTOOLS_NETSTAT_NAME_SIZE
* \brief The network statistics name size 
*/
#define QSC_WINTOOLS_NETSTAT_NAME_SIZE 256ULL

/*!
* \def QSC_WINTOOLS_PROCESS_LIST_SIZE
* \brief The process list buffer size
*/
#define QSC_WINTOOLS_PROCESS_LIST_SIZE 16384ULL

/*!
* \def QSC_WINTOOLS_REGISTRY_BUFFER_SIZE
* \brief The registry buffer size
*/
#define QSC_WINTOOLS_REGISTRY_BUFFER_SIZE 1024ULL

/*!
* \def QSC_WINTOOLS_REGISTRY_LIST_SIZE
* \brief The registry list buffer size
*/
#define QSC_WINTOOLS_REGISTRY_LIST_SIZE 8192ULL

/*!
* \def QSC_WINTOOLS_RUNAS_BUFFER_SIZE
* \brief The runas buffer size
*/
#define QSC_WINTOOLS_RUNAS_BUFFER_SIZE 260ULL

/*!
* \def QSC_WINTOOLS_SERVICE_LIST_SIZE
* \brief The service list size
*/
#define QSC_WINTOOLS_SERVICE_LIST_SIZE 16384ULL

/*!
* \def QSC_WINTOOLS_SERVICE_BUFFER_SIZE
* \brief The service list buffer size
*/
#define QSC_WINTOOLS_SERVICE_BUFFER_SIZE 512ULL

/*!
* \def QSC_WINTOOLS_SERVICE_LIST_DESCRIPTION
* \brief Include the service descriptions in the service list output
*/
#define QSC_WINTOOLS_SERVICE_LIST_DESCRIPTION

///*!
//* \def QSC_WINTOOLS_SERVICE_LIST_ACTIVE_ONLY
//* \brief Only include running services when listing services
//*/
//#define QSC_WINTOOLS_SERVICE_LIST_ACTIVE_ONLY

/*! \enum qsc_winutils_registry_value_types
* \brief The registry value option types
*/
typedef enum
{
    REG_SZ_TYPE = 0x00U,                    /*!< String type value */
    REG_DWORD_TYPE = 0x01U,                 /*!< Dword type value */
    REG_QWORD_TYPE = 0x02U,                 /*!< Qword type value */
    REG_BINARY_TYPE = 0x03U                 /*!< Binary type value */
} qsc_winutils_registry_value_types;

/*! \enum qsc_winutils_service_states
* \brief The service states enumeration
*/
typedef enum
{
    QSC_WINUTILS_SERVICE_START = 0x00U,     /*!< Start the service */
    QSC_WINUTILS_SERVICE_STOP = 0x01U,      /*!< Stop the service */
    QSC_WINUTILS_SERVICE_PAUSE = 0x02U,     /*!< Pause the service */
    QSC_WINUTILS_SERVICE_RESUME = 0x03U     /*!< Resume the service */
} qsc_winutils_service_states;

/**
* \brief Get a list of file attributes
*
* \param result:    [char*] The result output string
* \param reslen:    [size_t] The length of the result string
* \param path:      [const char*] The file path
*
* \return           [size_t] Returns The length of the attribute string
*/
QSC_EXPORT_API size_t qsc_winutils_file_get_attributes(char* result, size_t reslen, const char* path);

/**
* \brief Set a file attribute.
* Valid attributes are readonly, hidden, system, archive, normal, temporary, offline, noindex, encrypted
*
* \param path:      [const char*] The file path
* \param attr:      [const char*] The file attribute
*
* \return           [bool] Returns true if the attribute was applied
*/
QSC_EXPORT_API bool qsc_winutils_file_set_attribute(const char* path, const char* attr);

/**
* \brief Get a list of network statistics seperated by newline characters
*
* \param result:    [char*] The result output string
* \param reslen:    [size_t] The length of the result string
*
* \return           [size_t] Returns the size of the result string
*/
QSC_EXPORT_API size_t qsc_winutils_network_statistics(char* result, size_t reslen);

/**
* \brief Create a list of processes and their descriptions
*
* \param result:    [char*] The result output string
* \param reslen:    [size_t] The length of the result string
*
* \return           [size_t] Returns the length of the process list string
*/
QSC_EXPORT_API size_t qsc_winutils_process_list(char* result, size_t reslen);

/**
* \brief Elevate the token access
*
* \return           [bool] Returns true if successful
*/
QSC_EXPORT_API bool qsc_winutils_process_token_elevate(void);

/**
* \brief Terminate a process
*
* \param name:      [const char*] The process name
*
* \return           [bool] Returns true if the process is terminated
*/
QSC_EXPORT_API bool qsc_winutils_process_terminate(const char* name);

/**
* \brief Create a registry key and add a value
*
* \param keypath:   [const char*] The fully qualified path; root\subkey
* \param value:     [const char*] The value to add
* \param vtype:     [qsc_winutils_registry_value_types] The value type
*
* \return           [bool] Returns true if the key was created
*/
QSC_EXPORT_API bool qsc_winutils_registry_key_add(const char* keypath, const char* value, qsc_winutils_registry_value_types vtype);

/**
* \brief Delete a registry key
*
* \param keypath:   [const char*] The fully qualified path; root\subkey
*
* \return           [bool] Returns true if the key was deleted
*/
QSC_EXPORT_API bool qsc_winutils_registry_key_delete(const char* keypath);

/**
* \brief Create a list of registry keys under a starting key, ex. 'HKEY_CURRENT_USER\Software'
*
* \param result:    [char*] The result output string
* \param reslen:    [size_t] The length of the result string
* \param keypath:   [const char*] The path of the starting key
*
* \return           [size_t] Returns the size of the result string
*/
QSC_EXPORT_API size_t qsc_winutils_registry_key_list(char* result, size_t reslen, const char* keypath);

/**
* \brief Run an application using the executable path
*
* \param path:      [const char*] The executable path and name
*
* \return           [bool] Returns true if the application is started
*/
QSC_EXPORT_API bool qsc_winutils_run_executable(const char* path);

/**
* \brief Run an application using the executable name and login credentials
*
* \param user:      [const char*] The user name
* \param password:  [const char*] The users password
* \param expath:    [const char*] The full path to the executable
*
* \return           [bool] Returns true if the application is started
*/
QSC_EXPORT_API bool qsc_winutils_run_as_user(const char* user, const char* password, const char* expath);

/**
* \brief Create a list of running services
*
* \param result:    [char*] The result output string
* \param reslen:    [size_t] The length of the result string
*
* \return           [size_t] Returns The length of the services list string
*/
QSC_EXPORT_API size_t qsc_winutils_service_list(char* result, size_t reslen);

/**
* \brief Get the size of the services list string
*
* \return           [size_t] Returns The length of the services list string
*/
QSC_EXPORT_API size_t qsc_winutils_service_list_size(void);

/**
* \brief Change the running state of a system service
*
* \param name:      [const char*] The service name
* \param state:     [qsc_winutils_service_states] The state enumeration
*
* \return           [bool] Returns true if the action succeeded
*/
QSC_EXPORT_API bool qsc_winutils_service_state(const char* name, qsc_winutils_service_states state);

/**
* \brief Create a list of system user accounts and their descriptions
*
* \param result:    [char*] The result output string
* \param reslen:    [size_t] The length of the result string
*
* \return           [size_t] Returns The length of the user list string
*/
QSC_EXPORT_API size_t qsc_winutils_user_list(char* result, size_t reslen);

/**
* \brief Get the logged in user account name
*
* \param result:    [char*] The result output string
* \param reslen:    [size_t] The length of the result string
*
* \return           [size_t] Returns The length of the user string
*/
QSC_EXPORT_API size_t qsc_winutils_current_user(char* result, size_t reslen);

/**
* \brief Test the winutils functions
*/
QSC_EXPORT_API void qsc_winutils_test(void);

#endif
