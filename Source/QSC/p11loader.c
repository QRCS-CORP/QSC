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

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "p11internal.h"
#include "memutils.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#   include <windows.h>
#else
#   include <pthread.h>
#   include <unistd.h>
#   include <dlfcn.h>
#endif

/** \file p11loader.c
 * \brief Process-shared Cryptoki library loader, ownership and bounded mechanism discovery.
 * \details No vendor libraries are statically linked. All module dispatch is serialized;
 * registry lock protects module lifetime and reference counts. Never call after fork.
 */

#if defined(QSC_SYSTEM_OS_WINDOWS)
/** \brief Process-global loader registry lock. */
static SRWLOCK p11_registry_mutex = SRWLOCK_INIT;
#else
/** \brief Process-global loader registry lock. */
static pthread_mutex_t p11_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
/** \brief Process-shared module list; guarded by p11_registry_mutex. */
static qsc_hw_pkcs11_module* p11_registry = NULL;

/** \brief Lock process module registry, including loading/unloading.
 * \note Never recursively acquire registry lock from module backend callbacks.
 */
static void p11_registry_lock(void)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	AcquireSRWLockExclusive(&p11_registry_mutex);
#else
	(void)pthread_mutex_lock(&p11_registry_mutex);
#endif
}

/** \brief Release process module registry lock. */
static void p11_registry_unlock(void)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	ReleaseSRWLockExclusive(&p11_registry_mutex);
#else
	(void)pthread_mutex_unlock(&p11_registry_mutex);
#endif
}

/** \brief Return the process identifier for fork isolation.
 * \return Unique process ID within the current operating-system PID epoch.
 */
static uint64_t p11_process_id(void)
{
	uint64_t id;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	id = (uint64_t)GetCurrentProcessId();
#else
	id = (uint64_t)getpid();
#endif
	return id;
}

bool p11_module_current(const qsc_hw_pkcs11_module* module)
{
	bool result;
	result = (module != NULL && module->process_id == p11_process_id());
	return result;
}

void p11_module_lock(qsc_hw_pkcs11_module* module)
{
	qsc_async_mutex_lock(module->mutex);
}

void p11_module_unlock(qsc_hw_pkcs11_module* module)
{
	qsc_async_mutex_unlock(module->mutex);
}

qsc_hw_status p11_status_from_rv(CK_RV result)
{
	qsc_hw_status status;

	status = qsc_hw_status_internal;

	switch (result)
	{
		case CKR_OK:
			status = qsc_hw_status_success;
			break;
		case CKR_ARGUMENTS_BAD:
		case CKR_SLOT_ID_INVALID:
			status = qsc_hw_status_invalid_parameter;
			break;
		case CKR_BUFFER_TOO_SMALL:
			status = qsc_hw_status_buffer_too_small;
			break;
		case CKR_HOST_MEMORY:
			status = qsc_hw_status_memory;
			break;
		case CKR_FUNCTION_NOT_SUPPORTED:
		case CKR_MECHANISM_INVALID:
			status = qsc_hw_status_unsupported;
			break;
		case CKR_USER_NOT_LOGGED_IN:
			status = qsc_hw_status_auth_required;
			break;
		case CKR_PIN_INCORRECT:
		case CKR_PIN_INVALID:
		case CKR_PIN_LEN_RANGE:
			status = qsc_hw_status_auth_failed;
			break;
		case CKR_PIN_LOCKED:
			status = qsc_hw_status_locked;
			break;
		case CKR_TOKEN_NOT_PRESENT:
		case CKR_DEVICE_REMOVED:
		case CKR_DEVICE_ERROR:
			status = qsc_hw_status_device_removed;
			break;
		case CKR_SESSION_COUNT:
		case CKR_OPERATION_ACTIVE:
			status = qsc_hw_status_busy;
			break;
		case CKR_SESSION_HANDLE_INVALID:
		case CKR_OBJECT_HANDLE_INVALID:
			status = qsc_hw_status_stale_key;
			break;
		case CKR_FUNCTION_CANCELED:
			status = qsc_hw_status_timeout;
			break;
		default:
			break;
	}

	return status;
}

/** \brief Verify an absolute local library path has no parent/current traversal segments.
 * \param path Caller supplied NUL-terminated path.
 * \return True if valid for trusted application configuration (not a signature trust check).
 */
static bool p11_path_valid(const char* path)
{
	bool valid;
	size_t i;
	size_t start;

	valid = false;

	if (path != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		valid = (((path[0U] >= 'A' && path[0U] <= 'Z') || (path[0U] >= 'a' && path[0U] <= 'z')) &&
			path[1U] == ':' && (path[2U] == '\\' || path[2U] == '/'));
#else
		valid = (path[0U] == '/');
#endif
		start = 0U;

		for (i = 0U; valid == true && i < QSC_HW_PKCS11_MAX_PATH && path[i] != '\0'; ++i)
		{
			if (path[i] == '/' || path[i] == '\\')
			{
				if ((i - start == 1U && path[start] == '.') ||
					(i - start == 2U && path[start] == '.' && path[start + 1U] == '.'))
				{
					valid = false;
				}
				start = i + 1U;
			}
		}

		if (valid == true && i >= QSC_HW_PKCS11_MAX_PATH)
		{
			valid = false;
		}

		if (valid == true)
		{
			valid = !((i - start == 1U && path[start] == '.') ||
				(i - start == 2U && path[start] == '.' && path[start + 1U] == '.'));
		}
	}

	return valid;
}

/** \brief Load the vendor-provided shared library through a restricted OS loader.
 * \param path Trusted absolute path.
 * \return OS library handle or NULL.
 */
static void* p11_library_open(const char* path)
{
	void* library;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	library = (void*)LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
#else
	library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
	return library;
}

/** \brief Obtain C_GetFunctionList from a loaded Cryptoki module.
 * \param library OS dynamic library handle.
 * \return Function pointer or NULL on missing entrypoint.
 */
static CK_C_GetFunctionList p11_library_get_functions(void* library)
{
	CK_C_GetFunctionList functions;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	functions = (CK_C_GetFunctionList)GetProcAddress((HMODULE)library, "C_GetFunctionList");
#else
	functions = (CK_C_GetFunctionList)dlsym(library, "C_GetFunctionList");
#endif
	return functions;
}

/** \brief Unload one OS dynamic library reference.
 * \param library Non-NULL OS library handle.
 */
static void p11_library_close(void* library)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	(void)FreeLibrary((HMODULE)library);
#else
	(void)dlclose(library);
#endif
}

qsc_hw_status qsc_hw_pkcs11_module_open(qsc_hw_pkcs11_module** module, const char* absolute_path)
{
	qsc_hw_pkcs11_module* current;
	qsc_hw_pkcs11_module* fresh;
	CK_C_GetFunctionList getlist;
	CK_FUNCTION_LIST_PTR functions;
	CK_C_INITIALIZE_ARGS initargs;
	CK_RV rv;
	void* library;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (module != NULL)
	{
		*module = NULL;
	}

	if (module != NULL && p11_path_valid(absolute_path) == true)
	{
		p11_registry_lock();
		library = p11_library_open(absolute_path);
		status = qsc_hw_status_unsupported;

		if (library != NULL)
		{
			current = p11_registry;

			while (current != NULL)
			{
				if (current->library == library && p11_module_current(current) == true)
				{
					break;
				}
				current = current->next;
			}

			if (current != NULL)
			{
				if (current->clients < SIZE_MAX)
				{
					current->clients += 1U;
					*module = current;
					status = qsc_hw_status_success;
				}
				else
				{
					status = qsc_hw_status_busy;
				}
				p11_library_close(library);
			}
			else
			{
				getlist = p11_library_get_functions(library);
				functions = NULL;
				status = qsc_hw_status_unsupported;

				if (getlist != NULL)
				{
					rv = getlist(&functions);

					if (rv == CKR_OK && functions != NULL && functions->version.major >= 2U &&
						functions->C_Initialize != NULL && functions->C_Finalize != NULL &&
						functions->C_GetSlotList != NULL && functions->C_GetTokenInfo != NULL &&
						functions->C_GetMechanismList != NULL && functions->C_GetMechanismInfo != NULL &&
						functions->C_OpenSession != NULL && functions->C_CloseSession != NULL &&
						functions->C_Login != NULL && functions->C_Logout != NULL)
					{
						fresh = (qsc_hw_pkcs11_module*)qsc_memutils_calloc(1U, sizeof(qsc_hw_pkcs11_module));

						if (fresh != NULL)
						{
							fresh->mutex = qsc_async_mutex_create();

							if (fresh->mutex != NULL)
							{
								qsc_memutils_clear(&initargs, sizeof(initargs));
								initargs.flags = CKF_OS_LOCKING_OK;
								rv = functions->C_Initialize(&initargs);

								if (rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
								{
									fresh->library = library;
									fresh->functions = functions;
									fresh->owns_initialization = (rv == CKR_OK);
									fresh->process_id = p11_process_id();
									fresh->clients = 1U;
									fresh->next = p11_registry;
									p11_registry = fresh;
									*module = fresh;
									status = qsc_hw_status_success;
								}
								else
								{
									status = p11_status_from_rv(rv);
								}
							}
							else
							{
								status = qsc_hw_status_memory;
							}

							if (status != qsc_hw_status_success)
							{
								if (fresh->mutex != NULL)
								{
									(void)qsc_async_mutex_destroy(fresh->mutex);
								}
								qsc_memutils_alloc_free(fresh);
							}
						}
						else
						{
							status = qsc_hw_status_memory;
						}
					}
				}

				if (status != qsc_hw_status_success)
				{
					p11_library_close(library);
				}
			}
		}

		p11_registry_unlock();
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_module_close(qsc_hw_pkcs11_module** module)
{
	qsc_hw_pkcs11_module* current;
	qsc_hw_pkcs11_module** cursor;
	CK_RV rv;
	qsc_hw_status status;
	bool destroy;

	status = qsc_hw_status_invalid_parameter;
	destroy = false;

	if (module != NULL && *module != NULL)
	{
		current = *module;

		if (p11_module_current(current) == false)
		{
			status = qsc_hw_status_stale_key;
		}
		else
		{
			p11_registry_lock();
			p11_module_lock(current);
			status = qsc_hw_status_busy;

			if (current->sessions == 0U)
			{
				if (current->clients > 1U)
				{
					current->clients -= 1U;
					*module = NULL;
					status = qsc_hw_status_success;
				}
				else
				{
					rv = CKR_OK;

					if (current->owns_initialization == true)
					{
						rv = current->functions->C_Finalize(NULL_PTR);
					}

					if (rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED)
					{
						cursor = &p11_registry;

						while (*cursor != NULL && *cursor != current)
						{
							cursor = &(*cursor)->next;
						}

						if (*cursor == current)
						{
							*cursor = current->next;
						}
						destroy = true;
						status = qsc_hw_status_success;
					}
					else
					{
						status = p11_status_from_rv(rv);
					}
				}
			}

			p11_module_unlock(current);

			if (destroy == true)
			{
				(void)qsc_async_mutex_destroy(current->mutex);
				p11_library_close(current->library);
				qsc_memutils_secure_erase(current, sizeof(qsc_hw_pkcs11_module));
				qsc_memutils_alloc_free(current);
				*module = NULL;
			}

			p11_registry_unlock();
		}
	}

	return status;
}

/** \brief Convert CK_ULONG-sized unsigned slot/mechanism identifiers safely.
 * \param value Public 64-bit identifier.
 * \param converted Output CK_ULONG identifier on success.
 * \return True if the value fits the underlying platform ABI.
 */
static bool p11_to_native(uint64_t value, CK_ULONG* converted)
{
	bool result;
	result = (value <= (uint64_t)(~(CK_ULONG)0));

	if (result == true)
	{
		*converted = (CK_ULONG)value;
	}

	return result;
}

/** \brief Bounded, two-call enumeration of slots or mechanisms under module lock.
 * \param module Loaded module.
 * \param slot Native slot for mechanism enumeration; ignored for slots.
 * \param slots True for slot enumeration, false for mechanism enumeration.
 * \param present Slot token-presence filter.
 * \param output Public entry buffer or NULL for count query.
 * \param count In/out capacity and required/actual entry count.
 * \return Typed result with bounded allocation and checked conversions.
 */
static qsc_hw_status p11_enumerate(qsc_hw_pkcs11_module* module, CK_SLOT_ID slot, bool slots, bool present, uint64_t* output, size_t* count)
{
	CK_ULONG native_count;
	CK_ULONG i;
	CK_ULONG* entries;
	CK_RV rv;
	qsc_hw_status status;
	size_t capacity;

	status = qsc_hw_status_invalid_parameter;

	if (module != NULL && count != NULL && p11_module_current(module) == true)
	{
		capacity = *count;
		*count = 0U;
		native_count = 0U;
		p11_module_lock(module);
		rv = (slots == true) ? module->functions->C_GetSlotList(present ? CK_TRUE : CK_FALSE, NULL_PTR, &native_count) :
			module->functions->C_GetMechanismList(slot, NULL_PTR, &native_count);
		status = p11_status_from_rv(rv);

		if (rv == CKR_OK)
		{
			if (native_count > QSC_HW_PKCS11_MAX_ITEMS)
			{
				status = qsc_hw_status_policy;
			}
			else
			{
				*count = (size_t)native_count;

				if (output != NULL && capacity < (size_t)native_count)
				{
					status = qsc_hw_status_buffer_too_small;
				}
				else if (output != NULL && native_count != 0U)
				{
					entries = (CK_ULONG*)qsc_memutils_calloc((size_t)native_count, sizeof(CK_ULONG));

					if (entries != NULL)
					{
						rv = (slots == true) ? module->functions->C_GetSlotList(present ? CK_TRUE : CK_FALSE, (CK_SLOT_ID_PTR)entries, &native_count) :
							module->functions->C_GetMechanismList(slot, (CK_MECHANISM_TYPE_PTR)entries, &native_count);
						status = p11_status_from_rv(rv);

						if (rv == CKR_OK && (size_t)native_count <= capacity && native_count <= QSC_HW_PKCS11_MAX_ITEMS)
						{
							*count = (size_t)native_count;
							for (i = 0U; i < native_count; ++i)
							{
								output[i] = (uint64_t)entries[i];
							}
						}
						else if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
						{
								if (native_count > QSC_HW_PKCS11_MAX_ITEMS)
								{
									status = qsc_hw_status_policy;
									*count = 0U;
								}
								else
								{
									status = qsc_hw_status_buffer_too_small;
									*count = (size_t)native_count;
								}
						}
						qsc_memutils_alloc_free(entries);
					}
					else
					{
						status = qsc_hw_status_memory;
					}
				}
			}
		}
		p11_module_unlock(module);
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_slot_list(qsc_hw_pkcs11_module* module, bool token_present, uint64_t* slots, size_t* count)
{
	qsc_hw_status status;
	status = p11_enumerate(module, 0U, true, token_present, slots, count);
	return status;
}

qsc_hw_status qsc_hw_pkcs11_mechanism_list(qsc_hw_pkcs11_module* module, uint64_t slot, uint64_t* mechanisms, size_t* count)
{
	CK_ULONG native;
	qsc_hw_status status;
	status = qsc_hw_status_invalid_parameter;

	if (p11_to_native(slot, &native) == true)
	{
		status = p11_enumerate(module, (CK_SLOT_ID)native, false, false, mechanisms, count);
	}

	return status;
}

/** \brief Copy a space-padded fixed-width PKCS#11 label into a bounded NUL-terminated string.
 * \param target Output character array with at least source length + 1 bytes.
 * \param source Public metadata fixed-width input.
 * \param length Exact padded source byte length.
 */
static void p11_copy_trimmed(char* target, const CK_UTF8CHAR* source, size_t length)
{
	size_t used;
	used = length;

	while (used > 0U && source[used - 1U] == (CK_UTF8CHAR)' ')
	{
		used -= 1U;
	}

	qsc_memutils_copy(target, source, used);
	target[used] = '\0';
}

qsc_hw_status qsc_hw_pkcs11_token_info_get(qsc_hw_pkcs11_module* module, uint64_t slot, qsc_hw_pkcs11_token_info* info)
{
	CK_TOKEN_INFO token;
	CK_ULONG native;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (info != NULL)
	{
		qsc_memutils_clear(info, sizeof(qsc_hw_pkcs11_token_info));
	}

	if (module != NULL && info != NULL && p11_module_current(module) == true && p11_to_native(slot, &native) == true)
	{
		p11_module_lock(module);
		rv = module->functions->C_GetTokenInfo((CK_SLOT_ID)native, &token);
		status = p11_status_from_rv(rv);

		if (rv == CKR_OK)
		{
			p11_copy_trimmed(info->label, token.label, sizeof(token.label));
			p11_copy_trimmed(info->serial, token.serialNumber, sizeof(token.serialNumber));
			info->protected_authentication = ((token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0U);
			info->token_initialized = ((token.flags & CKF_TOKEN_INITIALIZED) != 0U);
		}
		p11_module_unlock(module);
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_mechanism_info_get(qsc_hw_pkcs11_module* module, uint64_t slot, uint64_t mechanism, qsc_hw_pkcs11_mechanism_info* info)
{
	CK_MECHANISM_INFO native_info;
	CK_ULONG native_slot;
	CK_ULONG native_mechanism;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (info != NULL)
	{
		qsc_memutils_clear(info, sizeof(qsc_hw_pkcs11_mechanism_info));
	}

	if (module != NULL && info != NULL && p11_module_current(module) == true &&
		p11_to_native(slot, &native_slot) == true && p11_to_native(mechanism, &native_mechanism) == true)
	{
		p11_module_lock(module);
		rv = module->functions->C_GetMechanismInfo((CK_SLOT_ID)native_slot, (CK_MECHANISM_TYPE)native_mechanism, &native_info);
		status = p11_status_from_rv(rv);

		if (rv == CKR_OK)
		{
			info->min_key_bits = (uint64_t)native_info.ulMinKeySize;
			info->max_key_bits = (uint64_t)native_info.ulMaxKeySize;
			info->flags = (uint64_t)native_info.flags;
		}
		p11_module_unlock(module);
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
