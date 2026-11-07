#include "p11internal.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "memutils.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* \cond DOXYGEN_NO_DOCUMENT */

/** \file p11session.c
 * \brief Serialized, bounded Cryptoki sessions and transient PIN authentication.
 * \details No implicit Security Officer login, credential caching, or automatic PIN retry.
 */

/** \brief Validate a portable slot fits native CK_SLOT_ID.
 * \param slot Portable slot identifier.
 * \return True if slot is representable by the current Cryptoki ABI.
 */
static bool p11_session_slot_valid(uint64_t slot)
{
	bool valid;
	valid = (slot <= (uint64_t)(~(CK_ULONG)0));
	return valid;
}

qsc_hw_status qsc_hw_pkcs11_session_open(qsc_hw_pkcs11_session** session, qsc_hw_pkcs11_module* module, uint64_t slot, bool read_write)
{
	qsc_hw_pkcs11_session* next;
	CK_SESSION_HANDLE handle;
	CK_FLAGS flags;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (session != NULL)
	{
		*session = NULL;
	}

	if (session != NULL && module != NULL && p11_module_current(module) == true && p11_session_slot_valid(slot) == true)
	{
		status = qsc_hw_status_busy;
		p11_module_lock(module);

		if (module->sessions < SIZE_MAX)
		{
			flags = CKF_SERIAL_SESSION;

			if (read_write == true)
			{
				flags |= CKF_RW_SESSION;
			}

			handle = CK_INVALID_HANDLE;
			rv = module->functions->C_OpenSession((CK_SLOT_ID)slot, flags, NULL_PTR, NULL_PTR, &handle);
			status = p11_status_from_rv(rv);

			if (rv == CKR_OK)
			{
				next = (qsc_hw_pkcs11_session*)qsc_memutils_calloc(1U, sizeof(qsc_hw_pkcs11_session));

				if (next != NULL)
				{
					next->module = module;
					next->handle = handle;
					next->slot = (CK_SLOT_ID)slot;
					next->read_write = read_write;
					module->sessions += 1U;
					*session = next;
				}
				else
				{
					(void)module->functions->C_CloseSession(handle);
					status = qsc_hw_status_memory;
				}
			}
		}
		p11_module_unlock(module);
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_session_login(qsc_hw_pkcs11_session* session, const uint8_t* pin, size_t pinlen)
{
	uint8_t* temporary;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (session != NULL && p11_module_current(session->module) == true &&
		pinlen <= QSC_HW_PKCS11_MAX_PIN_LENGTH && (pin != NULL || pinlen == 0U))
	{
		temporary = NULL;
		status = qsc_hw_status_memory;

		if (pinlen != 0U)
		{
			temporary = (uint8_t*)qsc_memutils_malloc(pinlen);

			if (temporary != NULL)
			{
				qsc_memutils_copy(temporary, pin, pinlen);
			}
		}

		if (pinlen == 0U || temporary != NULL)
		{
			p11_module_lock(session->module);
			rv = session->module->functions->C_Login(session->handle, CKU_USER, (CK_UTF8CHAR_PTR)temporary, (CK_ULONG)pinlen);
			status = p11_status_from_rv(rv);

			if (rv == CKR_USER_ALREADY_LOGGED_IN)
			{
				status = qsc_hw_status_success;
			}

			session->authenticated = (status == qsc_hw_status_success);
			p11_module_unlock(session->module);
		}

		if (temporary != NULL)
		{
			qsc_memutils_secure_erase(temporary, pinlen);
			qsc_memutils_alloc_free(temporary);
		}
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_session_logout(qsc_hw_pkcs11_session* session)
{
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (session != NULL && p11_module_current(session->module) == true)
	{
		p11_module_lock(session->module);
		rv = session->module->functions->C_Logout(session->handle);
		status = p11_status_from_rv(rv);
		session->authenticated = false;
		p11_module_unlock(session->module);
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_session_close(qsc_hw_pkcs11_session** session)
{
	qsc_hw_pkcs11_session* active;
	qsc_hw_pkcs11_module* module;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (session != NULL && *session != NULL)
	{
		active = *session;
		module = active->module;

		if (p11_module_current(module) == false)
		{
			status = qsc_hw_status_stale_key;
		}
		else if (active->keys != 0U)
		{
			status = qsc_hw_status_busy;
		}
		else
		{
			p11_module_lock(module);
			rv = module->functions->C_CloseSession(active->handle);
			status = p11_status_from_rv(rv);

			if (rv == CKR_OK || rv == CKR_SESSION_HANDLE_INVALID || rv == CKR_DEVICE_REMOVED || rv == CKR_TOKEN_NOT_PRESENT)
			{
				module->sessions -= 1U;
				qsc_memutils_secure_erase(active, sizeof(qsc_hw_pkcs11_session));
				qsc_memutils_alloc_free(active);
				*session = NULL;
			}
			p11_module_unlock(module);
		}
	}

	return status;
}

#endif

/* \endcond DOXYGEN_NO_DOCUMENT */

