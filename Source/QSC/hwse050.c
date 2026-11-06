#include "hwse050.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED) && defined(QSC_HARDWARE_SE050_ENABLED)

#include "memutils.h"
#include "stringutils.h"

/** \def QSC_HW_SE050_CKM_ECDSA
 * \brief OASIS PKCS#11 CKM_ECDSA mechanism identifier.
 */
#define QSC_HW_SE050_CKM_ECDSA UINT64_C(0x00001041)
/** \def QSC_HW_SE050_CKM_EC_KEY_PAIR_GEN
 * \brief OASIS PKCS#11 CKM_EC_KEY_PAIR_GEN mechanism identifier.
 */
#define QSC_HW_SE050_CKM_EC_KEY_PAIR_GEN UINT64_C(0x00001040)

/** \brief Determine whether a fixed-size expected serial is well-terminated and nonempty.
 * \param serial Fixed 17-byte input array.
 * \return Number of bytes before NUL, or zero if empty or unterminated.
 */
static size_t hwse050_serial_length(const char* serial)
{
	size_t length;

	length = 0U;

	while (length < 17U && serial[length] != '\0')
	{
		++length;
	}

	if (length > 16U)
	{
		length = 0U;
	}

	return length;
}

/** \brief Check the NXP slot's actual PKCS#11 mechanisms, without inventing unsupported functions.
 * \param module Loaded external Cryptoki module.
 * \param slot Selected currently enumerated slot.
 * \param generation_required Require EC key pair generation in addition to signing.
 * \return Success only when all requested mechanisms are listed by the token.
 */
static qsc_hw_status hwse050_mechanisms(qsc_hw_pkcs11_module* module, uint64_t slot, bool generation_required)
{
	uint64_t* mechanisms;
	qsc_hw_status status;
	size_t count;
	size_t i;
	bool sign_found;
	bool generate_found;

	mechanisms = NULL;
	count = 0U;
	sign_found = false;
	generate_found = false;
	status = qsc_hw_pkcs11_mechanism_list(module, slot, NULL, &count);

	if (status == qsc_hw_status_success && count != 0U && count <= QSC_HW_PKCS11_MAX_ITEMS)
	{
		mechanisms = (uint64_t*)qsc_memutils_calloc(count, sizeof(uint64_t));
		status = qsc_hw_status_memory;

		if (mechanisms != NULL)
		{
			status = qsc_hw_pkcs11_mechanism_list(module, slot, mechanisms, &count);

			if (status == qsc_hw_status_success)
			{
				for (i = 0U; i < count; ++i)
				{
					if (mechanisms[i] == QSC_HW_SE050_CKM_ECDSA)
					{
						sign_found = true;
					}

					if (mechanisms[i] == QSC_HW_SE050_CKM_EC_KEY_PAIR_GEN)
					{
						generate_found = true;
					}
				}

				if (sign_found == false || (generation_required == true && generate_found == false))
				{
					status = qsc_hw_status_unsupported;
				}
			}

			qsc_memutils_alloc_free(mechanisms);
		}
	}
	else if (status == qsc_hw_status_success)
	{
		status = qsc_hw_status_unsupported;
	}

	return status;
}

qsc_hw_status qsc_hw_se050_preflight(qsc_hw_pkcs11_module* module, uint64_t slot,
	const qsc_hw_se050_policy* policy)
{
	qsc_hw_pkcs11_token_info info;
	qsc_hw_status status;
	size_t length;

	status = qsc_hw_status_invalid_parameter;

	if (module != NULL && policy != NULL && policy->size == sizeof(qsc_hw_se050_policy) &&
		policy->version == QSC_HW_ABI_VERSION)
	{
		length = hwse050_serial_length(policy->expected_serial);

		if (length > 0U && length <= 16U)
		{
			status = qsc_hw_status_policy;

			if (policy->require_scp03 == false || policy->scp03_confirmed == true)
			{
				qsc_memutils_clear(&info, sizeof(info));
				status = qsc_hw_pkcs11_token_info_get(module, slot, &info);

				if (status == qsc_hw_status_success)
				{
					if (info.token_initialized == false || qsc_stringutils_string_size(info.serial) != length ||
						qsc_stringutils_compare_strings(info.serial, policy->expected_serial, length + 1U) == false ||
						(policy->require_protected_authentication == true && info.protected_authentication == false))
					{
						status = qsc_hw_status_policy;
					}
					else
					{
						status = hwse050_mechanisms(module, slot, policy->require_ec_key_generation);
					}
				}
			}
		}
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED && QSC_HARDWARE_SE050_ENABLED */
