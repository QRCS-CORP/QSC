#include "p11internal.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "memutils.h"

/** \file p11sign.c
 * \brief CKM_ECDSA prehashed signing using a verified sensitive, nonextractable private token key.
 */

qsc_hw_status qsc_hw_pkcs11_key_sign(qsc_hw_pkcs11_key* key, const uint8_t* digest, size_t digestlen, uint8_t* signature, size_t* signaturelen)
{
	CK_MECHANISM mechanism;
	CK_ULONG native_length;
	size_t expected;
	size_t capacity;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && signaturelen != NULL && digest != NULL && p11_module_current(key->session->module) == true)
	{
		expected = 0U;

		switch (key->algorithm)
		{
			case qsc_hw_algorithm_ecdsa_p256:
				expected = 64U;
				break;
			case qsc_hw_algorithm_ecdsa_p384:
				expected = 96U;
				break;
			case qsc_hw_algorithm_ecdsa_p521:
				expected = 132U;
				break;
			default:
				status = qsc_hw_status_unsupported;
				break;
		}

		if (expected != 0U)
		{
			/* The token receives a caller-prehashed digest. P-521 uses SHA-512 (64 bytes). */
			if (digestlen == (expected == 132U ? 64U : expected / 2U))
			{
				capacity = *signaturelen;
				*signaturelen = expected;

				if (signature == NULL || capacity >= expected)
				{
					p11_module_lock(key->session->module);
					status = p11_key_validate_locked(key);

					if (status == qsc_hw_status_success && signature != NULL)
					{
						if (key->session->module->functions->C_SignInit == NULL_PTR ||
							key->session->module->functions->C_Sign == NULL_PTR)
						{
							status = qsc_hw_status_unsupported;
						}
						else
						{
						mechanism.mechanism = CKM_ECDSA;
						mechanism.pParameter = NULL_PTR;
						mechanism.ulParameterLen = 0UL;
						rv = key->session->module->functions->C_SignInit(key->session->handle, &mechanism, key->handle);
						status = p11_status_from_rv(rv);

						if (rv == CKR_OK)
						{
							native_length = (CK_ULONG)expected;
							rv = key->session->module->functions->C_Sign(key->session->handle, (CK_BYTE_PTR)digest,
								(CK_ULONG)digestlen, (CK_BYTE_PTR)signature, &native_length);
							status = p11_status_from_rv(rv);

							if (rv == CKR_OK && native_length != (CK_ULONG)expected)
							{
								status = qsc_hw_status_policy;
							}
						}
						}
					}
					p11_module_unlock(key->session->module);
				}
				else
				{
					status = qsc_hw_status_buffer_too_small;
				}

				if (status != qsc_hw_status_success && signature != NULL && capacity >= expected)
				{
					qsc_memutils_secure_erase(signature, capacity);
				}
			}
		}
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
