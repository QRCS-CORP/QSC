#include "p11internal.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "memutils.h"

/** \file p11keys.c
 * \brief Protected PKCS#11 EC private-key discovery, generation and public-point retrieval.
 * \details Never reads CKA_VALUE from a private-key object. All Cryptoki calls serialize per module.
 */

/** \brief DER OID of NIST P-256. */
static const uint8_t p11_oid_p256[10U] = { 0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U };
/** \brief DER OID of NIST P-384. */
static const uint8_t p11_oid_p384[7U] = { 0x06U, 0x05U, 0x2BU, 0x81U, 0x04U, 0x00U, 0x22U };
/** \brief DER OID of NIST P-521. */
static const uint8_t p11_oid_p521[7U] = { 0x06U, 0x05U, 0x2BU, 0x81U, 0x04U, 0x00U, 0x23U };

bool p11_key_curve(qsc_hw_algorithm algorithm, const uint8_t** oid, size_t* oidlen, size_t* pointlen, bool* sign)
{
	bool valid;
	valid = (oid != NULL && oidlen != NULL && pointlen != NULL && sign != NULL);

	if (valid == true)
	{
		*oid = NULL;
		*oidlen = 0U;
		*pointlen = 0U;
		*sign = false;

		switch (algorithm)
		{
			case qsc_hw_algorithm_ecdsa_p256:
			case qsc_hw_algorithm_ecdh_p256:
				*oid = p11_oid_p256;
				*oidlen = sizeof(p11_oid_p256);
				*pointlen = 65U;
				break;
			case qsc_hw_algorithm_ecdsa_p384:
			case qsc_hw_algorithm_ecdh_p384:
				*oid = p11_oid_p384;
				*oidlen = sizeof(p11_oid_p384);
				*pointlen = 97U;
				break;
			case qsc_hw_algorithm_ecdsa_p521:
			case qsc_hw_algorithm_ecdh_p521:
				*oid = p11_oid_p521;
				*oidlen = sizeof(p11_oid_p521);
				*pointlen = 133U;
				break;
			default:
				valid = false;
				break;
		}

		*sign = (algorithm == qsc_hw_algorithm_ecdsa_p256 ||
			algorithm == qsc_hw_algorithm_ecdsa_p384 || algorithm == qsc_hw_algorithm_ecdsa_p521);
	}

	return valid;
}

/** \brief Validate token metadata and all private attributes without exporting private material.
 * \param key Live key; call with its module mutex held.
 * \return Success only for exact token, object ID, curve and nonextractable usage.
 */
qsc_hw_status p11_key_validate_locked(const qsc_hw_pkcs11_key* key)
{
	CK_TOKEN_INFO token;
	CK_OBJECT_CLASS object_class;
	CK_KEY_TYPE key_type;
	CK_BBOOL sensitive;
	CK_BBOOL extractable;
	CK_BBOOL token_object;
	CK_BBOOL permitted;
	CK_BBOOL private_attribute;
	CK_ATTRIBUTE attributes[8U];
	uint8_t object_id[QSC_HW_PKCS11_MAX_KEY_ID];
	uint8_t curve[10U];
	const uint8_t* expected;
	size_t expectedlen;
	size_t pointlen;
	bool sign;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_stale_key;

	if (key != NULL && key->session != NULL && p11_module_current(key->session->module) == true &&
		p11_key_curve(key->algorithm, &expected, &expectedlen, &pointlen, &sign) == true &&
		key->session->module->functions->C_GetTokenInfo != NULL_PTR &&
		key->session->module->functions->C_GetAttributeValue != NULL_PTR)
	{
		rv = key->session->module->functions->C_GetTokenInfo(key->session->slot, &token);
		status = p11_status_from_rv(rv);

		if (rv == CKR_OK)
		{
			status = qsc_hw_status_stale_key;

			if (qsc_memutils_are_equal(token.serialNumber, key->serial, sizeof(key->serial)) == true)
			{
				object_class = 0UL;
				key_type = 0UL;
				sensitive = CK_FALSE;
				extractable = CK_TRUE;
				token_object = CK_FALSE;
				permitted = CK_FALSE;
				private_attribute = CK_FALSE;
				qsc_memutils_clear(object_id, sizeof(object_id));
				qsc_memutils_clear(curve, sizeof(curve));
				attributes[0U].type = CKA_CLASS;
				attributes[0U].pValue = &object_class;
				attributes[0U].ulValueLen = sizeof(object_class);
				attributes[1U].type = CKA_KEY_TYPE;
				attributes[1U].pValue = &key_type;
				attributes[1U].ulValueLen = sizeof(key_type);
				attributes[2U].type = CKA_SENSITIVE;
				attributes[2U].pValue = &sensitive;
				attributes[2U].ulValueLen = sizeof(sensitive);
				attributes[3U].type = CKA_EXTRACTABLE;
				attributes[3U].pValue = &extractable;
				attributes[3U].ulValueLen = sizeof(extractable);
				attributes[4U].type = CKA_ID;
				attributes[4U].pValue = object_id;
				attributes[4U].ulValueLen = sizeof(object_id);
				attributes[5U].type = CKA_EC_PARAMS;
				attributes[5U].pValue = curve;
				attributes[5U].ulValueLen = sizeof(curve);
				attributes[6U].type = CKA_TOKEN;
				attributes[6U].pValue = &token_object;
				attributes[6U].ulValueLen = sizeof(token_object);
				attributes[7U].type = CKA_PRIVATE;
				attributes[7U].pValue = &private_attribute;
				attributes[7U].ulValueLen = sizeof(private_attribute);
				rv = key->session->module->functions->C_GetAttributeValue(key->session->handle, key->handle, attributes, 8UL);

				if (rv == CKR_OK && object_class == CKO_PRIVATE_KEY && key_type == CKK_EC &&
					attributes[4U].ulValueLen == key->idlen && attributes[5U].ulValueLen == expectedlen &&
					qsc_memutils_are_equal(object_id, key->id, key->idlen) == true &&
					qsc_memutils_are_equal(curve, expected, expectedlen) == true)
				{
					status = qsc_hw_status_policy;

					if (sensitive == CK_TRUE && extractable == CK_FALSE && token_object == CK_TRUE && private_attribute == CK_TRUE)
					{
						attributes[0U].type = sign == true ? CKA_SIGN : CKA_DERIVE;
						attributes[0U].pValue = &permitted;
						attributes[0U].ulValueLen = sizeof(permitted);
						rv = key->session->module->functions->C_GetAttributeValue(key->session->handle, key->handle, attributes, 1UL);
						status = (rv == CKR_OK && permitted == CK_TRUE) ? qsc_hw_status_success : qsc_hw_status_policy;
					}
				}
				else if (rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_ATTRIBUTE_VALUE_INVALID)
				{
					status = qsc_hw_status_policy;
				}
				else if (rv != CKR_OK)
				{
					status = p11_status_from_rv(rv);
				}
			}
		}
	}

	return status;
}

/** \brief Find at most two objects matching the exact token class and CKA_ID.
 * \param session Token session; caller holds module mutex.
 * \param object_class Required object class.
 * \param id Nonempty identifier.
 * \param idlen Identifier length.
 * \param handle Receives the single matching transient handle.
 * \return Unsupported when absent, policy on duplicates, or typed backend error.
 */
static qsc_hw_status p11_find_locked(qsc_hw_pkcs11_session* session, CK_OBJECT_CLASS object_class, const uint8_t* id, size_t idlen, CK_OBJECT_HANDLE* handle)
{
	CK_OBJECT_HANDLE matches[2U];
	CK_ULONG count;
	CK_ATTRIBUTE attrs[2U];
	CK_RV rv;
	CK_RV final_rv;
	qsc_hw_status status;

	*handle = CK_INVALID_HANDLE;

	status = qsc_hw_status_unsupported;

	if (session->module->functions->C_FindObjectsInit != NULL_PTR &&
		session->module->functions->C_FindObjects != NULL_PTR &&
		session->module->functions->C_FindObjectsFinal != NULL_PTR)
	{
		attrs[0U].type = CKA_CLASS;
		attrs[0U].pValue = &object_class;
		attrs[0U].ulValueLen = sizeof(object_class);
		attrs[1U].type = CKA_ID;
		attrs[1U].pValue = (void*)id;
		attrs[1U].ulValueLen = (CK_ULONG)idlen;
		rv = session->module->functions->C_FindObjectsInit(session->handle, attrs, 2UL);
		status = p11_status_from_rv(rv);

		if (rv == CKR_OK)
		{
			count = 0UL;
			rv = session->module->functions->C_FindObjects(session->handle, matches, 2UL, &count);
			final_rv = session->module->functions->C_FindObjectsFinal(session->handle);
			status = p11_status_from_rv(rv);

			if (rv == CKR_OK && final_rv != CKR_OK)
			{
				status = p11_status_from_rv(final_rv);
			}
			else if (rv == CKR_OK && count == 0UL)
			{
				status = qsc_hw_status_unsupported;
			}
			else if (rv == CKR_OK && count != 1UL)
			{
				status = qsc_hw_status_policy;
			}
			else if (rv == CKR_OK && final_rv == CKR_OK)
			{
				*handle = matches[0U];
			}
		}
	}

	return status;
}

/** \brief Create an ephemeral checked reference for an existing private token object.
 * \param key Output pointer.
 * \param session Active session, caller holds module mutex.
 * \param id Exact CKA_ID bytes.
 * \param idlen Identifier length.
 * \param algorithm Expected curve and operation.
 * \param handle Native private object handle.
 * \return Success only after protected attributes and token serial verified.
 */
static qsc_hw_status p11_key_adopt_locked(qsc_hw_pkcs11_key** key, qsc_hw_pkcs11_session* session, const uint8_t* id, size_t idlen, qsc_hw_algorithm algorithm, CK_OBJECT_HANDLE handle)
{
	qsc_hw_pkcs11_key* next;
	CK_TOKEN_INFO token;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_memory;
	next = (qsc_hw_pkcs11_key*)qsc_memutils_calloc(1U, sizeof(qsc_hw_pkcs11_key));

	if (next != NULL)
	{
		next->session = session;
		next->handle = handle;
		next->algorithm = algorithm;
		next->idlen = idlen;
		qsc_memutils_copy(next->id, id, idlen);
		rv = CKR_FUNCTION_NOT_SUPPORTED;

		if (session->module->functions->C_GetTokenInfo != NULL_PTR)
		{
			rv = session->module->functions->C_GetTokenInfo(session->slot, &token);
		}
		status = p11_status_from_rv(rv);

		if (rv == CKR_OK)
		{
			qsc_memutils_copy(next->serial, token.serialNumber, sizeof(next->serial));
			status = p11_key_validate_locked(next);
		}

		if (status == qsc_hw_status_success && session->keys < SIZE_MAX)
		{
			session->keys += 1U;
			*key = next;
		}
		else
		{
			if (status == qsc_hw_status_success)
			{
				status = qsc_hw_status_busy;
			}
			qsc_memutils_secure_erase(next, sizeof(qsc_hw_pkcs11_key));
			qsc_memutils_alloc_free(next);
		}
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_key_find(qsc_hw_pkcs11_key** key, qsc_hw_pkcs11_session* session, const uint8_t* id, size_t idlen, qsc_hw_algorithm algorithm)
{
	CK_OBJECT_HANDLE handle;
	const uint8_t* oid;
	size_t oidlen;
	size_t pointlen;
	bool sign;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (key != NULL && session != NULL && id != NULL && idlen != 0U && idlen <= QSC_HW_PKCS11_MAX_KEY_ID &&
		p11_module_current(session->module) == true && p11_key_curve(algorithm, &oid, &oidlen, &pointlen, &sign) == true)
	{
		p11_module_lock(session->module);
		status = p11_find_locked(session, CKO_PRIVATE_KEY, id, idlen, &handle);

		if (status == qsc_hw_status_success)
		{
			status = p11_key_adopt_locked(key, session, id, idlen, algorithm, handle);
		}
		p11_module_unlock(session->module);
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_key_generate(qsc_hw_pkcs11_key** key, qsc_hw_pkcs11_session* session, const uint8_t* id, size_t idlen, qsc_hw_algorithm algorithm)
{
	CK_OBJECT_HANDLE existing;
	CK_OBJECT_HANDLE existing_public;
	CK_OBJECT_HANDLE public_object;
	CK_OBJECT_HANDLE private_object;
	CK_MECHANISM mechanism;
	CK_MECHANISM_INFO support;
	CK_OBJECT_CLASS pubclass;
	CK_OBJECT_CLASS privclass;
	CK_KEY_TYPE keytype;
	CK_BBOOL yes;
	CK_BBOOL no;
	CK_ATTRIBUTE pubattrs[6U];
	CK_ATTRIBUTE privattrs[8U];
	const uint8_t* oid;
	size_t oidlen;
	size_t pointlen;
	bool sign;
	CK_RV rv;
	CK_RV destroy_private;
	CK_RV destroy_public;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (session != NULL && p11_module_current(session->module) == true &&
		(session->module->functions->C_FindObjectsInit == NULL_PTR ||
		 session->module->functions->C_FindObjects == NULL_PTR ||
		 session->module->functions->C_FindObjectsFinal == NULL_PTR))
	{
		status = qsc_hw_status_unsupported;
	}
	else if (key != NULL && session != NULL && session->read_write == true && id != NULL && idlen != 0U &&
		idlen <= QSC_HW_PKCS11_MAX_KEY_ID && p11_module_current(session->module) == true &&
		p11_key_curve(algorithm, &oid, &oidlen, &pointlen, &sign) == true)
	{
		p11_module_lock(session->module);
		status = p11_find_locked(session, CKO_PRIVATE_KEY, id, idlen, &existing);

		if (status == qsc_hw_status_unsupported)
		{
			status = p11_find_locked(session, CKO_PUBLIC_KEY, id, idlen, &existing_public);

			if (status == qsc_hw_status_success)
			{
				status = qsc_hw_status_policy;
			}
		}

		if (status == qsc_hw_status_unsupported)
		{
			if (session->module->functions->C_GetMechanismInfo == NULL_PTR ||
				session->module->functions->C_GenerateKeyPair == NULL_PTR ||
				session->module->functions->C_DestroyObject == NULL_PTR)
			{
				status = qsc_hw_status_unsupported;
			}
			else
			{
				rv = session->module->functions->C_GetMechanismInfo(session->slot, CKM_EC_KEY_PAIR_GEN, &support);
				status = p11_status_from_rv(rv);

				if (rv == CKR_OK && (support.flags & CKF_GENERATE_KEY_PAIR) == 0UL)
				{
					status = qsc_hw_status_unsupported;
				}
			}

			if (status == qsc_hw_status_success)
			{
				yes = CK_TRUE;
				no = CK_FALSE;
				pubclass = CKO_PUBLIC_KEY;
				privclass = CKO_PRIVATE_KEY;
				keytype = CKK_EC;
				mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
				mechanism.pParameter = NULL_PTR;
				mechanism.ulParameterLen = 0UL;
				pubattrs[0U].type = CKA_CLASS;
				pubattrs[0U].pValue = &pubclass;
				pubattrs[0U].ulValueLen = sizeof(pubclass);
				pubattrs[1U].type = CKA_KEY_TYPE;
				pubattrs[1U].pValue = &keytype;
				pubattrs[1U].ulValueLen = sizeof(keytype);
				pubattrs[2U].type = CKA_TOKEN;
				pubattrs[2U].pValue = &yes;
				pubattrs[2U].ulValueLen = sizeof(yes);
				pubattrs[3U].type = CKA_ID;
				pubattrs[3U].pValue = (void*)id;
				pubattrs[3U].ulValueLen = (CK_ULONG)idlen;
				pubattrs[4U].type = CKA_EC_PARAMS;
				pubattrs[4U].pValue = (void*)oid;
				pubattrs[4U].ulValueLen = (CK_ULONG)oidlen;
				pubattrs[5U].type = sign == true ? CKA_VERIFY : CKA_DERIVE;
				pubattrs[5U].pValue = &yes;
				pubattrs[5U].ulValueLen = sizeof(yes);
				privattrs[0U].type = CKA_CLASS;
				privattrs[0U].pValue = &privclass;
				privattrs[0U].ulValueLen = sizeof(privclass);
				privattrs[1U].type = CKA_KEY_TYPE;
				privattrs[1U].pValue = &keytype;
				privattrs[1U].ulValueLen = sizeof(keytype);
				privattrs[2U].type = CKA_TOKEN;
				privattrs[2U].pValue = &yes;
				privattrs[2U].ulValueLen = sizeof(yes);
				privattrs[3U].type = CKA_ID;
				privattrs[3U].pValue = (void*)id;
				privattrs[3U].ulValueLen = (CK_ULONG)idlen;
				privattrs[4U].type = CKA_SENSITIVE;
				privattrs[4U].pValue = &yes;
				privattrs[4U].ulValueLen = sizeof(yes);
				privattrs[5U].type = CKA_EXTRACTABLE;
				privattrs[5U].pValue = &no;
				privattrs[5U].ulValueLen = sizeof(no);
				privattrs[6U].type = sign == true ? CKA_SIGN : CKA_DERIVE;
				privattrs[6U].pValue = &yes;
				privattrs[6U].ulValueLen = sizeof(yes);
				privattrs[7U].type = CKA_PRIVATE;
				privattrs[7U].pValue = &yes;
				privattrs[7U].ulValueLen = sizeof(yes);
				public_object = CK_INVALID_HANDLE;
				private_object = CK_INVALID_HANDLE;
				rv = session->module->functions->C_GenerateKeyPair(session->handle, &mechanism, pubattrs, 6UL,
					privattrs, 8UL, &public_object, &private_object);
				status = p11_status_from_rv(rv);

				if (rv == CKR_OK)
				{
					status = p11_key_adopt_locked(key, session, id, idlen, algorithm, private_object);

					if (status != qsc_hw_status_success)
					{
						/* Newly generated objects are ours; rollback them on a failed custody check. */
						destroy_private = session->module->functions->C_DestroyObject(session->handle, private_object);
						destroy_public = session->module->functions->C_DestroyObject(session->handle, public_object);

						if (destroy_private != CKR_OK || destroy_public != CKR_OK)
						{
							status = qsc_hw_status_internal;
						}
					}
				}
			}
		}
		else if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_policy;
		}
		p11_module_unlock(session->module);
	}

	return status;
}

/** \brief Resolve token public object of a private key and decode DER OCTET STRING EC_POINT.
 * \param key Live nonexportable private-key reference.
 * \param output Caller SEC1 output or NULL for size query.
 * \param outputlen In/out byte count.
 * \return Typed operation result.
 */
qsc_hw_status qsc_hw_pkcs11_key_public(qsc_hw_pkcs11_key* key, uint8_t* output, size_t* outputlen)
{
	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE attributes[5U];
	CK_OBJECT_CLASS object_class;
	CK_KEY_TYPE key_type;
	CK_BBOOL token_object;
	uint8_t point[140U];
	uint8_t public_curve[10U];
	const uint8_t* oid;
	size_t oidlen;
	size_t expected;
	size_t offset;
	size_t capacity;
	bool sign;
	CK_RV rv;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && outputlen != NULL && p11_module_current(key->session->module) == true &&
		p11_key_curve(key->algorithm, &oid, &oidlen, &expected, &sign) == true)
	{
		capacity = *outputlen;
		*outputlen = expected;

		if (output == NULL || capacity >= expected)
		{
			p11_module_lock(key->session->module);
			status = p11_key_validate_locked(key);

			if (status == qsc_hw_status_success)
			{
				status = p11_find_locked(key->session, CKO_PUBLIC_KEY, key->id, key->idlen, &handle);
			}

			if (status == qsc_hw_status_success)
			{
				object_class = 0UL;
				key_type = 0UL;
				token_object = CK_FALSE;
				qsc_memutils_clear(public_curve, sizeof(public_curve));
				attributes[0U].type = CKA_EC_POINT;
				attributes[0U].pValue = point;
				attributes[0U].ulValueLen = sizeof(point);
				attributes[1U].type = CKA_CLASS;
				attributes[1U].pValue = &object_class;
				attributes[1U].ulValueLen = sizeof(object_class);
				attributes[2U].type = CKA_KEY_TYPE;
				attributes[2U].pValue = &key_type;
				attributes[2U].ulValueLen = sizeof(key_type);
				attributes[3U].type = CKA_EC_PARAMS;
				attributes[3U].pValue = public_curve;
				attributes[3U].ulValueLen = sizeof(public_curve);
				attributes[4U].type = CKA_TOKEN;
				attributes[4U].pValue = &token_object;
				attributes[4U].ulValueLen = sizeof(token_object);
				rv = key->session->module->functions->C_GetAttributeValue(key->session->handle, handle, attributes, 5UL);
				status = p11_status_from_rv(rv);

				if (rv == CKR_OK)
				{
					offset = 0U;

					if (object_class != CKO_PUBLIC_KEY || key_type != CKK_EC || token_object != CK_TRUE ||
						attributes[3U].ulValueLen != oidlen || qsc_memutils_are_equal(public_curve, oid, oidlen) == false)
					{
						status = qsc_hw_status_policy;
					}

					if (status == qsc_hw_status_success && attributes[0U].ulValueLen == expected + 2U && point[0U] == 0x04U && point[1U] == expected)
					{
						offset = 2U;
					}
					else if (status == qsc_hw_status_success && attributes[0U].ulValueLen == expected + 3U && point[0U] == 0x04U && point[1U] == 0x81U && point[2U] == expected)
					{
						offset = 3U;
					}
					else
					{
						status = qsc_hw_status_policy;
					}

					if (status == qsc_hw_status_success && point[offset] != 0x04U)
					{
						status = qsc_hw_status_policy;
					}

					if (status == qsc_hw_status_success && output != NULL)
					{
						qsc_memutils_copy(output, point + offset, expected);
					}
				}
			}
			p11_module_unlock(key->session->module);
		}
		else
		{
			status = qsc_hw_status_buffer_too_small;
		}

		if (status != qsc_hw_status_success && output != NULL && capacity >= expected)
		{
			qsc_memutils_secure_erase(output, capacity);
		}
	}

	return status;
}

qsc_hw_status qsc_hw_pkcs11_key_release(qsc_hw_pkcs11_key** key)
{
	qsc_hw_pkcs11_key* active;
	qsc_hw_pkcs11_module* module;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && *key != NULL)
	{
		active = *key;
		module = active->session->module;

		if (p11_module_current(module) == true)
		{
			p11_module_lock(module);
			active->session->keys -= 1U;
			qsc_memutils_secure_erase(active, sizeof(qsc_hw_pkcs11_key));
			qsc_memutils_alloc_free(active);
			*key = NULL;
			p11_module_unlock(module);
			status = qsc_hw_status_success;
		}
		else
		{
			status = qsc_hw_status_stale_key;
		}
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
