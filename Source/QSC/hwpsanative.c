#include "hwpsanative.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PSA_ENABLED) && defined(QSC_HARDWARE_PSA_NATIVE_ENABLED)

#include <psa/crypto.h>
#include "memutils.h"

/** \brief Convert a standard PSA Crypto status into the QSC hardware error contract.
 * \param error PSA status code from an actual platform API operation.
 * \return Portable typed status. Does not log private data or credentials.
 */
static qsc_hw_status hwpsa_native_status(psa_status_t error)
{
	qsc_hw_status status;

	status = qsc_hw_status_internal;

	if (error == PSA_SUCCESS)
	{
		status = qsc_hw_status_success;
	}
	else if (error == PSA_ERROR_DOES_NOT_EXIST)
	{
		status = qsc_hw_status_stale_key;
	}
	else if (error == PSA_ERROR_NOT_SUPPORTED)
	{
		status = qsc_hw_status_unsupported;
	}
	else if (error == PSA_ERROR_NOT_PERMITTED)
	{
		status = qsc_hw_status_policy;
	}
	else if (error == PSA_ERROR_INVALID_ARGUMENT)
	{
		status = qsc_hw_status_invalid_parameter;
	}
	else if (error == PSA_ERROR_BUFFER_TOO_SMALL)
	{
		status = qsc_hw_status_buffer_too_small;
	}
	else if (error == PSA_ERROR_INSUFFICIENT_MEMORY)
	{
		status = qsc_hw_status_memory;
	}
	else if (error == PSA_ERROR_BAD_STATE)
	{
		status = qsc_hw_status_auth_required;
	}
#ifdef PSA_ERROR_COMMUNICATION_FAILURE
	else if (error == PSA_ERROR_COMMUNICATION_FAILURE)
	{
		status = qsc_hw_status_device_removed;
	}
#endif
#ifdef PSA_ERROR_HARDWARE_FAILURE
	else if (error == PSA_ERROR_HARDWARE_FAILURE)
	{
		status = qsc_hw_status_device_removed;
	}
#endif
#ifdef PSA_ERROR_ALREADY_EXISTS
	else if (error == PSA_ERROR_ALREADY_EXISTS)
	{
		status = qsc_hw_status_policy;
	}
#endif

	return status;
}

/** \brief Map QSC ECDSA and ECDH curves to PSA types, bits and exact algorithms.
 * \param algorithm Requested QSC curve and operation.
 * \param bits Output curve order field size, in bits.
 * \param psa_algorithm Output PSA algorithm identifier.
 * \param usage Output required PSA key usage flag.
 * \return True for recognized curves and operations.
 */
static bool hwpsa_native_map(qsc_hw_algorithm algorithm, size_t* bits, psa_algorithm_t* psa_algorithm, psa_key_usage_t* usage)
{
	bool valid;

	valid = true;

	switch (algorithm)
	{
		case qsc_hw_algorithm_ecdsa_p256:
		{
			*bits = 256U;
			*psa_algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
			*usage = PSA_KEY_USAGE_SIGN_HASH;
			break;
		}
		case qsc_hw_algorithm_ecdsa_p384:
		{
			*bits = 384U;
			*psa_algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
			*usage = PSA_KEY_USAGE_SIGN_HASH;
			break;
		}
		case qsc_hw_algorithm_ecdsa_p521:
		{
			*bits = 521U;
			*psa_algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
			*usage = PSA_KEY_USAGE_SIGN_HASH;
			break;
		}
		case qsc_hw_algorithm_ecdh_p256:
		{
			*bits = 256U;
			*psa_algorithm = PSA_ALG_ECDH;
			*usage = PSA_KEY_USAGE_DERIVE;
			break;
		}
		case qsc_hw_algorithm_ecdh_p384:
		{
			*bits = 384U;
			*psa_algorithm = PSA_ALG_ECDH;
			*usage = PSA_KEY_USAGE_DERIVE;
			break;
		}
		case qsc_hw_algorithm_ecdh_p521:
		{
			*bits = 521U;
			*psa_algorithm = PSA_ALG_ECDH;
			*usage = PSA_KEY_USAGE_DERIVE;
			break;
		}
		default:
		{
			*bits = 0U;
			*psa_algorithm = PSA_ALG_NONE;
			*usage = 0U;
			valid = false;
			break;
		}
	}

	return valid;
}

/** \brief Query PSA metadata and enforce exact persistent key, curve and location.
 * \param service Initialized native PSA service.
 * \param key_id Persistent key ID.
 * \param output Complete versioned QSC attributes output.
 * \return Typed PSA status or policy refusal.
 */
static qsc_hw_status hwpsa_native_query(void* service, uint32_t key_id, qsc_hw_psa_key_attributes* output)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	qsc_hw_psa_native_service* state;
	qsc_hw_status status;
	psa_status_t result;
	psa_key_lifetime_t lifetime;
	psa_key_usage_t usage;
	psa_algorithm_t actual_algorithm;
	psa_algorithm_t expected_algorithm;
	psa_key_usage_t expected_usage;
	qsc_hw_algorithm algorithm;
	size_t bits;
	size_t expected_bits;
	uint32_t actual_location;

	state = (qsc_hw_psa_native_service*)service;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && key_id != 0U && output != NULL &&
		output->size == sizeof(qsc_hw_psa_key_attributes) && output->version == QSC_HW_ABI_VERSION)
	{
		result = psa_get_key_attributes((psa_key_id_t)key_id, &attributes);
		status = hwpsa_native_status(result);

		if (status == qsc_hw_status_success)
		{
			lifetime = psa_get_key_lifetime(&attributes);
			actual_location = (uint32_t)PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
			usage = psa_get_key_usage_flags(&attributes);
			actual_algorithm = psa_get_key_algorithm(&attributes);
			bits = psa_get_key_bits(&attributes);
			algorithm = qsc_hw_algorithm_none;
			status = qsc_hw_status_policy;

			if (psa_get_key_type(&attributes) == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) &&
				PSA_KEY_LIFETIME_IS_VOLATILE(lifetime) == false && actual_location == state->location &&
				(usage & (PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY)) == 0U)
			{
				if ((usage & PSA_KEY_USAGE_SIGN_HASH) != 0U && (usage & PSA_KEY_USAGE_DERIVE) == 0U)
				{
					if (bits == 256U)
					{
						algorithm = qsc_hw_algorithm_ecdsa_p256;
					}
					else if (bits == 384U)
					{
						algorithm = qsc_hw_algorithm_ecdsa_p384;
					}
					else if (bits == 521U)
					{
						algorithm = qsc_hw_algorithm_ecdsa_p521;
					}
				}
				else if ((usage & PSA_KEY_USAGE_DERIVE) != 0U && (usage & PSA_KEY_USAGE_SIGN_HASH) == 0U)
				{
					if (bits == 256U)
					{
						algorithm = qsc_hw_algorithm_ecdh_p256;
					}
					else if (bits == 384U)
					{
						algorithm = qsc_hw_algorithm_ecdh_p384;
					}
					else if (bits == 521U)
					{
						algorithm = qsc_hw_algorithm_ecdh_p521;
					}
				}

				if (hwpsa_native_map(algorithm, &expected_bits, &expected_algorithm, &expected_usage) == true &&
					bits == expected_bits && actual_algorithm == expected_algorithm &&
					(usage & expected_usage) == expected_usage)
				{
					output->size = sizeof(qsc_hw_psa_key_attributes);
					output->version = QSC_HW_ABI_VERSION;
					output->key_id = key_id;
					output->algorithm = algorithm;
					output->usage = (expected_usage == PSA_KEY_USAGE_DERIVE) ? qsc_hw_usage_agree : qsc_hw_usage_sign;
					output->persistent = true;
					output->private_exportable = false;
					output->hardware_protected = (state->hardware_verified == true &&
						state->location != (uint32_t)PSA_KEY_LOCATION_LOCAL_STORAGE);
					status = qsc_hw_status_success;
				}
			}
		}
	}

	psa_reset_key_attributes(&attributes);
	return status;
}

/** \brief Create a persistent PSA ECC identity with non-exportable private key.
 * \param service Initialized native PSA service.
 * \param key_id New persistent PSA key ID.
 * \param policy Requested QSC algorithm, usage and export requirements.
 * \param attributes Generated metadata output.
 * \return Typed error or success. PSA persistent object is rolled back on failure.
 */
static qsc_hw_status hwpsa_native_create(void* service, uint32_t key_id, const qsc_hw_key_policy* policy,
	qsc_hw_psa_key_attributes* attributes)
{
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	qsc_hw_psa_native_service* state;
	psa_key_id_t generated;
	psa_algorithm_t algorithm;
	psa_key_usage_t usage;
	psa_status_t result;
	qsc_hw_status status;
	size_t bits;

	state = (qsc_hw_psa_native_service*)service;
	status = qsc_hw_status_invalid_parameter;
	generated = PSA_KEY_ID_NULL;

	if (state != NULL && state->initialized == true && key_id != 0U && policy != NULL &&
		attributes != NULL && policy->allow_export == false &&
		hwpsa_native_map(policy->algorithm, &bits, &algorithm, &usage) == true &&
		((usage == PSA_KEY_USAGE_DERIVE && policy->usage == qsc_hw_usage_agree) ||
			(usage == PSA_KEY_USAGE_SIGN_HASH && policy->usage == qsc_hw_usage_sign)))
	{
		psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&key_attributes, bits);
		psa_set_key_algorithm(&key_attributes, algorithm);
		psa_set_key_usage_flags(&key_attributes, usage);
		psa_set_key_lifetime(&key_attributes,
			PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, state->location));
		psa_set_key_id(&key_attributes, (psa_key_id_t)key_id);
		result = psa_generate_key(&key_attributes, &generated);
		status = hwpsa_native_status(result);

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_internal;

			if (generated == (psa_key_id_t)key_id)
			{
				status = hwpsa_native_query(service, key_id, attributes);
			}

			if (status != qsc_hw_status_success)
			{
				(void)psa_destroy_key(generated);
			}
		}
	}

	psa_reset_key_attributes(&key_attributes);
	return status;
}

/** \brief Destroy only a newly created PSA persistent key on post-create failure.
 * \param service Initialized native PSA service.
 * \param key_id Newly generated persistent ID.
 * \return Typed secure-service status.
 */
static qsc_hw_status hwpsa_native_rollback(void* service, uint32_t key_id)
{
	qsc_hw_psa_native_service* state;
	qsc_hw_status status;

	state = (qsc_hw_psa_native_service*)service;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && key_id != 0U)
	{
		status = hwpsa_native_status(psa_destroy_key((psa_key_id_t)key_id));
	}

	return status;
}

/** \brief Obtain public SEC1 EC point from the PSA key service.
 * \param service Initialized native PSA client.
 * \param key_id Persistent key ID.
 * \param output Caller-owned public buffer.
 * \param outputlen In/out byte capacity/actual length.
 * \return Typed result; no private bytes.
 */
static qsc_hw_status hwpsa_native_public(void* service, uint32_t key_id, uint8_t* output, size_t* outputlen)
{
	qsc_hw_psa_native_service* state;
	qsc_hw_status status;

	state = (qsc_hw_psa_native_service*)service;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && output != NULL && outputlen != NULL)
	{
		status = hwpsa_native_status(psa_export_public_key((psa_key_id_t)key_id, output, *outputlen, outputlen));
	}

	return status;
}

/** \brief Call PSA sign_hash only for the explicitly selected ECDSA profile.
 * \param service Native PSA client state.
 * \param key_id Persistent key ID.
 * \param selected Requested QSC ECDSA algorithm.
 * \param digest Precomputed hash input.
 * \param digestlen Exact digest length.
 * \param signature Caller buffer containing raw r||s on success.
 * \param signaturelen In/out output capacity/actual size.
 * \return Typed native PSA Crypto status.
 */
static qsc_hw_status hwpsa_native_sign(void* service, uint32_t key_id, qsc_hw_algorithm selected,
	const uint8_t* digest, size_t digestlen, uint8_t* signature, size_t* signaturelen)
{
	qsc_hw_psa_native_service* state;
	psa_algorithm_t algorithm;
	psa_key_usage_t usage;
	size_t bits;
	qsc_hw_status status;

	state = (qsc_hw_psa_native_service*)service;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && digest != NULL && signature != NULL && signaturelen != NULL &&
		hwpsa_native_map(selected, &bits, &algorithm, &usage) == true && usage == PSA_KEY_USAGE_SIGN_HASH)
	{
		status = hwpsa_native_status(psa_sign_hash((psa_key_id_t)key_id, algorithm,
			digest, digestlen, signature, *signaturelen, signaturelen));
	}

	return status;
}

/** \brief Execute PSA raw ECDH; derived secret enters caller memory only by policy.
 * \param service Native PSA client state.
 * \param key_id Persistent key ID.
 * \param selected QSC ECDH curve.
 * \param peer SEC1 point from caller.
 * \param peerlen Public point byte count.
 * \param secret Caller-owned raw shared-secret output.
 * \param secretlen In/out output capacity/actual byte count.
 * \return Typed PSA raw key agreement result.
 */
static qsc_hw_status hwpsa_native_agree(void* service, uint32_t key_id, qsc_hw_algorithm selected,
	const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen)
{
	qsc_hw_psa_native_service* state;
	psa_algorithm_t algorithm;
	psa_key_usage_t usage;
	size_t bits;
	qsc_hw_status status;

	state = (qsc_hw_psa_native_service*)service;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && peer != NULL && secret != NULL && secretlen != NULL &&
		hwpsa_native_map(selected, &bits, &algorithm, &usage) == true && usage == PSA_KEY_USAGE_DERIVE)
	{
		status = hwpsa_native_status(psa_raw_key_agreement(algorithm, (psa_key_id_t)key_id,
			peer, peerlen, secret, *secretlen, secretlen));
	}

	return status;
}

/** \brief Request random bytes from the platform PSA Crypto service.
 * \param service Native PSA client state.
 * \param output Caller-owned byte buffer.
 * \param length Output byte count.
 * \return Typed PSA random generation result.
 */
static qsc_hw_status hwpsa_native_random(void* service, uint8_t* output, size_t length)
{
	qsc_hw_psa_native_service* state;
	qsc_hw_status status;

	state = (qsc_hw_psa_native_service*)service;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && (output != NULL || length == 0U))
	{
		status = hwpsa_native_status(psa_generate_random(output, length));
	}

	return status;
}

qsc_hw_status qsc_hw_psa_native_initialize(qsc_hw_psa_context* context,
	qsc_hw_psa_native_service* service, uint32_t key_id, uint32_t location, bool hardware_verified)
{
	qsc_hw_psa_callbacks callbacks = { 0U };
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && service != NULL && context->initialized == false && service->initialized == false &&
		key_id != 0U && (hardware_verified == false || location != (uint32_t)PSA_KEY_LOCATION_LOCAL_STORAGE))
	{
		status = hwpsa_native_status(psa_crypto_init());

		if (status == qsc_hw_status_success)
		{
			service->size = sizeof(qsc_hw_psa_native_service);
			service->version = QSC_HW_ABI_VERSION;
			service->location = location;
			service->hardware_verified = hardware_verified;
			service->initialized = true;
			callbacks.size = sizeof(callbacks);
			callbacks.version = QSC_HW_ABI_VERSION;
			callbacks.query = hwpsa_native_query;
			callbacks.create = hwpsa_native_create;
			callbacks.rollback = hwpsa_native_rollback;
			callbacks.public_key = hwpsa_native_public;
			callbacks.sign_hash = hwpsa_native_sign;
			callbacks.agree = hwpsa_native_agree;
			callbacks.random = hwpsa_native_random;
			status = qsc_hw_psa_initialize(context, &callbacks, service, key_id, hardware_verified);

			if (status != qsc_hw_status_success)
			{
				qsc_memutils_secure_erase(service, sizeof(qsc_hw_psa_native_service));
			}
		}
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PSA_ENABLED && QSC_HARDWARE_PSA_NATIVE_ENABLED */
