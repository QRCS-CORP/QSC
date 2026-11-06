#include "hwpsa.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PSA_ENABLED)

#include "memutils.h"

/** \struct hwpsa_key
 * \brief Transient identity snapshot with no private key bytes.
 */
typedef struct hwpsa_key
{
	uint32_t key_id; /**< Pinned persistent PSA key ID. */
	qsc_hw_psa_key_attributes attributes; /**< Metadata used to detect replacement. */
} hwpsa_key;

/** \brief Get fixed EC sizes for supported PSA prehashed ECDSA or ECDH curves.
 * \param algorithm Named QSC curve operation.
 * \param digestlen Output hash size or shared-secret size, in bytes.
 * \param siglen Output raw signature size, in bytes, or zero for ECDH.
 * \param pointlen Output SEC1 uncompressed point length.
 * \return True for supported NIST curves only.
 */
static bool hwpsa_lengths(qsc_hw_algorithm algorithm, size_t* digestlen, size_t* siglen, size_t* pointlen)
{
	bool valid;

	valid = true;

	switch (algorithm)
	{
		case qsc_hw_algorithm_ecdsa_p256:
		case qsc_hw_algorithm_ecdh_p256:
		{
			*digestlen = 32U;
			*siglen = 64U;
			*pointlen = 65U;
			break;
		}
		case qsc_hw_algorithm_ecdsa_p384:
		case qsc_hw_algorithm_ecdh_p384:
		{
			*digestlen = 48U;
			*siglen = 96U;
			*pointlen = 97U;
			break;
		}
		case qsc_hw_algorithm_ecdsa_p521:
		case qsc_hw_algorithm_ecdh_p521:
		{
			*digestlen = 64U;
			*siglen = 132U;
			*pointlen = 133U;
			break;
		}
		default:
		{
			*digestlen = 0U;
			*siglen = 0U;
			*pointlen = 0U;
			valid = false;
			break;
		}
	}

	return valid;
}

/** \brief Validate actual key properties and restrict the operation family.
 * \param context Initialized PSA provider context.
 * \param attributes Actual PSA key details returned by the secure service.
 * \return Success, unsupported, stale identity or key-policy rejection.
 */
static qsc_hw_status hwpsa_attributes_check(const qsc_hw_psa_context* context, const qsc_hw_psa_key_attributes* attributes)
{
	size_t dlen;
	size_t slen;
	size_t plen;
	uint32_t required;
	qsc_hw_status status;

	status = qsc_hw_status_policy;

	if (attributes->size == sizeof(qsc_hw_psa_key_attributes) && attributes->version == QSC_HW_ABI_VERSION &&
		attributes->key_id == context->key_id && attributes->persistent == true &&
		attributes->private_exportable == false &&
		hwpsa_lengths(attributes->algorithm, &dlen, &slen, &plen) == true)
	{
		if (attributes->algorithm == qsc_hw_algorithm_ecdsa_p256 ||
			attributes->algorithm == qsc_hw_algorithm_ecdsa_p384 ||
			attributes->algorithm == qsc_hw_algorithm_ecdsa_p521)
		{
			required = qsc_hw_usage_sign;
		}
		else
		{
			required = qsc_hw_usage_agree;
		}

		if (attributes->usage == required)
		{
			status = qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Query the live PSA key and require stable original properties.
 * \param context Caller-owned PSA context.
 * \param reference Transient original identity snapshot.
 * \return Success if identical, otherwise stale-key or provider error.
 */
static qsc_hw_status hwpsa_key_check(qsc_hw_psa_context* context, const hwpsa_key* reference)
{
	qsc_hw_psa_key_attributes live = { 0U };
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && context->initialized == true && reference != NULL && reference->key_id == context->key_id)
	{
		live.size = sizeof(live);
		live.version = QSC_HW_ABI_VERSION;
		status = context->callbacks.query(context->service, reference->key_id, &live);

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_stale_key;

			if (live.size == reference->attributes.size && live.version == reference->attributes.version &&
				live.key_id == reference->attributes.key_id && live.algorithm == reference->attributes.algorithm &&
				live.usage == reference->attributes.usage && live.persistent == reference->attributes.persistent &&
				live.private_exportable == reference->attributes.private_exportable &&
				live.hardware_protected == reference->attributes.hardware_protected)
			{
				status = hwpsa_attributes_check(context, &live);
			}
		}
	}

	return status;
}

/** \brief Return truthful provider metadata for one approved PSA identity.
 * \param context Pinned PSA provider context.
 * \param attributes Validated nonsecret PSA key attributes.
 * \param info Caller-owned generic QSC key info.
 */
static void hwpsa_info(const qsc_hw_psa_context* context, const qsc_hw_psa_key_attributes* attributes, qsc_hw_key_info* info)
{
	info->size = sizeof(qsc_hw_key_info);
	info->version = QSC_HW_ABI_VERSION;
	info->algorithm = attributes->algorithm;
	info->usage = attributes->usage;
	info->extractable = false;
	info->custody = qsc_hw_custody_software;

	if (context->hardware_verified == true && attributes->hardware_protected == true)
	{
		info->custody = qsc_hw_custody_hardware_nonexportable;
	}
}

/** \brief Allocate a transient provider key only after policy checks.
 * \param context Initialized PSA context.
 * \param attributes Live PSA attributes.
 * \param key Generic provider backend handle output.
 * \param info Generic key metadata output.
 * \return Success, policy or allocation failure.
 */
static qsc_hw_status hwpsa_bind(qsc_hw_psa_context* context, const qsc_hw_psa_key_attributes* attributes, void** key, qsc_hw_key_info* info)
{
	hwpsa_key* result;
	qsc_hw_status status;

	status = hwpsa_attributes_check(context, attributes);

	if (status == qsc_hw_status_success)
	{
		result = (hwpsa_key*)qsc_memutils_calloc(1U, sizeof(hwpsa_key));

		if (result != NULL)
		{
			result->key_id = attributes->key_id;
			result->attributes = *attributes;
			hwpsa_info(context, attributes, info);
			*key = result;
		}
		else
		{
			status = qsc_hw_status_memory;
		}
	}

	return status;
}

/** \brief Publish only callbacks actually available from the PSA client.
 * \param context Caller-owned PSA scope.
 * \param capabilities Versioned public output.
 * \return Success or invalid parameter.
 */
static qsc_hw_status hwpsa_capabilities(void* context, qsc_hw_capabilities* capabilities)
{
	qsc_hw_psa_context* state;
	qsc_hw_status status;

	state = (qsc_hw_psa_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && capabilities != NULL &&
		capabilities->size == sizeof(qsc_hw_capabilities) && capabilities->version == QSC_HW_ABI_VERSION)
	{
		capabilities->flags = qsc_hw_capability_key_open;
		capabilities->max_sessions = 1U;
		capabilities->thread_safe = false;
		capabilities->requires_serialization = true;
		capabilities->operation_can_block = true;
		capabilities->supports_cancel = false;

		if (state->callbacks.create != NULL)
		{
			capabilities->flags |= qsc_hw_capability_generate;
		}

		if (state->callbacks.sign_hash != NULL)
		{
			capabilities->flags |= qsc_hw_capability_sign;
		}

		if (state->callbacks.agree != NULL)
		{
			capabilities->flags |= qsc_hw_capability_agree;
		}

		if (state->callbacks.public_key != NULL)
		{
			capabilities->flags |= qsc_hw_capability_public_key;
		}

		if (state->callbacks.random != NULL)
		{
			capabilities->flags |= qsc_hw_capability_random;
		}

		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Build exact canonical locator for the configured persistent PSA id.
 * \param context Initialized PSA scope.
 * \param output Writable buffer of QSC_HW_PSA_LOCATOR_SIZE bytes.
 */
static void hwpsa_locator_format(const qsc_hw_psa_context* context, char* output)
{
	static const char prefix[] = "psa://";
	static const char hex[] = "0123456789abcdef";
	uint32_t shift;
	size_t i;

	for (i = 0U; i < sizeof(prefix) - 1U; ++i)
	{
		output[i] = prefix[i];
	}

	for (i = 0U; i < 8U; ++i)
	{
		shift = (uint32_t)((7U - i) * 4U);
		output[6U + i] = hex[(context->key_id >> shift) & 0x0FU];
	}

	output[14U] = '\0';
}

/** \brief Compare an external locator to one fixed NUL-terminated identity.
 * \param locator Caller-supplied NUL-terminated locator.
 * \param expected Expected fixed canonical locator.
 * \return True only for exact match with bounded length.
 */
static bool hwpsa_locator_equal(const char* locator, const char* expected)
{
	size_t length;
	bool valid;

	length = 0U;

	while (length < QSC_HW_PSA_LOCATOR_SIZE && locator[length] != '\0')
	{
		++length;
	}

	valid = (length == QSC_HW_PSA_LOCATOR_SIZE - 1U);

	if (valid == true)
	{
		valid = qsc_memutils_are_equal((const uint8_t*)locator, (const uint8_t*)expected, QSC_HW_PSA_LOCATOR_SIZE);
	}

	return valid;
}

/** \brief Open a PSA protected identity without exporting or retaining private material.
 * \param context Caller-owned PSA context.
 * \param locator Exact pinned persistent key locator.
 * \param key New transient key reference output.
 * \param info Generic public key metadata output.
 * \return Typed status; never selects an ambiguous key.
 */
static qsc_hw_status hwpsa_open_key(void* context, const char* locator, void** key, qsc_hw_key_info* info)
{
	qsc_hw_psa_key_attributes attributes = { 0U };
	qsc_hw_psa_context* state;
	char expected[QSC_HW_PSA_LOCATOR_SIZE] = { 0U };
	qsc_hw_status status;

	state = (qsc_hw_psa_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (state != NULL && state->initialized == true && locator != NULL && key != NULL && info != NULL)
	{
		hwpsa_locator_format(state, expected);
		status = qsc_hw_status_stale_key;

		if (hwpsa_locator_equal(locator, expected) == true)
		{
			attributes.size = sizeof(attributes);
			attributes.version = QSC_HW_ABI_VERSION;
			status = state->callbacks.query(state->service, state->key_id, &attributes);

			if (status == qsc_hw_status_success)
			{
				status = hwpsa_bind(state, &attributes, key, info);
			}
		}
	}

	return status;
}

/** \brief Generate a new persistent PSA identity, never overwrite or auto-delete existing keys.
 * \param context Caller-owned PSA scope.
 * \param policy Requested persistent hardware key policy.
 * \param key New transient reference output.
 * \param info Generic public metadata output.
 * \return Success or typed failure; attempts rollback on rejected new key.
 */
static qsc_hw_status hwpsa_generate_key(void* context, const qsc_hw_key_policy* policy, void** key, qsc_hw_key_info* info)
{
	qsc_hw_psa_key_attributes attributes = { 0U };
	qsc_hw_psa_context* state;
	qsc_hw_status status;
	qsc_hw_status rollback;

	state = (qsc_hw_psa_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (state != NULL && state->initialized == true && state->callbacks.create != NULL &&
		policy != NULL && key != NULL && info != NULL && policy->allow_export == false &&
		policy->usage != qsc_hw_usage_none && policy->usage != qsc_hw_usage_attest)
	{
		attributes.size = sizeof(attributes);
		attributes.version = QSC_HW_ABI_VERSION;
		status = state->callbacks.query(state->service, state->key_id, &attributes);

		if (status == qsc_hw_status_stale_key)
		{
			qsc_memutils_clear(&attributes, sizeof(attributes));
			attributes.size = sizeof(attributes);
			attributes.version = QSC_HW_ABI_VERSION;
			status = state->callbacks.create(state->service, state->key_id, policy, &attributes);

			if (status == qsc_hw_status_success)
			{
				status = hwpsa_bind(state, &attributes, key, info);

				if (status != qsc_hw_status_success)
				{
					rollback = state->callbacks.rollback(state->service, state->key_id);

					if (rollback != qsc_hw_status_success)
					{
						status = qsc_hw_status_internal;
					}
				}
			}
		}
		else if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_policy;
		}
	}

	return status;
}

/** \brief Release only the transient host-side handle, not persistent PSA object.
 * \param context Unused caller-owned PSA context.
 * \param key Transient backend allocation.
 */
static void hwpsa_release_key(void* context, void* key)
{
	(void)context;

	if (key != NULL)
	{
		qsc_memutils_secure_erase(key, sizeof(hwpsa_key));
		qsc_memutils_alloc_free(key);
	}
}

/** \brief Return an uncompressed SEC1 EC point from a protected PSA key.
 * \param context Caller-owned PSA scope.
 * \param key Valid transient reference.
 * \param output Caller-owned output or NULL for size query.
 * \param outputlen In/out output byte capacity/required length.
 * \return Typed error or success, with partial failure output erased.
 */
static qsc_hw_status hwpsa_public_key(void* context, void* key, uint8_t* output, size_t* outputlen)
{
	qsc_hw_psa_context* state;
	hwpsa_key* identity;
	size_t hashlen;
	size_t siglen;
	size_t pointlen;
	size_t capacity;
	size_t written;
	qsc_hw_status status;

	state = (qsc_hw_psa_context*)context;
	identity = (hwpsa_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && identity != NULL && outputlen != NULL && state->callbacks.public_key != NULL &&
		hwpsa_lengths(identity->attributes.algorithm, &hashlen, &siglen, &pointlen) == true)
	{
		status = hwpsa_key_check(state, identity);

		if (status == qsc_hw_status_success)
		{
			capacity = *outputlen;
			status = qsc_hw_status_buffer_too_small;

			if (output == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (capacity >= pointlen)
			{
				written = capacity;
				status = state->callbacks.public_key(state->service, identity->key_id, output, &written);

				if (status == qsc_hw_status_success && (written != pointlen || output[0U] != 0x04U))
				{
					status = qsc_hw_status_policy;
				}

				if (status != qsc_hw_status_success)
				{
					qsc_memutils_secure_erase(output, capacity);
				}
			}

			*outputlen = pointlen;
		}
	}

	return status;
}

/** \brief Sign exact curve profile digest with raw PSA-style r||s signature.
 * \param context Initialized PSA context.
 * \param key Transient key handle.
 * \param algorithm Requested ECDSA curve.
 * \param message Precomputed digest bytes.
 * \param msglen Exact digest length for selected curve profile.
 * \param signature Caller buffer or NULL for size query.
 * \param signaturelen In/out buffer length.
 * \return Success or typed error; output cleared on backend failure.
 */
static qsc_hw_status hwpsa_sign(void* context, void* key, qsc_hw_algorithm algorithm,
	const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	qsc_hw_psa_context* state;
	hwpsa_key* identity;
	size_t digestlen;
	size_t siglen;
	size_t pointlen;
	size_t capacity;
	size_t written;
	qsc_hw_status status;

	state = (qsc_hw_psa_context*)context;
	identity = (hwpsa_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && identity != NULL && message != NULL && signaturelen != NULL &&
		state->callbacks.sign_hash != NULL && algorithm == identity->attributes.algorithm &&
		hwpsa_lengths(algorithm, &digestlen, &siglen, &pointlen) == true &&
		(algorithm == qsc_hw_algorithm_ecdsa_p256 || algorithm == qsc_hw_algorithm_ecdsa_p384 ||
			algorithm == qsc_hw_algorithm_ecdsa_p521) && msglen == digestlen)
	{
		status = hwpsa_key_check(state, identity);

		if (status == qsc_hw_status_success)
		{
			capacity = *signaturelen;
			status = qsc_hw_status_buffer_too_small;

			if (signature == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (capacity >= siglen)
			{
				written = capacity;
				status = state->callbacks.sign_hash(state->service, identity->key_id, algorithm, message,
					msglen, signature, &written);

				if (status == qsc_hw_status_success && written != siglen)
				{
					status = qsc_hw_status_policy;
				}

				if (status != qsc_hw_status_success)
				{
					qsc_memutils_secure_erase(signature, capacity);
				}
			}

			*signaturelen = siglen;
		}
	}

	return status;
}

/** \brief Perform ECDH and export only the explicitly permitted derived secret.
 * \param context PSA scope.
 * \param key Key with agreement permission.
 * \param peer SEC1 uncompressed curve public point.
 * \param peerlen Exact input length.
 * \param secret Host-side secret output or NULL for sizing.
 * \param secretlen In/out output capacity and actual length.
 * \return Typed status, clearing partial secret on failure.
 */
static qsc_hw_status hwpsa_agree(void* context, void* key, const uint8_t* peer, size_t peerlen,
	uint8_t* secret, size_t* secretlen)
{
	qsc_hw_psa_context* state;
	hwpsa_key* identity;
	size_t secret_size;
	size_t unused;
	size_t public_size;
	size_t capacity;
	size_t written;
	qsc_hw_status status;

	state = (qsc_hw_psa_context*)context;
	identity = (hwpsa_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && identity != NULL && peer != NULL && secretlen != NULL &&
		state->callbacks.agree != NULL &&
		hwpsa_lengths(identity->attributes.algorithm, &secret_size, &unused, &public_size) == true &&
		(identity->attributes.algorithm == qsc_hw_algorithm_ecdh_p256 ||
			identity->attributes.algorithm == qsc_hw_algorithm_ecdh_p384 ||
			identity->attributes.algorithm == qsc_hw_algorithm_ecdh_p521) &&
		peerlen == public_size && peer[0U] == 0x04U)
	{
		if (identity->attributes.algorithm == qsc_hw_algorithm_ecdh_p521)
		{
			secret_size = 66U;
		}

		status = hwpsa_key_check(state, identity);

		if (status == qsc_hw_status_success)
		{
			capacity = *secretlen;
			status = qsc_hw_status_buffer_too_small;

			if (secret == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (capacity >= secret_size)
			{
				written = capacity;
				status = state->callbacks.agree(state->service, identity->key_id, identity->attributes.algorithm,
					peer, peerlen, secret, &written);

				if (status == qsc_hw_status_success && written != secret_size)
				{
					status = qsc_hw_status_policy;
				}

				if (status != qsc_hw_status_success)
				{
					qsc_memutils_secure_erase(secret, capacity);
				}
			}

			*secretlen = secret_size;
		}
	}

	return status;
}

/** \brief Request platform PSA random bytes and clear partial output on failure.
 * \param context Caller-owned PSA scope.
 * \param output Caller-owned writable output.
 * \param length Requested byte length.
 * \return Typed status; does not attest SP800-90 entropy provenance.
 */
static qsc_hw_status hwpsa_random(void* context, uint8_t* output, size_t length)
{
	qsc_hw_psa_context* state;
	qsc_hw_status status;

	state = (qsc_hw_psa_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && state->callbacks.random != NULL &&
		(output != NULL || length == 0U))
	{
		status = state->callbacks.random(state->service, output, length);

		if (status != qsc_hw_status_success && output != NULL && length > 0U)
		{
			qsc_memutils_secure_erase(output, length);
		}
	}

	return status;
}

/** \brief Provider-close hook; does not alter PSA persistent keys or OEM context.
 * \param context Caller-owned PSA scope.
 */
static void hwpsa_dispose_callback(void* context)
{
	qsc_hw_psa_dispose((qsc_hw_psa_context*)context);
}

qsc_hw_status qsc_hw_psa_initialize(qsc_hw_psa_context* context, const qsc_hw_psa_callbacks* callbacks,
	void* service, uint32_t key_id, bool hardware_verified)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && context->initialized == true)
	{
		status = qsc_hw_status_busy;
	}
	else if (context != NULL && callbacks != NULL && service != NULL && key_id != 0U &&
		callbacks->size == sizeof(qsc_hw_psa_callbacks) && callbacks->version == QSC_HW_ABI_VERSION &&
		callbacks->query != NULL && (callbacks->create == NULL || callbacks->rollback != NULL))
	{
		context->callbacks = *callbacks;
		context->service = service;
		context->key_id = key_id;
		context->hardware_verified = hardware_verified;
		context->initialized = true;
		status = qsc_hw_status_success;
	}

	return status;
}

qsc_hw_status qsc_hw_psa_get_operations(qsc_hw_provider_ops* operations)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (operations != NULL)
	{
		qsc_memutils_clear(operations, sizeof(qsc_hw_provider_ops));
		operations->size = sizeof(qsc_hw_provider_ops);
		operations->version = QSC_HW_ABI_VERSION;
		operations->get_capabilities = hwpsa_capabilities;
		operations->release_key = hwpsa_release_key;
		operations->dispose = hwpsa_dispose_callback;
		operations->open_key = hwpsa_open_key;
		operations->generate_key = hwpsa_generate_key;
		operations->public_key = hwpsa_public_key;
		operations->sign = hwpsa_sign;
		operations->agree = hwpsa_agree;
		operations->random = hwpsa_random;
		status = qsc_hw_status_success;
	}

	return status;
}

qsc_hw_status qsc_hw_psa_locator(qsc_hw_psa_context* context, char* output, size_t* outputlen)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && context->initialized == true && outputlen != NULL)
	{
		status = qsc_hw_status_buffer_too_small;

		if (output == NULL)
		{
			status = qsc_hw_status_success;
		}
		else if (*outputlen >= QSC_HW_PSA_LOCATOR_SIZE)
		{
			hwpsa_locator_format(context, output);
			status = qsc_hw_status_success;
		}

		*outputlen = QSC_HW_PSA_LOCATOR_SIZE;
	}

	return status;
}

void qsc_hw_psa_dispose(qsc_hw_psa_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_secure_erase(context, sizeof(qsc_hw_psa_context));
	}
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PSA_ENABLED */
