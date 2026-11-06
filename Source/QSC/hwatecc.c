#include "hwatecc.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_ATECC_ENABLED)

#include "memutils.h"

/** \struct hwatecc_key
 * \brief Transient protected identity reference; stores no secret material.
 */
typedef struct hwatecc_key
{
	uint8_t serial[QSC_HW_ATECC_SERIAL_SIZE]; /**< Serial snapshot for stale-key checks. */
	uint8_t slot; /**< Pinned hardware slot. */
} hwatecc_key;

/** \brief Check the device's live serial number against its original identity.
 * \param context Initialized caller-owned backend context.
 * \return Success, device-removed, or stale-key error.
 */
static qsc_hw_status hwatecc_serial_check(qsc_hw_atecc_context* context)
{
	uint8_t serial[QSC_HW_ATECC_SERIAL_SIZE] = { 0U };
	qsc_hw_status status;

	status = context->callbacks.read_serial(context->device, serial);

	if (status == qsc_hw_status_success)
	{
		if (qsc_memutils_are_equal(serial, context->serial, sizeof(serial)) == false)
		{
			status = qsc_hw_status_stale_key;
		}
	}

	qsc_memutils_secure_erase(serial, sizeof(serial));
	return status;
}

/** \brief Enforce non-exportable locked-slot requirements for every protected operation.
 * \param context Initialized caller-owned backend context.
 * \return Success only if the original device and protected slot policy remain valid.
 */
static qsc_hw_status hwatecc_security_check(qsc_hw_atecc_context* context)
{
	qsc_hw_atecc_slot_policy policy = { false };
	qsc_hw_status status;

	status = hwatecc_serial_check(context);

	if (status == qsc_hw_status_success)
	{
		status = context->callbacks.read_slot_policy(context->device, context->slot, &policy);

		if (status == qsc_hw_status_success)
		{
			if (policy.configuration_locked == false || policy.data_locked == false ||
				policy.private_key == false || policy.signing_enabled == false || policy.private_exportable == true)
			{
				status = qsc_hw_status_policy;
			}
		}
	}

	return status;
}

/** \brief Format a bounded device/slot locator without parsing ambiguous vendor aliases.
 * \param context Initialized context.
 * \param output Writable QSC_HW_ATECC_LOCATOR_SIZE-byte buffer.
 * \note Caller establishes output capacity; this helper never allocates.
 */
static void hwatecc_locator_format(const qsc_hw_atecc_context* context, char* output)
{
	static const char prefix[] = "atecc://";
	static const char hex[] = "0123456789abcdef";
	size_t i;

	for (i = 0U; i < (sizeof(prefix) - 1U); ++i)
	{
		output[i] = prefix[i];
	}

	for (i = 0U; i < QSC_HW_ATECC_SERIAL_SIZE; ++i)
	{
		output[8U + (i * 2U)] = hex[context->serial[i] >> 4U];
		output[9U + (i * 2U)] = hex[context->serial[i] & 0x0FU];
	}

	output[26U] = '/';
	output[27U] = hex[context->slot >> 4U];
	output[28U] = hex[context->slot & 0x0FU];
	output[29U] = '\0';
}

/** \brief Compare a NUL-terminated caller locator with a fixed 29-character locator.
 * \param locator Caller-provided NUL-terminated string, checked with a fixed maximum.
 * \param expected Fixed expected 29-character locator including NUL.
 * \return True on exact match only; rejects non-terminated overlong forms.
 */
static bool hwatecc_locator_equal(const char* locator, const char* expected)
{
	size_t length;
	bool valid;

	length = 0U;

	while (length < QSC_HW_ATECC_LOCATOR_SIZE && locator[length] != '\0')
	{
		++length;
	}

	valid = (length == (QSC_HW_ATECC_LOCATOR_SIZE - 1U));

	if (valid == true)
	{
		valid = qsc_memutils_are_equal((const uint8_t*)locator, (const uint8_t*)expected,
			QSC_HW_ATECC_LOCATOR_SIZE);
	}

	return valid;
}

/** \brief Return supported operations, without claiming cryptographic attestation.
 * \param context Initialized ATECC context.
 * \param capabilities In/out versioned capability structure.
 * \return Success or typed backend failure.
 */
static qsc_hw_status hwatecc_capabilities(void* context, qsc_hw_capabilities* capabilities)
{
	qsc_hw_atecc_context* state;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;
	state = (qsc_hw_atecc_context*)context;

	if (state != NULL && state->initialized == true && capabilities != NULL)
	{
		status = hwatecc_security_check(state);

		if (status == qsc_hw_status_success)
		{
			capabilities->size = sizeof(qsc_hw_capabilities);
			capabilities->version = QSC_HW_ABI_VERSION;
			capabilities->flags = (uint32_t)(qsc_hw_capability_key_open | qsc_hw_capability_public_key | qsc_hw_capability_sign);
			capabilities->max_sessions = 1U;
			capabilities->thread_safe = false;
			capabilities->requires_serialization = true;
			capabilities->operation_can_block = true;
			capabilities->supports_cancel = false;
		}
	}

	return status;
}

/** \brief Resolve the one pinned pre-provisioned slot by exact persistent locator.
 * \param context Initialized ATECC context.
 * \param locator Exact generated locator including device serial and slot.
 * \param key Output transient key handle, owned by release callback.
 * \param info Output public key policy metadata.
 * \return Success or typed error, never a raw private key.
 */
static qsc_hw_status hwatecc_open_key(void* context, const char* locator, void** key, qsc_hw_key_info* info)
{
	qsc_hw_atecc_context* state;
	hwatecc_key* result;
	char expected[QSC_HW_ATECC_LOCATOR_SIZE] = { 0 };
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;
	state = (qsc_hw_atecc_context*)context;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (state != NULL && state->initialized == true && locator != NULL && key != NULL && info != NULL)
	{
		hwatecc_locator_format(state, expected);
		status = qsc_hw_status_stale_key;

		/* Bounded compare first; do not read attacker-supplied locator past its NUL. */
		if (hwatecc_locator_equal(locator, expected) == true)
		{
			status = hwatecc_security_check(state);

			if (status == qsc_hw_status_success)
			{
				result = (hwatecc_key*)qsc_memutils_calloc(1U, sizeof(hwatecc_key));

				if (result != NULL)
				{
					qsc_memutils_copy(result->serial, state->serial, sizeof(result->serial));
					result->slot = state->slot;
					info->size = sizeof(qsc_hw_key_info);
					info->version = QSC_HW_ABI_VERSION;
					info->algorithm = qsc_hw_algorithm_ecdsa_p256;
					info->usage = qsc_hw_usage_sign;
					info->custody = state->hardware_confirmed ? qsc_hw_custody_hardware_nonexportable : qsc_hw_custody_unknown;
					info->extractable = false;
					*key = result;
				}
				else
				{
					status = qsc_hw_status_memory;
				}
			}
		}
	}

	return status;
}

/** \brief Ensure one transient key still belongs to the live pinned token.
 * \param context Caller-owned context.
 * \param key Transient backend key reference.
 * \return Success or stale-key/protection failure.
 */
static qsc_hw_status hwatecc_key_valid(qsc_hw_atecc_context* context, const hwatecc_key* key)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && context != NULL && context->initialized == true)
	{
		status = qsc_hw_status_stale_key;

		if (key->slot == context->slot && qsc_memutils_are_equal(key->serial, context->serial, sizeof(key->serial)) == true)
		{
			status = hwatecc_security_check(context);
		}
	}

	return status;
}

/** \brief Read one P-256 SEC1 public point from the current hardware slot.
 * \param context Initialized backend state.
 * \param key Transient key handle.
 * \param output Caller-owned destination, NULL for sizing.
 * \param outputlen In/out buffer size.
 * \return Typed error or success; no private key bytes.
 */
static qsc_hw_status hwatecc_public_key(void* context, void* key, uint8_t* output, size_t* outputlen)
{
	uint8_t point[64U] = { 0U };
	qsc_hw_atecc_context* state;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;
	state = (qsc_hw_atecc_context*)context;

	if (state != NULL && outputlen != NULL)
	{
		status = hwatecc_key_valid(state, (const hwatecc_key*)key);

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_buffer_too_small;

			if (output == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (*outputlen >= QSC_HW_ATECC_PUBLIC_SIZE)
			{
				status = state->callbacks.read_public(state->device, state->slot, point);

				if (status == qsc_hw_status_success)
				{
					output[0U] = 0x04U;
					qsc_memutils_copy(output + 1U, point, sizeof(point));
				}
			}

			*outputlen = QSC_HW_ATECC_PUBLIC_SIZE;
		}
	}

	qsc_memutils_secure_erase(point, sizeof(point));
	return status;
}

/** \brief Sign one prehashed SHA-256 digest using the device's fixed P-256 slot.
 * \param context Caller-owned initialized backend state.
 * \param key Transient key handle.
 * \param algorithm Requested hardware signature scheme.
 * \param message Precomputed digest, exactly 32 bytes.
 * \param msglen Digest size.
 * \param signature Caller output or NULL for sizing.
 * \param signaturelen In/out output capacity.
 * \return Typed status, with partial signature securely erased on failure.
 */
static qsc_hw_status hwatecc_sign(void* context, void* key, qsc_hw_algorithm algorithm,
	const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	qsc_hw_atecc_context* state;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;
	state = (qsc_hw_atecc_context*)context;

	if (state != NULL && algorithm == qsc_hw_algorithm_ecdsa_p256 && message != NULL &&
		msglen == 32U && signaturelen != NULL)
	{
		status = hwatecc_key_valid(state, (const hwatecc_key*)key);

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_buffer_too_small;

			if (signature == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (*signaturelen >= QSC_HW_ATECC_SIGNATURE_SIZE)
			{
				status = state->callbacks.sign_digest(state->device, state->slot, message, signature);

				if (status != qsc_hw_status_success)
				{
					qsc_memutils_secure_erase(signature, QSC_HW_ATECC_SIGNATURE_SIZE);
				}
			}

			*signaturelen = QSC_HW_ATECC_SIGNATURE_SIZE;
		}
	}

	return status;
}

/** \brief Release a transient key reference, without deleting persistent slots.
 * \param context Unused owner context.
 * \param key Backend allocated key handle to securely erase and free.
 */
static void hwatecc_release_key(void* context, void* key)
{
	(void)context;

	if (key != NULL)
	{
		qsc_memutils_secure_erase(key, sizeof(hwatecc_key));
		qsc_memutils_alloc_free(key);
	}
}

/** \brief Provider close callback, which clears the caller-owned ATECC context.
 * \param context Caller-owned context; device handle is not closed.
 */
static void hwatecc_provider_dispose(void* context)
{
	qsc_hw_atecc_dispose((qsc_hw_atecc_context*)context);
}

qsc_hw_status qsc_hw_atecc_initialize(qsc_hw_atecc_context* context, const qsc_hw_atecc_callbacks* callbacks,
	void* device, uint8_t slot, bool physical_confirmed)
{
	qsc_hw_atecc_context candidate = { 0U };
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && callbacks != NULL && device != NULL && slot <= QSC_HW_ATECC_MAX_SLOT &&
		context->initialized == false && callbacks->size == sizeof(qsc_hw_atecc_callbacks) &&
		callbacks->version == QSC_HW_ABI_VERSION && callbacks->read_serial != NULL &&
		callbacks->read_slot_policy != NULL && callbacks->read_public != NULL && callbacks->sign_digest != NULL)
	{
		candidate.callbacks = *callbacks;
		candidate.device = device;
		candidate.slot = slot;
		candidate.hardware_confirmed = physical_confirmed;
		candidate.initialized = true;
		status = candidate.callbacks.read_serial(device, candidate.serial);

		if (status == qsc_hw_status_success)
		{
			status = hwatecc_security_check(&candidate);
		}

		if (status == qsc_hw_status_success)
		{
			*context = candidate;
		}
		else
		{
			qsc_memutils_secure_erase(&candidate, sizeof(candidate));
		}
	}
	else if (context != NULL && context->initialized == true)
	{
		status = qsc_hw_status_busy;
	}

	return status;
}

qsc_hw_status qsc_hw_atecc_get_operations(qsc_hw_provider_ops* operations)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (operations != NULL)
	{
		qsc_memutils_clear(operations, sizeof(qsc_hw_provider_ops));
		operations->size = sizeof(qsc_hw_provider_ops);
		operations->version = QSC_HW_ABI_VERSION;
		operations->get_capabilities = hwatecc_capabilities;
		operations->release_key = hwatecc_release_key;
		operations->dispose = hwatecc_provider_dispose;
		operations->open_key = hwatecc_open_key;
		operations->sign = hwatecc_sign;
		operations->public_key = hwatecc_public_key;
		status = qsc_hw_status_success;
	}

	return status;
}

qsc_hw_status qsc_hw_atecc_locator(qsc_hw_atecc_context* context, char* output, size_t* outputlen)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && context->initialized == true && outputlen != NULL)
	{
		status = hwatecc_serial_check(context);

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_buffer_too_small;

			if (output == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (*outputlen >= QSC_HW_ATECC_LOCATOR_SIZE)
			{
				hwatecc_locator_format(context, output);
				status = qsc_hw_status_success;
			}

			*outputlen = QSC_HW_ATECC_LOCATOR_SIZE;
		}
	}

	return status;
}

void qsc_hw_atecc_dispose(qsc_hw_atecc_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_secure_erase(context, sizeof(qsc_hw_atecc_context));
	}
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_ATECC_ENABLED */
