#include "hwprovider.h"

#if defined(QSC_HARDWARE_ENABLED)

#include "memutils.h"
#include <stddef.h>
#include <stdint.h>

/* \cond DOXYGEN_NO_DOCUMENT */

/** \struct qsc_hw_provider
 * \brief Private provider lifecycle state; never contains a private key.
 */
struct qsc_hw_provider
{
	qsc_hw_provider_ops operations; /**< Size-checked local copy of backend operations. */
	void* context; /**< Caller-owned backend context, valid until close. */
	uint64_t generation; /**< Incremented when a token/device reconnect invalidates handles. */
	size_t references; /**< Live transient key references. */
};

/** \struct qsc_hw_keyref
 * \brief Private key reference with immutable, validated policy and backend identity.
 */
struct qsc_hw_keyref
{
	qsc_hw_provider* provider; /**< Owner provider; cannot close while this handle exists. */
	void* backend_key; /**< Backend-owned transient token key handle. */
	uint64_t generation; /**< Provider generation at key open/generation. */
	qsc_hw_key_info info; /**< Verified public metadata, never private key bytes. */
	qsc_hw_key_policy policy; /**< Caller policy fixed when the key reference was opened. */
};

/** \brief Validate caller policy before contacting a device.
 * \param policy Caller policy or NULL.
 * \return True only for a complete, consistent supported policy.
 * \note Pure function; thread-safe.
 */
static bool hwprovider_policy_valid(const qsc_hw_key_policy* policy)
{
	bool valid;

	valid = false;

	if (policy != NULL)
	{
		valid = (policy->size == sizeof(qsc_hw_key_policy) &&
			policy->version == QSC_HW_ABI_VERSION &&
			policy->algorithm > qsc_hw_algorithm_none &&
			policy->algorithm <= qsc_hw_algorithm_ml_kem_1024 &&
			policy->usage != qsc_hw_usage_none &&
			(policy->usage & ~(uint32_t)(qsc_hw_usage_sign | qsc_hw_usage_agree | qsc_hw_usage_attest)) == 0U &&
			(policy->require_hardware == false || policy->allow_software_fallback == false));
	}

	return valid;
}

/** \brief Validate actual backend key metadata against caller requirements.
 * \param info Public backend key metadata.
 * \param policy Caller-required policy.
 * \return True when algorithm, usage, residency and exportability all match.
 * \note Pure function; no device operations or private key accesses.
 */
static bool hwprovider_key_acceptable(const qsc_hw_key_info* info, const qsc_hw_key_policy* policy)
{
	bool valid;

	valid = (info->size == sizeof(qsc_hw_key_info) &&
		info->version == QSC_HW_ABI_VERSION &&
		info->algorithm == policy->algorithm &&
		(info->usage & policy->usage) == policy->usage &&
		(info->custody == qsc_hw_custody_hardware_nonexportable ||
			(policy->require_hardware == false && policy->allow_software_fallback == true &&
				(info->custody == qsc_hw_custody_software || info->custody == qsc_hw_custody_hardware_wrapped))) &&
		(info->extractable == false || policy->allow_export == true) &&
		(info->custody != qsc_hw_custody_hardware_nonexportable || info->extractable == false) &&
		(policy->require_hardware == false ||
			(info->custody == qsc_hw_custody_hardware_nonexportable && info->extractable == false)));

	return valid;
}

/** \brief Resolve a successful backend open into an enforced, provider-owned key reference.
 * \param key Caller output reference.
 * \param provider Provider owning the new backend key.
 * \param backend_key Backend key handle (or NULL on failure).
 * \param info Backend metadata for the key.
 * \param policy Immutable requested policy.
 * \return Success, policy rejection or allocation error; releases rejected handles.
 * \note Caller must serialize against provider closure.
 */
static qsc_hw_status hwprovider_finish_key(qsc_hw_keyref** key, qsc_hw_provider* provider, void* backend_key, const qsc_hw_key_info* info, const qsc_hw_key_policy* policy)
{
	qsc_hw_keyref* ref;
	qsc_hw_status status;

	status = qsc_hw_status_internal;

	if (backend_key != NULL)
	{
		if (provider->references != SIZE_MAX && hwprovider_key_acceptable(info, policy) == true)
		{
			ref = (qsc_hw_keyref*)qsc_memutils_calloc(1U, sizeof(qsc_hw_keyref));

			if (ref != NULL)
			{
				ref->provider = provider;
				ref->backend_key = backend_key;
				ref->generation = provider->generation;
				ref->info = *info;
				ref->policy = *policy;
				provider->references += 1U;
				*key = ref;
				status = qsc_hw_status_success;
			}
			else
			{
				status = qsc_hw_status_memory;
			}
			}
		else
		{
			status = qsc_hw_status_policy;
		}

		if (status != qsc_hw_status_success)
		{
			provider->operations.release_key(provider->context, backend_key);
		}
	}

	return status;
}

qsc_hw_status qsc_hw_provider_open(qsc_hw_provider** provider, const qsc_hw_provider_ops* operations, void* context)
{
	qsc_hw_provider* state;
	qsc_hw_status status;
	size_t size;

	status = qsc_hw_status_invalid_parameter;

	if (provider != NULL)
	{
		*provider = NULL;
	}

	if (provider != NULL && operations != NULL)
	{
		if (operations->version != QSC_HW_ABI_VERSION)
		{
			status = qsc_hw_status_version;
		}
		else if (operations->size < offsetof(qsc_hw_provider_ops, dispose))
		{
			status = qsc_hw_status_invalid_parameter;
		}
		else if (operations->get_capabilities == NULL || operations->release_key == NULL)
		{
			status = qsc_hw_status_invalid_parameter;
		}
		else
		{
			state = (qsc_hw_provider*)qsc_memutils_calloc(1U, sizeof(qsc_hw_provider));

			if (state != NULL)
			{
				size = operations->size;

				if (size > sizeof(qsc_hw_provider_ops))
				{
					size = sizeof(qsc_hw_provider_ops);
				}

				qsc_memutils_copy(&state->operations, operations, size);
				state->context = context;
				state->generation = 1U;
				*provider = state;
				status = qsc_hw_status_success;
			}
			else
			{
				status = qsc_hw_status_memory;
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_provider_capabilities(qsc_hw_provider* provider, qsc_hw_capabilities* capabilities)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (provider != NULL && capabilities != NULL)
	{
		if (capabilities->size == sizeof(qsc_hw_capabilities) && capabilities->version == QSC_HW_ABI_VERSION)
		{
			status = provider->operations.get_capabilities(provider->context, capabilities);

			if (status == qsc_hw_status_success)
			{
				if ((capabilities->flags & qsc_hw_capability_key_open) != 0U && provider->operations.open_key == NULL)
				{
					status = qsc_hw_status_internal;
				}
				if ((capabilities->flags & qsc_hw_capability_generate) != 0U && provider->operations.generate_key == NULL)
				{
					status = qsc_hw_status_internal;
				}
				if ((capabilities->flags & qsc_hw_capability_sign) != 0U && provider->operations.sign == NULL)
				{
					status = qsc_hw_status_internal;
				}
				if ((capabilities->flags & qsc_hw_capability_agree) != 0U && provider->operations.agree == NULL)
				{
					status = qsc_hw_status_internal;
				}
				if ((capabilities->flags & qsc_hw_capability_random) != 0U && provider->operations.random == NULL)
				{
					status = qsc_hw_status_internal;
				}
				if ((capabilities->flags & qsc_hw_capability_attest) != 0U && provider->operations.attest == NULL)
				{
					status = qsc_hw_status_internal;
				}
				if ((capabilities->flags & qsc_hw_capability_public_key) != 0U && provider->operations.public_key == NULL)
				{
					status = qsc_hw_status_internal;
				}
				if (capabilities->size != sizeof(qsc_hw_capabilities) || capabilities->version != QSC_HW_ABI_VERSION ||
					(capabilities->flags & ~((uint32_t)(qsc_hw_capability_key_open | qsc_hw_capability_generate | qsc_hw_capability_sign | qsc_hw_capability_agree | qsc_hw_capability_random | qsc_hw_capability_attest | qsc_hw_capability_public_key))) != 0U)
				{
					status = qsc_hw_status_internal;
				}
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_open(qsc_hw_keyref** key, qsc_hw_provider* provider, const char* locator, const qsc_hw_key_policy* policy)
{
	qsc_hw_key_info info;
	void* backend_key;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (key != NULL && provider != NULL && locator != NULL && locator[0U] != '\0' && hwprovider_policy_valid(policy) == true)
	{
		status = qsc_hw_status_unsupported;

		if (provider->operations.open_key != NULL)
		{
			qsc_memutils_clear(&info, sizeof(info));
			info.size = sizeof(info);
			info.version = QSC_HW_ABI_VERSION;
			backend_key = NULL;
			status = provider->operations.open_key(provider->context, locator, &backend_key, &info);

			if (status == qsc_hw_status_success)
			{
				status = hwprovider_finish_key(key, provider, backend_key, &info, policy);
			}
			else if (backend_key != NULL)
			{
				provider->operations.release_key(provider->context, backend_key);
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_generate(qsc_hw_keyref** key, qsc_hw_provider* provider, const qsc_hw_key_policy* policy)
{
	qsc_hw_key_info info;
	void* backend_key;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (key != NULL && provider != NULL && hwprovider_policy_valid(policy) == true)
	{
		status = qsc_hw_status_unsupported;

		if (provider->operations.generate_key != NULL)
		{
			qsc_memutils_clear(&info, sizeof(info));
			info.size = sizeof(info);
			info.version = QSC_HW_ABI_VERSION;
			backend_key = NULL;
			status = provider->operations.generate_key(provider->context, policy, &backend_key, &info);

			if (status == qsc_hw_status_success)
			{
				status = hwprovider_finish_key(key, provider, backend_key, &info, policy);
			}
			else if (backend_key != NULL)
			{
				provider->operations.release_key(provider->context, backend_key);
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_get_info(const qsc_hw_keyref* key, qsc_hw_key_info* info)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && info != NULL)
	{
		if (info->size == sizeof(qsc_hw_key_info) && info->version == QSC_HW_ABI_VERSION)
		{
			if (key->generation == key->provider->generation)
			{
				*info = key->info;
				status = qsc_hw_status_success;
			}
			else
			{
				status = qsc_hw_status_stale_key;
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_public(qsc_hw_keyref* key, uint8_t* output, size_t* outputlen)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && outputlen != NULL)
	{
		status = qsc_hw_status_stale_key;

		if (key->generation == key->provider->generation)
		{
			status = qsc_hw_status_unsupported;

			if (key->provider->operations.public_key != NULL)
			{
				status = key->provider->operations.public_key(key->provider->context, key->backend_key, output, outputlen);
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_sign(qsc_hw_keyref* key, const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	qsc_hw_status status;
	size_t capacity;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && signaturelen != NULL && (message != NULL || msglen == 0U))
	{
		status = qsc_hw_status_stale_key;

		if (key->generation == key->provider->generation)
		{
			status = qsc_hw_status_policy;

			if ((key->info.usage & qsc_hw_usage_sign) != 0U && (key->policy.usage & qsc_hw_usage_sign) != 0U)
			{
				status = qsc_hw_status_unsupported;

				if (key->provider->operations.sign != NULL)
				{
					capacity = *signaturelen;
					status = key->provider->operations.sign(key->provider->context, key->backend_key, key->info.algorithm, message, msglen, signature, signaturelen);

					if (status != qsc_hw_status_success && status != qsc_hw_status_buffer_too_small && signature != NULL && capacity > 0U)
					{
						qsc_memutils_secure_erase(signature, capacity);
					}
				}
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_agree(qsc_hw_keyref* key, const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen)
{
	qsc_hw_status status;
	size_t capacity;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && secretlen != NULL && peer != NULL && peerlen > 0U)
	{
		status = qsc_hw_status_stale_key;

		if (key->generation == key->provider->generation)
		{
			status = qsc_hw_status_policy;

			if ((key->policy.usage & qsc_hw_usage_agree) != 0U && (key->info.usage & qsc_hw_usage_agree) != 0U && key->policy.allow_derived_secret_export == true)
			{
				status = qsc_hw_status_unsupported;

				if (key->provider->operations.agree != NULL)
				{
					capacity = *secretlen;
					status = key->provider->operations.agree(key->provider->context, key->backend_key, peer, peerlen, secret, secretlen);
					if (status != qsc_hw_status_success && secret != NULL && capacity > 0U)
					{
						qsc_memutils_secure_erase(secret, capacity);
					}
				}
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_attest(qsc_hw_keyref* key, const uint8_t* challenge, size_t challengelen, uint8_t* evidence, size_t* evidencelen)
{
	qsc_hw_status status;
	size_t capacity;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && challenge != NULL && challengelen > 0U && evidencelen != NULL)
	{
		status = qsc_hw_status_stale_key;

		if (key->generation == key->provider->generation)
		{
			status = qsc_hw_status_policy;

			if ((key->policy.usage & qsc_hw_usage_attest) != 0U && (key->info.usage & qsc_hw_usage_attest) != 0U)
			{
				status = qsc_hw_status_unsupported;

				if (key->provider->operations.attest != NULL)
				{
					capacity = *evidencelen;
					status = key->provider->operations.attest(key->provider->context, key->backend_key, challenge, challengelen, evidence, evidencelen);

					if (status != qsc_hw_status_success && status != qsc_hw_status_buffer_too_small && evidence != NULL && capacity > 0U)
					{
						qsc_memutils_secure_erase(evidence, capacity);
					}
				}
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_provider_random(qsc_hw_provider* provider, uint8_t* output, size_t length)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (provider != NULL && (output != NULL || length == 0U))
	{
		status = qsc_hw_status_unsupported;

		if (provider->operations.random != NULL)
		{
			status = provider->operations.random(provider->context, output, length);
			if (status != qsc_hw_status_success && output != NULL && length > 0U)
			{
				qsc_memutils_secure_erase(output, length);
			}
		}
	}

	return status;
}

/** \brief Invalidate all previously opened keys after device removal/reconnect.
 * \param provider Live provider; caller serializes this call with all key operations.
 * \return Success, or invalid_parameter/internal failure on generation exhaustion.
 * \note References remain allocated and must be released, but subsequent operations fail stale_key.
 */
qsc_hw_status qsc_hw_provider_invalidate(qsc_hw_provider* provider)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (provider != NULL)
	{
		status = qsc_hw_status_internal;

		if (provider->generation < UINT64_MAX)
		{
			provider->generation += 1U;
			status = qsc_hw_status_success;
		}
	}

	return status;
}

qsc_hw_status qsc_hw_key_release(qsc_hw_keyref** key)
{
	qsc_hw_keyref* ref;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (key != NULL && *key != NULL)
	{
		ref = *key;
		ref->provider->operations.release_key(ref->provider->context, ref->backend_key);
		ref->provider->references -= 1U;
		qsc_memutils_secure_erase(ref, sizeof(qsc_hw_keyref));
		qsc_memutils_alloc_free(ref);
		*key = NULL;
		status = qsc_hw_status_success;
	}

	return status;
}

qsc_hw_status qsc_hw_provider_close(qsc_hw_provider** provider)
{
	qsc_hw_provider* state;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (provider != NULL && *provider != NULL)
	{
		state = *provider;
		status = qsc_hw_status_busy;

		if (state->references == 0U)
		{
			if (state->operations.dispose != NULL)
			{
				state->operations.dispose(state->context);
			}

			qsc_memutils_secure_erase(state, sizeof(qsc_hw_provider));
			qsc_memutils_alloc_free(state);
			*provider = NULL;
			status = qsc_hw_status_success;
		}
	}

	return status;
}

#endif

/* \endcond DOXYGEN_NO_DOCUMENT */

