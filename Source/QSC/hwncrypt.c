#include "hwncrypt.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_NCRYPT_ENABLED)

#include "memutils.h"
#include "stringutils.h"

#if defined(_WIN32)

/** \def WIN32_LEAN_AND_MEAN
 * \brief Restrict Windows platform headers to required interfaces.
 */
#if !defined(WIN32_LEAN_AND_MEAN)
#	define WIN32_LEAN_AND_MEAN
#endif
/** \def NOMINMAX
 * \brief Prevent Windows min/max macros from changing identifiers.
 */
#if !defined(NOMINMAX)
#	define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#if defined(_MSC_VER)
#	pragma comment(lib, "ncrypt.lib")
#endif

/** \def HWNCRYPT_MAX_NAME
 * \brief Maximum UTF-8 byte length of a persistent Windows key name, excluding NUL.
 */
#define HWNCRYPT_MAX_NAME 127U

/** \struct hwncrypt_native
 * \brief Private native KSP and key-name state; contains no private key bytes.
 */
typedef struct hwncrypt_native
{
	NCRYPT_PROV_HANDLE provider; /**< Owned Microsoft Platform Crypto Provider handle. */
	wchar_t name[HWNCRYPT_MAX_NAME + 1U]; /**< Persistent UTF-16 key name. */
	char locator[HWNCRYPT_MAX_NAME + 1U]; /**< Persistent UTF-8 key locator. */
	DWORD scope; /**< NCRYPT_MACHINE_KEY_FLAG for machine scope, otherwise zero. */
} hwncrypt_native;

/** \struct hwncrypt_key
 * \brief Backend-private reference to an opened persisted TPM identity.
 */
typedef struct hwncrypt_key
{
	NCRYPT_KEY_HANDLE handle; /**< Owned key handle; persistent key is not deleted on release. */
	qsc_hw_algorithm algorithm; /**< Verified signature curve. */
} hwncrypt_key;

/** \brief Convert a Windows NCrypt status to the existing QSC hardware error taxonomy.
 * \param result SECURITY_STATUS returned by a Windows crypto operation.
 * \return Typed error; no vendor status or sensitive material is logged.
 * \note Mapping is conservative; unknown statuses are internal errors.
 */
static qsc_hw_status hwncrypt_status(SECURITY_STATUS result)
{
	qsc_hw_status status;

	status = qsc_hw_status_internal;

	if (result == ERROR_SUCCESS)
	{
		status = qsc_hw_status_success;
	}
	else if (result == NTE_BAD_KEYSET || result == NTE_NOT_FOUND || result == NTE_BAD_KEY_STATE)
	{
		status = qsc_hw_status_stale_key;
	}
	else if (result == NTE_NO_MEMORY)
	{
		status = qsc_hw_status_memory;
	}
	else if (result == NTE_BAD_ALGID || result == NTE_NOT_SUPPORTED)
	{
		status = qsc_hw_status_unsupported;
	}
	else if (result == NTE_PERM || result == NTE_SILENT_CONTEXT)
	{
		status = qsc_hw_status_auth_required;
	}
	else if (result == NTE_EXISTS || result == NTE_BAD_FLAGS || result == NTE_INVALID_PARAMETER)
	{
		status = qsc_hw_status_policy;
	}
	else if (result == NTE_BUFFER_TOO_SMALL)
	{
		status = qsc_hw_status_buffer_too_small;
	}

	return status;
}

/** \brief Resolve a QSC supported signing scheme to its NCrypt algorithm and digest size.
 * \param algorithm Requested QSC scheme.
 * \param name Output receives immutable Windows algorithm name on success.
 * \param digestlen Output digest byte count.
 * \param keylen Output curve coordinate length in bytes.
 * \return True for supported ECDSA variants; no software fallback.
 */
static bool hwncrypt_algorithm(qsc_hw_algorithm algorithm, LPCWSTR* name, size_t* digestlen, size_t* keylen)
{
	bool valid;

	valid = true;

	switch (algorithm)
	{
		case qsc_hw_algorithm_ecdsa_p256:
		{
			*name = NCRYPT_ECDSA_P256_ALGORITHM;
			*digestlen = 32U;
			*keylen = 32U;
			break;
		}
		case qsc_hw_algorithm_ecdsa_p384:
		{
			*name = NCRYPT_ECDSA_P384_ALGORITHM;
			*digestlen = 48U;
			*keylen = 48U;
			break;
		}
		case qsc_hw_algorithm_ecdsa_p521:
		{
			*name = NCRYPT_ECDSA_P521_ALGORITHM;
			*digestlen = 64U;
			*keylen = 66U;
			break;
		}
		default:
		{
			valid = false;
			break;
		}
	}

	return valid;
}

/** \brief Validate algorithm, export policy and use restrictions of a native key.
 * \param key Live NCrypt key handle.
 * \param info Receives verified QSC key metadata with hardware/nonexportable custody.
 * \return Success only when the device enforces signing and zero export policy.
 */
static qsc_hw_status hwncrypt_key_info(NCRYPT_KEY_HANDLE key, qsc_hw_key_info* info)
{
	wchar_t name[80U];
	DWORD exportflags;
	DWORD usage;
	DWORD written;
	LPCWSTR expected;
	qsc_hw_algorithm algorithm;
	qsc_hw_status status;
	size_t digestlen;
	size_t keylen;

	status = qsc_hw_status_policy;
	exportflags = 0U;
	usage = 0U;
	written = 0U;

	if (NCryptGetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&exportflags, (DWORD)sizeof(exportflags), &written, 0U) == ERROR_SUCCESS &&
		written == sizeof(exportflags) && exportflags == 0U &&
		NCryptGetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, (DWORD)sizeof(usage), &written, 0U) == ERROR_SUCCESS &&
		written == sizeof(usage) && usage == NCRYPT_ALLOW_SIGNING_FLAG &&
		NCryptGetProperty(key, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)name, (DWORD)sizeof(name), &written, 0U) == ERROR_SUCCESS &&
		written >= sizeof(wchar_t) && written <= sizeof(name))
	{
		status = qsc_hw_status_unsupported;
		algorithm = qsc_hw_algorithm_none;

		if ((written % sizeof(wchar_t)) == 0U && name[(written / sizeof(wchar_t)) - 1U] == L'\0' &&
			lstrcmpW(name, NCRYPT_ECDSA_P256_ALGORITHM) == 0)
		{
			algorithm = qsc_hw_algorithm_ecdsa_p256;
		}
		else if ((written % sizeof(wchar_t)) == 0U && name[(written / sizeof(wchar_t)) - 1U] == L'\0' &&
			lstrcmpW(name, NCRYPT_ECDSA_P384_ALGORITHM) == 0)
		{
			algorithm = qsc_hw_algorithm_ecdsa_p384;
		}
		else if ((written % sizeof(wchar_t)) == 0U && name[(written / sizeof(wchar_t)) - 1U] == L'\0' &&
			lstrcmpW(name, NCRYPT_ECDSA_P521_ALGORITHM) == 0)
		{
			algorithm = qsc_hw_algorithm_ecdsa_p521;
		}

		if (hwncrypt_algorithm(algorithm, &expected, &digestlen, &keylen) == true)
		{
			info->size = sizeof(qsc_hw_key_info);
			info->version = QSC_HW_ABI_VERSION;
			info->algorithm = algorithm;
			info->usage = qsc_hw_usage_sign;
			info->custody = qsc_hw_custody_hardware_nonexportable;
			info->extractable = false;
			status = qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Return provider-level operations available from this TPM KSP.
 * \param context Live initialized provider context.
 * \param capabilities Caller-initialized versioned output.
 * \return Success or invalid parameter; hardware attestation is not claimed.
 */
static qsc_hw_status hwncrypt_capabilities(void* context, qsc_hw_capabilities* capabilities)
{
	qsc_hw_ncrypt_context* state;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;
	state = (qsc_hw_ncrypt_context*)context;

	if (state != NULL && state->native_state != NULL && capabilities != NULL)
	{
		capabilities->flags = qsc_hw_capability_key_open | qsc_hw_capability_generate | qsc_hw_capability_sign | qsc_hw_capability_public_key;
		capabilities->max_sessions = 0U;
		capabilities->thread_safe = false;
		capabilities->requires_serialization = true;
		capabilities->operation_can_block = true;
		capabilities->supports_cancel = false;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Release a transient handle but never erase a persisted TPM identity.
 * \param context Unused backend context.
 * \param key Owned transient native key handle.
 */
static void hwncrypt_key_release(void* context, void* key)
{
	hwncrypt_key* native;

	(void)context;
	native = (hwncrypt_key*)key;

	if (native != NULL)
	{
		if (native->handle != 0U)
		{
			(void)NCryptFreeObject(native->handle);
		}

		qsc_memutils_clear(native, sizeof(hwncrypt_key));
		qsc_memutils_alloc_free(native);
	}
}

/** \brief Verify opened native handle and transfer ownership to adapter key reference.
 * \param key Native key handle to adopt, or leave caller-owned on failure.
 * \param result Output backend key handle.
 * \param info Output verified metadata.
 * \return Success or typed policy/internal error.
 */
static qsc_hw_status hwncrypt_adopt(NCRYPT_KEY_HANDLE key, void** result, qsc_hw_key_info* info)
{
	hwncrypt_key* native;
	qsc_hw_status status;

	status = hwncrypt_key_info(key, info);

	if (status == qsc_hw_status_success)
	{
		native = (hwncrypt_key*)qsc_memutils_malloc(sizeof(hwncrypt_key));

		if (native == NULL)
		{
			status = qsc_hw_status_memory;
		}
		else
		{
			native->handle = key;
			native->algorithm = info->algorithm;
			*result = native;
		}
	}

	return status;
}

/** \brief Open a persistent TPM signing key by its configured exact UTF-8 locator.
 * \param context Live initialized backend.
 * \param locator Exact configured persistent key name.
 * \param key Output transient key on success.
 * \param info Verified public key-policy metadata.
 * \return Typed status, without invoking software key storage.
 */
static qsc_hw_status hwncrypt_open_key(void* context, const char* locator, void** key, qsc_hw_key_info* info)
{
	qsc_hw_ncrypt_context* state;
	hwncrypt_native* native;
	NCRYPT_KEY_HANDLE handle;
	SECURITY_STATUS result;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;
	state = (qsc_hw_ncrypt_context*)context;
	handle = 0U;

	if (state != NULL && state->native_state != NULL && locator != NULL && key != NULL && info != NULL)
	{
		*key = NULL;
		native = (hwncrypt_native*)state->native_state;
		status = qsc_hw_status_policy;

		if (qsc_stringutils_string_size(locator) == qsc_stringutils_string_size(native->locator) &&
			qsc_stringutils_string_comparison(locator, native->locator) == 0)
		{
			result = NCryptOpenKey(native->provider, &handle, native->name, 0U, native->scope | NCRYPT_SILENT_FLAG);
			status = hwncrypt_status(result);

			if (status == qsc_hw_status_success)
			{
				status = hwncrypt_adopt(handle, key, info);
			}
		}
	}

	if (status != qsc_hw_status_success && handle != 0U)
	{
		(void)NCryptFreeObject(handle);
	}

	return status;
}

/** \brief Generate a non-exportable persisted TPM signing identity without overwriting one.
 * \param context Live initialized backend with a configured key name and scope.
 * \param policy Caller key policy; hardware signing only.
 * \param key Output transient handle on success.
 * \param info Verified metadata.
 * \return Typed result; failed new persistent key is rolled back before return.
 */
static qsc_hw_status hwncrypt_generate_key(void* context, const qsc_hw_key_policy* policy, void** key, qsc_hw_key_info* info)
{
	qsc_hw_ncrypt_context* state;
	hwncrypt_native* native;
	NCRYPT_KEY_HANDLE handle;
	LPCWSTR algorithm;
	DWORD exportflags;
	DWORD usage;
	SECURITY_STATUS result;
	qsc_hw_status status;
	size_t digestlen;
	size_t keylen;
	bool created;

	status = qsc_hw_status_invalid_parameter;
	state = (qsc_hw_ncrypt_context*)context;
	handle = 0U;
	created = false;

	if (state != NULL && state->native_state != NULL && policy != NULL && key != NULL && info != NULL)
	{
		*key = NULL;
		status = qsc_hw_status_unsupported;
		native = (hwncrypt_native*)state->native_state;

		if (hwncrypt_algorithm(policy->algorithm, &algorithm, &digestlen, &keylen) == true &&
			(policy->usage & qsc_hw_usage_sign) != 0U && (policy->usage & ~((uint32_t)qsc_hw_usage_sign)) == 0U &&
			policy->allow_export == false && NCryptIsAlgSupported(native->provider, algorithm, 0U) == ERROR_SUCCESS)
		{
			result = NCryptCreatePersistedKey(native->provider, &handle, algorithm, native->name, 0U, native->scope);
			status = hwncrypt_status(result);

			if (status == qsc_hw_status_success)
			{
				created = true;
				exportflags = 0U;
				usage = NCRYPT_ALLOW_SIGNING_FLAG;
				result = NCryptSetProperty(handle, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&exportflags, (DWORD)sizeof(exportflags), 0U);

				if (result == ERROR_SUCCESS)
				{
					result = NCryptSetProperty(handle, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, (DWORD)sizeof(usage), 0U);
				}
				if (result == ERROR_SUCCESS)
				{
					result = NCryptFinalizeKey(handle, NCRYPT_SILENT_FLAG);
				}

				status = hwncrypt_status(result);

				if (status == qsc_hw_status_success)
				{
					status = hwncrypt_adopt(handle, key, info);
				}
			}
		}
	}

	if (status != qsc_hw_status_success && handle != 0U)
	{
		if (created == true)
		{
			(void)NCryptDeleteKey(handle, 0U);
		}
		else
		{
			(void)NCryptFreeObject(handle);
		}
	}

	return status;
}

/** \brief Produce a raw ECDSA signature over a precomputed digest in a protected key.
 * \param context Live backend context, not modified.
 * \param key Live transient protected key.
 * \param algorithm Exact signature algorithm.
 * \param message Precomputed digest of required hash length.
 * \param msglen Digest length in bytes.
 * \param signature Output signature in raw r||s format or NULL for size query.
 * \param signaturelen In/out capacity and result size.
 * \return Typed status; no implicit hashing or software fallback.
 */
static qsc_hw_status hwncrypt_sign(void* context, void* key, qsc_hw_algorithm algorithm, const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	hwncrypt_key* native;
	LPCWSTR name;
	DWORD written;
	qsc_hw_status status;
	size_t digestlen;
	size_t keylen;
	size_t capacity;
	SECURITY_STATUS result;

	status = qsc_hw_status_invalid_parameter;
	native = (hwncrypt_key*)key;
	written = 0U;

	if (context != NULL && native != NULL && signaturelen != NULL && message != NULL &&
		native->algorithm == algorithm && hwncrypt_algorithm(algorithm, &name, &digestlen, &keylen) == true && msglen == digestlen)
	{
		capacity = *signaturelen;
		status = qsc_hw_status_buffer_too_small;
		*signaturelen = keylen * 2U;

		if (signature == NULL)
		{
			status = qsc_hw_status_success;
		}
		else if (capacity >= keylen * 2U && capacity <= UINT32_MAX)
		{
			result = NCryptSignHash(native->handle, NULL, (PBYTE)message, (DWORD)msglen, signature,
				(DWORD)capacity, &written, NCRYPT_SILENT_FLAG);
			status = hwncrypt_status(result);

			if (status == qsc_hw_status_success && written != keylen * 2U)
			{
				status = qsc_hw_status_internal;
			}

			if (status != qsc_hw_status_success)
			{
				qsc_memutils_secure_erase(signature, capacity);
			}
			else
			{
				*signaturelen = written;
			}
		}
	}

	return status;
}

/** \brief Export only validated uncompressed public EC point bytes.
 * \param context Live backend context.
 * \param key Opened TPM key; private key material is never exported.
 * \param output SEC1 0x04||X||Y buffer or NULL for required length query.
 * \param outputlen In/out capacity/required length.
 * \return Typed status, rejects malformed and wrong-curve CNG blobs.
 */
static qsc_hw_status hwncrypt_public_key(void* context, void* key, uint8_t* output, size_t* outputlen)
{
	uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + (2U * 66U)];
	BCRYPT_ECCKEY_BLOB blobhead;
	hwncrypt_key* native;
	LPCWSTR algorithm;
	DWORD written;
	qsc_hw_status status;
	size_t digestlen;
	size_t keylen;
	size_t required;
	size_t capacity;
	ULONG magic;
	SECURITY_STATUS result;

	status = qsc_hw_status_invalid_parameter;
	native = (hwncrypt_key*)key;
	written = 0U;

	if (context != NULL && native != NULL && outputlen != NULL &&
		hwncrypt_algorithm(native->algorithm, &algorithm, &digestlen, &keylen) == true)
	{
		capacity = *outputlen;
		required = (keylen * 2U) + 1U;
		*outputlen = required;
		status = qsc_hw_status_buffer_too_small;

		if (output == NULL)
		{
			status = qsc_hw_status_success;
		}
		else if (capacity >= required)
		{
			result = NCryptExportKey(native->handle, 0U, BCRYPT_ECCPUBLIC_BLOB, NULL, blob,
				(DWORD)sizeof(blob), &written, 0U);
			status = hwncrypt_status(result);

			if (status == qsc_hw_status_success)
			{
				qsc_memutils_copy(&blobhead, blob, sizeof(blobhead));
				magic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;

				if (native->algorithm == qsc_hw_algorithm_ecdsa_p384)
				{
					magic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
				}
				else if (native->algorithm == qsc_hw_algorithm_ecdsa_p521)
				{
					magic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
				}

				if (blobhead.dwMagic == magic && blobhead.cbKey == keylen && written == sizeof(blobhead) + (keylen * 2U))
				{
					output[0U] = 0x04U;
					qsc_memutils_copy(output + 1U, blob + sizeof(blobhead), keylen * 2U);
				}
				else
				{
					status = qsc_hw_status_internal;
				}
			}

			if (status != qsc_hw_status_success)
			{
				qsc_memutils_clear(output, capacity);
			}
		}
	}

	qsc_memutils_clear(blob, sizeof(blob));
	return status;
}

/** \brief Signal wrapper closure by freeing the native provider handle.
 * \param context Caller-owned qsc_hw_ncrypt_context to dispose.
 */
static void hwncrypt_on_close(void* context)
{
	qsc_hw_ncrypt_dispose((qsc_hw_ncrypt_context*)context);
}

#endif /* _WIN32 */

qsc_hw_status qsc_hw_ncrypt_initialize(qsc_hw_ncrypt_context* context, const char* name, bool machine_key)
{
	qsc_hw_status status;
#if defined(_WIN32)
	hwncrypt_native* native;
	SECURITY_STATUS result;
	DWORD implementation;
	DWORD written;
	int converted;
	size_t length;
#endif

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && name != NULL && context->native_state == NULL && name[0U] != '\0')
	{
#if defined(_WIN32)
		length = qsc_stringutils_string_size(name);
		status = qsc_hw_status_policy;

		if (length > 0U && length <= HWNCRYPT_MAX_NAME)
		{
			native = (hwncrypt_native*)qsc_memutils_calloc(1U, sizeof(hwncrypt_native));
			status = qsc_hw_status_memory;

			if (native != NULL)
			{
				converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1, native->name, (int)(HWNCRYPT_MAX_NAME + 1U));
				status = qsc_hw_status_invalid_parameter;

				if (converted > 1)
				{
					qsc_memutils_copy(native->locator, name, length + 1U);
					native->scope = (machine_key == true) ? NCRYPT_MACHINE_KEY_FLAG : 0U;
					result = NCryptOpenStorageProvider(&native->provider, MS_PLATFORM_CRYPTO_PROVIDER, 0U);
					status = hwncrypt_status(result);

					if (status == qsc_hw_status_success)
					{
						implementation = 0U;
						written = 0U;
						result = NCryptGetProperty(native->provider, NCRYPT_IMPL_TYPE_PROPERTY,
							(PBYTE)&implementation, (DWORD)sizeof(implementation), &written, 0U);

						if (result != ERROR_SUCCESS || written != sizeof(implementation) ||
							(implementation & NCRYPT_IMPL_HARDWARE_FLAG) == 0U ||
							(implementation & NCRYPT_IMPL_SOFTWARE_FLAG) != 0U)
						{
							status = qsc_hw_status_unsupported;
						}
					}
				}

				if (status == qsc_hw_status_success)
				{
					context->native_state = native;
				}
				else
				{
					if (native->provider != 0U)
					{
						(void)NCryptFreeObject(native->provider);
					}

					qsc_memutils_clear(native, sizeof(hwncrypt_native));
					qsc_memutils_alloc_free(native);
				}
			}
		}
#else
		(void)machine_key;
		status = qsc_hw_status_unsupported;
#endif
	}

	if (context != NULL && name != NULL && name[0U] == '\0')
	{
		status = qsc_hw_status_policy;
	}

	return status;
}

qsc_hw_status qsc_hw_ncrypt_get_operations(qsc_hw_provider_ops* operations)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (operations != NULL)
	{
		qsc_memutils_clear(operations, sizeof(qsc_hw_provider_ops));
#if defined(_WIN32)
		operations->size = sizeof(qsc_hw_provider_ops);
		operations->version = QSC_HW_ABI_VERSION;
		operations->get_capabilities = hwncrypt_capabilities;
		operations->release_key = hwncrypt_key_release;
		operations->dispose = hwncrypt_on_close;
		operations->open_key = hwncrypt_open_key;
		operations->generate_key = hwncrypt_generate_key;
		operations->sign = hwncrypt_sign;
		operations->public_key = hwncrypt_public_key;
		status = qsc_hw_status_success;
#else
		status = qsc_hw_status_unsupported;
#endif
	}

	return status;
}

bool qsc_hw_ncrypt_algorithm_available(const qsc_hw_ncrypt_context* context, qsc_hw_algorithm algorithm)
{
	bool available;
#if defined(_WIN32)
	hwncrypt_native* native;
	LPCWSTR name;
	size_t digestlen;
	size_t keylen;
#endif

	available = false;

#if defined(_WIN32)
	if (context != NULL && context->native_state != NULL)
	{
		native = (hwncrypt_native*)context->native_state;

		if (hwncrypt_algorithm(algorithm, &name, &digestlen, &keylen) == true)
		{
			available = (NCryptIsAlgSupported(native->provider, name, 0U) == ERROR_SUCCESS);
		}
	}
#else
	(void)context;
	(void)algorithm;
#endif

	return available;
}

void qsc_hw_ncrypt_dispose(qsc_hw_ncrypt_context* context)
{
	if (context != NULL && context->native_state != NULL)
	{
#if defined(_WIN32)
		hwncrypt_native* native;

		native = (hwncrypt_native*)context->native_state;

		if (native->provider != 0U)
		{
			(void)NCryptFreeObject(native->provider);
		}

		qsc_memutils_clear(native, sizeof(hwncrypt_native));
		qsc_memutils_alloc_free(native);
#endif
		context->native_state = NULL;
	}
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_NCRYPT_ENABLED */
