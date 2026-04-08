#include "tlspolicy.h"
#include "tlsgroups.h"
#include "tlssigalgs.h"
#include "memutils.h"

static bool tls_cipher_suite_is_supported(qsc_tls_cipher_suite suite)
{
	bool res;

	res = false;

	switch (suite)
	{
	case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
	case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
	case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
		res = true;
		break;
	default:
		break;
	}

	return res;
}

static bool tls_policy_contains_cipher_suite(const qsc_tls_policy* policy, qsc_tls_cipher_suite suite)
{
	bool res;
	size_t i;

	res = false;
	i = 0U;

	if (policy != NULL)
	{
		while (i < policy->permittedciphersuitecount)
		{
			if (policy->permittedciphersuites[i] == suite)
			{
				res = true;
				break;
			}

			++i;
		}
	}

	return res;
}

static bool tls_policy_contains_group(const qsc_tls_policy* policy, qsc_tls_named_group group)
{
	bool res;
	size_t i;

	res = false;
	i = 0U;

	if (policy != NULL)
	{
		while (i < policy->permittedgroupcount)
		{
			if (policy->permittedgroups[i] == group)
			{
				res = true;
				break;
			}

			++i;
		}
	}

	return res;
}

static bool tls_policy_contains_signature(const qsc_tls_policy* policy, qsc_tls_signature_scheme scheme)
{
	bool res;
	size_t i;

	res = false;
	i = 0U;

	if (policy != NULL)
	{
		while (i < policy->permittedsignaturecount)
		{
			if (policy->permittedsignatures[i] == scheme)
			{
				res = true;
				break;
			}

			++i;
		}
	}

	return res;
}

void qsc_tls_policy_clear(qsc_tls_policy* policy)
{
	QSC_ASSERT(policy != NULL);

	if (policy != NULL)
	{
		qsc_memutils_clear((uint8_t*)policy, sizeof(qsc_tls_policy));
	}
}

bool qsc_tls_policy_add_cipher_suite(qsc_tls_policy* policy, qsc_tls_cipher_suite suite)
{
	QSC_ASSERT(policy != NULL);

	bool res;

	res = false;

	if (policy != NULL && tls_cipher_suite_is_supported(suite) == true)
	{
		if (tls_policy_contains_cipher_suite(policy, suite) == true)
		{
			res = true;
		}
		else if (policy->permittedciphersuitecount < QSC_TLS_MAX_CIPHER_SUITES)
		{
			policy->permittedciphersuites[policy->permittedciphersuitecount] = suite;
			++policy->permittedciphersuitecount;
			res = true;
		}
	}

	return res;
}

bool qsc_tls_policy_add_group(qsc_tls_policy* policy, qsc_tls_named_group group)
{
	QSC_ASSERT(policy != NULL);

	bool res;

	res = false;

	if (policy != NULL && qsc_tls_group_is_supported(group) == true)
	{
		if (tls_policy_contains_group(policy, group) == true)
		{
			res = true;
		}
		else if (policy->permittedgroupcount < QSC_TLS_MAX_GROUPS)
		{
			policy->permittedgroups[policy->permittedgroupcount] = group;
			++policy->permittedgroupcount;
			res = true;
		}
	}

	return res;
}

bool qsc_tls_policy_add_signature(qsc_tls_policy* policy, qsc_tls_signature_scheme scheme)
{
	QSC_ASSERT(policy != NULL);

	bool res;

	res = false;

	if (policy != NULL && qsc_tls_signature_scheme_is_supported(scheme) == true)
	{
		if (tls_policy_contains_signature(policy, scheme) == true)
		{
			res = true;
		}
		else if (policy->permittedsignaturecount < QSC_TLS_MAX_SIGNATURE_SCHEMES)
		{
			policy->permittedsignatures[policy->permittedsignaturecount] = scheme;
			++policy->permittedsignaturecount;
			res = true;
		}
	}

	return res;
}

void qsc_tls_policy_initialize_default(qsc_tls_policy* policy)
{
	QSC_ASSERT(policy != NULL);

	if (policy != NULL)
	{
		qsc_tls_policy_clear(policy);
		policy->allowclassical = true;
		policy->allowhybrid = false;
		policy->allowpqkex = true;
		policy->allowpqsignatures = false;

		(void)qsc_tls_policy_add_cipher_suite(policy, qsc_tls_cipher_suite_tls_aes_256_gcm_sha384);
		(void)qsc_tls_policy_add_cipher_suite(policy, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256);
		(void)qsc_tls_policy_add_cipher_suite(policy, qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256);

#if defined(QSC_EDDH_S1EC25519)
		(void)qsc_tls_policy_add_group(policy, qsc_tls_group_x25519);
#elif defined(QSC_ECDSA_S1P256) || defined(QSC_ECDH_S1P256)
		(void)qsc_tls_policy_add_group(policy, qsc_tls_group_secp256r1);
#elif defined(QSC_ECDSA_S3P384) || defined(QSC_ECDH_S3P384)
		(void)qsc_tls_policy_add_group(policy, qsc_tls_group_secp384r1);
#elif defined(QSC_ECDSA_S5P521) || defined(QSC_ECDH_S5P521)
		(void)qsc_tls_policy_add_group(policy, qsc_tls_group_secp521r1);
#endif

#if defined(QSC_ECDSA_S1P256)
		(void)qsc_tls_policy_add_signature(policy, qsc_tls_sig_ecdsa_secp256r1_sha256);
#elif defined(QSC_ECDSA_S3P384)
		(void)qsc_tls_policy_add_signature(policy, qsc_tls_sig_ecdsa_secp384r1_sha384);
#elif defined(QSC_EDDSA_S1EC25519)
		(void)qsc_tls_policy_add_signature(policy, qsc_tls_sig_ed25519);
#endif
	}
}

bool qsc_tls_policy_group_allowed(const qsc_tls_policy* policy, qsc_tls_named_group group)
{
	bool res;

	res = false;

	if (policy != NULL && qsc_tls_group_is_supported(group) == true)
	{
		if (qsc_tls_group_is_hybrid(group) == true)
		{
			res = policy->allowhybrid;
		}
		else if (qsc_tls_group_is_pure_kem(group) == true)
		{
			res = policy->allowpqkex;
		}
		else
		{
			res = policy->allowclassical;
		}

		if (res == true)
		{
			res = tls_policy_contains_group(policy, group);
		}
	}

	return res;
}

bool qsc_tls_policy_signature_allowed(const qsc_tls_policy* policy, qsc_tls_signature_scheme scheme)
{
	bool res;

	res = false;

	if (policy != NULL && qsc_tls_signature_scheme_is_supported(scheme) == true)
	{
		res = tls_policy_contains_signature(policy, scheme);

		if (res == true && qsc_tls_signature_scheme_is_pq(scheme) == true)
		{
			res = policy->allowpqsignatures;
		}
	}

	return res;
}

bool qsc_tls_policy_cipher_suite_allowed(const qsc_tls_policy* policy, qsc_tls_cipher_suite suite)
{
	QSC_ASSERT(policy != NULL);

	bool res;

	res = false;

	if (policy != NULL && tls_cipher_suite_is_supported(suite) == true)
	{
		res = tls_policy_contains_cipher_suite(policy, suite);
	}

	return res;
}

bool qsc_tls_policy_validate_peer_group_selection(const qsc_tls_policy* policy, const qsc_tls_named_group* groups, size_t groupcount, qsc_tls_named_group selected)
{
	QSC_ASSERT(groups != NULL);
	QSC_ASSERT(policy != NULL);

	bool res;
	size_t i;

	res = false;
	i = 0U;

	if (policy != NULL && groups != NULL && groupcount != 0U && qsc_tls_policy_group_allowed(policy, selected) == true)
	{
		while (i < groupcount)
		{
			if (groups[i] == selected)
			{
				res = true;
				break;
			}

			++i;
		}
	}

	return res;
}

bool qsc_tls_policy_validate_peer_signature_selection(const qsc_tls_policy* policy, const qsc_tls_signature_scheme* schemes, size_t schemecount, qsc_tls_signature_scheme selected)
{
	QSC_ASSERT(policy != NULL);
	QSC_ASSERT(schemecount != 0U);

	bool res;
	size_t i;

	res = false;
	i = 0U;

	if (policy != NULL && schemes != NULL && schemecount != 0U && qsc_tls_policy_signature_allowed(policy, selected) == true)
	{
		while (i < schemecount)
		{
			if (schemes[i] == selected)
			{
				res = true;
				break;
			}

			++i;
		}
	}

	return res;
}
