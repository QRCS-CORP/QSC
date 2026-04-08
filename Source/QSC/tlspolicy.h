#ifndef QSC_TLS_POLICY_H
#define QSC_TLS_POLICY_H

#include "qsccommon.h"
#include "tlslimits.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlspolicy.h
 * \brief TLS algorithm and group-selection policy.
 */

/**
 * \struct qsc_tls_policy
 * \brief Describes the locally permitted TLS 1.3 groups, signature schemes, and cipher suites.
 */
typedef struct qsc_tls_policy
{
	qsc_tls_named_group permittedgroups[QSC_TLS_MAX_GROUPS];
	size_t permittedgroupcount;
	qsc_tls_signature_scheme permittedsignatures[QSC_TLS_MAX_SIGNATURE_SCHEMES];
	size_t permittedsignaturecount;
	qsc_tls_cipher_suite permittedciphersuites[QSC_TLS_MAX_CIPHER_SUITES];
	size_t permittedciphersuitecount;
	bool allowclassical;
	bool allowhybrid;
	bool allowpqkex;
	bool allowpqsignatures;
} qsc_tls_policy;

/**
 * \brief Clear a TLS policy structure and initialize all fields to disabled/empty values.
 *
 * \param policy: [struct] The policy structure to clear.
 */
QSC_EXPORT_API void qsc_tls_policy_clear(qsc_tls_policy* policy);

/**
 * \brief Initialize the default TLS policy.
 *
 * \details The default policy enables a deterministic baseline classical profile,
 * selecting a single preferred key exchange group and a single preferred signature
 * scheme based on the compiled-in primitive set. Supported baseline cipher suites are
 * added in local preference order.
 *
 * \param policy: [struct] The policy structure to initialize.
 */
QSC_EXPORT_API void qsc_tls_policy_initialize_default(qsc_tls_policy* policy);

/**
 * \brief Add a permitted key exchange group to the policy if it is supported and not already present.
 *
 * \param policy: [struct] The policy structure to update.
 * \param group: [enum] The named group to add.
 *
 * \return Returns true if the group was added or already present.
 */
QSC_EXPORT_API bool qsc_tls_policy_add_group(qsc_tls_policy* policy, qsc_tls_named_group group);

/**
 * \brief Add a permitted signature scheme to the policy if it is supported and not already present.
 *
 * \param policy: [struct] The policy structure to update.
 * \param scheme: [enum] The signature scheme to add.
 *
 * \return Returns true if the scheme was added or already present.
 */
QSC_EXPORT_API bool qsc_tls_policy_add_signature(qsc_tls_policy* policy, qsc_tls_signature_scheme scheme);

/**
 * \brief Add a permitted cipher suite to the policy if it is supported and not already present.
 *
 * \param policy: [struct] The policy structure to update.
 * \param suite: [enum] The cipher suite to add.
 *
 * \return Returns true if the suite was added or already present.
 */
QSC_EXPORT_API bool qsc_tls_policy_add_cipher_suite(qsc_tls_policy* policy, qsc_tls_cipher_suite suite);

/**
 * \brief Determine whether a named group is permitted by the policy.
 *
 * \param policy: [const struct] The policy to query.
 * \param group: [enum] The named group to test.
 *
 * \return Returns true if the group is permitted.
 */
QSC_EXPORT_API bool qsc_tls_policy_group_allowed(const qsc_tls_policy* policy, qsc_tls_named_group group);

/**
 * \brief Determine whether a signature scheme is permitted by the policy.
 *
 * \param policy: [const struct] The policy to query.
 * \param scheme: [enum] The signature scheme to test.
 *
 * \return Returns true if the signature scheme is permitted.
 */
QSC_EXPORT_API bool qsc_tls_policy_signature_allowed(const qsc_tls_policy* policy, qsc_tls_signature_scheme scheme);

/**
 * \brief Determine whether a cipher suite is permitted by the policy.
 *
 * \param policy: [const struct] The policy to query.
 * \param suite: [enum] The cipher suite to test.
 *
 * \return Returns true if the cipher suite is permitted.
 */
QSC_EXPORT_API bool qsc_tls_policy_cipher_suite_allowed(const qsc_tls_policy* policy, qsc_tls_cipher_suite suite);

/**
 * \brief Validate a selected peer key exchange group against the local policy and a peer-advertised list.
 *
 * \param policy: [const struct] The local policy.
 * \param groups: [const enum*] The peer-advertised group list.
 * \param groupcount: [size_t] The number of peer-advertised groups.
 * \param selected: [enum] The selected group to validate.
 *
 * \return Returns true if the selection is valid.
 */
QSC_EXPORT_API bool qsc_tls_policy_validate_peer_group_selection(const qsc_tls_policy* policy, const qsc_tls_named_group* groups, size_t groupcount, qsc_tls_named_group selected);

/**
 * \brief Validate a selected peer signature scheme against the local policy and a peer-advertised list.
 *
 * \param policy: [const struct] The local policy.
 * \param schemes: [const enum*] The peer-advertised signature scheme list.
 * \param schemecount: [size_t] The number of peer-advertised signature schemes.
 * \param selected: [enum] The selected signature scheme to validate.
 *
 * \return Returns true if the selection is valid.
 */
QSC_EXPORT_API bool qsc_tls_policy_validate_peer_signature_selection(const qsc_tls_policy* policy, const qsc_tls_signature_scheme* schemes, size_t schemecount, qsc_tls_signature_scheme selected);

QSC_CPLUSPLUS_ENABLED_END

#endif
