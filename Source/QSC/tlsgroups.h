#ifndef QSC_TLS_GROUPS_H
#define QSC_TLS_GROUPS_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsgroups.h
 * \brief Defines the TLS named-group registry and key-share helper interface.
 *
 * \details
 * This header exposes the passive registry and key-exchange helpers used by the
 * TLS implementation to query named-group properties, validate share lengths,
 * generate key shares, and derive shared secrets. The module owns group
 * metadata and key-exchange execution only. It does not own handshake flow,
 * extension sequencing, or transcript state.
 */

typedef struct qsc_tls_group_descriptor
{
	qsc_tls_named_group group;          /*!< The TLS wire identifier of the named group. */
	const char* name;                   /*!< The stable TLS group name. */
	const char* opensslname;            /*!< The OpenSSL-style display name. */
	size_t classicalpublickeysize;      /*!< The classical public-key share size in bytes. */
	size_t classicalprivatekeysize;     /*!< The classical private-key size in bytes. */
	size_t kempublickeysize;            /*!< The KEM public-key share size in bytes. */
	size_t kemprivatekeysize;           /*!< The KEM private-key size in bytes. */
	size_t ciphertextsize;              /*!< The KEM ciphertext size in bytes. */
	size_t sharedsecretsize;            /*!< The combined shared-secret size in bytes. */
	size_t serversharesize;             /*!< The encoded server-share size in bytes. */
	size_t serverprivatestatesize;      /*!< The deferred server private-state size in bytes. */
	bool supported;                     /*!< The registry support flag for the group. */
	bool ishybrid;                      /*!< The hybrid-group flag. */
	bool ispurekem;                     /*!< The pure-KEM group flag. */
} qsc_tls_group_descriptor;

/**
 * \brief Get the descriptor for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [const qsc_tls_group_descriptor*] The group descriptor pointer, or NULL when not found.
 */
QSC_EXPORT_API const qsc_tls_group_descriptor* qsc_tls_group_descriptor_get(qsc_tls_named_group group);

/**
 * \brief Determine whether a named group is implemented and enabled at runtime.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [bool] Returns true when the group is supported by the active build.
 */
QSC_EXPORT_API bool qsc_tls_group_is_supported(qsc_tls_named_group group);

/**
 * \brief Determine whether a named group is hybrid.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [bool] Returns true when the group combines classical and KEM material.
 */
QSC_EXPORT_API bool qsc_tls_group_is_hybrid(qsc_tls_named_group group);

/**
 * \brief Determine whether a named group is a pure KEM group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [bool] Returns true when the group is pure KEM.
 */
QSC_EXPORT_API bool qsc_tls_group_is_pure_kem(qsc_tls_named_group group);

/**
 * \brief Determine whether a group uses encapsulation semantics.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [bool] Returns true when the server share is a ciphertext or hybrid encapsulation payload.
 */
QSC_EXPORT_API bool qsc_tls_group_uses_encapsulation(qsc_tls_named_group group);

/**
 * \brief Get the encoded client public-key share size for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The total client share size in bytes, or zero on unsupported input.
 */
QSC_EXPORT_API size_t qsc_tls_group_public_key_size(qsc_tls_named_group group);

/**
 * \brief Get the private-key size for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The private-key size in bytes, or zero on unsupported input.
 */
QSC_EXPORT_API size_t qsc_tls_group_private_key_size(qsc_tls_named_group group);

/**
 * \brief Get the shared-secret size for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The shared-secret size in bytes, or zero on unsupported input.
 */
QSC_EXPORT_API size_t qsc_tls_group_shared_secret_size(qsc_tls_named_group group);

/**
 * \brief Get the ciphertext size for a KEM or hybrid named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The ciphertext size in bytes, or zero when not applicable.
 */
QSC_EXPORT_API size_t qsc_tls_group_ciphertext_size(qsc_tls_named_group group);

/**
 * \brief Get the classical public-key share size for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The classical share size in bytes, or zero when not applicable.
 */
QSC_EXPORT_API size_t qsc_tls_group_classical_public_key_size(qsc_tls_named_group group);

/**
 * \brief Get the KEM public-key share size for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The KEM public-key size in bytes, or zero when not applicable.
 */
QSC_EXPORT_API size_t qsc_tls_group_kem_public_key_size(qsc_tls_named_group group);

/**
 * \brief Get the encoded client key-share size for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The client share size in bytes, or zero on unsupported input.
 */
QSC_EXPORT_API size_t qsc_tls_group_client_share_size(qsc_tls_named_group group);

/**
 * \brief Get the encoded server share size for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [size_t] The server share size in bytes, or zero on unsupported input.
 */
QSC_EXPORT_API size_t qsc_tls_group_server_share_size(qsc_tls_named_group group);

/**
 * \brief Validate a client key-share length against the named-group contract.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param sharelen: [size_t] The encoded client share length in bytes.
 *
 * \return [bool] Returns true when the length matches the expected size exactly.
 */
QSC_EXPORT_API bool qsc_tls_group_validate_client_share_length(qsc_tls_named_group group, size_t sharelen);

/**
 * \brief Validate a server key-share length against the named-group contract.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param sharelen: [size_t] The encoded server share length in bytes.
 *
 * \return [bool] Returns true when the length matches the expected size exactly.
 */
QSC_EXPORT_API bool qsc_tls_group_validate_server_share_length(qsc_tls_named_group group, size_t sharelen);

/**
 * \brief Get the active ML-KEM parameter strength selected by the build.
 *
 * \return [uint16_t] The active ML-KEM parameter strength in bits, or zero when ML-KEM is not enabled.
 */
QSC_EXPORT_API uint16_t qsc_tls_group_active_mlkem_parameter_bits(void);

/**
 * \brief Get the stable TLS group name.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [const char*] The stable TLS group name, or "unknown" when not found.
 */
QSC_EXPORT_API const char* qsc_tls_group_name(qsc_tls_named_group group);

/**
 * \brief Get the active display name for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [const char*] The active group name string.
 */
QSC_EXPORT_API const char* qsc_tls_group_active_name(qsc_tls_named_group group);

/**
 * \brief Get the OpenSSL-style display name for a named group.
 *
 * \param group: [enum] The TLS named-group identifier.
 *
 * \return [const char*] The OpenSSL-style name, or "unknown" when not found.
 */
QSC_EXPORT_API const char* qsc_tls_group_openssl_name(qsc_tls_named_group group);

/**
 * \brief Generate a deterministic client key share from caller-supplied seed material.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param seed: [const uint8_t*] The seed input buffer.
 * \param seedlen: [size_t] The seed input length in bytes.
 * \param publickey: [uint8_t*] The output public-key share buffer.
 * \param publickeylen: [size_t] The public-key buffer length in bytes.
 * \param privatekey: [uint8_t*] The output private-key buffer.
 * \param privatekeylen: [size_t] The private-key buffer length in bytes.
 *
 * \return [qsc_tls_status] Returns the TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_group_key_share_generate(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, 
	uint8_t* publickey, size_t publickeylen, uint8_t* privatekey, size_t privatekeylen);

/**
 * \brief Generate a random client key share using the active CSP.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param publickey: [uint8_t*] The output public-key share buffer.
 * \param publickeylen: [size_t] The public-key buffer length in bytes.
 * \param privatekey: [uint8_t*] The output private-key buffer.
 * \param privatekeylen: [size_t] The private-key buffer length in bytes.
 *
 * \return [qsc_tls_status] Returns the TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_group_key_share_generate_random(qsc_tls_named_group group, uint8_t* publickey, size_t publickeylen, uint8_t* privatekey, size_t privatekeylen);

/**
 * \brief Derive a shared secret from a local private key and a peer public key.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param localprivatekey: [const uint8_t*] The local private-key buffer.
 * \param localprivatekeylen: [size_t] The local private-key length in bytes.
 * \param peerpublickey: [const uint8_t*] The peer public-key buffer.
 * \param peerpublickeylen: [size_t] The peer public-key length in bytes.
 * \param sharedsecret: [uint8_t*] The output shared-secret buffer.
 * \param sharedsecretlen: [size_t*] On input, the output capacity. On success, the number of bytes written.
 *
 * \return [qsc_tls_status] Returns the TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_group_shared_secret_derive(qsc_tls_named_group group, const uint8_t* localprivatekey, size_t localprivatekeylen, 
	const uint8_t* peerpublickey, size_t peerpublickeylen, uint8_t* sharedsecret, size_t* sharedsecretlen);

/**
 * \brief Generate a server share and the corresponding shared secret for encapsulation groups.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param seed: [const uint8_t*] The server seed input buffer.
 * \param seedlen: [size_t] The server seed length in bytes.
 * \param clientpublickey: [const uint8_t*] The encoded client share buffer.
 * \param clientpublickeylen: [size_t] The encoded client share length in bytes.
 * \param servershare: [uint8_t*] The output encoded server share buffer.
 * \param serversharelen: [size_t] The server share buffer length in bytes.
 * \param serverprivatekey: [uint8_t*] The output deferred private-state buffer.
 * \param serverprivatekeylen: [size_t] The deferred private-state buffer length in bytes.
 * \param sharedsecret: [uint8_t*] The output shared-secret buffer.
 * \param sharedsecretlen: [size_t*] On input, the output capacity. On success, the number of bytes written.
 *
 * \return [qsc_tls_status] Returns the TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_group_server_share_generate(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, 
	const uint8_t* clientpublickey, size_t clientpublickeylen, uint8_t* servershare, size_t serversharelen, uint8_t* serverprivatekey,
	size_t serverprivatekeylen, uint8_t* sharedsecret, size_t* sharedsecretlen);

/**
 * \brief Generate a random server share and the corresponding shared secret for encapsulation groups.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param clientpublickey: [const uint8_t*] The encoded client share buffer.
 * \param clientpublickeylen: [size_t] The encoded client share length in bytes.
 * \param servershare: [uint8_t*] The output encoded server share buffer.
 * \param serversharelen: [size_t] The server share buffer length in bytes.
 * \param serverprivatekey: [uint8_t*] The output deferred private-state buffer.
 * \param serverprivatekeylen: [size_t] The deferred private-state buffer length in bytes.
 * \param sharedsecret: [uint8_t*] The output shared-secret buffer.
 * \param sharedsecretlen: [size_t*] On input, the output capacity. On success, the number of bytes written.
 *
 * \return [qsc_tls_status] Returns the TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_group_server_share_generate_random(qsc_tls_named_group group, const uint8_t* clientpublickey,
	size_t clientpublickeylen, uint8_t* servershare, size_t serversharelen, uint8_t* serverprivatekey, size_t serverprivatekeylen, uint8_t* sharedsecret, size_t* sharedsecretlen);

/**
 * \brief Derive the client shared secret from a deferred server share.
 *
 * \param group: [enum] The TLS named-group identifier.
 * \param clientprivatekey: [const uint8_t*] The encoded client private-key buffer.
 * \param clientprivatekeylen: [size_t] The encoded client private-key length in bytes.
 * \param servershare: [const uint8_t*] The encoded server share buffer.
 * \param serversharelen: [size_t] The encoded server share length in bytes.
 * \param sharedsecret: [uint8_t*] The output shared-secret buffer.
 * \param sharedsecretlen: [size_t*] On input, the output capacity. On success, the number of bytes written.
 *
 * \return [qsc_tls_status] Returns the TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_group_client_shared_secret_derive(qsc_tls_named_group group, const uint8_t* clientprivatekey,
	size_t clientprivatekeylen, const uint8_t* servershare, size_t serversharelen, uint8_t* sharedsecret, size_t* sharedsecretlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
