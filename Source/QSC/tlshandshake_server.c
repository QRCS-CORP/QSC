#include "tlshandshake.h"
#include "csp.h"
#include "tlssigalgs.h"

#define QSC_TLS_HELLO_RANDOM_SIZE 32U

static qsc_tls_hash_algorithm tls_handshake_hash_from_suite(qsc_tls_cipher_suite suite)
{
	qsc_tls_hash_algorithm hash;

	hash = qsc_tls_hash_sha256;

	switch (suite)
	{
	case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
		hash = qsc_tls_hash_sha384;
		break;
	case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
	case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
	default:
		hash = qsc_tls_hash_sha256;
		break;
	}

	return hash;
}

static bool tls_server_client_offered_cipher_suite(const uint8_t* cipherspan, size_t cipherspanlen, qsc_tls_cipher_suite suite)
{
	bool res;
	size_t i;
	uint16_t value;

	res = false;
	i = 0U;
	value = 0U;

	if (cipherspan != NULL && cipherspanlen >= sizeof(uint16_t) && (cipherspanlen & 1U) == 0U)
	{
		while (i < cipherspanlen)
		{
			value = (uint16_t)(((uint16_t)cipherspan[i] << 8) | cipherspan[i + 1U]);

			if ((qsc_tls_cipher_suite)value == suite)
			{
				res = true;
				break;
			}

			i += sizeof(uint16_t);
		}
	}

	return res;
}

static qsc_tls_status tls_select_client_cipher_suite(const qsc_tls_connection_state* state, const uint8_t* cipherspan, size_t cipherspanlen, qsc_tls_cipher_suite* suite)
{
	qsc_tls_status status;
	size_t i;

	status = qsc_tls_status_not_supported;
	i = 0U;

	if (state == NULL || cipherspan == NULL || suite == NULL || cipherspanlen < sizeof(uint16_t) || (cipherspanlen & 1U) != 0U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (qsc_tls_policy_cipher_suite_allowed(&state->policy, state->params.ciphersuite) == true && tls_server_client_offered_cipher_suite(cipherspan, cipherspanlen, state->params.ciphersuite) == true)
	{
		*suite = state->params.ciphersuite;
		status = qsc_tls_status_success;
	}
	else
	{
		while (i < state->policy.permittedciphersuitecount && status != qsc_tls_status_success)
		{
			if (qsc_tls_policy_cipher_suite_allowed(&state->policy, state->policy.permittedciphersuites[i]) == true && tls_server_client_offered_cipher_suite(cipherspan, cipherspanlen, state->policy.permittedciphersuites[i]) == true)
			{
				*suite = state->policy.permittedciphersuites[i];
				status = qsc_tls_status_success;
			}

			++i;
		}
	}

	return status;
}

static bool tls_clienthello_contains_group(const qsc_tls_named_group* groups, size_t groupcount, qsc_tls_named_group group)
{
	bool res;
	size_t i;

	res = false;

	for (i = 0U; i < groupcount; ++i)
	{
		if (groups[i] == group)
		{
			res = true;
			break;
		}
	}

	return res;
}

static bool tls_handshake_buffer_equals(const uint8_t* left, size_t leftlen, const uint8_t* right, size_t rightlen)
{
	bool res;

	res = false;

	if (left != NULL && right != NULL && leftlen == rightlen)
	{
		res = qsc_memutils_are_equal(left, right, leftlen);
	}

	return res;
}

static qsc_tls_status tls_server_share_seed(qsc_tls_named_group group, uint8_t* seed, size_t seedlen)
{
	qsc_tls_status status;

	((void)group);
	status = qsc_tls_status_success;

	if (seed == NULL || seedlen == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_csp_generate(seed, seedlen) == false)
	{
		status = qsc_tls_status_invalid_state;
	}

	return status;
}

static bool tls_server_ticket_matches(const qsc_tls_connection_state* state, const uint8_t* identity, size_t identitylen)
{
	bool res;

	res = false;

	if (state != NULL && identity != NULL && qsc_tls_connection_state_is_resumption_enabled(state) == true)
	{
		res = (state->resumptionticket.ticketlen == identitylen && qsc_memutils_are_equal(state->resumptionticket.ticket, identity, identitylen));
	}

	return res;
}

static qsc_tls_status tls_server_mix_resumption_secret(qsc_tls_connection_state* state)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->resumedhandshake == true)
	{
		status = qsc_tls_status_not_supported;
	}

	return status;
}

static qsc_tls_status tls_handshake_fill_hello_random(uint8_t* output, size_t outlen, bool isclient)
{
	qsc_tls_status status;

	((void)isclient);
	status = qsc_tls_status_success;

	if (output == NULL || outlen < QSC_TLS_HELLO_RANDOM_SIZE)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_csp_generate(output, QSC_TLS_HELLO_RANDOM_SIZE) == false)
	{
		status = qsc_tls_status_invalid_state;
	}

	return status;
}

static qsc_tls_status tls_extensions_encode_supported_versions_server(uint8_t* output, size_t outlen, size_t* extlen)
{
	qsc_tls_status status;
	size_t offset;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)qsc_tls_extension_supported_versions);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, 2U);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, QSC_TLS_PROTOCOL_VERSION_13);
		}

		*extlen = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

static qsc_tls_status tls_extensions_encode_key_share_server(qsc_tls_named_group group, const uint8_t* share, size_t sharelen, uint8_t* output, size_t outlen, size_t* extlen)
{
	qsc_tls_status status;
	size_t offset;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL || share == NULL || sharelen == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)qsc_tls_extension_key_share);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)(QSC_TLS_KEYSHARE_ENTRY_HEADER_SIZE + sharelen));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)group);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_vector16(output, outlen, &offset, share, sharelen);
		}

		*extlen = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

static void tls_server_hello_retry_request_random(uint8_t* output)
{
	static const uint8_t hrrrandom[QSC_TLS_HELLO_RANDOM_SIZE] =
	{
		0xCFU, 0x21U, 0xADU, 0x74U, 0xE5U, 0x9AU, 0x61U, 0x11U,
		0xBEU, 0x1DU, 0x8CU, 0x02U, 0x1EU, 0x65U, 0xB8U, 0x91U,
		0xC2U, 0xA2U, 0x11U, 0x16U, 0x7AU, 0xBBU, 0x8CU, 0x5EU,
		0x07U, 0x9EU, 0x09U, 0xE2U, 0xC8U, 0xA8U, 0x33U, 0x9CU
	};

	qsc_memutils_copy(output, hrrrandom, sizeof(hrrrandom));
}

static qsc_tls_named_group tls_server_select_preferred_group(const qsc_tls_connection_state* state)
{
	qsc_tls_named_group group;
	size_t i;

	group = qsc_tls_group_none;
	i = 0U;

	while (i < state->offeredgroupcount && group == qsc_tls_group_none)
	{
		if (qsc_tls_policy_group_allowed(&state->policy, state->offeredgroups[i]) == true && tls_clienthello_contains_group(state->peercapabilities.groups, state->peercapabilities.groupcount, state->offeredgroups[i]) == true)
		{
			group = state->offeredgroups[i];
		}

		++i;
	}

	return group;
}

static qsc_tls_status tls_extensions_parse_client_key_share(const uint8_t* input, size_t inlen, qsc_tls_named_group* group, uint8_t* share, size_t maxsharelen, size_t* sharelen)
{
	const uint8_t* span;
	size_t offset;
	size_t spanlen;
	uint16_t listlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	listlen = 0U;
	span = NULL;
	spanlen = 0U;

	if (input == NULL || group == NULL || share == NULL || sharelen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_codec_read_u16(input, inlen, &offset, &listlen);

		if (status == qsc_tls_status_success)
		{
			if ((size_t)listlen != (inlen - offset))
			{
				status = qsc_tls_status_invalid_length;
			}
		}

		if (status == qsc_tls_status_success)
		{
			{
				uint16_t groupid;
				groupid = 0U;
				status = qsc_tls_codec_read_u16(input, inlen, &offset, &groupid);

				if (status == qsc_tls_status_success)
				{
					*group = (qsc_tls_named_group)groupid;
				}
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &offset, &span, &spanlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (qsc_tls_group_is_supported(*group) == false)
			{
				status = qsc_tls_status_not_supported;
			}
			else if (qsc_tls_group_validate_client_share_length(*group, spanlen) == false)
			{
				status = qsc_tls_status_invalid_length;
			}
			else if (spanlen > maxsharelen)
			{
				status = qsc_tls_status_buffer_too_small;
			}
			else
			{
				qsc_memutils_copy(share, span, spanlen);
				*sharelen = spanlen;
			}
		}
	}

	return status;
}

static qsc_tls_status tls_server_parse_client_hello(qsc_tls_connection_state* state, const uint8_t* input, size_t inlen)
{
	qsc_tls_named_group groups[QSC_TLS_MAX_GROUPS] = { 0 };
	qsc_tls_signature_scheme sigs[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0 };
	qsc_tls_signature_scheme certsigs[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0 };
	uint8_t parsedpeershare[QSC_TLS_KEY_SHARE_MAX_SIZE] = { 0U };
	uint8_t random[QSC_TLS_HELLO_RANDOM_SIZE] = { 0U };
	const uint8_t* alpnprotocol;
	const uint8_t* cipherspan;
	const uint8_t* compspan;
	const uint8_t* extspan;
	const uint8_t* pskidentity;
	const uint8_t* pskbinder;
	const uint8_t* servername;
	size_t alpnprotocollen;
	size_t servernamelen;
	size_t cipherspanlen;
	size_t compspanlen;
	size_t extoff;
	size_t extslen;
	size_t groupcount;
	size_t off;
	size_t parsedpeersharelen;
	size_t pskidentitylen;
	size_t pskbinderlen;
	size_t pskbinderoffset;
	size_t sigcount;
	uint32_t bodylen;
	uint32_t u32age;
	uint16_t exttype;
	uint16_t extbodylen;
	uint16_t u16v;
	uint16_t version;
	uint8_t hstype;
	uint8_t sidlen;
	qsc_tls_cipher_suite parsedsuite;
	qsc_tls_hash_algorithm parsedhash;
	qsc_tls_named_group parsedgroup;
	bool seenversion;
	bool seenkeyshare;
	bool seengroups;
	bool seensigs;
	bool seencertsigs;
	bool seenpskmodes;
	bool seenpsk;
	bool permitpskdhe;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	off = 0U;
	hstype = 0U;
	bodylen = 0U;
	u16v = 0U;
	sidlen = 0U;
	cipherspan = NULL;
	cipherspanlen = 0U;
	compspan = NULL;
	compspanlen = 0U;
	extspan = NULL;
	extslen = 0U;
	exttype = 0U;
	extbodylen = 0U;
	seenversion = false;
	seenkeyshare = false;
	seengroups = false;
	seensigs = false;
	seencertsigs = false;
	seenpskmodes = false;
	seenpsk = false;
	permitpskdhe = false;
	pskidentity = NULL;
	pskbinder = NULL;
	servername = NULL;
	alpnprotocol = NULL;
	pskidentitylen = 0U;
	pskbinderlen = 0U;
	pskbinderoffset = 0U;
	servernamelen = 0U;
	alpnprotocollen = 0U;
	extoff = 0U;
	version = 0U;
	u32age = 0U;
	parsedsuite = qsc_tls_cipher_suite_none;
	parsedhash = qsc_tls_hash_sha256;
	parsedgroup = qsc_tls_group_none;
	parsedpeersharelen = 0U;
	groupcount = 0U;
	sigcount = 0U;
	state->servernameack = false;
	state->peeralpnsize = 0U;
	qsc_memutils_clear(state->peeralpn, sizeof(state->peeralpn));

	if (state == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_codec_read_u8(input, inlen, &off, &hstype);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u24(input, inlen, &off, &bodylen);
		}

		if (status == qsc_tls_status_success)
		{
			if (hstype != (uint8_t)qsc_tls_handshake_type_client_hello || (inlen - off) != (size_t)bodylen)
			{
				status = qsc_tls_status_invalid_message;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &off, &u16v);

			if (status == qsc_tls_status_success && u16v != QSC_TLS_PROTOCOL_VERSION_12)
			{
				status = qsc_tls_status_not_supported;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_bytes(input, inlen, &off, random, sizeof(random));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u8(input, inlen, &off, &sidlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (sidlen > sizeof(state->legacysessionid))
			{
				status = qsc_tls_status_invalid_length;
			}
			else if (sidlen != 0U)
			{
				status = qsc_tls_codec_read_bytes(input, inlen, &off, state->legacysessionid, sidlen);

				if (status == qsc_tls_status_success)
				{
					state->legacysessionidlen = sidlen;
				}
			}
			else
			{
				state->legacysessionidlen = 0U;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &off, &cipherspan, &cipherspanlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = tls_select_client_cipher_suite(state, cipherspan, cipherspanlen, &parsedsuite);
			if (status == qsc_tls_status_success)
			{
				parsedhash = tls_handshake_hash_from_suite(parsedsuite);
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector8_span(input, inlen, &off, &compspan, &compspanlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (compspanlen != 1U || compspan[0U] != 0U)
			{
				status = qsc_tls_status_invalid_message;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &off, &extspan, &extslen);
		}

		while (status == qsc_tls_status_success && extoff < extslen)
		{
			status = qsc_tls_codec_read_u16(extspan, extslen, &extoff, &exttype);

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_read_u16(extspan, extslen, &extoff, &extbodylen);
			}

			if (status == qsc_tls_status_success)
			{
				if ((size_t)extbodylen > (extslen - extoff))
				{
					status = qsc_tls_status_invalid_length;
				}
			}

			if (status == qsc_tls_status_success)
			{
				if (exttype == (uint16_t)qsc_tls_extension_supported_versions)
				{
					if (seenversion == true || extbodylen != 3U)
					{
						status = qsc_tls_status_invalid_message;
					}
					else
					{
						uint8_t versionslen;
						versionslen = 0U;
						status = qsc_tls_codec_read_u8(extspan, extslen, &extoff, &versionslen);

						if (status == qsc_tls_status_success && versionslen != 2U)
						{
							status = qsc_tls_status_invalid_length;
						}

						if (status == qsc_tls_status_success)
						{
							status = qsc_tls_codec_read_u16(extspan, extslen, &extoff, &version);
						}

						if (status == qsc_tls_status_success && version != QSC_TLS_PROTOCOL_VERSION_13)
						{
							status = qsc_tls_status_not_supported;
						}

						seenversion = (status == qsc_tls_status_success);
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_supported_groups)
				{
					if (seengroups == true)
					{
						status = qsc_tls_status_invalid_message;
					}
					else
					{
						status = qsc_tls_extensions_decode_supported_groups(extspan + extoff - 4U, (size_t)extbodylen + 4U, groups, QSC_TLS_MAX_GROUPS, &groupcount);
						extoff += (size_t)extbodylen;
						seengroups = (status == qsc_tls_status_success);
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_signature_algorithms)
				{
					if (seensigs == true)
					{
						status = qsc_tls_status_invalid_message;
					}
					else
					{
						status = qsc_tls_extensions_decode_signature_algorithms(extspan + extoff - 4U, (size_t)extbodylen + 4U, sigs, QSC_TLS_MAX_SIGNATURE_SCHEMES, &sigcount);
						extoff += (size_t)extbodylen;
						seensigs = (status == qsc_tls_status_success);
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_signature_algorithms_cert)
				{
					if (seencertsigs == true)
					{
						status = qsc_tls_status_invalid_message;
					}
					else
					{
						size_t certsigcount;
						certsigcount = 0U;
						status = qsc_tls_extensions_decode_signature_algorithms_cert(extspan + extoff - 4U, (size_t)extbodylen + 4U, certsigs, QSC_TLS_MAX_SIGNATURE_SCHEMES, &certsigcount);
						extoff += (size_t)extbodylen;
						if (status == qsc_tls_status_success)
						{
							state->peercapabilities.certsigschemecount = certsigcount;
							seencertsigs = true;
						}
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_psk_key_exchange_modes)
				{
					if (seenpskmodes == true)
					{
						status = qsc_tls_status_invalid_message;
					}
					else
					{
						status = qsc_tls_extensions_decode_psk_key_exchange_modes(extspan + extoff - 4U, (size_t)extbodylen + 4U, &permitpskdhe);
						extoff += (size_t)extbodylen;
						seenpskmodes = (status == qsc_tls_status_success);
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_pre_shared_key)
				{
					if (seenpsk == true)
					{
						status = qsc_tls_status_invalid_message;
					}
					else
					{
						status = qsc_tls_extensions_decode_pre_shared_key_client(extspan + extoff - 4U, (size_t)extbodylen + 4U, &pskidentity, &pskidentitylen, &u32age, &pskbinder, &pskbinderlen, &pskbinderoffset);
						extoff += (size_t)extbodylen;
						seenpsk = (status == qsc_tls_status_success);
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_key_share)
				{
					if (seenkeyshare == true)
					{
						status = qsc_tls_status_invalid_message;
					}
					else
					{
						status = tls_extensions_parse_client_key_share(extspan + extoff, (size_t)extbodylen, &parsedgroup, parsedpeershare, sizeof(parsedpeershare), &parsedpeersharelen);
						extoff += (size_t)extbodylen;
						seenkeyshare = (status == qsc_tls_status_success);
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_server_name)
				{
					status = qsc_tls_extensions_decode_server_name_client(extspan + extoff - 4U, (size_t)extbodylen + 4U, &servername, &servernamelen);
					extoff += (size_t)extbodylen;

					if (status == qsc_tls_status_success)
					{
						state->servernameack = (servernamelen != 0U);
					}
				}
				else if (exttype == (uint16_t)qsc_tls_extension_application_layer_protocol_negotiation)
				{
					status = qsc_tls_extensions_decode_alpn_client(extspan + extoff - 4U, (size_t)extbodylen + 4U, &alpnprotocol, &alpnprotocollen);
					extoff += (size_t)extbodylen;

					if (status == qsc_tls_status_success)
					{
						if (state->localalpnsize != 0U && tls_handshake_buffer_equals(state->localalpn, state->localalpnsize, alpnprotocol, alpnprotocollen) == false)
						{
							status = qsc_tls_status_not_supported;
						}
						else if (alpnprotocollen > sizeof(state->peeralpn) - 1U)
						{
							status = qsc_tls_status_invalid_length;
						}
						else
						{
							qsc_memutils_copy(state->peeralpn, alpnprotocol, alpnprotocollen);
							state->peeralpn[alpnprotocollen] = 0U;
							state->peeralpnsize = alpnprotocollen;
						}
					}
				}
				else
				{
					extoff += (size_t)extbodylen;
				}
			}
		}

		if (status == qsc_tls_status_success)
		{
			if (seenversion == false || seengroups == false || seensigs == false || seenkeyshare == false)
			{
				status = qsc_tls_status_invalid_message;
			}
		}

		if (status == qsc_tls_status_success && off != (4U + (size_t)bodylen))
		{
			status = qsc_tls_status_invalid_message;
		}

		if (status == qsc_tls_status_success)
		{
			if (qsc_tls_policy_validate_peer_group_selection(&state->policy, groups, groupcount, parsedgroup) == false)
			{
				status = qsc_tls_status_not_supported;
			}
		}

		if (status == qsc_tls_status_success && qsc_tls_handshake_has_local_certificate(state) == true)
		{
			const qsc_tls_signature_scheme* activesigs;
			size_t activesigcount;

			activesigs = (seencertsigs == true) ? certsigs : sigs;
			activesigcount = (seencertsigs == true) ? state->peercapabilities.certsigschemecount : sigcount;

			if (qsc_tls_policy_validate_peer_signature_selection(&state->policy, activesigs, activesigcount, state->localcert.verifyscheme) == false)
			{
				status = qsc_tls_status_not_supported;
			}
		}

		if (status == qsc_tls_status_success && seenpsk == true)
		{
			uint8_t expectedbinder[QSC_TLS_HASH_MAX_SIZE] = { 0U };
			size_t extbase;

			extbase = (size_t)(extspan - input);

			if (permitpskdhe == false || tls_server_ticket_matches(state, pskidentity, pskidentitylen) == false || state->resumptionticket.ciphersuite != parsedsuite || state->resumptionticket.hash != parsedhash)
			{
				status = qsc_tls_status_not_supported;
			}
			else
			{
				status = qsc_tls_connection_state_get_psk_binder(state, input, extbase + (extoff - (size_t)extbodylen) + pskbinderoffset, expectedbinder, sizeof(expectedbinder));
				
				if (status == qsc_tls_status_success)
				{
					if (pskbinderlen != qsc_tls_transcript_hash_size(parsedhash) || qsc_memutils_are_equal(expectedbinder, pskbinder, pskbinderlen) == false)
					{
						status = qsc_tls_status_authentication_failure;
					}
					else
					{
						state->resumedhandshake = true;
					}
				}
			}

			qsc_memutils_secure_erase(expectedbinder, sizeof(expectedbinder));
		}

		if (status == qsc_tls_status_success)
		{
			state->params.ciphersuite = parsedsuite;
			state->params.hash = parsedhash;
			state->params.group = parsedgroup;
			state->params.keysharelength = qsc_tls_group_public_key_size(parsedgroup);

			if (state->transcript.hash != parsedhash)
			{
				status = qsc_tls_transcript_initialize(&state->transcript, parsedhash);
			}

			if (status == qsc_tls_status_success && seenpsk == false)
			{
				state->resumedhandshake = false;
			}

			if (status == qsc_tls_status_success)
			{
				qsc_memutils_copy(state->peershare, parsedpeershare, parsedpeersharelen);
				state->peersharelen = parsedpeersharelen;
				qsc_memutils_clear(&state->peercapabilities, sizeof(state->peercapabilities));
				qsc_memutils_copy(state->peercapabilities.groups, groups, groupcount * sizeof(qsc_tls_named_group));
				state->peercapabilities.groupcount = groupcount;
				qsc_memutils_copy(state->peercapabilities.sigschemes, sigs, sigcount * sizeof(qsc_tls_signature_scheme));
				state->peercapabilities.sigschemecount = sigcount;

				if (seencertsigs == true)
				{
					qsc_memutils_copy(state->peercapabilities.certsigschemes, certsigs, state->peercapabilities.certsigschemecount * sizeof(qsc_tls_signature_scheme));
				}
				else
				{
					qsc_memutils_copy(state->peercapabilities.certsigschemes, sigs, sigcount * sizeof(qsc_tls_signature_scheme));
					state->peercapabilities.certsigschemecount = sigcount;
				}

				status = qsc_tls_handshake_append_message(&state->transcript, qsc_tls_handshake_type_client_hello, input + 4U, (size_t)bodylen);
			}
		}
	}

	qsc_memutils_secure_erase(random, sizeof(random));
	qsc_memutils_secure_erase(parsedpeershare, sizeof(parsedpeershare));

	return status;
}

static qsc_tls_status tls_server_build_server_hello(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* msglen)
{
	uint8_t random[QSC_TLS_HELLO_RANDOM_SIZE] = { 0U };
	size_t bodylen;
	size_t extlen;
	size_t off;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	off = 0U;
	bodylen = 0U;
	extlen = 0U;

	if (state == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = tls_handshake_fill_hello_random(random, sizeof(random), false);

		if (status != qsc_tls_status_success)
		{
			return status;
		}

		extlen = 6U + 8U + state->localsharelen;

		if (state->resumedhandshake == true)
		{
			extlen += 6U;
		}

		bodylen = 2U + sizeof(random) + 1U + state->legacysessionidlen + 2U + 1U + 2U + extlen;
		status = qsc_tls_codec_write_u8(output, outlen, &off, (uint8_t)qsc_tls_handshake_type_server_hello);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u24(output, outlen, &off, (uint32_t)bodylen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &off, QSC_TLS_PROTOCOL_VERSION_12);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &off, random, sizeof(random));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &off, (uint8_t)state->legacysessionidlen);
		}

		if (status == qsc_tls_status_success && state->legacysessionidlen != 0U)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &off, state->legacysessionid, state->legacysessionidlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &off, (uint16_t)state->params.ciphersuite);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &off, 0U);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &off, (uint16_t)extlen);
		}

		if (status == qsc_tls_status_success)
		{
			size_t partlen = 0U;

			status = tls_extensions_encode_supported_versions_server(output + off, outlen - off, &partlen);

			if (status == qsc_tls_status_success)
			{
				off += partlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			size_t partlen = 0U;

			status = tls_extensions_encode_key_share_server(state->params.group, state->localshare, state->localsharelen, output + off, outlen - off, &partlen);

			if (status == qsc_tls_status_success)
			{
				off += partlen;
			}
		}

		if (status == qsc_tls_status_success && state->resumedhandshake == true)
		{
			size_t partlen = 0U;

			status = qsc_tls_extensions_encode_pre_shared_key_server(output + off, outlen - off, &partlen, 0U);

			if (status == qsc_tls_status_success)
			{
				off += partlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_append_message(&state->transcript, qsc_tls_handshake_type_server_hello, output + 4U, bodylen);
		}

		*msglen = (status == qsc_tls_status_success) ? off : 0U;
		qsc_memutils_secure_erase(random, sizeof(random));
	}

	return status;
}

static qsc_tls_status tls_server_build_hello_retry_request(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* msglen)
{
	uint8_t random[QSC_TLS_HELLO_RANDOM_SIZE] = { 0U };
	size_t bodylen;
	size_t extlen;
	size_t off;
	size_t partlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	bodylen = 0U;
	extlen = 0U;
	off = 0U;
	partlen = 0U;
	tls_server_hello_retry_request_random(random);

	if (state == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		extlen = 6U + 6U;
		bodylen = 2U + sizeof(random) + 1U + state->legacysessionidlen + 2U + 1U + 2U + extlen;
		status = qsc_tls_codec_write_u8(output, outlen, &off, (uint8_t)qsc_tls_handshake_type_server_hello);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u24(output, outlen, &off, (uint32_t)bodylen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &off, QSC_TLS_PROTOCOL_VERSION_12);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &off, random, sizeof(random));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &off, (uint8_t)state->legacysessionidlen);
		}

		if (status == qsc_tls_status_success && state->legacysessionidlen != 0U)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &off, state->legacysessionid, state->legacysessionidlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &off, (uint16_t)state->params.ciphersuite);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &off, 0U);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &off, (uint16_t)extlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = tls_extensions_encode_supported_versions_server(output + off, outlen - off, &partlen);
			if (status == qsc_tls_status_success)
			{
				off += partlen;
			}
		}
		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_extensions_encode_key_share_hello_retry_request(output + off, outlen - off, &partlen, state->params.group);

			if (status == qsc_tls_status_success)
			{
				off += partlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_rewrite_transcript_for_hrr(state, output, off);
		}

		*msglen = (status == qsc_tls_status_success) ? off : 0U;
	}

	qsc_memutils_secure_erase(random, sizeof(random));

	return status;
}

static qsc_tls_status tls_server_build_encrypted_extensions(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* msglen)
{
	uint8_t extbuf[QSC_TLS_MAX_EXTENSION_SIZE] = { 0U };
	size_t bodylen;
	size_t extlen;
	size_t off;
	size_t partlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	bodylen = 2U;
	extlen = 0U;
	off = 0U;
	partlen = 0U;

	if (state == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		if (state->servernameack == true)
		{
			status = qsc_tls_extensions_encode_server_name_ack(extbuf + extlen, sizeof(extbuf) - extlen, &partlen);

			if (status == qsc_tls_status_success)
			{
				extlen += partlen;
			}
		}

		if (status == qsc_tls_status_success && state->localalpnsize != 0U)
		{
			partlen = 0U;
			status = qsc_tls_extensions_encode_alpn_server(extbuf + extlen, sizeof(extbuf) - extlen, &partlen, state->localalpn, state->localalpnsize);
			
			if (status == qsc_tls_status_success)
			{
				extlen += partlen;
				qsc_memutils_copy(state->peeralpn, state->localalpn, state->localalpnsize);
				state->peeralpn[state->localalpnsize] = 0U;
				state->peeralpnsize = state->localalpnsize;
			}
		}

		if (status == qsc_tls_status_success)
		{
			bodylen += extlen;
			status = qsc_tls_codec_write_u8(output, outlen, &off, (uint8_t)qsc_tls_handshake_type_encrypted_extensions);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u24(output, outlen, &off, (uint32_t)bodylen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &off, (uint16_t)extlen);
		}

		if (status == qsc_tls_status_success && extlen != 0U)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &off, extbuf, extlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_append_message(&state->transcript, qsc_tls_handshake_type_encrypted_extensions, output + 4U, bodylen);
		}

		*msglen = (status == qsc_tls_status_success) ? off : 0U;
	}

	qsc_memutils_secure_erase(extbuf, sizeof(extbuf));

	return status;
}

static qsc_tls_status tls_server_build_certificate(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* msglen)
{
	qsc_tls_certificate_entry_view entries[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES] = { 0U };
	size_t bodylen;
	size_t i;
	size_t off;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	bodylen = 0U;
	off = 0U;
	i = 0U;

	if (state == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		while (i < state->localcert.chainlength)
		{
			entries[i].certdata = state->localcert.chain[i].data;
			entries[i].certdatalen = state->localcert.chain[i].datalen;
			entries[i].extensions = NULL;
			entries[i].extensionslen = 0U;
			++i;
		}

		status = qsc_tls_certificate_message_build(NULL, 0U, entries, state->localcert.chainlength, output + 4U, outlen - 4U, &bodylen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &off, (uint8_t)qsc_tls_handshake_type_certificate);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u24(output, outlen, &off, (uint32_t)bodylen);
		}

		if (status == qsc_tls_status_success)
		{
			off += bodylen;
			status = qsc_tls_handshake_append_message(&state->transcript, qsc_tls_handshake_type_certificate, output + 4U, bodylen);
		}

		*msglen = (status == qsc_tls_status_success) ? off : 0U;
	}

	return status;
}

static qsc_tls_status tls_server_build_certificate_verify(qsc_tls_connection_state* state, uint8_t* output, size_t outlen, size_t* msglen)
{
	uint8_t input[QSC_TLS_HASH_MAX_SIZE + 128U] = { 0U };
	uint8_t signature[QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE] = { 0U };
	uint8_t transcripthash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	size_t bodylen;
	size_t inputlen;
	size_t off;
	size_t signaturelen;
	size_t transcripthashlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	bodylen = 0U;
	inputlen = 0U;
	off = 0U;
	signaturelen = 0U;
	transcripthashlen = 0U;

	if (state == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_transcript_snapshot(&state->transcript, transcripthash, sizeof(transcripthash), &transcripthashlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_certificate_verify_input_build(true, transcripthash, transcripthashlen, input, sizeof(input), &inputlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (state->localcert.signcallback != NULL)
			{
				signaturelen = qsc_tls_signature_scheme_signature_size(state->localcert.verifyscheme);

				if (signaturelen == 0U || signaturelen > sizeof(signature) || state->localcert.signcallback(state->localcert.verifyscheme, input, inputlen, signature, &signaturelen, state->localcert.signstate) == false)
				{
					status = qsc_tls_status_authentication_failure;
				}
			}
			else if (state->localcert.staticsignature == true)
			{
				signaturelen = state->localcert.verifysignaturelen;

				if (signaturelen == 0U || signaturelen > sizeof(signature))
				{
					status = qsc_tls_status_invalid_state;
				}
				else
				{
					qsc_memutils_copy(signature, state->localcert.verifysignature, signaturelen);
				}
			}
			else
			{
				status = qsc_tls_status_invalid_state;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_certificate_verify_build(state->localcert.verifyscheme, signature, signaturelen, output + 4U, outlen - 4U, &bodylen);
		}
		
		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &off, (uint8_t)qsc_tls_handshake_type_certificate_verify);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u24(output, outlen, &off, (uint32_t)bodylen);
		}

		if (status == qsc_tls_status_success)
		{
			off += bodylen;
			status = qsc_tls_handshake_append_message(&state->transcript, qsc_tls_handshake_type_certificate_verify, output + 4U, bodylen);
		}

		*msglen = (status == qsc_tls_status_success) ? off : 0U;
	}

	qsc_memutils_secure_erase(transcripthash, sizeof(transcripthash));
	qsc_memutils_secure_erase(input, sizeof(input));
	qsc_memutils_secure_erase(signature, sizeof(signature));

	return status;
}

qsc_tls_status qsc_tls_server_process_client_hello(qsc_tls_connection_state* state, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	size_t off;
	size_t partlen;
	bool usecert;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	off = 0U;
	partlen = 0U;
	usecert = false;

	if (state == NULL || input == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->stage != qsc_tls_connection_stage_none && state->stage != qsc_tls_connection_stage_hello_retry_request_sent)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		usecert = qsc_tls_handshake_has_local_certificate(state);

		if (state->resumedhandshake == true)
		{
			usecert = false;
		}

		if (state->stage == qsc_tls_connection_stage_none)
		{
			if (inlen > sizeof(state->firstclienthello))
			{
				status = qsc_tls_status_buffer_too_small;
			}
			else
			{
				qsc_memutils_copy(state->firstclienthello, input, inlen);
				state->firstclienthellolen = inlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = tls_server_parse_client_hello(state, input, inlen);
		}

		if (status == qsc_tls_status_success)
		{
			qsc_tls_named_group preferredgroup;

			preferredgroup = tls_server_select_preferred_group(state);

			if (preferredgroup == qsc_tls_group_none)
			{
				status = qsc_tls_status_not_supported;
			}
			else if (preferredgroup != state->params.group)
			{
				if (state->helloretryrequested == true)
				{
					status = qsc_tls_status_invalid_message;
				}
				else
				{
					state->params.group = preferredgroup;
					state->params.keysharelength = qsc_tls_group_public_key_size(preferredgroup);
					state->negotiatedsharedsecretlen = qsc_tls_group_shared_secret_size(preferredgroup);
					status = tls_server_build_hello_retry_request(state, output, outlen, &off);

					if (status == qsc_tls_status_success)
					{
						state->stage = qsc_tls_connection_stage_hello_retry_request_sent;
						state->helloretryrequested = true;
						*msglen = off;
						return status;
					}
				}
			}

			state->params.hash = tls_handshake_hash_from_suite(state->params.ciphersuite);
			state->localprivatekeylen = qsc_tls_group_private_key_size(state->params.group);

			if (qsc_tls_group_uses_encapsulation(state->params.group) == true)
			{
				uint8_t seed[QSC_SHA2_256_HASH_SIZE] = { 0U };
				uint8_t sharedsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
				size_t sharedsecretlen;

				sharedsecretlen = sizeof(sharedsecret);
				status = tls_server_share_seed(state->params.group, seed, sizeof(seed));

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_group_server_share_generate(state->params.group, seed, sizeof(seed), state->peershare, state->peersharelen, state->localshare, sizeof(state->localshare), state->localprivatekey, sizeof(state->localprivatekey), sharedsecret, &sharedsecretlen);
				}

				qsc_memutils_secure_erase(seed, sizeof(seed));

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_schedule_derive_handshake_secret(state->params.hash, state->handshakesecret, sizeof(state->handshakesecret), sharedsecret, sharedsecretlen, NULL, 0U);

					if (status == qsc_tls_status_success)
					{
						state->handshakesecretlen = qsc_tls_transcript_hash_size(state->params.hash);

						if (qsc_tls_group_is_hybrid(state->params.group) == true)
						{
							state->localsharelen = qsc_tls_group_ciphertext_size(state->params.group) + qsc_tls_group_classical_public_key_size(state->params.group);
						}
						else
						{
							state->localsharelen = qsc_tls_group_ciphertext_size(state->params.group);
						}
					}
				}

				qsc_memutils_secure_erase(sharedsecret, sizeof(sharedsecret));
			}
			else
			{
				uint8_t seed[QSC_SHA2_256_HASH_SIZE] = { 0U };
				uint8_t sharedsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
				size_t sharedsecretlen;

				sharedsecretlen = sizeof(sharedsecret);
				status = tls_server_share_seed(state->params.group, seed, sizeof(seed));

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_group_key_share_generate(state->params.group, seed, sizeof(seed), state->localshare, sizeof(state->localshare), state->localprivatekey, sizeof(state->localprivatekey));
				}

				qsc_memutils_secure_erase(seed, sizeof(seed));

				if (status == qsc_tls_status_success)
				{
					state->localsharelen = qsc_tls_group_public_key_size(state->params.group);
					status = qsc_tls_group_shared_secret_derive(state->params.group, state->localprivatekey, state->localprivatekeylen, state->peershare, state->peersharelen, sharedsecret, &sharedsecretlen);

					if (status == qsc_tls_status_success)
					{
						status = qsc_tls_schedule_derive_handshake_secret(state->params.hash, state->handshakesecret, sizeof(state->handshakesecret), sharedsecret, sharedsecretlen, NULL, 0U);

						if (status == qsc_tls_status_success)
						{
							state->handshakesecretlen = qsc_tls_transcript_hash_size(state->params.hash);
						}
					}
				}

				qsc_memutils_secure_erase(sharedsecret, sizeof(sharedsecret));
			}
		}

		if (status == qsc_tls_status_success && state->resumedhandshake == true)
		{
			status = tls_server_mix_resumption_secret(state);
		}

		if (status == qsc_tls_status_success)
		{
			status = tls_server_build_server_hello(state, output + off, outlen - off, &partlen);
		}

		if (status == qsc_tls_status_success)
		{
			off += partlen;
		}

		/* TLS 1.3 handshake traffic keys are derived from the transcript
		 * through ServerHello only. Install them immediately after the
		 * ServerHello transcript point, before appending later handshake
		 * messages to the transcript. */
		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_install_handshake_record_keys(state);
		}

		if (status == qsc_tls_status_success)
		{
			status = tls_server_build_encrypted_extensions(state, output + off, outlen - off, &partlen);
		}

		if (status == qsc_tls_status_success)
		{
			off += partlen;
		}

		if (status == qsc_tls_status_success && usecert == true)
		{
			status = tls_server_build_certificate(state, output + off, outlen - off, &partlen);
		}

		if (status == qsc_tls_status_success && usecert == true)
		{
			off += partlen;
		}

		if (status == qsc_tls_status_success && usecert == true)
		{
			status = tls_server_build_certificate_verify(state, output + off, outlen - off, &partlen);
		}

		if (status == qsc_tls_status_success && usecert == true)
		{
			off += partlen;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_build_finished(state, output + off, outlen - off, &partlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_append_message(&state->transcript, qsc_tls_handshake_type_finished, output + off + 4U, partlen - 4U);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_transcript_snapshot(&state->transcript, state->apptraffictranscripthash, sizeof(state->apptraffictranscripthash), &state->apptraffictranscripthashlen);
		}

		if (status == qsc_tls_status_success)
		{
			off += partlen;
			state->stage = qsc_tls_connection_stage_server_flight_sent;
		}

		*msglen = (status == qsc_tls_status_success) ? off : 0U;
	}

	return status;
}

qsc_tls_status qsc_tls_server_process_client_finished(qsc_tls_connection_state* state, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(input != NULL);
	
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->stage != qsc_tls_connection_stage_server_flight_sent)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_verify_finished(state, input, inlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_append_message(&state->transcript, qsc_tls_handshake_type_finished, input + 4U, inlen - 4U);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_handshake_install_application_record_keys(state);
		}

		if (status == qsc_tls_status_success)
		{
			state->stage = qsc_tls_connection_stage_connected;
			state->handshakecomplete = true;
		}
	}

	return status;
}

