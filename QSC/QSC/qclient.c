#include "qclient.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"

#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

#if defined(QSC_QSMP_PUBKEY_SPHINCS)
#	define qsc_qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
#	define qsc_qsmp_cipher_decapsulate qsc_mceliece_decapsulate
#	define qsc_qsmp_cipher_encapsulate qsc_mceliece_encapsulate
#	define qsc_qsmp_signature_sign qsc_sphincsplus_sign
#	define qsc_qsmp_signature_verify qsc_sphincsplus_verify
#else
#	define qsc_qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
#	define qsc_qsmp_cipher_decapsulate qsc_kyber_decapsulate
#	define qsc_qsmp_cipher_encapsulate qsc_kyber_encapsulate
#	define qsc_qsmp_signature_sign qsc_dilithium_sign
#	define qsc_qsmp_signature_verify qsc_dilithium_verify
#endif

void qsc_qsmp_client_decode_public_key(qsc_qsmp_client_key* clientkey, const char input[QSC_QSMP_PUBKEY_STRING_SIZE])
{
	assert(clientkey != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char keyid[QSC_QSMP_KEYID_SIZE] = { 0 };
	char tmpvk[QSC_QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t spos;
	size_t slen;

	if (clientkey != NULL)
	{
		spos = sizeof(QSC_QSMP_PUBKEY_HEADER) + sizeof(QSC_QSMP_PUBKEY_VERSION) + sizeof(QSC_QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		slen = QSC_QSMP_CONFIG_SIZE - 1;
		qsc_memutils_copy(clientkey->config, ((uint8_t*)input + spos), slen);

		spos += slen + sizeof(QSC_QSMP_PUBKEY_EXPIRATION_PREFIX) - 3;
		qsc_intutils_hex_to_bin(((char*)input + spos), clientkey->keyid, QSC_QSMP_KEYID_SIZE * 2);

		spos += (QSC_QSMP_KEYID_SIZE * 2) + sizeof(QSC_QSMP_PUBKEY_EXPIRATION_PREFIX);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1;
		qsc_memutils_copy(dtm, ((uint8_t*)input + spos), slen);
		clientkey->expiration = qsc_timestamp_datetime_to_seconds(dtm);
		spos += QSC_TIMESTAMP_STRING_SIZE;

		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), ((char*)input + spos), (QSC_QSMP_PUBKEY_STRING_SIZE - (spos + sizeof(QSC_QSMP_PUBKEY_FOOTER))));
		qsc_encoding_base64_decode(clientkey->verkey, QSC_QSMP_VERIFYKEY_SIZE, tmpvk, QSC_QSMP_PUBKEY_ENCODING_SIZE);
	}
}

void qsc_qsmp_client_dispose(qsc_qsmp_kex_client_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_rcs_dispose(&ctx->rxcpr);
		qsc_rcs_dispose(&ctx->txcpr);
		qsc_memutils_clear(ctx->config, sizeof(ctx->config));
		qsc_memutils_clear(ctx->keyid, sizeof(ctx->keyid));
		qsc_memutils_clear(ctx->pkhash, sizeof(ctx->pkhash));
		qsc_memutils_clear(ctx->prikey, sizeof(ctx->prikey));
		qsc_memutils_clear(ctx->pubkey, sizeof(ctx->pubkey));
		qsc_memutils_clear(ctx->token, sizeof(ctx->token));
		qsc_memutils_clear(ctx->verkey, sizeof(ctx->verkey));
		ctx->exflag = 0;
		ctx->expiration = 0;
	}
}

void qsc_qsmp_client_initialize(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_client_key* ckey)
{
	assert(ckey != NULL);
	assert(ctx != NULL);

	if (ckey != NULL && ctx != NULL)
	{
		qsc_qsmp_client_dispose(ctx);
		qsc_memutils_copy(ctx->keyid, ckey->keyid, QSC_QSMP_KEYID_SIZE);
#if defined(QSC_QSMP_PUBKEY_SPHINCS)
		qsc_memutils_copy(ctx->config, QSC_QSMP_CONFIG_SPXMPK, QSC_QSMP_CONFIG_SIZE);
#else
		qsc_memutils_copy(ctx->config, QSC_QSMP_CONFIG_DLMKBR, QSC_QSMP_CONFIG_SIZE);
#endif
		qsc_memutils_copy(ctx->verkey, ckey->verkey, sizeof(ctx->verkey));
		ctx->expiration = ckey->expiration;
		ctx->exflag = qsc_qsmp_message_none;
	}
}

qsc_qsmp_errors qsc_qsmp_client_connection_request(qsc_qsmp_kex_client_state* ctx, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsc_qsmp_errors res;
	uint64_t tm;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_epochtime_seconds();

		if (tm <= ctx->expiration)
		{
			/* generate the session token */
			qsc_memutils_clear(ctx->token, QSC_QSMP_STOKEN_SIZE);

			if (qsc_acp_generate(ctx->token, QSC_QSMP_STOKEN_SIZE) == true)
			{
				/* assign the packet parameters */
				qsc_memutils_copy(packetout->message, ctx->keyid, QSC_QSMP_KEYID_SIZE);
				qsc_memutils_copy(((uint8_t*)packetout->message + QSC_QSMP_KEYID_SIZE), ctx->token, QSC_QSMP_STOKEN_SIZE);
#if defined(QSC_QSMP_PUBKEY_SPHINCS)
				qsc_memutils_copy(((uint8_t*)packetout->message + QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE), QSC_QSMP_CONFIG_SPXMPK, QSC_QSMP_CONFIG_SIZE);
#else
				qsc_memutils_copy(((uint8_t*)packetout->message + QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE), QSC_QSMP_CONFIG_DLMKBR, QSC_QSMP_CONFIG_SIZE);
#endif
				/* assemble the connection-request packet */
				packetout->msglen = QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE + QSC_QSMP_CONFIG_SIZE;
				packetout->flag = qsc_qsmp_message_connect_request;
				packetout->sequence = 1;

				/* store a hash of the session token, the configuration string, and the public signature key: pkh = H(stok || cfg || psk) */
				qsc_memutils_clear(ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, keccak_rate_256, packetout->message, QSC_QSMP_STOKEN_SIZE + QSC_QSMP_CONFIG_SIZE);
				qsc_sha3_update(&kstate, keccak_rate_256, ctx->verkey, QSC_QSMP_VERIFYKEY_SIZE);
				qsc_sha3_finalize(&kstate, keccak_rate_256, ctx->pkhash);

				res = qsc_qsmp_error_none;
				ctx->exflag = qsc_qsmp_message_connect_request;
			}
			else
			{
				ctx->exflag = qsc_qsmp_message_none;
				res = qsc_qsmp_random_failure;
			}
		}
		else
		{
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_key_expired;
		}
	}

	return res;
}

qsc_qsmp_errors qsc_qsmp_client_exstart_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;
	uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };
	uint8_t khash[QSC_QSMP_PKCODE_SIZE] = { 0 };
	size_t mlen;
	size_t slen;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_connect_request && packetin->flag == qsc_qsmp_message_connect_response)
		{
			slen = 0;
			mlen = QSC_QSMP_SIGNATURE_SIZE + QSC_SHA3_256_HASH_SIZE;

			if (qsc_qsmp_signature_verify(khash, &slen, packetin->message, mlen, ctx->verkey) == true)
			{
				uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
				uint8_t pubk[QSC_QSMP_PUBLICKEY_SIZE] = { 0 };

				qsc_memutils_copy(pubk, ((uint8_t*)packetin->message + mlen), QSC_QSMP_PUBLICKEY_SIZE);

				/* verify the public key hash */
				qsc_sha3_compute256(phash, pubk, QSC_QSMP_PUBLICKEY_SIZE);

				if (qsc_intutils_verify(phash, khash, QSC_SHA3_256_HASH_SIZE) == 0)
				{
					uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
					qsc_keccak_state kstate = { 0 };

					/* generate and encapsulate the secret */
					qsc_memutils_clear(packetout->message, sizeof(packetout->message));
					qsc_qsmp_cipher_encapsulate(sec, packetout->message, pubk, qsc_acp_generate);

					/* expand the secret with cshake (P) adding the public verification keys hash; prand = P(pv || sec) */
					qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
					qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp;
					kp.key = prnd;
					kp.keylen = QSC_RCS256_KEY_SIZE;
					kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
					kp.info = NULL;
					kp.infolen = 0;
					qsc_rcs_initialize(&ctx->txcpr, &kp, true);

					/* assemble the exstart-request packet */
					packetout->flag = qsc_qsmp_message_exstart_request;
					packetout->msglen = QSC_QSMP_CIPHERTEXT_SIZE;
					packetout->sequence = 3;

					res = qsc_qsmp_error_none;
					ctx->exflag = qsc_qsmp_message_exstart_request;
				}
				else
				{
					qsc_qsmp_packet_error_message(packetout, qsc_qsmp_hash_invalid);
					res = qsc_qsmp_hash_invalid;
					ctx->exflag = qsc_qsmp_message_none;
				}
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_authentication_failure);
				res = qsc_qsmp_authentication_failure;
				ctx->exflag = qsc_qsmp_message_none;
			}
		}
		else
		{
			qsc_qsmp_packet_error_message(packetout, qsc_qsmp_invalid_request);
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_invalid_request;
		}
	}

	return res;
}

qsc_qsmp_errors qsc_qsmp_client_exchange_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exstart_request && packetin->flag == qsc_qsmp_message_exstart_response)
		{
			uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };

			/* generate the channel-2 keypair */
			qsc_qsmp_cipher_generate_keypair(ctx->pubkey, ctx->prikey, qsc_acp_generate);

			/* assemble the exchange-request packet */
			qsc_memutils_clear(packetout->message, sizeof(packetout->message));
			packetout->flag = qsc_qsmp_message_exchange_request;
			packetout->msglen = QSC_QSMP_PUBLICKEY_SIZE + QSC_RCS256_MAC_SIZE;
			packetout->sequence = 5;

			/* serialize the packet header and add it to associated data */
			qsc_qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&ctx->txcpr, hdr, QSC_QSMP_HEADER_SIZE);
			/* encrypt the public encryption key using the channel-1 VPN */
			qsc_rcs_transform(&ctx->txcpr, packetout->message, ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);

			res = qsc_qsmp_error_none;
			ctx->exflag = qsc_qsmp_message_exchange_request;
		}
		else
		{
			qsc_qsmp_packet_error_message(packetout, qsc_qsmp_invalid_request);
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_invalid_request;
		}
	}

	return res;
}

qsc_qsmp_errors qsc_qsmp_client_establish_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exchange_request && packetin->flag == qsc_qsmp_message_exchange_response)
		{
			uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };

			/* decapsulate the shared secret */
			if (qsc_qsmp_cipher_decapsulate(sec, ((uint8_t*)packetin->message + QSC_QSMP_MACTAG_SIZE), ctx->prikey) == true)
			{
				uint8_t kcode[QSC_QSMP_MACTAG_SIZE] = { 0 };
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
				qsc_keccak_state kstate;

				/* expand the shared secret */
				qsc_keccak_dispose(&kstate);
				qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

				/* mac the cipher-text */
				qsc_kmac256_compute(kcode, QSC_QSMP_MACTAG_SIZE, ((uint8_t*)packetin->message + QSC_QSMP_MACTAG_SIZE), QSC_QSMP_CIPHERTEXT_SIZE, ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE + QSC_RCS_NONCE_SIZE), QSC_QSMP_MACKEY_SIZE, NULL, 0);

				/* verify the against the embedded cipher-text mac */
				if (qsc_intutils_verify(packetin->message, kcode, QSC_QSMP_MACTAG_SIZE) == 0)
				{
					/* initialize the symmetric cipher, and raise client channel-2 rx */
					qsc_rcs_keyparams kp;
					kp.key = prnd;
					kp.keylen = QSC_RCS256_KEY_SIZE;
					kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
					kp.info = NULL;
					kp.infolen = 0;
					qsc_rcs_initialize(&ctx->rxcpr, &kp, false);

					/* assemble the establish-request packet */
					qsc_memutils_clear(packetout->message, sizeof(packetout->message));
					packetout->flag = qsc_qsmp_message_establish_request;
					packetout->msglen = 0;
					packetout->sequence = 7;

					res = qsc_qsmp_error_none;
					ctx->exflag = qsc_qsmp_message_session_established;
				}
				else
				{
					qsc_qsmp_packet_error_message(packetout, qsc_qsmp_authentication_failure);
					res = qsc_qsmp_authentication_failure;
					ctx->exflag = qsc_qsmp_message_none;
				}
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_decapsulation_failure);
				res = qsc_qsmp_decapsulation_failure;
				ctx->exflag = qsc_qsmp_message_none;
			}
		}
		else
		{
			qsc_qsmp_packet_error_message(packetout, qsc_qsmp_invalid_request);
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_invalid_request;
		}
	}

	return res;
}

qsc_qsmp_errors qsc_qsmp_client_decrypt_packet(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, uint8_t* message, size_t* msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(msglen != NULL);
	assert(packetin != NULL);

	uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };
	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_session_established)
		{
			qsc_qsmp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSC_QSMP_HEADER_SIZE);
			*msglen = packetin->msglen - QSC_RCS256_MAC_SIZE;

			if (qsc_rcs_transform(&ctx->rxcpr, message, packetin->message, *msglen) == true)
			{
				res = qsc_qsmp_error_none;
			}
			else
			{
				*msglen = 0;
				res = qsc_qsmp_authentication_failure;
			}
		}
		else
		{
			*msglen = 0;
			res = qsc_qsmp_channel_down;
		}
	}

	return res;
}

qsc_qsmp_errors qsc_qsmp_client_encrypt_packet(qsc_qsmp_kex_client_state* ctx, const uint8_t* message, size_t msglen, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetout != NULL && message != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_session_established)
		{
			uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };

			qsc_memutils_clear(packetout->message, sizeof(packetout->message));
			packetout->flag = qsc_qsmp_message_encrypted_message;
			packetout->msglen = (uint32_t)msglen + QSC_RCS256_MAC_SIZE;
			packetout->sequence += 1;

			qsc_qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&ctx->txcpr, hdr, QSC_QSMP_HEADER_SIZE);
			qsc_rcs_transform(&ctx->txcpr, packetout->message, message, msglen);

			res = qsc_qsmp_error_none;
		}
		else
		{
			res = qsc_qsmp_channel_down;
		}
	}

	return res;
}