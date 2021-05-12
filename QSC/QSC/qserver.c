#include "qserver.h"
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
#	define qsc_qsmp_signature_generate_keypair qsc_sphincsplus_generate_keypair
#	define qsc_qsmp_signature_sign qsc_sphincsplus_sign
#	define qsc_qsmp_signature_verify qsc_sphincsplus_verify
#else
#	define qsc_qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
#	define qsc_qsmp_cipher_decapsulate qsc_kyber_decapsulate
#	define qsc_qsmp_cipher_encapsulate qsc_kyber_encapsulate
#	define qsc_qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
#	define qsc_qsmp_signature_sign qsc_dilithium_sign
#	define qsc_qsmp_signature_verify qsc_dilithium_verify
#endif

void qsc_qsmp_server_deserialize_signature_key(qsc_qsmp_server_key* serverkey, const uint8_t input[QSC_QSMP_SIGKEY_ENCODED_SIZE])
{
	size_t pos;

	memcpy(serverkey->config, input, QSC_QSMP_CONFIG_SIZE);
	pos = QSC_QSMP_CONFIG_SIZE;
	memcpy(&serverkey->expiration, ((uint8_t*)input + pos), QSC_QSMP_TIMESTAMP_SIZE);
	pos += QSC_QSMP_TIMESTAMP_SIZE;
	memcpy(serverkey->keyid, ((uint8_t*)input + pos), QSC_QSMP_KEYID_SIZE);
	pos += QSC_QSMP_KEYID_SIZE;
	memcpy(serverkey->sigkey, ((uint8_t*)input + pos), QSC_QSMP_SIGNKEY_SIZE);
	pos += QSC_QSMP_SIGNKEY_SIZE;
	memcpy(serverkey->verkey, ((uint8_t*)input + pos), QSC_QSMP_VERIFYKEY_SIZE);
	pos += QSC_QSMP_VERIFYKEY_SIZE;
}

void qsc_qsmp_server_serialize_signature_key(uint8_t output[QSC_QSMP_SIGKEY_ENCODED_SIZE], const qsc_qsmp_server_key* serverkey)
{
	size_t pos;

	memcpy(output, serverkey->config, QSC_QSMP_CONFIG_SIZE);
	pos = QSC_QSMP_CONFIG_SIZE;
	memcpy(((uint8_t*)output + pos), &serverkey->expiration, QSC_QSMP_TIMESTAMP_SIZE);
	pos += QSC_QSMP_TIMESTAMP_SIZE;
	memcpy(((uint8_t*)output + pos), serverkey->keyid, QSC_QSMP_KEYID_SIZE);
	pos += QSC_QSMP_KEYID_SIZE;
	memcpy(((uint8_t*)output + pos), serverkey->sigkey, QSC_QSMP_SIGNKEY_SIZE);
	pos += QSC_QSMP_SIGNKEY_SIZE;
	memcpy(((uint8_t*)output + pos), serverkey->verkey, QSC_QSMP_VERIFYKEY_SIZE);
	pos += QSC_QSMP_VERIFYKEY_SIZE;
}

void qsc_qsmp_server_dispose(qsc_qsmp_kex_server_state* ctx)
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
		qsc_memutils_clear(ctx->sigkey, sizeof(ctx->sigkey));
		qsc_memutils_clear(ctx->verkey, sizeof(ctx->verkey));
		ctx->exflag = 0;
		ctx->expiration = 0;
	}
}

void qsc_qsmp_server_encode_public_key(qsc_qsmp_kex_server_state* ctx, char output[QSC_QSMP_PUBKEY_STRING_SIZE], const qsc_qsmp_server_key* serverkey)
{
	assert(ctx != NULL);
	assert(serverkey != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[QSC_QSMP_KEYID_SIZE * 2] = { 0 };
	char tmpvk[QSC_QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t slen;
	size_t spos;
	size_t tpos;

	if (ctx != NULL && serverkey != NULL)
	{
		spos = 0;
		tpos = 0;
		slen = sizeof(QSC_QSMP_PUBKEY_HEADER) - 1;
		qsc_memutils_copy(output, QSC_QSMP_PUBKEY_HEADER, slen);
		spos = slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_VERSION) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_VERSION, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
#if defined(QSC_QSMP_PUBKEY_SPHINCS)
		slen = sizeof(QSC_QSMP_CONFIG_SPXMPK) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_CONFIG_SPXMPK, slen);
#else
		slen = sizeof(QSC_QSMP_CONFIG_DLMKBR) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_CONFIG_DLMKBR, slen);
#endif
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_KEYID_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(serverkey->keyid, hexid, sizeof(ctx->keyid));
		slen = sizeof(hexid);
		qsc_memutils_copy(((char*)output + spos), hexid, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_EXPIRATION_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(serverkey->expiration, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy(((char*)output + spos), dtm, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(serverkey->verkey);
		qsc_encoding_base64_encode(tmpvk, QSC_QSMP_PUBKEY_ENCODING_SIZE, serverkey->verkey, slen);
		spos += qsc_stringutils_add_line_breaks(((char*)output + spos), QSC_QSMP_PUBKEY_STRING_SIZE - spos, QSC_QSMP_PUBKEY_LINE_LENGTH, tmpvk, sizeof(tmpvk));
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_FOOTER) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_FOOTER, slen);
		spos += slen;
		output[spos] = '\n';
	}
}

void qsc_qsmp_server_initialize(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_server_key* skey)
{
	assert(ctx != NULL);
	assert(skey != NULL);

	if (ctx != NULL && skey != NULL)
	{
		qsc_qsmp_server_dispose(ctx);
		qsc_memutils_copy(ctx->keyid, skey->keyid, QSC_QSMP_KEYID_SIZE);
#if defined(QSC_QSMP_PUBKEY_SPHINCS)
		qsc_memutils_copy(ctx->config, QSC_QSMP_CONFIG_SPXMPK, QSC_QSMP_CONFIG_SIZE);
#else
		qsc_memutils_copy(ctx->config, QSC_QSMP_CONFIG_DLMKBR, QSC_QSMP_CONFIG_SIZE);
#endif
		qsc_memutils_copy(ctx->sigkey, skey->sigkey, sizeof(ctx->sigkey));
		qsc_memutils_copy(ctx->verkey, skey->verkey, sizeof(ctx->verkey));
		ctx->exflag = qsc_qsmp_message_none;
		ctx->expiration = skey->expiration;
	}
}

qsc_qsmp_errors qsc_qsmp_server_connection_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	char confs[QSC_QSMP_CONFIG_SIZE + 1] = { 0 };
	uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
	qsc_keccak_state kstate = { 0 };
	qsc_qsmp_errors res;
	uint64_t tm;
	size_t mlen;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (packetin->flag == qsc_qsmp_message_connect_request)
		{
			tm = qsc_timestamp_epochtime_seconds();

			/* check the keys expiration date */
			if (tm <= ctx->expiration)
			{
				/* copy the session token and configuration string */
				qsc_memutils_copy(ctx->keyid, packetout->message, QSC_QSMP_KEYID_SIZE);
				qsc_memutils_copy(ctx->token, ((uint8_t*)packetin->message + QSC_QSMP_KEYID_SIZE), QSC_QSMP_STOKEN_SIZE);
				qsc_memutils_copy(confs, ((uint8_t*)packetin->message + QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE), QSC_QSMP_CONFIG_SIZE);

				/* store a hash of the session token, the configuration string, and the public signature key: pkh = H(stok || cfg || psk) */
				qsc_memutils_clear(ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_keccak_dispose(&kstate);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, keccak_rate_256, packetin->message, QSC_QSMP_STOKEN_SIZE + QSC_QSMP_CONFIG_SIZE);
				qsc_sha3_update(&kstate, keccak_rate_256, ctx->verkey, QSC_QSMP_VERIFYKEY_SIZE);
				qsc_sha3_finalize(&kstate, keccak_rate_256, ctx->pkhash);

				/* initialize the packet and asymmetric encryption keys */
				qsc_memutils_clear(ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);
				qsc_memutils_clear(ctx->prikey, QSC_QSMP_PRIVATEKEY_SIZE);
				qsc_memutils_clear(packetout->message, sizeof(packetout->message));

				/* generate the asymmetric encryption key-pair */
				qsc_qsmp_cipher_generate_keypair(ctx->pubkey, ctx->prikey, qsc_acp_generate);

				/* hash the public encryption key */
				qsc_sha3_compute256(phash, ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);

				/* sign the hash and add to the message */
				mlen = 0;
				qsc_qsmp_signature_sign(packetout->message, &mlen, phash, QSC_SHA3_256_HASH_SIZE, ctx->sigkey, qsc_acp_generate);

				/* copy the public key to the message */
				qsc_memutils_copy(((uint8_t*)packetout->message + mlen), ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);

				/* assemble the connection-response packet */
				packetout->flag = qsc_qsmp_message_connect_response;
				packetout->msglen = QSC_QSMP_SIGNATURE_SIZE + QSC_SHA3_256_HASH_SIZE + QSC_QSMP_PUBLICKEY_SIZE;
				packetout->sequence = 2;

				res = qsc_qsmp_error_none;
				ctx->exflag = qsc_qsmp_message_connect_response;
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_key_expired);
				ctx->exflag = qsc_qsmp_message_none;
				res = qsc_qsmp_key_expired;
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

qsc_qsmp_errors qsc_qsmp_server_exstart_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_connect_response && packetin->flag == qsc_qsmp_message_exstart_request)
		{
			uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };

			/* decapsulate the shared secret */
			if (qsc_qsmp_cipher_decapsulate(sec, packetin->message, ctx->prikey) == true)
			{
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
				qsc_keccak_state kstate = { 0 };

				/* expand the secret with cshake (P) adding the public verification keys hash; prand = P(pv || sec) */
				qsc_keccak_dispose(&kstate);
				qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

				/* initialize the symmetric cipher, and raise server channel-1 rx */
				qsc_rcs_keyparams kp;
				kp.key = prnd;
				kp.keylen = QSC_RCS256_KEY_SIZE;
				kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
				kp.info = NULL;
				kp.infolen = 0;
				qsc_rcs_initialize(&ctx->rxcpr, &kp, false);

				/* channel-1 VPN is established */

				/* assemble the exstart-response packet */
				qsc_memutils_clear(packetout->message, sizeof(packetout->message));
				packetout->flag = qsc_qsmp_message_exstart_response;
				packetout->message[0] = (uint8_t)qsc_qsmp_message_remote_connected;
				packetout->msglen = 1;
				packetout->sequence = 4;

				res = qsc_qsmp_error_none;
				ctx->exflag = qsc_qsmp_message_exstart_response;
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_decapsulation_failure);
				ctx->exflag = qsc_qsmp_message_none;
				res = qsc_qsmp_decapsulation_failure;
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

qsc_qsmp_errors qsc_qsmp_server_exchange_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exstart_response && packetin->flag == qsc_qsmp_message_exchange_request)
		{
			uint8_t pubk[QSC_QSMP_PUBLICKEY_SIZE] = { 0 };
			uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };

			/* serialize the packet header and add it to associated data */
			qsc_qsmp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSC_QSMP_HEADER_SIZE);

			/* authenticate and decrypt the cipher-text */
			if (qsc_rcs_transform(&ctx->rxcpr, pubk, packetin->message, QSC_QSMP_PUBLICKEY_SIZE) == true)
			{
				uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };
				uint8_t cpt[QSC_QSMP_CIPHERTEXT_SIZE] = { 0 };
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
				qsc_keccak_state kstate = { 0 };

				/* generate and encapsulate the shared secret */
				qsc_qsmp_cipher_encapsulate(sec, cpt, pubk, qsc_acp_generate);

				/* expand the shared secret */
				qsc_keccak_dispose(&kstate);
				qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

				/* initialize the symmetric cipher, and raise server channel-2 tx */
				qsc_rcs_keyparams kp;
				kp.key = prnd;
				kp.keylen = QSC_RCS256_KEY_SIZE;
				kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
				kp.info = NULL;
				kp.infolen = 0;
				qsc_rcs_initialize(&ctx->txcpr, &kp, true);

				/* assemble the exstart-response packet */
				qsc_memutils_clear(packetout->message, sizeof(packetout->message));
				packetout->flag = qsc_qsmp_message_exchange_response;
				packetout->msglen = QSC_QSMP_CIPHERTEXT_SIZE + QSC_QSMP_MACTAG_SIZE;
				packetout->sequence = 6;

				/* mac the asymmetric cipher-text, and append the MAC code */
				qsc_kmac256_compute(packetout->message, QSC_QSMP_MACTAG_SIZE, cpt, QSC_QSMP_CIPHERTEXT_SIZE, ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE + QSC_RCS_NONCE_SIZE), QSC_QSMP_MACKEY_SIZE, NULL, 0);
				qsc_memutils_copy(((uint8_t*)packetout->message + QSC_QSMP_MACTAG_SIZE), cpt, QSC_QSMP_CIPHERTEXT_SIZE);

				res = qsc_qsmp_error_none;
				ctx->exflag = qsc_qsmp_message_exchange_response;
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

qsc_qsmp_errors qsc_qsmp_server_establish_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exchange_response && packetin->flag == qsc_qsmp_message_establish_request)
		{
			/* assemble the establish-response packet */
			qsc_memutils_clear(packetout->message, sizeof(packetout->message));
			packetout->flag = qsc_qsmp_message_establish_response;
			packetout->msglen = 1;
			packetout->sequence = 8;
			packetout->message[0] = (uint8_t)qsc_qsmp_message_session_established;

			res = qsc_qsmp_error_none;
			ctx->exflag = qsc_qsmp_message_session_established;
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

qsc_qsmp_errors qsc_qsmp_server_decrypt_packet(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, uint8_t* message, size_t* msglen)
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

qsc_qsmp_errors qsc_qsmp_server_encrypt_packet(qsc_qsmp_kex_server_state* ctx, uint8_t* message, size_t msglen, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_invalid_input;

	if (ctx != NULL && message != NULL && packetout != NULL)
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

void qsc_qsmp_server_generate_keypair(qsc_qsmp_client_key* pubkey, qsc_qsmp_server_key* prikey, const uint8_t keyid[QSC_QSMP_KEYID_SIZE])
{
	assert(prikey != NULL);
	assert(pubkey != NULL);

	if (prikey != NULL && pubkey != NULL)
	{
		prikey->expiration = qsc_timestamp_epochtime_seconds() + QSC_QSMP_PUBKEY_DURATION_SECONDS;

#if defined(QSC_QSMP_PUBKEY_SPHINCS)
		qsc_memutils_copy(prikey->config, QSC_QSMP_CONFIG_SPXMPK, QSC_QSMP_CONFIG_SIZE);
#else
		qsc_memutils_copy(prikey->config, QSC_QSMP_CONFIG_DLMKBR, QSC_QSMP_CONFIG_SIZE);
#endif

		qsc_memutils_copy(prikey->keyid, keyid, QSC_QSMP_KEYID_SIZE);

		qsc_qsmp_signature_generate_keypair(prikey->verkey, prikey->sigkey, qsc_acp_generate);

		pubkey->expiration = prikey->expiration;
		qsc_memutils_copy(pubkey->config, prikey->config, QSC_QSMP_CONFIG_SIZE);
		qsc_memutils_copy(pubkey->verkey, prikey->verkey, QSC_QSMP_VERIFYKEY_SIZE);
		qsc_memutils_copy(pubkey->keyid, prikey->keyid, QSC_QSMP_KEYID_SIZE);
	}
}