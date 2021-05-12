/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/**
* \file qserver.h
* \brief <b>QSMP Server functions</b> \n
* Functions used to implement the server in the Quantum Secure Messaging Protocol (QSMP) VPN.
*
* \author		John G. Underhill
* \version		1.0.0.0a
* \date			May 1, 2021
* \updated		May 1, 2021
* \contact:		develop@vtdev.com
* \copyright	GPL version 3 license (GPLv3)
*/

#ifndef QSC_QSMP_SERVER_H
#define QSC_QSMP_SERVER_H

#include "qsmp.h"
#include "rcs.h"

/*!
* \struct qsc_qsmp_server_key
* \brief The QSMP server key structure
*/
QSC_EXPORT_API typedef struct qsc_qsmp_server_key
{
	uint64_t expiration;						/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSC_QSMP_CONFIG_SIZE];		/*!< The primitive configuration string */
	uint8_t keyid[QSC_QSMP_KEYID_SIZE];			/*!< The key identity string */
	uint8_t sigkey[QSC_QSMP_SIGNKEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSC_QSMP_VERIFYKEY_SIZE];	/*!< The asymmetric signature verification-key */
} qsc_qsmp_server_key;

/*!
* \struct qsc_qsmp_kex_server_state
* \brief The QSMP server state structure
*/
QSC_EXPORT_API typedef struct qsc_qsmp_kex_server_state
{
	qsc_rcs_state rxcpr;						/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;						/*!< The transmit channel cipher state */
	uint8_t config[QSC_QSMP_CONFIG_SIZE];		/*!< The primitive configuration string */
	uint8_t keyid[QSC_QSMP_KEYID_SIZE];			/*!< The key identity string */
	uint8_t pkhash[QSC_QSMP_PKCODE_SIZE];		/*!< The session token hash */
	uint8_t prikey[QSC_QSMP_PRIVATEKEY_SIZE];	/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSC_QSMP_PUBLICKEY_SIZE];	/*!< The asymmetric cipher public key */
	uint8_t sigkey[QSC_QSMP_SIGNKEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSC_QSMP_VERIFYKEY_SIZE];	/*!< The asymmetric signature verification-key */
	uint8_t token[QSC_QSMP_STOKEN_SIZE];		/*!< The session token */
	qsc_qsmp_flags exflag;						/*!< The KEX position flag */
	uint64_t expiration;						/*!< The expiration time, in seconds from epoch */
} qsc_qsmp_kex_server_state;

/**
* \brief Dispose of a server state structure
*
* \param ctx: A pointer to the server state structure
*/
QSC_EXPORT_API void qsc_qsmp_server_dispose(qsc_qsmp_kex_server_state* ctx);

/**
* \brief Encode a public key structure and copy to a string
*
* \param ctx: A pointer to the server state structure
* \param output: The output encoded public key string
* \param serverkey: A pointer to the server key structure
*/
QSC_EXPORT_API void qsc_qsmp_server_encode_public_key(qsc_qsmp_kex_server_state* ctx, char output[QSC_QSMP_PUBKEY_STRING_SIZE], const qsc_qsmp_server_key* serverkey);

/**
* \brief Decode a secret signature key structure and copy to a string
*
* \param serverkey: A pointer to the output server key structure
* \param input: The input encoded secret key string
*/
QSC_EXPORT_API void qsc_qsmp_server_deserialize_signature_key(qsc_qsmp_server_key* serverkey, const uint8_t input[QSC_QSMP_SIGKEY_ENCODED_SIZE]);

/**
* \brief Encode a secret key structure and copy to a string
*
* \param output: The output encoded public key string
* \param serverkey: A pointer to the secret server key structure
*/
QSC_EXPORT_API void qsc_qsmp_server_serialize_signature_key(uint8_t output[QSC_QSMP_SIGKEY_ENCODED_SIZE], const qsc_qsmp_server_key* serverkey);

/**
* \brief Initialize a server state structure
*
* \param ctx: A pointer to the server state structure
* \param ckey: [const] A pointer to a server key structure
*/
QSC_EXPORT_API void qsc_qsmp_server_initialize(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_server_key* skey);

/**
* \brief Build a server connection response packet.
* The server generates an asymmetric encryption key-pair, signs the public key, and sends it to client.
*
* \param ctx: A pointer to the server state structure
* \param packetin: [const] A pointer to the input packet structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_server_connection_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout);

/**
* \brief Build a server exstart response packet.
* The server decapsulates the shared secret, loads the symmetric key, and initializes VPN channel-1.
*
* \param ctx: A pointer to the server state structure
* \param packetin: [const] A pointer to the input packet structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_server_exstart_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout);

/**
* \brief Build a server exchange response packet.
* The server decrypts public key, encapsulates the secret for VPN channel-2, and sends to client.
*
* \param ctx: A pointer to the server state structure
* \param packetin: [const] A pointer to the input packet structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_server_exchange_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout);

/**
* \brief Build a server establish response packet.
* The server respose to established, both channels are active, and the VPN is established.
*
* \param ctx: A pointer to the server state structure
* \param packetin: [const] A pointer to the input packet structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_server_establish_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout);

/**
* \brief Decrypt a message and copy it to the message output
*
* \param ctx: A pointer to the server state structure
* \param packetin: [const] A pointer to the input packet structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_server_decrypt_packet(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, uint8_t* message, size_t* msglen);

/**
* \brief Encrypt a message and build an output packet
*
* \param ctx: A pointer to the server state structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_server_encrypt_packet(qsc_qsmp_kex_server_state* ctx, uint8_t* message, size_t msglen, qsc_qsmp_packet* packetout);

/**
* \brief Generate a QSMP key-pair.
* Generates the public and private keys.
*
* \param pubkey: The public key, distributed to clients
* \param prikey: The private key, a secret key known only by the server
* \param keyid: The key identity string
*/
QSC_EXPORT_API void qsc_qsmp_server_generate_keypair(qsc_qsmp_client_key* pubkey, qsc_qsmp_server_key* prikey, const uint8_t keyid[QSC_QSMP_KEYID_SIZE]);

#endif