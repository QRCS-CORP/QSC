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
* \file qsmp.h
* \brief <b>QSMP Client functions</b> \n
* Functions used to implement the client in the Quantum Secure Messaging Protocol (QSMP) VPN.
*
* \author		John G. Underhill
* \version		1.0.0.0a
* \date			May 1, 2021
* \updated		May 1, 2021
* \contact:		develop@vtdev.com
* \copyright	GPL version 3 license (GPLv3)
*/

#ifndef QSC_QSMP_CLIENT_H
#define QSC_QSMP_CLIENT_H

#include "qsmp.h"
#include "rcs.h"

/*!
* \struct qsc_qsmp_client_key
* \brief The QSMP client state structure
*/
QSC_EXPORT_API typedef struct qsc_qsmp_kex_client_state
{
	qsc_rcs_state rxcpr;						/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;						/*!< The transmit channel cipher state */
	uint8_t config[QSC_QSMP_CONFIG_SIZE];		/*!< The primitive configuration string */
	uint8_t keyid[QSC_QSMP_KEYID_SIZE];			/*!< The key identity string */
	uint8_t pkhash[QSC_QSMP_PKCODE_SIZE];		/*!< The session token hash */
	uint8_t prikey[QSC_QSMP_PRIVATEKEY_SIZE];	/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSC_QSMP_PUBLICKEY_SIZE];	/*!< The asymmetric cipher public key */
	uint8_t token[QSC_QSMP_STOKEN_SIZE];		/*!< The session token */
	uint8_t verkey[QSC_QSMP_VERIFYKEY_SIZE];	/*!< The asymmetric signature verification-key */
	qsc_qsmp_flags exflag;						/*!< The KEX position flag */
	uint64_t expiration;						/*!< The expiration time, in seconds from epoch */
} qsc_qsmp_kex_client_state;

/**
* \brief Decode a public key string and populate a client key structure
*
* \param clientkey: A pointer to the output client key
* \param input: [const] The input encoded key
*/
QSC_EXPORT_API void qsc_qsmp_client_decode_public_key(qsc_qsmp_client_key* clientkey, const char input[QSC_QSMP_PUBKEY_STRING_SIZE]);

/**
* \brief Dispose of a client state structure
*
* \param ctx: A pointer to the client state structure
*/
QSC_EXPORT_API void qsc_qsmp_client_dispose(qsc_qsmp_kex_client_state* ctx);

/**
* \brief Initialize a client state structure
*
* \param ctx: A pointer to the client state structure
* \param ckey: [const] A pointer to a client key structure
*/
QSC_EXPORT_API void qsc_qsmp_client_initialize(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_client_key* ckey);

/**
* \brief Build a client connection request packet.
* The client sends a session token, configuration string, and version string, and initiates a connection request.
*
* \param ctx: A pointer to the client state structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_client_connection_request(qsc_qsmp_kex_client_state* ctx, qsc_qsmp_packet* packetout);

/**
* \brief Build a client exstart request packet.
* The client verifies public encapsulation key, creates the shared secret, 
* initializes the client transmit channel, encapsulates the secret, and sends to server.
*
* \param ctx: A pointer to the client state structure
* \param packetin: [const] A pointer to the input packet structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_client_exstart_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout);

/**
* \brief Build a client exchange request packet.
* The client generates its own asymmetric encryption key-pair, and sends the public key to the server over the encrypted channel.
*
* \param ctx: A pointer to the client state structure
* \param packetin: [const] A pointer to the input packet structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_client_exchange_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout);

/**
* \brief Build a client establish request packet.
* The client decrypts the secret, and establishes channel 2, sends an established response.
*
* \param ctx: A pointer to the client state structure
* \param packetin: [const] A pointer to the input packet structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_client_establish_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout);

/**
* \brief Decrypt a message and copy it to the message output
*
* \param ctx: A pointer to the client state structure
* \param packetin: [const] A pointer to the input packet structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_client_decrypt_packet(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, uint8_t* message, size_t* msglen);

/**
* \brief Encrypt a message and build an output packet
*
* \param ctx: A pointer to the client state structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
QSC_EXPORT_API qsc_qsmp_errors qsc_qsmp_client_encrypt_packet(qsc_qsmp_kex_client_state* ctx, const uint8_t* message, size_t msglen, qsc_qsmp_packet* packetout);

#endif