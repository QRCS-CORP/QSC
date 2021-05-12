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
* \brief <b>QSMP support header</b> \n
* Common parameters and functions of the qclient and qserver implementations.
*
* \author		John G. Underhill
* \version		1.0.0.0a
* \date			May 1, 2021
* \updated		May 1, 2021
* \contact:		develop@vtdev.com
* \copyright	GPL version 3 license (GPLv3)
*
* \remarks
* \section Param Sets:
* kyber-dilithium-rcs256-shake256
* mceliece-sphincs-rcs512-shake512
*
* \section Overview
* Legend:
* -cng: the cryptographic configuration string
* -cprrx: a receive channels symmetric cipher instance
* -cprtx: a transmit channels symmetric cipher instance
* -cpt: the symmetric ciphers cipher-text
* -cpta: the asymmetric ciphers cipher-text
* -kid: the public keys unique identity string
* -pekh: the public asymmetric encryption key hash
* -psk: the public signature verification key
* -sec: a shared secret derived from asymmetric encapsulation and decapsulation
* -spkh: the signed hash of the asymmetric public encapsulation-key
* -sth: the session hash token, a hash of the session token, the configuration string, and the public signature verification-key
* -stok: is a random string used as the session-token in the key exchange
*
* -DAsk: the asymmetric encapsulation function and public key
* -EAsk: the asymmetric decapsulation function and secret key
* -Dk: the symmetric decryption function and key
* -Ek: the symmetric encryption function and key
* -Exp: the key expansion function: cshake-256
* -H: the hash function: sha3-256
* -Mmk: the MAC function and key: kmac-256
* -SAsk sign with the secret signature key
* -VApk verify a signature the public signature key
*
* KEX Sequence
* Connect Request:
* The client first checks the expiration date on the public key, if invalid, it queries the server for a new
* public verification key.
* The client sends a connection request with it's configuration string, protocol version, key identity, and a session token.
* The key identity (kid) is a multi-part 16-byte address and key identity string, used to identify the intended target server and key.
*
* The client stores a hash of the session token, the configuration string, and the public signature verification-key.
* sth = H(stok || cfg || psk)
* The client sends the key identity string, configuration string, and the session token to the server.
* Client{kid, cfg, stok}-> Server
*
* Connect Response:
* The server responds with either an error message, or a response packet.
* The error message can be busy, unrecognized, or unauthorized.
* Any error during the key exchange will generate an error-packet sent to the client, that will tear down the connection on both sides.
* The server stores a hash of the session token, the configuration string, and the public signature verification-key.
* sth = H(stok || cfg || psk)
* The response message contains a signed hash of the asymmetric public encryption-key, and a copy of that key.
* pekh = H(pke)
* spkh = Ssk(pekh)
* Server{spkh, pke}-> Client
*
* Exstart Request:
* The client verifies the signature of the public encrytion keys hash,
* then generates its own hash for the public key, and compares them.
* If the hash matches, the client uses the public-key to encapsulate the shared secret.
* cph = Vsk(H(pk)) cph := ph
* cpta = EApk(sec)
* The client then expands the shared secret and session token hash,
* and uses the output to key the clients transmit-channel cipher.
* k,n = Exp(sec || sth)
* cprtx(k,n)
* Client{cpta}-> Server
*
* Exstart Response:
* The server decapsulates the shared-secret, combines it with the session token hash,
* and keys the servers receive-channel cipher. Channel-1 VPN is established.
* sec = DApk(cpta)
* k,n = Exp(sec, sth)
* cprrx(k,n)
*
* The server sends the client an established message for the first channel.
* Server{m}-> Client
*
* Exchange Request:
* The client generates an asymmetric cipher key-pair, and encrypts the public encapsulation-key using the channel-1 VPN,
* and sends the encrypted encapsulation-key to the server.
* pk,sk = G(cfg)
* cpt = Ek(pk)
* Client{cpt}-> Server
*
* Exchange Response:
* The server decrypts the public encapsulation key, and uses it to encapsulate a shared-secret for channel 2.
* pk = Dk(cpt)
* cpta = EApk(sec)
* The server then expands the shared secret and session token hash, and creates the symmetric ciphers key, nonce, and a mac-key.
* The ciphertext is input to the MAC function, and the output code is added to the message.
* k,n,mk = Exp(sec, sth)
* cc = Mmk(cpta)
* The servers channel-2 transmission channel is initialized, and the authenticated cipher-text is sent to the client.
* cprtx(k,n)
* Server{cc, cpta}-> Client
*
* Established Request:
* The client decapsulates the shared secret, combines it with the session token hash, and expands it.
* sec = DAsk(cpta)
* k,n,mk = Exp(sec, sth)
* The client then computes the mac code for the ciphertext, and compares it with the code appended to the cipher-text.
* mc = Mmk(cpta), mc := cc
* The client then keys the clients receive channel, the second VPN is established,
* and the client sends an established message.
* cprrx(k,n)
* Client{m}-> Server
*
* Established Response:
* The server sends the client an established message, ackowledging both channels are established.
* Server{m}-> Client
*
* Transmission:
* The host, client or server, transmitting a message, first encrypts the message,
* updates the MAC function with the cipher-text, and appends a MAC code to the end of the cipher-text.
* The serialized packet header, including the message size, key identity, and sequence number,
* is added to the MAC state through the additional-data parameter of the authenticated stream cipher RCS.
* This unique data is added to the MAC function with every packet, along with the encrypted cipher-text.
* (cpt || mc) = Ek(sh, m)
*
*The packet is decrypted by serializing the packet header and adding it to the MAC state,
* then finalizing the MAC on the cipher-text and comparing the output code with the code appended to the cipher-text.
* If the code matches, the cipher-text is decrypted, and the message passed up to the application.
* m = Dk(sh, cpt) == 0 ? m : NULL
*/

#ifndef QSC_QSMP_H
#define QSC_QSMP_H

#include "common.h"
#if defined(QSC_QSMP_PUBKEY_SPHINCS)
#	include "mceliece.h"
#	include "sphincsplus.h"
#else
#	include "dilithium.h"
#	include "kyber.h"
#endif

/*!
* \def QSC_QSMP_PUBKEY_SPHINCS
* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece, default is Dilithium/Kyber
*/
#if !defined(QSC_QSMP_PUBKEY_SPHINCS)
//#	define QSC_QSMP_PUBKEY_SPHINCS
#endif

#if defined(QSC_QSMP_PUBKEY_SPHINCS)
/*!
* \def QSC_QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_QSMP_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)
/*!
* \def QSC_QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSC_QSMP_PRIVATEKEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSC_QSMP_PUBLICKEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSC_QSMP_SIGNKEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSC_QSMP_VERIFYKEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSC_QSMP_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)
/*!
* \def QSC_QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	define QSC_QSMP_PUBKEY_ENCODING_SIZE 44
/*!
* \def QSC_QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	define QSC_QSMP_PUBKEY_STRING_SIZE 272
#else
/*!
* \def QSC_QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSC_QSMP_CIPHERTEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)
/*!
* \def QSC_QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSC_QSMP_PRIVATEKEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSC_QSMP_PUBLICKEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSC_QSMP_SIGNKEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSC_QSMP_VERIFYKEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSC_QSMP_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)
/*!
* \def QSC_QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	define QSC_QSMP_PUBKEY_ENCODING_SIZE 1964
/*!
* \def QSC_QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	define QSC_QSMP_PUBKEY_STRING_SIZE 2222
#endif

/*!
* \def QSC_QSMP_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define QSC_QSMP_CONFIG_SIZE 40
/*!
* \def QSC_QSMP_HASH_SIZE
* \brief The size of the hash function output
*/
#define QSC_QSMP_HASH_SIZE 32
/*!
* \def QSC_QSMP_HEADER_SIZE
* \brief The QSMP packet header size
*/
#define QSC_QSMP_HEADER_SIZE 9
/*!
* \def QSC_QSMP_KEYID_SIZE
* \brief The QSMP key identity size
*/
#define QSC_QSMP_KEYID_SIZE 16
/*!
* \def QSC_QSMP_MACKEY_SIZE
* \brief The QSMP mac key size
*/
#define QSC_QSMP_MACKEY_SIZE 32
/*!
* \def QSC_QSMP_MACTAG_SIZE
* \brief The size of the mac function output
*/
#define QSC_QSMP_MACTAG_SIZE 32
/*!
* \def QSC_QSMP_TIMESTAMP_SIZE
* \brief The key expiration timestamp size
*/
#define QSC_QSMP_TIMESTAMP_SIZE 8
/*!
* \def QSC_QSMP_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (may exceed mtu)
*/
#define QSC_QSMP_MESSAGE_MAX (QSC_QSMP_SIGNATURE_SIZE + QSC_QSMP_PUBLICKEY_SIZE + QSC_QSMP_HASH_SIZE + QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_PKCODE_SIZE
* \brief The size of the session token hash
*/
#define QSC_QSMP_PKCODE_SIZE 32
/*!
* \def QSC_QSMP_PUBKEY_DURATION_DAYS
* \brief The number of days a public key remains valid
*/
#define QSC_QSMP_PUBKEY_DURATION_DAYS 365
/*!
* \def QSC_QSMP_PUBKEY_DURATION_SECONDS
* \brief The number of seconds a public key remains valid
*/
#define QSC_QSMP_PUBKEY_DURATION_SECONDS (QSC_QSMP_PUBKEY_DURATION_DAYS * 24 * 60 * 60)
/*!
* \def QSC_QSMP_PUBKEY_LINE_LENGTH
* \brief The line length of the printed QSMP public key
*/
#define QSC_QSMP_PUBKEY_LINE_LENGTH 64
/*!
* \def QSC_QSMP_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define QSC_QSMP_SECRET_SIZE 32
/*!
* \def QSC_QSMP_STOKEN_SIZE
* \brief The session token size
*/
#define QSC_QSMP_STOKEN_SIZE 32
/*!
* \def QSC_QSMP_SIGKEY_ENCODED_SIZE
* \brief The secret signature key size
*/
#define QSC_QSMP_SIGKEY_ENCODED_SIZE (QSC_QSMP_KEYID_SIZE + QSC_QSMP_TIMESTAMP_SIZE + QSC_QSMP_CONFIG_SIZE + QSC_QSMP_SIGNKEY_SIZE + QSC_QSMP_VERIFYKEY_SIZE)

static const char QSC_QSMP_CONFIG_DLMKBR[QSC_QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s2_sha3-256_rcs-256 ";
static const char QSC_QSMP_CONFIG_SPXMPK[QSC_QSMP_CONFIG_SIZE] = "sphincs-s2_mceliece-s2_rcs-512_sha3-512";
static const char QSC_QSMP_PUBKEY_HEADER[] = "------BEGIN QSMP PUBLIC KEY BLOCK------";
static const char QSC_QSMP_PUBKEY_VERSION[] = "Version: QSMP v1.0";
static const char QSC_QSMP_PUBKEY_CONFIG_PREFIX[] = "Configuration: ";
static const char QSC_QSMP_PUBKEY_KEYID_PREFIX[] = "Host ID: ";
static const char QSC_QSMP_PUBKEY_EXPIRATION_PREFIX[] = "Expiration: ";
static const char QSC_QSMP_PUBKEY_FOOTER[] = "------END QSMP PUBLIC KEY BLOCK------";

/*!
* \enum qsc_qsmp_configuration
* \brief The cryptographic asymmetric primitive configuration
*/
QSC_EXPORT_API typedef enum qsc_qsmp_configuration
{
	qsc_qsmp_configuration_none = 0,				/*!< No configuration was specified */
	qsc_qsmp_configuration_sphincs_mceliece = 1,	/*!< The Sphincs+ and McEliece configuration */
	qsc_qsmp_configuration_dilithium_kyber = 2,		/*!< The Dilithium and Kyber configuration */
} qsc_qsmp_configuration;

/*!
* \enum qsc_qsmp_errors
* \brief The QSMP error values
*/
QSC_EXPORT_API typedef enum qsc_qsmp_errors
{
	qsc_qsmp_error_none = 0,						/*!< No error was detected */
	qsc_qsmp_authentication_failure = 1,			/*!< The symmetric cipher had an authentication failure */
	qsc_qsmp_random_failure = 2,					/*!< The random generator has failed */
	qsc_qsmp_key_expired = 3,						/*!< The QSMP public key has expired  */
	qsc_qsmp_invalid_request = 4,					/*!< The packet flag was unexpected */
	qsc_qsmp_decapsulation_failure = 5,				/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qsc_qsmp_channel_down = 6,						/*!< The communications channel has failed */
	qsc_qsmp_hash_invalid = 7,						/*!< The expected hash was not generated */
	qsc_qsmp_invalid_input = 8,						/*!< The expected input was invalid */

} qsc_qsmp_errors;

/*!
* \enum qsc_qsmp_flags
* \brief The QSMP packet flags
*/
QSC_EXPORT_API typedef enum qsc_qsmp_flags
{
	qsc_qsmp_message_none = 0x00,					/*!< No flag was specified */
	qsc_qsmp_message_connect_request = 0x01,		/*!< The QSMP key-exchange client connection request flag  */
	qsc_qsmp_message_connect_response = 0x02,		/*!< The QSMP key-exchange server connection response flag */
	qsc_qsmp_message_exstart_request = 0x03,		/*!< The QSMP key-exchange client exstart request flag */
	qsc_qsmp_message_exstart_response = 0x04,		/*!< The QSMP key-exchange server exstart response flag */
	qsc_qsmp_message_exchange_request = 0x05,		/*!< The QSMP key-exchange client exchange request flag */
	qsc_qsmp_message_exchange_response = 0x06,		/*!< The QSMP key-exchange server exchange response flag */
	qsc_qsmp_message_establish_request = 0x07,		/*!< The QSMP key-exchange client establish request flag */
	qsc_qsmp_message_establish_response = 0x08,		/*!< The QSMP key-exchange server establish response flag */
	qsc_qsmp_message_remote_connected = 0x09,		/*!< The remote host is connected to the VPN */
	qsc_qsmp_message_remote_terminated = 0x0A,		/*!< The remote host has terminated the connection */
	qsc_qsmp_message_session_established = 0x0B,	/*!< The VPN is in the established state */
	qsc_qsmp_message_encrypted_message = 0x0C,		/*!< The message has been encrypted by the VPN */
	qsc_qsmp_message_connection_terminate = 0x0D,	/*!< The connection is to be terminated */
	qsc_qsmp_message_error_condition = 0xFF,		/*!< The connection experienced an error */
} qsc_qsmp_flags;

/*!
* \struct qsc_qsmp_packet
* \brief The QSMP packet structure
*/
QSC_EXPORT_API typedef struct qsc_qsmp_packet
{
	uint8_t flag;									/*!< The packet flag */
	uint32_t msglen;								/*!< The packets message length */
	uint32_t sequence;								/*!< The packet sequence number */
	uint8_t message[QSC_QSMP_MESSAGE_MAX];			/*!< The packets message data */
} qsc_qsmp_packet;

/*!
* \struct qsc_qsmp_client_key
* \brief The QSMP client key structure
*/
QSC_EXPORT_API typedef struct qsc_qsmp_client_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSC_QSMP_CONFIG_SIZE];			/*!< The primitive configuration string */
	uint8_t keyid[QSC_QSMP_KEYID_SIZE];				/*!< The key identity string */
	uint8_t verkey[QSC_QSMP_VERIFYKEY_SIZE];		/*!< The asymmetric signatures verification-key */
} qsc_qsmp_client_key;


/**
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSC_EXPORT_API void qsc_qsmp_packet_clear(qsc_qsmp_packet* packet);

/**
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSC_EXPORT_API void qsc_qsmp_packet_error_message(qsc_qsmp_packet* packet, qsc_qsmp_errors error);

/**
* \brief Deserialize a byte array to a packet header
*
* \param packet: The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
QSC_EXPORT_API void qsc_qsmp_packet_header_deserialize(const uint8_t* header, qsc_qsmp_packet* packet);

/**
* \brief Serialize a packet header to a byte array
*
* \param packet: A pointer to the packet structure to serialize
* \param header: The header byte array
*/
QSC_EXPORT_API void qsc_qsmp_packet_header_serialize(const qsc_qsmp_packet* packet, uint8_t* header);

/**
* \brief Serialize a packet to a byte array
*
* \param packet: The header byte array to deserialize
* \param pstream: A pointer to the packet structure
*/
QSC_EXPORT_API size_t qsc_qsmp_packet_to_stream(const qsc_qsmp_packet* packet, uint8_t* pstream);

/**
* \brief Deserialize a byte array to a packet
*
* \param pstream: The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
QSC_EXPORT_API void qsc_qsmp_stream_to_packet(const uint8_t* pstream, qsc_qsmp_packet* packet);

#endif