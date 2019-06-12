/* The GPL version 3 License (GPLv3)
* 
* Copyright (c) 2017 vtdev.com
* This file is part of the CEX Cryptographic library.
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
* 
*
* Implementation Details:
* An implementation of the Rijndael Shake eXtended (RSX) symmetric block cipher.
* Written by John Underhill, January 17, 2018
* Contact: develop@vtdev.com */

/*!
* \mainpage <b>The RSX cipher</b>
* \section intro_sec Welcome
* The RSX (Rijndael Shake eXtended) cipher, is a hybrid of Rijndael (AES) and the Keccak SHAKE-256 extended output function. \n
* The cipher has four modes, AES128 and AES256, which are the standard AES configurations, and two extended modes, RSX256 and RSX512. \n
* In extended mode, the key schedule has been replaced by SHAKE-256, which can safely produce a larger round-key array,  \n
* enabling an increased number of mixing rounds.
* The extended cSHAKE implementation can also be used, by passing the custumization string and length, through the keyparams structure. \n
* AES-128 has a round count of 10, AES-256 is 14 rounds, RSX-256 is 22 rounds, and RSX-512, which uses a 512 bit cipher input-key, uses 30 rounds. \n
* Increasing the number of rounds, increases the amount of diffusion applied to the state, which makes rijndael harder to break with differentially based attacks,  \n
* and by increasing the key size, maintains a high margin of security against future attacks by quantum computers.
* 
* \section Implementation
* The base cipher, Rijndael, and the extended form of the cipher, can operate using one of the three provided cipher modes of operation: \n
* Electronic Code Book mode (ECB), which can be used for testing or creating more complex algorithms,  \n
* a segmented integer counter (CTR), and the Cipher Block Chaining mode (CBC). \n
* This implementation has both a C reference, and an implementation that uses the AES-NI instructions. \n
* The AES-NI implementation can be enabled by adding the RSX_AESNI_ENABLED constant to your preprocessor definitions. \n
* The AES128 and AES256 implementations along with the CBC, CTR, and CBC modes are tested using vectors from SP800-38a. \n
* SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a> \n
* See the documentation and the aes_kat.h tests for usage examples.
*
* \author    John Underhill
* \version   1.1.0.0
* \date      April 12, 2018
* \copyright GPL version 3 license (GPLv3)
*/

/**
* \file rsx.h
* \brief <b>RSX header definition</b> \n
* Rijndael SHAKE Extended.
*
* \author John Underhill
* \date January 17, 2018
*
* <b>RSX256 CTR Example</b> \n
* \code
* // initialize the keyparams structure
* rsx_keyparams kp = { key, 32 };
* uint8_t output[16];
*
* // initialize the roundkey array for the state
* #if defined(RSX_AESNI_ENABLED)
*	__m128i rkeys[RSX256_ROUNDKEY_DIMENSION];
* #else
*	uint32_t rkeys[RSX256_ROUNDKEY_DIMENSION];
* #endif
*
* rsx_state state = { rkeys, RSX256_ROUNDKEY_DIMENSION };
*
* // initialize the cipher
* rsx_initialize(&state, &kp, true);
* // pass in the iv and message (external), and encrypt the 1 block message to output
* rsx_ctr_transform(&state, output, iv, message);
* note: the counter/state are updated internally
* \endcode
*
* \remarks For usage examples, see rsx_kat.h. \n
* To enable AES-NI, add RSX_AESNI_ENABLED to the preprocessor definitions.
*/

#ifndef RSX_H
#define RSX_H

//#define RSX_AESNI_ENABLED /* just for testing, use preprocessor */

#include <stdbool.h>
#include <stdint.h>
#include "sha3.h"
#if defined(RSX_AESNI_ENABLED)
#	include <wmmintrin.h>
#endif

/*! \enum cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum
{
	CBC = 1,	/*!< cipher block chaining */
	CTR = 2,	/*!< segmented integer counter */
	ECB = 3,	/*!< electronic codeBook mode */
} cipher_mode;

typedef struct rsx_keyparams
{
	uint8_t* key;
	size_t keylen;
	uint8_t* dcode;
	size_t codelen;
} rsx_keyparams;

typedef struct rsx_state
{
#if defined(RSX_AESNI_ENABLED)
	__m128i* roundkeys;
#else
	uint32_t* roundkeys;
#endif
	size_t rkeylen;
} rsx_state;

/*!
\def RSX_BLOCK_SIZE
* The number of input/output bytes required by the function
*/
#define RSX_BLOCK_SIZE 16

/*!
\def AES128_KEY_SIZE
* The size in bytes of the AES128 input cipher-key
*/
#define AES128_KEY_SIZE 16

/*!
\def AES256_KEY_SIZE
* The size in bytes of the AES256 input cipher-key
*/
#define AES256_KEY_SIZE 32

/*!
\def RSX256_KEY_SIZE
* The size in bytes of the RSX256 input cipher-key
*/
#define RSX256_KEY_SIZE 32

/*!
\def RSX512_KEY_SIZE
* The size in bytes of the RSX512 input cipher-key
*/
#define RSX512_KEY_SIZE 64

/*!
\def AES128_ROUND_COUNT
* The number of rijndael rounds used by AES128
*/
#define AES128_ROUND_COUNT 10

/*!
\def AES256_ROUND_COUNT
* The number of rijndael rounds used by AES256
*/
#define AES256_ROUND_COUNT 14

/*!
\def RSX256_ROUND_COUNT
* The number of rijndael rounds used by RSX256
*/
#define RSX256_ROUND_COUNT 22

/*!
\def RSX512_ROUND_COUNT
* The number of rijndael rounds used by RSX512
*/
#define RSX512_ROUND_COUNT 30

/*!
\def ROUNDKEY_ELEMENT_SIZE
* The size in bytes of the round key array elements
*/
#if defined(RSX_AESNI_ENABLED)
#	define ROUNDKEY_ELEMENT_SIZE 16
#else
#	define ROUNDKEY_ELEMENT_SIZE 4
#	define RSX_PREFETCH_TABLES
#endif

/*!
\def AES128_ROUNDKEY_DIMENSION
* The number of rounds keys (array elements) used by AES128
*/
#define AES128_ROUNDKEY_DIMENSION ((AES128_ROUND_COUNT + 1) * (RSX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def AES256_ROUNDKEY_DIMENSION
* The number of rounds keys (array elements) used by AES256
*/
#define AES256_ROUNDKEY_DIMENSION ((AES256_ROUND_COUNT + 1) * (RSX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RSX256_ROUNDKEY_DIMENSION
* The number of rounds keys (array elements) used by RSX256
*/
#define RSX256_ROUNDKEY_DIMENSION ((RSX256_ROUND_COUNT + 1) * (RSX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RSX512_ROUNDKEY_DIMENSION
* The number of rounds keys (array elements) used by RSX512
*/
#define RSX512_ROUNDKEY_DIMENSION ((RSX512_ROUND_COUNT + 1) * (RSX_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/* Public API */

/**
* \brief Decrypt one (16 byte) block of cipher-text using Cipher Block Chaining (CBC) mode.
*
* \param output The output byte array; receives the decrypted plain-text
* \param iv The initialization vector; must be 16 bytes in length
* \param input The input cipher-text block of bytes
* \param rkeys The round key array, generated with the initialize function
* \param rkeylen The number of round keys in the rkey array
*/
void rsx_cbc_decrypt(rsx_state* state, uint8_t* output, uint8_t* iv, const uint8_t* input);

/**
* \brief Encrypt one (16 byte) block of plain-text using Cipher Block Chaining (CBC) mode.
*
* \param output The output byte array; receives the encrypted cipher-text
* \param iv The initialization vector; must be 16 bytes in length
* \param input The input plain-text block of bytes
* \param rkeys The round key array, generated with the initialize function
* \param rkeylen The number of round keys in the rkey array
*/
void rsx_cbc_encrypt(rsx_state* state, uint8_t* output, uint8_t* iv, const uint8_t* input);

/**
* \brief Encrypt/Decrypt one (16 byte) block of plain-text using a segmented integer counter (CTR) mode.
*
* \param output The output byte array; receives the encrypted cipher-text
* \param nonce The initialization vector; must be 16 bytes in length
* \param input The input plain-text block of bytes
* \param rkeys The round key array, generated with the initialize function
* \param rkeylen The number of round keys in the rkey array
*/
void rsx_ctr_transform(rsx_state* state, uint8_t* output, uint8_t* nonce, const uint8_t* input);

/**
* \brief Decrypt one (16 byte) block of cipher-text using Electronic CodeBook Mode (ECB) mode. \n
* ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param output The output byte array; receives the decrypted plain-text
* \param input The input cipher-text block of bytes
* \param rkeys The round key array, generated with the initialize function
* \param rkeylen The number of round keys in the rkey array
*/
void rsx_ecb_decrypt(rsx_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Encrypt one (16 byte) block of cipher-text using Electronic CodeBook Mode (ECB) mode. \n
* ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
* 
*
* \param output The output byte array; receives the encrypted cipher-text
* \param input The input plain-text block of bytes
* \param rkeys The round key array, generated with the initialize function
* \param rkeylen The number of round keys in the rkey array
*/
void rsx_ecb_encrypt(rsx_state* state, uint8_t* output, const uint8_t* input);

/**
* \brief Initialize the round key array (key schedule) to the rkey array. \n
* AES128 and AES256 use the traditional rijndael key schedule, RSX256 and RSX512 use the SHAKE256 kdf.
*
* \param roundkeys The output array of round keys generated by the key schedule
* \param inputkey The input cipher-key, expanded to the rkeys array
* \param encryption Initialize the key scheduule for encryption, false for decryption
* \param cipher The cipher type; (AES128, AES256, RSX256, or RSX512) determines the rkey size, and how the round keys are generated
*/
int32_t rsx_initialize(rsx_state* state, rsx_keyparams* keyparams, bool encryption);

#endif
