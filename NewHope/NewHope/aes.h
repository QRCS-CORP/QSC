/* 
* Implementation Details:
* An implementation of the Rijndael (AES) symmetric block cipher.
* Written by John Underhill, May 7, 2018
* Contact: develop@vtdev.com */

/*!
* \author    John Underhill
* \version   1.0.0.0
* \date      May 7, 2018
* \copyright Public Domain
*/

/**
* \file aes.h
* \brief <b>AES header definition</b> \n
* Rijndael SHAKE Extended.
*
* \author John Underhill
* \date January 17, 2018
*
* <b>AES256 CTR Example</b> \n
* \code
* // transform a single block of bytes
* uint32_t roundkeys[AES256_ROUNDKEY_DIMENSION];
* uint8_t output[16];
*
* // use the external input key to initialize the key-schedule and output the round key array
* aes_initialize(roundkeys, inputkey, true, AES256);
* // pass in the iv and message (external), and the round key array, and encrypt the message to output
* aes_ctr_transform(output, iv, message, roundkeys, AES256_ROUNDKEY_DIMENSION);
* \endcode
*
* \remarks For usage examples, see aes_kat.h. \n
* To enable AES-NI, add AES_AESNI_ENABLED to the preprocessor definitions.
*/

#ifndef AES_H
#define AES_H

//#define AES_AESNI_ENABLED /* just for testing, use preprocessor */

#include <cstdbool>
#include <stdint.h>

/* bogus integral type warnings */
/*lint -e970 */
/*lint -e731 */

#ifdef AES_AESNI_ENABLED
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
	GCM = 4		/*!< galois counter mode */
} cipher_mode;

/*! \enum cipher_type
* The pre-defined cipher implementations
*/
typedef enum
{
	AES128 = 1,	/*!< standard AES128 implementation */
	AES256 = 2	/*!< standard AES256 implementation */
} cipher_type;

/*!
\def AES_BLOCK_SIZE
* The number of input/output bytes required by the function
*/
#define AES_BLOCK_SIZE 16

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
\def ROUNDKEY_ELEMENT_SIZE
* The size in bytes of the round key array elements
*/
#ifdef AES_AESNI_ENABLED
#	define ROUNDKEY_ELEMENT_SIZE 16
#else
#	define ROUNDKEY_ELEMENT_SIZE 4
#endif

/*!
\def AES128_ROUNDKEY_DIMENSION
* The number of rounds keys (array elements) used by AES128
*/
#define AES128_ROUNDKEY_DIMENSION ((AES128_ROUND_COUNT + 1) * (AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def AES256_ROUNDKEY_DIMENSION
* The number of rounds keys (array elements) used by AES256
*/
#define AES256_ROUNDKEY_DIMENSION ((AES256_ROUND_COUNT + 1) * (AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

//#define AES_PREFETCH_TABLES

/* Public API */

#ifdef AES_AESNI_ENABLED

	/**
	* \brief Decrypt one (16 byte) block of cipher-text using Cipher Block Chaining (CBC) mode.
	*
	* \param output The output byte array; receives the decrypted plain-text
	* \param iv The initialization vector; must be 16 bytes in length
	* \param input The input cipher-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_cbc_decrypt(uint8_t* output, uint8_t* iv, const uint8_t* input, const __m128i* rkeys, size_t rkeylen);

	/**
	* \brief Encrypt one (16 byte) block of plain-text using Cipher Block Chaining (CBC) mode.
	*
	* \param output The output byte array; receives the encrypted cipher-text
	* \param iv The initialization vector; must be 16 bytes in length
	* \param input The input plain-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_cbc_encrypt(uint8_t* output, uint8_t* iv, const uint8_t* input, const __m128i* rkeys, size_t rkeylen);

	/**
	* \brief Encrypt/Decrypt one (16 byte) block of plain-text using a segmented integer counter (CTR) mode.
	* \param output The output byte array; receives the encrypted cipher-text
	* \param nonce The initialization vector; must be 16 bytes in length
	* \param input The input plain-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_ctr_transform(uint8_t* output, uint8_t* nonce, const uint8_t* input, const __m128i* rkeys, size_t rkeylen);

	/**
	* \brief Decrypt one (16 byte) block of cipher-text using Electronic CodeBook Mode (ECB) mode. \n
	* ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
	*
	* \param output The output byte array; receives the decrypted plain-text
	* \param input The input cipher-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_ecb_decrypt(uint8_t* output, const uint8_t* input, const __m128i* rkeys, size_t rkeylen);

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
	void aes_ecb_encrypt(uint8_t* output, const uint8_t* input, const __m128i* rkeys, size_t rkeylen);

	/**
	* \brief Initialize the round key array (key schedule) to the rkey array. \n
	*
	* \param roundkeys The output array of round keys generated by the key schedule
	* \param inputkey The input cipher-key, expanded to the rkeys array
	* \param encryption Initialize the key scheduule for encryption, false for decryption
	* \param cipher The cipher type; (AES128 or AES256) determines the rkey size, and how the round keys are generated
	*/
	void aes_initialize(__m128i* roundkeys, const uint8_t* inputkey, bool encryption, cipher_type cipher);

#else

	/**
	* \brief Decrypt one (16 byte) block of cipher-text using Cipher Block Chaining (CBC) mode.
	*
	* \param output The output byte array; receives the decrypted plain-text
	* \param iv The initialization vector; must be 16 bytes in length
	* \param input The input cipher-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_cbc_decrypt(uint8_t* output, uint8_t* iv, const uint8_t* input, const uint32_t* rkeys, size_t rkeylen);

	/**
	* \brief Encrypt one (16 byte) block of plain-text using Cipher Block Chaining (CBC) mode.
	*
	* \param output The output byte array; receives the encrypted cipher-text
	* \param iv The initialization vector; must be 16 bytes in length
	* \param input The input plain-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_cbc_encrypt(uint8_t* output, uint8_t* iv, const uint8_t* input, const uint32_t* rkeys, size_t rkeylen);

	/**
	* \brief Encrypt/Decrypt one (16 byte) block of plain-text using a segmented integer counter (CTR) mode.
	* \param output The output byte array; receives the encrypted cipher-text
	* \param nonce The initialization vector; must be 16 bytes in length
	* \param input The input plain-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_ctr_transform(uint8_t* output, uint8_t* nonce, const uint8_t* input, const uint32_t* rkeys, size_t rkeylen);

	/**
	* \brief Decrypt one (16 byte) block of cipher-text using Electronic CodeBook Mode (ECB) mode. \n
	* ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
	*
	* \param output The output byte array; receives the decrypted plain-text
	* \param input The input cipher-text block of bytes
	* \param rkeys The round key array, generated with the initialize function
	* \param rkeylen The number of round keys in the rkey array
	*/
	void aes_ecb_decrypt(uint8_t* output, const uint8_t* input, const uint32_t* rkeys, size_t rkeylen);

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
	void aes_ecb_encrypt(uint8_t* output, const uint8_t* input, const uint32_t* rkeys, size_t rkeylen);

	/**
	* \brief Initialize the round key array (key schedule) to the rkey array. \n
	*
	* \param roundkeys The output array of round keys generated by the key schedule
	* \param inputkey The input cipher-key, expanded to the rkeys array
	* \param encryption Initialize the key scheduule for encryption, false for decryption
	* \param cipher The cipher type; (AES128 or AES256) determines the rkey size, and how the round keys are generated
	*/
	void aes_initialize(uint32_t* roundkeys, const uint8_t* inputkey, bool encryption, cipher_type cipher);

#endif

#endif
