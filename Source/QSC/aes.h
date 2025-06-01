/* 
 * ================= LICENSE INFORMATION =================
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_AES_H
#define QSC_AES_H

#include "qsccommon.h"
#include "intrinsics.h"

/*! \def QSC_HBA_KMAC_EXTENSION
 * \brief Enables the cSHAKE/KMAC extensions for the HBA cipher mode.
 *
 * When defined, the HBA-256 mode uses cSHAKE/KMAC for message authentication.
 */
#define QSC_HBA_KMAC_EXTENSION

/*! \def QSC_HBA_HKDF_EXTENSION
 * \brief Enables the HKDF extensions for the HBA cipher mode as an alternative to the cSHAKE mode.
 *
 * When defined (and if QSC_HBA_KMAC_EXTENSION is not defined), HMAC(SHA2) is used by default.
 */
#define QSC_HBA_HKDF_EXTENSION

#if defined(QSC_HBA_KMAC_EXTENSION)
#	include "sha3.h"
#else
#	include "sha2.h"
#endif

/*!
 * \file aes.h
 * \brief An implementation of the AES symmetric cipher along with modes and an AEAD scheme.
 *
 * \details
 * This header provides the interface for an implementation of the AES block cipher.
 * Supported features include:
 *   - AES-128 and AES-256 key sizes.
 *   - Multiple cipher modes: Cipher Block Chaining (CBC), Counter (CTR) with both Big Endian 
 *     and Little Endian counter increments, and Electronic Code Book (ECB).
 *   - PKCS#7 padding for block alignment.
 *   - A Hash-Based Authenticated (HBA-256) mode for authenticated encryption using AES-256.
 *
 * The HBA-256 mode supports both cSHAKE-based (via KMAC) and HKDF-based authentication.
 * See QSC_HBA_KMAC_EXTENSION and QSC_HBA_HKDF_EXTENSION for details on enabling each mode.
 *
 * \par Example Usage (AES-256 CTR mode):
 * \code
 * #include "aes.h"
 *
 * const size_t MSG_LEN = 200;
 * const size_t CST_LEN = 20;
 * uint8_t msg[MSG_LEN] = { 0U };
 * uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
 * uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0U };
 * uint8_t cust[CST_LEN] = { 0U };
 *
 * uint8_t output[MSG_LEN] = { 0U };
 * qsc_aes_keyparams kp = { .key = key, .keylen = QSC_AES256_KEY_SIZE, .nonce = nonce, .noncelen = QSC_AES_BLOCK_SIZE, .info = cust, .infolen = CST_LEN };
 *
 * qsc_aes_state ctx;
 * qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
 * qsc_aes_ctrbe_transform(&ctx, output, msg, MSG_LEN);
 * \endcode
 *
 * \sa qsc_aes_initialize, qsc_aes_dispose, qsc_aes_cbc_encrypt, qsc_aes_ctrbe_transform, qsc_aes_hba256_initialize
 *
 * \section aes_links Reference Links
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf">AES Specification NIST FIPS 197</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">CBC and CTR Mode (NIST SP 800-38A)</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 Implementation NIST FIPS 202</a>
 */

QSC_CPLUSPLUS_ENABLED_START

/*! 
 * \enum qsc_aes_cipher_type
 * \brief Pre-defined cipher key sizes for AES.
 *
 * The enumeration lists supported AES cipher types.
 */
typedef enum
{
	qsc_aes_cipher_128 = 0x01U,	/*!< AES-128 block cipher (128-bit key) */
	qsc_aes_cipher_256 = 0x02U	/*!< AES-256 block cipher (256-bit key) */
} qsc_aes_cipher_type;

/*! 
 * \enum qsc_aes_cipher_mode
 * \brief Pre-defined AES cipher mode implementations.
 *
 * Modes include CBC (Cipher Block Chaining), CTR (Counter mode), and ECB (Electronic Code Book).
 * Note: ECB mode is considered insecure and should only be used for testing or as a building block.
 */
typedef enum
{
	qsc_aes_mode_cbc = 0x01U,	/*!< Cipher Block Chaining (CBC) mode */
	qsc_aes_mode_ctr = 0x02U,	/*!< Counter (CTR) mode using a segmented integer counter */
	qsc_aes_mode_ecb = 0x03U	/*!< Electronic CodeBook (ECB) mode (insecure) */
} qsc_aes_cipher_mode;

/***********************************
*     AES CONSTANTS AND SIZES      *
***********************************/

/*!
 * \def QSC_AES_BLOCK_SIZE
 * \brief Internal AES block size in bytes.
 *
 * All AES operations use a fixed block size of 16 bytes.
 */
#define QSC_AES_BLOCK_SIZE 16U

/*!
 * \def QSC_AES_IV_SIZE
 * \brief Initialization vector (IV) size in bytes.
 *
 * The IV (or nonce) size is equal to the block size.
 */
#define QSC_AES_IV_SIZE 16U

/*!
 * \def QSC_AES128_KEY_SIZE
 * \brief Key size in bytes for AES-128.
 */
#define QSC_AES128_KEY_SIZE 16U

/*!
 * \def QSC_AES256_KEY_SIZE
 * \brief Key size in bytes for AES-256.
 */
#define QSC_AES256_KEY_SIZE 32U

/*!
 * \def QSC_GCM256_MAC_SIZE
 * \brief Size in bytes of the MAC code for GCM-AES-256.
 */
#define QSC_GCM256_MAC_SIZE 16U

/*!
 * \def QSC_GCM_MAXAAD_SIZE
 * \brief Maximum allowed size (in bytes) for Associated Additional Data (AAD) in GCM.
 */
#define QSC_GCM_MAXAAD_SIZE 256U

/*!
 * \def QSC_GCM_NONCE_SIZE
 * \brief The standard nonce size used by GCM-AES-256.
 */
#define QSC_GCM_NONCE_SIZE 12U

/*!
 * \def QSC_HBA256_MAC_SIZE
 * \brief Size in bytes of the MAC code for HBA-256.
 */
#define QSC_HBA256_MAC_SIZE 32U

/*!
 * \def QSC_HBA_MAXAAD_SIZE
 * \brief Maximum allowed size (in bytes) for Associated Additional Data (AAD) in HBA.
 */
#define QSC_HBA_MAXAAD_SIZE 256U

/*!
 * \def QSC_HBA_MAXINFO_SIZE
 * \brief Maximum allowed size (in bytes) for key information tweaks in HBA.
 */
#define QSC_HBA_MAXINFO_SIZE 256U

/*!
 * \def QSC_HBA_KMAC_AUTH
 * \brief When defined, enables the use of KMAC for authenticating HBA.
 *
 * If QSC_HBA_KMAC_EXTENSION is disabled, HMAC (SHA2) is used by default.
 */
#if defined(QSC_HBA_KMAC_EXTENSION)
#	define QSC_HBA_KMAC_AUTH
#endif

/*! 
 * \struct qsc_aes_keyparams
 * \brief Structure for AES key parameters.
 *
 * This structure contains pointers to the key, nonce, and optional info data
 * used to initialize the AES cipher ctx.
 *
 * \note The key must be random and secret. The info field is optional (e.g., a salt).
 */
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;   /*!< [const] Pointer to the input cipher key */
	size_t keylen;        /*!< [size_t] Length (in bytes) of the cipher key */
	uint8_t* nonce;       /*!< [uint8_t*] Pointer to the nonce or initialization vector */
	size_t noncelen;	  /*!< [size_t] Length (in bytes) of the nonce */
	const uint8_t* info;  /*!< [const] Pointer to the optional information tweak */
	size_t infolen;       /*!< [size_t] Length (in bytes) of the information tweak */
} qsc_aes_keyparams;

/*! 
 * \struct qsc_aes_state
 * \brief AES cipher ctx structure.
 *
 * Contains the expanded round-key array, round count, and a pointer to the nonce.
 *
 * \sa qsc_aes_initialize, qsc_aes_dispose
 */
QSC_EXPORT_API typedef struct
{
#if defined(QSC_SYSTEM_AESNI_ENABLED)
	__m128i roundkeys[31U];			/*!< [__m128i] Round-key array for hardware accelerated AES */
#	if defined(QSC_SYSTEM_HAS_AVX512)
		QSC_ALIGN(64) __m512i roundkeysw[31U];		/*!< [__m512i] Extended round-key array for AVX-512 optimizations */
#	endif
#else
	uint32_t roundkeys[124U];		/*!< [uint32_t] Round-key array as 32-bit sub-keys for software-based AES */
#endif
	size_t roundkeylen;				/*!< [size_t] Number of round-key elements */
	size_t rounds;					/*!< [size_t] Number of transformation rounds */
	uint8_t* nonce;					/*!< [uint8_t*] Pointer to the nonce or initialization vector */
} qsc_aes_state;

/* Function Declarations */

/**
 * \brief Erase and dispose of the AES ctx.
 *
 * Securely clears the round-key array and resets the key length.
 *
 * \param ctx: [struct] Pointer to a qsc_aes_state structure.
 *
 * \sa qsc_aes_initialize
 */
QSC_EXPORT_API void qsc_aes_dispose(qsc_aes_state* ctx);

/**
 * \brief Initialize the AES ctx with the given key parameters.
 *
 * Expands the input cipher key into a round-key array for encryption or decryption.
 * Note that for CTR mode the cipher is always initialized for encryption.
 *
 * \param ctx:      [struct] Pointer to the qsc_aes_state structure to initialize.
 * \param keyparams:  [const struct] Pointer to a constant qsc_aes_keyparams structure containing key, nonce, and optional info.
 * \param encryption: [bool] Set to \c true to initialize for encryption; \c false for decryption.
 * \param ctype:      [enum] Specifies the AES cipher type (qsc_aes_cipher_128 or qsc_aes_cipher_256).
 *
 * \warning Ensure that \c ctx->roundkeys is cleared and its size set before calling.
 *
 * \sa qsc_aes_dispose
 */
QSC_EXPORT_API void qsc_aes_initialize(qsc_aes_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption, qsc_aes_cipher_type ctype);

/* CBC Mode */

/**
 * \brief Decrypt ciphertext using AES in Cipher Block Chaining (CBC) mode.
 *
 * Decrypts the input data in CBC mode and removes PKCS#7 padding.
 *
 * \param ctx:     [struct] Pointer to an initialized qsc_aes_state structure.
 * \param output:    [uint8_t*] Pointer to the output buffer where plaintext will be stored.
 * \param outputlen: [size_t*] Pointer to a size_t that receives the length of the decrypted data.
 * \param input:     [const uint8_t*] Pointer to the input ciphertext.
 * \param length:    [size_t] Number of bytes of input ciphertext.
 *
 * \warning The ctx must be initialized by qsc_aes_initialize.
 *
 * \sa qsc_aes_cbc_encrypt, qsc_pkcs7_padding_length
 */
QSC_EXPORT_API void qsc_aes_cbc_decrypt(qsc_aes_state* ctx, uint8_t* output, size_t* outputlen, const uint8_t* input, size_t length);

/**
 * \brief Encrypt plaintext using AES in Cipher Block Chaining (CBC) mode.
 *
 * Encrypts the input data in CBC mode, automatically applying PKCS#7 padding to the final block.
 *
 * \param ctx:  [struct] Pointer to an initialized qsc_aes_state structure.
 * \param output: [uint8_t*] Pointer to the output buffer where ciphertext will be stored.
 * \param input:  [const uint8_t*] Pointer to the input plaintext.
 * \param length: [size_t] Number of bytes of input plaintext.
 *
 * \warning The ctx must be initialized by qsc_aes_initialize.
 *
 * \sa qsc_aes_cbc_decrypt, qsc_pkcs7_add_padding
 */
QSC_EXPORT_API void qsc_aes_cbc_encrypt(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
 * \brief Decrypt a single 16-byte block using AES in CBC mode.
 *
 * Decrypts one block of ciphertext and performs the XOR with the previous ciphertext block (or IV).
 *
 * \param ctx:  [struct] Pointer to an initialized qsc_aes_state structure.
 * \param output: [uint8_t*] Pointer to a 16-byte buffer to receive the decrypted block.
 * \param input:  [const uint8_t*] Pointer to a 16-byte block of ciphertext.
 *
 * \warning The ctx must be initialized by qsc_aes_initialize.
 */
QSC_EXPORT_API void qsc_aes_cbc_decrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input);

/**
 * \brief Encrypt a single 16-byte block using AES in CBC mode.
 *
 * Encrypts one block of plaintext by XOR-ing with the previous ciphertext block (or IV) and applying AES encryption.
 *
 * \param ctx:  [struct] Pointer to an initialized qsc_aes_state structure.
 * \param output: [uint8_t*] Pointer to a 16-byte buffer to receive the ciphertext block.
 * \param input:  [const uint8_t*] Pointer to a 16-byte block of plaintext.
 *
 * \warning The ctx must be initialized by qsc_aes_initialize.
 */
QSC_EXPORT_API void qsc_aes_cbc_encrypt_block(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input);

/* PKCS#7 Padding */

/**
 * \brief Add PKCS#7 padding to a plaintext block.
 *
 * Pads the input block with a padding byte equal to the number of padded bytes.
 *
 * \param input:  [uint8_t*] Pointer to the plaintext block (will be modified in-place).
 * \param length: [size_t] Number of bytes that are less than the block size (i.e. QSC_AES_BLOCK_SIZE - actual data length).
 *
 * \sa qsc_pkcs7_padding_length
 */
QSC_EXPORT_API void qsc_pkcs7_add_padding(uint8_t* input, size_t length);

/**
 * \brief Determine the length of PKCS#7 padding in a decrypted block.
 *
 * Analyzes a block of decrypted data and returns the number of padding bytes.
 *
 * \param input: [const uint8_t*] Pointer to a decrypted block of plaintext.
 *
 * \return [size_t] The number of padding bytes, or 0U if the padding is invalid.
 *
 * \sa qsc_pkcs7_add_padding
 */
QSC_EXPORT_API size_t qsc_pkcs7_padding_length(const uint8_t* input);

/* CTR Mode */

/**
 * \brief Transform data using AES in Counter (CTR) mode with Big Endian counter incrementation.
 *
 * Encrypts or decrypts data in CTR mode. The same function is used for both operations.
 *
 * \param ctx:  [struct] Pointer to an initialized qsc_aes_state structure.
 * \param output: [uint8_t*] Pointer to the buffer where the transformed data will be stored.
 * \param input:  [const uint8_t*] Pointer to the input data.
 * \param length: [size_t] Number of bytes to process.
 *
 * \warning The ctx must be initialized by qsc_aes_initialize.
 *
 * \sa qsc_aes_ctrle_transform
 */
QSC_EXPORT_API void qsc_aes_ctrbe_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
 * \brief Transform data using AES in Counter (CTR) mode with Little Endian counter incrementation.
 *
 * Encrypts or decrypts data in CTR mode using a little endian counter.
 *
 * \param ctx:  [struct] Pointer to an initialized qsc_aes_state structure.
 * \param output: [uint8_t*] Pointer to the buffer where the transformed data will be stored.
 * \param input:  [const uint8_t*] Pointer to the input data.
 * \param length: [size_t] Number of bytes to process.
 *
 * \warning The ctx must be initialized by qsc_aes_initialize.
 *
 * \sa qsc_aes_ctrbe_transform
 */
QSC_EXPORT_API void qsc_aes_ctrle_transform(qsc_aes_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/* ECB Mode */

/**
 * \brief Decrypt a single 16-byte block using AES in Electronic CodeBook (ECB) mode.
 *
 * ECB mode should only be used for testing or as a building block due to its inherent insecurity.
 *
 * \param ctx:  [const struct] Pointer to an initialized qsc_aes_state structure.
 * \param output: [uint8_t*] Pointer to a 16-byte buffer to receive the decrypted plaintext.
 * \param input:  [const uint8_t*] Pointer to a 16-byte ciphertext block.
 *
 * \warning ECB mode does not provide semantic security.
 */
QSC_EXPORT_API void qsc_aes_ecb_decrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input);

/**
 * \brief Encrypt a single 16-byte block using AES in Electronic CodeBook (ECB) mode.
 *
 * \param ctx:  [const struct] Pointer to an initialized qsc_aes_state structure.
 * \param output: [uint8_t*] Pointer to a 16-byte buffer to receive the ciphertext.
 * \param input:  [const uint8_t*] Pointer to a 16-byte plaintext block.
 *
 * \warning ECB mode is insecure and should be used only for testing.
 */
QSC_EXPORT_API void qsc_aes_ecb_encrypt_block(const qsc_aes_state* ctx, uint8_t* output, const uint8_t* input);

/* HBA-256 Authenticated Encryption */

/*! 
 * \struct qsc_aes_hba256_state
 * \brief State structure for AES-based Hash Based Authentication (HBA-256).
 *
 * Combines an AES-256 cipher ctx with a MAC ctx (using either KMAC or HMAC) to implement an AEAD scheme.
 *
 * \sa qsc_aes_hba256_initialize, qsc_aes_hba256_transform, qsc_aes_hba256_dispose
 */
QSC_EXPORT_API typedef struct
{
#if defined(QSC_HBA_KMAC_EXTENSION)
	qsc_keccak_state kstate;			/*!< [struct] MAC ctx for KMAC authentication */
#else
	qsc_hmac256_state kstate;			/*!< [struct] MAC ctx for HMAC(SHA2) authentication */
#endif
	qsc_aes_state cstate;				/*!< [struct] Underlying AES cipher ctx */
	uint64_t counter;					/*!< [uint64_t] Counter for the number of processed bytes */
	uint8_t mkey[QSC_HBA256_MAC_SIZE];	/*!< [uint8_t[QSC_HBA256_MAC_SIZE]] MAC generator key */
	uint8_t cust[QSC_HBA_MAXINFO_SIZE];	/*!< [uint8_t[QSC_HBA_MAXINFO_SIZE]] Customization key (user provided tweak) */
	size_t custlen;						/*!< [size_t] Length of the customization key */
	bool encrypt;						/*!< [bool] Transformation mode: true for encryption, false for decryption */
} qsc_aes_hba256_state;

/**
 * \brief Dispose of an HBA-256 ctx.
 *
 * Securely clears all internal ctx and keys used by the HBA-256 authenticated encryption mode.
 *
 * \param ctx:	[struct] Pointer to a qsc_aes_hba256_state structure.
 *
 * \warning Must be called before the ctx goes out of scope.
 *
 * \sa qsc_aes_hba256_initialize, qsc_aes_hba256_transform
 */
QSC_EXPORT_API void qsc_aes_hba256_dispose(qsc_aes_hba256_state* ctx);

/**
 * \brief Initialize the HBA-256 ctx for authenticated encryption or decryption.
 *
 * Generates the cipher key and MAC key from the provided key parameters and sets up the internal states.
 *
 * \param ctx:     [struct] Pointer to a qsc_aes_hba256_state structure to initialize.
 * \param keyparams: [const struct] Pointer to a constant qsc_aes_keyparams structure that provides the key, nonce, and optional info.
 * \param encrypt:   [bool] Set to \c true for encryption mode, or \c false for decryption mode.
 *
 * \warning Must be called before using qsc_aes_hba256_set_associated or qsc_aes_hba256_transform.
 *
 * \sa qsc_aes_hba256_transform, qsc_aes_hba256_dispose
 */
QSC_EXPORT_API void qsc_aes_hba256_initialize(qsc_aes_hba256_state* ctx, const qsc_aes_keyparams* keyparams, bool encrypt);

/**
 * \brief Set the associated data (AAD) for HBA-256 authenticated encryption.
 *
 * The associated data is used to authenticate additional information (such as headers) that is not encrypted.
 * It must be set after initialization and before each call to qsc_aes_hba256_transform.
 *
 * \param ctx:	[struct] Pointer to the qsc_aes_hba256_state structure.
 * \param data:		[const uint8_t*] Pointer to the associated data.
 * \param datalen:	[size_t] Length of the associated data in bytes.
 *
 * \sa qsc_aes_hba256_transform
 */
QSC_EXPORT_API void qsc_aes_hba256_set_associated(qsc_aes_hba256_state* ctx, const uint8_t* data, size_t datalen);

/**
 * \brief Transform data using the HBA-256 authenticated encryption mode.
 *
 * In encryption mode, this function encrypts the plaintext using AES-256 in CTR mode, computes a MAC
 * over the nonce and ciphertext, and appends the MAC to the output. In decryption mode, it first verifies
 * the MAC before decrypting the ciphertext.
 *
 * \param ctx:	[struct] Pointer to an initialized qsc_aes_hba256_state structure.
 * \param output:	[uint8_t*] Pointer to the output buffer (must be large enough to hold ciphertext plus MAC in encryption mode).
 * \param input:	[const uint8_t*] Pointer to the input data (ciphertext with appended MAC in decryption mode, plaintext in encryption mode).
 * \param length:	[size_t] Length of the input data in bytes (excluding the MAC for decryption).
 *
 * \return			[bool] Returns \c true if the transformation (and MAC verification in decryption mode) was successful; otherwise, \c false.
 *
 * \sa qsc_aes_hba256_initialize, qsc_aes_hba256_set_associated
 */
QSC_EXPORT_API bool qsc_aes_hba256_transform(qsc_aes_hba256_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/* GCM-AES-256 RFC 5288/5116 */

/*! 
 * \struct qsc_aes_gcm256_state
 * \brief State structure for AES-based Galois Counter Mode (GCM-256).
 *
 * Combines an AES-256 cipher ctx with a Galois counter mode to implement an AEAD scheme.
 *
 * \sa qsc_aes_gcm256_set_associated, qsc_aes_gcm256_decrypt, qsc_aes_gcm256_dispose, qsc_aes_gcm256_encrypt, qsc_aes_gcm256_initialize
 */
QSC_EXPORT_API typedef struct qsc_aes_gcm256_state 
{
    qsc_aes_state cstate;                   /*!< [struct] Underlying AES cipher ctx */
    QSC_SIMD_ALIGN uint8_t C[QSC_AES_BLOCK_SIZE];			/*!< uint8_t[QSC_AES_BLOCK_SIZE] Current counter block */
    QSC_SIMD_ALIGN uint8_t H[QSC_AES_BLOCK_SIZE];          /*!< uint8_t[QSC_AES_BLOCK_SIZE] Hash subkey H = AES(K,0U) */
    QSC_SIMD_ALIGN uint8_t J0[QSC_AES_BLOCK_SIZE];         /*!< uint8_t[QSC_AES_BLOCK_SIZE] Pre-counter block */
    QSC_SIMD_ALIGN uint8_t S[QSC_AES_BLOCK_SIZE];          /*!< uint8_t[QSC_AES_BLOCK_SIZE] GHASH accumulator */
    uint64_t aadlen;						/*!< [uint64_t] AAD length in bits */
    uint64_t ctlen;							/*!< [uint64_t] Ciphertext length in bits */
	bool encrypt;							/*!< [bool] Initialized for encryption */
} qsc_aes_gcm256_state;

/**
 * \brief Decrypt data using the GCM-AES-256 authenticated encryption mode.
 *
 * This function decrypts the plaintext using AES-256 in GCM-CTR mode, computes a MAC
 * over the nonce and ciphertext, and writes the MAC to the tag parameter.
 *
 * \param ctx:	[struct] Pointer to an initialized qsc_aes_gcm256_state structure.
 * \param output:	[uint8_t*] Pointer to the plaintext buffer.
 * \param input:	[const uint8_t*] Pointer to the ciphertext data with the appended MAC.
 * \param length:	[size_t] Length of the input ciphertext in bytes including the MAC tag length.
 *
 * \return			[bool] Returns \c true if the transformation and MAC verification was successful; otherwise, \c false.
 *
 * \sa qsc_aes_gcm256_initialize, qsc_aes_gcm256_set_associated
 */
QSC_EXPORT_API bool qsc_aes_gcm256_decrypt(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/*!
 * \brief Dispose of an GCM-256 ctx.
 *
 * Securely clears all internal ctx and keys used by the GCM-256 authenticated encryption mode.
 *
 * \param ctx:	[struct] Pointer to a qsc_aes_gcm256_state structure.
 *
 * \warning Must be called before the ctx goes out of scope.
 *
 * \sa qsc_aes_gcm256_set_associated, qsc_aes_gcm_decrypt, qsc_aes_gcm_encrypt, qsc_aes_gcm_initialize
 */
QSC_EXPORT_API void qsc_aes_gcm256_dispose(qsc_aes_gcm256_state* ctx);

/**
 * \brief Encrypt data using the GCM-AES-256 authenticated encryption mode.
 *
 * In encryption mode, this function encrypts the plaintext using AES-256 in CTR mode, computes a MAC
 * over the nonce and ciphertext, and appends the MAC to the output.
 *
 * \param ctx:	[struct] Pointer to an initialized qsc_aes_gcm256_state structure.
 * \param output:	[uint8_t*] Pointer to the output buffer; must be large enough to hold ciphertext plus MAC.
 * \param input:	[const uint8_t*] Pointer to the input data; ciphertext with appended MAC.
 * \param length:	[size_t] Length of the input data in bytes (excluding the MAC for decryption).
 *
 * \sa qsc_aes_gcm256_initialize, qsc_aes_gcm256_set_associated
 */
QSC_EXPORT_API void qsc_aes_gcm256_encrypt(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
 * \brief Initialize the GCM-256 ctx for authenticated encryption or decryption.
 *
 * Generates the cipher key and MAC key from the provided key parameters and sets up the internal states.
 *
 * \param ctx:     [struct] Pointer to a qsc_aes_gcm256_state structure to initialize.
 * \param keyparams: [const struct] Pointer to a constant qsc_aes_keyparams structure that provides the key, nonce, and optional info.
 * \param encryption:	[bool] A flag that specifies true for encryption, false for decryption.
 *
 * \warning Must be called before using qsc_aes_gcm256_set_associated, qsc_aes_gcm256_encrypt or qsc_aes_gcm256_decrypt.
 *
 * \sa qsc_aes_gcm256_decrypt, qsc_aes_gcm256_encrypt, qsc_aes_gcm256_dispose
 */
QSC_EXPORT_API void qsc_aes_gcm256_initialize(qsc_aes_gcm256_state* ctx, const qsc_aes_keyparams* keyparams, bool encryption);

/**
 * \brief Set the associated data (AAD) for GCM-256 authenticated encryption.
 *
 * The associated data is used to authenticate additional information (such as headers) that is not encrypted.
 * It must be set after initialization and before each call to qsc_aes_gcm256_encrypt
 *
 * \param ctx:	[struct] Pointer to the qsc_aes_gcm256_state structure.
 * \param data:		[const uint8_t*] Pointer to the associated data.
 * \param datalen:	[size_t] Length of the associated data in bytes.
 *
 * \sa qsc_aes_gcm256_encrypt
 */
QSC_EXPORT_API void qsc_aes_gcm256_set_associated(qsc_aes_gcm256_state* ctx, const uint8_t* data, size_t datalen);

/**
 * \brief Transform an array of bytes.
 *
 * In encryption mode, the input plain-text is encrypted and an authentication MAC code is appended
 * to the cipher-text. In decryption mode, the input cipher-text is authenticated and compared to the MAC code.
 * If the codes do not match, the cipher-text is not decrypted and the call fails.
 *
 * \param ctx:			[qsc_aes_gcm256_state*] A pointer to the cipher state structure.
 * \param output:		[uint8_t*] A pointer to the output array.
 * \param input:		[const uint8_t*] A pointer to the input array.
 * \param length:		[size_t] The number of bytes to transform  (not including the tag length).
 *
 * \return				[bool] Returns true if the data was transformed successfully, false on failure.
 */
QSC_EXPORT_API bool qsc_aes_gcm256_transform(qsc_aes_gcm256_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

QSC_CPLUSPLUS_ENABLED_END

#endif
