/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QSC_KYBERBASE_H
#define QSC_KYBERBASE_H

#include "common.h"

#if defined(QSC_KYBER_S3Q3329N256K3)
#	define QSC_KYBER_K 3
#elif defined(QSC_KYBER_S5Q3329N256K4)
#	define QSC_KYBER_K 4
#elif defined(QSC_KYBER_S6Q3329N256K5)
#	define QSC_KYBER_K 5
#else
#	error No Kyber implementation is defined, check common.h!
#endif

 /*!
 \def QSC_KYBER_N
 * Read Only: The polynomial dimension N
 */
#define QSC_KYBER_N 256

 /*!
 \def QSC_KYBER_Q
 * Read Only: The modulus prime factor Q
 */
#define QSC_KYBER_Q 3329

 /*!
 \def QSC_KYBER_ETA
 * Read Only: The binomial distribution factor
 */
#define QSC_KYBER_ETA 2

 /*!
 \def QSC_KYBER_MSGBYTES
 * Read Only: The size in bytes of the shared secret
 */
#define QSC_KYBER_MSGBYTES 32

 /*!
 \def QSC_KYBER_SYMBYTES
 * Read Only: The size in bytes of hashes, and seeds
 */
#define QSC_KYBER_SYMBYTES 32

 /*!
 \def QSC_KYBER_POLYBYTES
 * Read Only: The secret key base multiplier
 */
#define QSC_KYBER_POLYBYTES 384

 /*!
 \def QSC_KYBER_POLYVEC_BYTES
 * Read Only: The base size of the compressed public key polynolial
 */
#if (QSC_KYBER_K == 3)
#	define QSC_KYBER_POLYVECBASE_BYTES 320
#elif (QSC_KYBER_K == 4 || QSC_KYBER_K == 5)
#	define QSC_KYBER_POLYVECBASE_BYTES 352
#endif

 /*!
 \def QSC_KYBER_POLYCOMPRESSED_BYTES
 * Read Only: The ciphertext compressed byte size
 */
#if (QSC_KYBER_K == 3)
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 128
#elif (QSC_KYBER_K == 4 || QSC_KYBER_K == 5)
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 160
#endif

 /*!
 \def QSC_KYBER_POLYVEC_COMPRESSED_BYTES
 * Read Only: The base size of the public key
 */
#define QSC_KYBER_POLYVEC_COMPRESSED_BYTES (QSC_KYBER_K * QSC_KYBER_POLYVECBASE_BYTES)

 /*!
 \def QSC_KYBER_POLYVEC_BYTES
 * Read Only: The base size of the secret key
 */
#define QSC_KYBER_POLYVEC_BYTES (QSC_KYBER_K * QSC_KYBER_POLYBYTES)

 /*!
 \def QSC_KYBER_INDCPA_PUBLICKEY_BYTES
 * Read Only: The base INDCPA formatted public key size in bytes
 */
#define QSC_KYBER_INDCPA_PUBLICKEY_BYTES (QSC_KYBER_POLYVEC_BYTES + QSC_KYBER_SYMBYTES)

 /*!
 \def QSC_KYBER_INDCPA_SECRETKEY_BYTES
 * Read Only: The base INDCPA formatted private key size in bytes
 */
#define QSC_KYBER_INDCPA_SECRETKEY_BYTES (QSC_KYBER_POLYVEC_BYTES)

 /*!
 \def QSC_KYBER_INDCPA_BYTES
 * Read Only: The size of the INDCPA formatted output cipher-text
 */
#define QSC_KYBER_INDCPA_BYTES (QSC_KYBER_POLYVEC_COMPRESSED_BYTES + QSC_KYBER_POLYCOMPRESSED_BYTES)

#define QSC_KYBER_PUBLICKEY_BYTES  (QSC_KYBER_INDCPA_PUBLICKEY_BYTES)
#define QSC_KYBER_SECRETKEY_BYTES  (QSC_KYBER_INDCPA_SECRETKEY_BYTES + QSC_KYBER_INDCPA_PUBLICKEY_BYTES + 2 * QSC_KYBER_SYMBYTES)
#define QSC_KYBER_CIPHERTEXT_BYTES (QSC_KYBER_INDCPA_BYTES)

#endif