#include "common.h"

/**
* \file katparser.h
* \brief KAT file support functions
*/

/**
* \brief Extract a set of values from a NIST PQC asymmetric signature scheme KAT file
*
* \param path: The KAT file relative path
* \param seed: The RNG seed
* \param seedlen: The RNG seed length
* \param msg: The message
* \param msglen: The message length
* \param pk: The public key
* \param pklen: The public key length
* \param sk: The secret key
* \param sklen: The secret key length
* \param sm: The signature and message
* \param smlen: The signature and message length
* \param setnum: The KAT set number to extract (0-99)
*/
void parse_nist_signature_kat(const char* path, uint8_t* seed, size_t* seedlen, uint8_t* msg, size_t* msglen,
	uint8_t* pk, size_t* pklen, uint8_t* sk, size_t* sklen, uint8_t* sm, size_t* smlen, uint32_t setnum);

/**
* \brief Extract a set of values from a NIST PQC asymmetric cipher KAT file
*
* \param path: The KAT file relative path
* \param seed: The RNG seed
* \param seedlen: The RNG seed length
* \param pk: The public key
* \param pklen: The public key length
* \param sk: The secret key
* \param sklen: The secret key length
* \param ct: The cipher-text
* \param ctlen: The cipher-text length
* \param ss: The shared secret
* \param sslen: The shared secret length
* \param setnum: The KAT set number to extract (0-99)
*/
void parse_nist_cipher_kat(const char* path, uint8_t* seed, size_t* seedlen, uint8_t* pk, size_t* pklen,
	uint8_t* sk, size_t* sklen, uint8_t* ct, size_t* ctlen, uint8_t* ss, size_t* sslen, uint32_t setnum);
