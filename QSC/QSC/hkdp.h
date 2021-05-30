#ifndef QSC_SKPD_H
#define QSC_SKPD_H

#include "common.h"
#include "rcs.h"
#include "sha3.h"

/*
* Symmetric Key Distribution Protocol SKDP
*
* Must have:
* -forward security
* -predictive resistance
* -hierarchal tree-based scaling
* -message and token authentication
* -identity based
* -fallback and reset mechanism
*
* Token based, exchanges a token with the server used in the derivation of each session-key.
* Uses the embedded key for authentication, and deriving new session keys.
* Derives session keys using the embedded key, the session counter, and the server token.
* Uses an identity field to route messages, and as input into the server key derivation.
* ex. key-id = { institution + branch + device + transaction-counter }
* Keys should be 256 and 512 bits long, and correspond to the function security ex. RCS-512.
* Server stores 2 keys, auth and token, these keys can be derived from master keys, using the identity string.
*
* Consider a hierarchal derivation:
* master->master + institution = intermediate-key-> intermediate-key + branch = branch-key->
* branch-key + device = device-key-> device-key + counter = session-key.
*
* Consider a branch-less scheme:
* Server
* stok = H(tkey || ctr)
* mk = H(mkey || ctr)
* etok = Emk(stok)
*
* Client
* mk = H(mkey || ctr)
* stok = Dmk(etok)
* k = H(stok || m-key)
* Ek(m)
*
* Advantages, disadvantages of each?
*
* Scheme:
* What would the application of this be, what is it intended to solve?
* 
*/


/*!
* \enum qsc_hkdp_errors
* \brief The QSMP error values
*/
QSC_EXPORT_API typedef enum qsc_hkdp_errors
{
	qsc_hkdp_error_none = 0,						/*!< No error was detected */
} qsc_hkdp_errors;

/*!
* \struct qsc_hkdp_server_key
* \brief The QSMP server key structure
*/
QSC_EXPORT_API typedef struct qsc_hkdp_server_key
{
	uint64_t expiration;						/*!< The expiration time, in seconds from epoch */
	//uint8_t config[QSC_QSMP_CONFIG_SIZE];		/*!< The primitive configuration string */
	//uint8_t keyid[QSC_QSMP_KEYID_SIZE];			/*!< The key identity string */
	//uint8_t sigkey[QSC_QSMP_SIGNKEY_SIZE];		/*!< The asymmetric signature signing-key */
	//uint8_t verkey[QSC_QSMP_VERIFYKEY_SIZE];	/*!< The asymmetric signature verification-key */
} qsc_qsmp_server_key;

/*!
* \struct qsc_qsmp_kex_server_state
* \brief The QSMP server state structure
*/
QSC_EXPORT_API typedef struct qsc_hkdp_server_state
{
	qsc_rcs_state rxcpr;						/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;						/*!< The transmit channel cipher state */
	//uint8_t config[QSC_QSMP_CONFIG_SIZE];		/*!< The primitive configuration string */
	//uint8_t keyid[QSC_QSMP_KEYID_SIZE];			/*!< The key identity string */
	//uint8_t pkhash[QSC_QSMP_PKCODE_SIZE];		/*!< The session token hash */
	//uint8_t prikey[QSC_QSMP_PRIVATEKEY_SIZE];	/*!< The asymmetric cipher private key */
	//uint8_t pubkey[QSC_QSMP_PUBLICKEY_SIZE];	/*!< The asymmetric cipher public key */
	//uint8_t sigkey[QSC_QSMP_SIGNKEY_SIZE];		/*!< The asymmetric signature signing-key */
	//uint8_t verkey[QSC_QSMP_VERIFYKEY_SIZE];	/*!< The asymmetric signature verification-key */
	//uint8_t token[QSC_QSMP_STOKEN_SIZE];		/*!< The session token */
	//qsc_qsmp_flags exflag;						/*!< The KEX position flag */
	uint64_t expiration;						/*!< The expiration time, in seconds from epoch */
} qsc_qsmp_kex_server_state;

/**
* \brief 
*
* \param ctx: A pointer to the HKDP server state structure
* \param skey: A pointer to the secret server key structure
*/
QSC_EXPORT_API qsc_hkdp_errors qsc_hkdp_server_initialize(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_server_key* skey);

#endif