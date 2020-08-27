#ifndef QCX_SPX_PARAMS_H
#define QCX_SPX_PARAMS_H

/* Toggles modes between the three shake-based K modes; 128,192,256 = 1,2,3 */
#define QCX_SPX_MODE 1

/* Implement the S 'robust' version of the signature scheme */
#define SPX_VERSION_SMALL

#ifndef QCX_SPX_MODE
#	define QCX_SPX_MODE 3
#endif

/* Note: kats are small version, fast version kats not implemented */
#ifdef SPX_VERSION_SMALL
#	if (QCX_SPX_MODE == 3)
		/* Hash output length in bytes. */
#		define SPX_N 32
		/* Height of the hypertree. */
#		define SPX_FULL_HEIGHT 64
		/* Number of subtree layer. */
#		define SPX_D 8
		/* FORS tree dimensions. */
#		define SPX_FORS_HEIGHT 14
#		define SPX_FORS_TREES 22
		/* Winternitz parameter, */
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 2)
#		define SPX_N 24
#		define SPX_FULL_HEIGHT 64
#		define SPX_D 8
#		define SPX_FORS_HEIGHT 16
#		define SPX_FORS_TREES 14
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 1)
#		define SPX_N 16
#		define SPX_FULL_HEIGHT 64
#		define SPX_D 8
#		define SPX_FORS_HEIGHT 15
#		define SPX_FORS_TREES 10
#		define SPX_WOTS_W 16
#	else
#		error the sphincsplus mode is invalid!
#	endif
#else
#	if (QCX_SPX_MODE == 3)
#		define SPX_N 32
#		define SPX_FULL_HEIGHT 68
#		define SPX_D 17
#		define SPX_FORS_HEIGHT 10
#		define SPX_FORS_TREES 30
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 2)
#		define SPX_N 24
#		define SPX_FULL_HEIGHT 66
#		define SPX_D 22
#		define SPX_FORS_HEIGHT 8
#		define SPX_FORS_TREES 33
#		define SPX_WOTS_W 16
#	elif (QCX_SPX_MODE == 1)
#		define SPX_N 16
#		define SPX_FULL_HEIGHT 60
#		define SPX_D 20
#		define SPX_FORS_HEIGHT 9
#		define SPX_FORS_TREES 30
#		define SPX_WOTS_W 16
#	else
#		error the sphincsplus mode is invalid!
#	endif
#endif

/* For clarity */
#define SPX_ADDR_BYTES 32

/* WOTS parameters */
#if SPX_WOTS_W == 256
#	define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
#	define SPX_WOTS_LOGW 4
#else
#	error SPX_WOTS_W assumed 16 or 256
#endif

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SPX_WOTS_W == 256
#	if SPX_N <= 1
#		define SPX_WOTS_LEN2 1
#	elif SPX_N <= 256
#		define SPX_WOTS_LEN2 2
#	else
#		error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#	endif
#elif SPX_WOTS_W == 16
#	if SPX_N <= 8
#		define SPX_WOTS_LEN2 2
#	elif SPX_N <= 136
#		define SPX_WOTS_LEN2 3
#	elif SPX_N <= 256
#		define SPX_WOTS_LEN2 4
#	else
#		error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#	endif
#endif

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if (SPX_TREE_HEIGHT * SPX_D) != SPX_FULL_HEIGHT
#error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define SPX_OPTRAND_BYTES 32

/*!
\def SPHINCSPLUS_ALGNAME
* Read Only: The formal algorithm name
*/
#define SPHINCSPLUS_ALGNAME "SPHINCS+"

/*!
\def SPHINCSPLUS_PUBLICKEY_SIZE
* Read Only: The public key size in bytes
*/
#define SPHINCSPLUS_PUBLICKEY_SIZE SPX_PK_BYTES

/*!
\def SPHINCSPLUS_SECRETKEY_SIZE
* Read Only: The private key size in bytes
*/
#define SPHINCSPLUS_SECRETKEY_SIZE SPX_SK_BYTES

/*!
\def SPHINCSPLUS_PUBLICKEY_SIZE
* Read Only: The seed size in bytes
*/
#define SPHINCSPLUS_SEED_SIZE 3 * SPX_N

/*!
\def SPHINCSPLUS_SIGNATURE_SIZE
* Read Only: The signature size in bytes
*/
#define SPHINCSPLUS_SIGNATURE_SIZE SPX_BYTES

#endif
