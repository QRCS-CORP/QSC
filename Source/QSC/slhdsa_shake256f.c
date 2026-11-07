#include "slhdsa.h"
#include "sha2.h"

/* \cond DOXYGEN_NO_DOCUMENT */

/* FIPS 205 independent SLH-DSA-SHAKE-256f compilation unit.
 * Only object-like parameter and symbol selectors; no function macros.
 */

/** \def SPX_N
 * \brief Hash output/security parameter for SHAKE-256f.
 */
#define SPX_N 32U

/** \def SPX_FULL_HEIGHT
 * \brief Hypertree height for SHAKE-256f.
 */
#define SPX_FULL_HEIGHT 68U

/** \def SPX_D
 * \brief Hypertree layers for SHAKE-256f.
 */
#define SPX_D 17U

/** \def SPX_FORS_HEIGHT
 * \brief FORS tree height for SHAKE-256f.
 */
#define SPX_FORS_HEIGHT 9U

/** \def SPX_FORS_TREES
 * \brief Number of FORS trees for SHAKE-256f.
 */
#define SPX_FORS_TREES 35U

/** \def sphincsplus_ref_sign_secretkeybytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_secretkeybytes qsc_slhdsa_shake256f_internal_sign_secretkeybytes

/** \def sphincsplus_ref_sign_publickeybytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_publickeybytes qsc_slhdsa_shake256f_internal_sign_publickeybytes

/** \def sphincsplus_ref_sign_bytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_bytes qsc_slhdsa_shake256f_internal_sign_bytes

/** \def sphincsplus_ref_sign_seedbytes
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_seedbytes qsc_slhdsa_shake256f_internal_sign_seedbytes

/** \def sphincsplus_ref_generate_seeded_keypair
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_generate_seeded_keypair qsc_slhdsa_shake256f_internal_generate_seeded_keypair

/** \def sphincsplus_ref_generate_keypair
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_generate_keypair qsc_slhdsa_shake256f_internal_generate_keypair

/** \def sphincsplus_ref_sign_signature
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign_signature qsc_slhdsa_shake256f_internal_sign_signature

/** \def sphincsplus_ref_sign
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_sign qsc_slhdsa_shake256f_internal_sign

/** \def sphincsplus_ref_verify
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_verify qsc_slhdsa_shake256f_internal_verify

/** \def sphincsplus_ref_open
 * \brief Private name mapping for this parameter-specific compilation.
 */
#define sphincsplus_ref_open qsc_slhdsa_shake256f_internal_open

/** \def SLH_DSA_KEYGEN
 * \brief Exported SHAKE-256f symbol binding for common API implementation.
 */
#define SLH_DSA_KEYGEN qsc_slhdsa_shake256f_generate_keypair

/** \def SLH_DSA_SEEDED_KEYGEN
 * \brief Exported SHAKE-256f symbol binding for common API implementation.
 */
#define SLH_DSA_SEEDED_KEYGEN qsc_slhdsa_shake256f_generate_seeded_keypair

/** \def SLH_DSA_SIGN
 * \brief Exported SHAKE-256f symbol binding for common API implementation.
 */
#define SLH_DSA_SIGN qsc_slhdsa_shake256f_sign

/** \def SLH_DSA_SIGN_DETERMINISTIC
 * \brief Exported SHAKE-256f symbol binding for common API implementation.
 */
#define SLH_DSA_SIGN_DETERMINISTIC qsc_slhdsa_shake256f_sign_deterministic

/** \def SLH_DSA_VERIFY
 * \brief Exported SHAKE-256f symbol binding for common API implementation.
 */
#define SLH_DSA_VERIFY qsc_slhdsa_shake256f_verify

/** \def SLH_DSA_SIGN_PREHASH
 * \brief Bind SHAKE-256f HashSLH-DSA sign_prehash to its independent public symbol.
 */
#define SLH_DSA_SIGN_PREHASH qsc_slhdsa_shake256f_sign_prehash

/** \def SLH_DSA_SIGN_PREHASH_DETERMINISTIC
 * \brief Bind SHAKE-256f HashSLH-DSA sign_prehash_deterministic to its independent public symbol.
 */
#define SLH_DSA_SIGN_PREHASH_DETERMINISTIC qsc_slhdsa_shake256f_sign_prehash_deterministic

/** \def SLH_DSA_VERIFY_PREHASH
 * \brief Bind SHAKE-256f HashSLH-DSA verify_prehash to its independent public symbol.
 */
#define SLH_DSA_VERIFY_PREHASH qsc_slhdsa_shake256f_verify_prehash

#include "slhdsa_shake_core.inc"

#if SPX_BYTES != QSC_SLHDSA_SHAKE256F_SIGNATURE_SIZE
#	error "SLH-DSA FIPS 205 signature size mismatch for SHAKE-256f"
#endif

#include "slhdsa_shake_api.inc"
#undef SLH_DSA_KEYGEN
#undef SLH_DSA_SEEDED_KEYGEN
#undef SLH_DSA_SIGN
#undef SLH_DSA_SIGN_DETERMINISTIC
#undef SLH_DSA_VERIFY
#undef SLH_DSA_VERIFY_PREHASH
#undef SLH_DSA_SIGN_PREHASH_DETERMINISTIC
#undef SLH_DSA_SIGN_PREHASH
#undef sphincsplus_ref_sign_secretkeybytes
#undef sphincsplus_ref_sign_publickeybytes
#undef sphincsplus_ref_sign_bytes
#undef sphincsplus_ref_sign_seedbytes
#undef sphincsplus_ref_generate_seeded_keypair
#undef sphincsplus_ref_generate_keypair
#undef sphincsplus_ref_sign_signature
#undef sphincsplus_ref_sign
#undef sphincsplus_ref_verify
#undef sphincsplus_ref_open
#undef SPX_N
#undef SPX_FULL_HEIGHT
#undef SPX_D
#undef SPX_FORS_HEIGHT
#undef SPX_FORS_TREES

 /* \endcond DOXYGEN_NO_DOCUMENT */
