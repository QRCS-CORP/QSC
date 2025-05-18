#include "dilithiumbase_avx2.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* params.h */
#if defined(QSC_SYSTEM_HAS_AVX2)

#if defined(QSC_DILITHIUM_S1P2544)
#   define DILITHIUM_MODE 2
#elif defined(QSC_DILITHIUM_S3P4016) 
#   define DILITHIUM_MODE 3
#elif defined(QSC_DILITHIUM_S5P4880)
#   define DILITHIUM_MODE 5
#else
#   error The dilithium mode is not supported!
#endif

#if (DILITHIUM_MODE == 2)
#   define DILITHIUM_K 4
#   define DILITHIUM_L 4
#elif (DILITHIUM_MODE == 3)
#   define DILITHIUM_K 6
#   define DILITHIUM_L 5
#elif (DILITHIUM_MODE == 5)
#   define DILITHIUM_K 8
#   define DILITHIUM_L 7
#endif

#define DILITHIUM_CRHBYTES 64ULL
#define DILITHIUM_CONTEXT_SIZE 257
#define DILITHIUM_D 13LL
#define DILITHIUM_Q 8380417LL
#define DILITHIUM_MONT -4186625LL /* 2^32 % DILITHIUM_Q */
#define DILITHIUM_N 256LL
#define DILITHIUM_QINV 58728449LL /* q^(-1) mod 2^32 */
#define DILITHIUM_RNDBYTES 32ULL
#define DILITHIUM_ROOT_OF_UNITY 1753LL
#define DILITHIUM_SEEDBYTES 32ULL
#define DILITHIUM_TRBYTES 64ULL

#if (DILITHIUM_MODE == 2)
#   define DILITHIUM_K 4
#   define DILITHIUM_L 4
#   define DILITHIUM_ETA 2
#   define DILITHIUM_TAU 39
#   define DILITHIUM_BETA 78
#   define DILITHIUM_GAMMA1 (1 << 17)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 88)
#   define DILITHIUM_OMEGA 80
#   define DILITHIUM_CTILDEBYTES 32
#elif (DILITHIUM_MODE == 3)
#   define DILITHIUM_K 6
#   define DILITHIUM_L 5
#   define DILITHIUM_ETA 4
#   define DILITHIUM_TAU 49
#   define DILITHIUM_BETA 196
#   define DILITHIUM_GAMMA1 (1 << 19)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 32)
#   define DILITHIUM_OMEGA 55
#   define DILITHIUM_CTILDEBYTES 48
#elif (DILITHIUM_MODE == 5)
#   define DILITHIUM_K 8
#   define DILITHIUM_L 7
#   define DILITHIUM_ETA 2
#   define DILITHIUM_TAU 60
#   define DILITHIUM_BETA 120
#   define DILITHIUM_GAMMA1 (1 << 19)
#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)
#   define DILITHIUM_OMEGA 75
#   define DILITHIUM_CTILDEBYTES 64
#endif

#define DILITHIUM_POLYT1_PACKEDBYTES  320ULL
#define DILITHIUM_POLYT0_PACKEDBYTES  416ULL
#define DILITHIUM_POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + DILITHIUM_K)

#if (DILITHIUM_GAMMA1 == (1 << 17))
#   define DILITHIUM_POLYZ_PACKEDBYTES 576
#elif (DILITHIUM_GAMMA1 == (1 << 19))
#   define DILITHIUM_POLYZ_PACKEDBYTES 640ULL
#endif

#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 88)
#   define DILITHIUM_POLYW1_PACKEDBYTES 192
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 32)
#   define DILITHIUM_POLYW1_PACKEDBYTES  128ULL
#endif

#if (DILITHIUM_ETA == 2)
#   define DILITHIUM_POLYETA_PACKEDBYTES 96ULL
#elif (DILITHIUM_ETA == 4)
#   define DILITHIUM_POLYETA_PACKEDBYTES 128ULL
#endif

#define DILITHIUM_PUBLICKEY_SIZE (DILITHIUM_SEEDBYTES + DILITHIUM_K * DILITHIUM_POLYT1_PACKEDBYTES)
#define DILITHIUM_PRIVATEKEY_SIZE (2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES \
                               + DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES \
                               + DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES \
                               + DILITHIUM_K * DILITHIUM_POLYT0_PACKEDBYTES)
#define DILITHIUM_SIGNATURE_SIZE (DILITHIUM_CTILDEBYTES + DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES + DILITHIUM_POLYVECH_PACKEDBYTES)

#define DILITHIUM_POLY_UNIFORM_NBLOCKS ((768ULL + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)

#if (DILITHIUM_ETA == 2)
#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((136ULL + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#elif (DILITHIUM_ETA == 4)
#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((227ULL + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#endif

#define DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS ((DILITHIUM_POLYZ_PACKEDBYTES + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#define DILITHIUM_REJ_UNIFORM_NBLOCKS ((768 + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)
#define DILITHIUM_REJ_UNIFORM_BUFLEN (DILITHIUM_REJ_UNIFORM_NBLOCKS * QSC_KECCAK_128_RATE)

#if DILITHIUM_ETA == 2
#define DILITHIUM_REJ_UNIFORM_ETA_NBLOCKS ((136 + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#elif DILITHIUM_ETA == 4
#define DILITHIUM_REJ_UNIFORM_ETA_NBLOCKS ((227 + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
#endif
#define DILITHIUM_REJ_UNIFORM_ETA_BUFLEN (DILITHIUM_REJ_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_256_RATE)

/*!
* \struct dilithium_poly
* \brief Array of coefficients of length N
*/
typedef struct
{
    int32_t coeffs[DILITHIUM_N];            /*!< The coefficients  */
} dilithium_poly;

/*!
* \struct dilithium_polyvecl
* \brief Vectors of polynomials of length L
*/
typedef struct
{
    dilithium_poly vec[DILITHIUM_L];    /*!< The poly vector of L  */
} dilithium_polyvecl;

/*!
* \struct dilithium_polyveck
* \brief Vectors of polynomials of length K
*/
typedef struct
{
    dilithium_poly vec[DILITHIUM_K];    /*!< The poly vector of K  */
} dilithium_polyveck;

QSC_ALIGN(64) static const uint8_t dilithium_rej_avx2[256][8] = {
  { 0,  0,  0,  0,  0,  0,  0,  0}, { 0,  0,  0,  0,  0,  0,  0,  0}, { 1,  0,  0,  0,  0,  0,  0,  0}, { 0,  1,  0,  0,  0,  0,  0,  0},
  { 2,  0,  0,  0,  0,  0,  0,  0}, { 0,  2,  0,  0,  0,  0,  0,  0}, { 1,  2,  0,  0,  0,  0,  0,  0}, { 0,  1,  2,  0,  0,  0,  0,  0},
  { 3,  0,  0,  0,  0,  0,  0,  0}, { 0,  3,  0,  0,  0,  0,  0,  0}, { 1,  3,  0,  0,  0,  0,  0,  0}, { 0,  1,  3,  0,  0,  0,  0,  0},
  { 2,  3,  0,  0,  0,  0,  0,  0}, { 0,  2,  3,  0,  0,  0,  0,  0}, { 1,  2,  3,  0,  0,  0,  0,  0}, { 0,  1,  2,  3,  0,  0,  0,  0},
  { 4,  0,  0,  0,  0,  0,  0,  0}, { 0,  4,  0,  0,  0,  0,  0,  0}, { 1,  4,  0,  0,  0,  0,  0,  0}, { 0,  1,  4,  0,  0,  0,  0,  0},
  { 2,  4,  0,  0,  0,  0,  0,  0}, { 0,  2,  4,  0,  0,  0,  0,  0}, { 1,  2,  4,  0,  0,  0,  0,  0}, { 0,  1,  2,  4,  0,  0,  0,  0},
  { 3,  4,  0,  0,  0,  0,  0,  0}, { 0,  3,  4,  0,  0,  0,  0,  0}, { 1,  3,  4,  0,  0,  0,  0,  0}, { 0,  1,  3,  4,  0,  0,  0,  0},
  { 2,  3,  4,  0,  0,  0,  0,  0}, { 0,  2,  3,  4,  0,  0,  0,  0}, { 1,  2,  3,  4,  0,  0,  0,  0}, { 0,  1,  2,  3,  4,  0,  0,  0},
  { 5,  0,  0,  0,  0,  0,  0,  0}, { 0,  5,  0,  0,  0,  0,  0,  0}, { 1,  5,  0,  0,  0,  0,  0,  0}, { 0,  1,  5,  0,  0,  0,  0,  0},
  { 2,  5,  0,  0,  0,  0,  0,  0}, { 0,  2,  5,  0,  0,  0,  0,  0}, { 1,  2,  5,  0,  0,  0,  0,  0}, { 0,  1,  2,  5,  0,  0,  0,  0},
  { 3,  5,  0,  0,  0,  0,  0,  0}, { 0,  3,  5,  0,  0,  0,  0,  0}, { 1,  3,  5,  0,  0,  0,  0,  0}, { 0,  1,  3,  5,  0,  0,  0,  0},
  { 2,  3,  5,  0,  0,  0,  0,  0}, { 0,  2,  3,  5,  0,  0,  0,  0}, { 1,  2,  3,  5,  0,  0,  0,  0}, { 0,  1,  2,  3,  5,  0,  0,  0},
  { 4,  5,  0,  0,  0,  0,  0,  0}, { 0,  4,  5,  0,  0,  0,  0,  0}, { 1,  4,  5,  0,  0,  0,  0,  0}, { 0,  1,  4,  5,  0,  0,  0,  0},
  { 2,  4,  5,  0,  0,  0,  0,  0}, { 0,  2,  4,  5,  0,  0,  0,  0}, { 1,  2,  4,  5,  0,  0,  0,  0}, { 0,  1,  2,  4,  5,  0,  0,  0},
  { 3,  4,  5,  0,  0,  0,  0,  0}, { 0,  3,  4,  5,  0,  0,  0,  0}, { 1,  3,  4,  5,  0,  0,  0,  0}, { 0,  1,  3,  4,  5,  0,  0,  0},
  { 2,  3,  4,  5,  0,  0,  0,  0}, { 0,  2,  3,  4,  5,  0,  0,  0}, { 1,  2,  3,  4,  5,  0,  0,  0}, { 0,  1,  2,  3,  4,  5,  0,  0},
  { 6,  0,  0,  0,  0,  0,  0,  0}, { 0,  6,  0,  0,  0,  0,  0,  0}, { 1,  6,  0,  0,  0,  0,  0,  0}, { 0,  1,  6,  0,  0,  0,  0,  0},
  { 2,  6,  0,  0,  0,  0,  0,  0}, { 0,  2,  6,  0,  0,  0,  0,  0}, { 1,  2,  6,  0,  0,  0,  0,  0}, { 0,  1,  2,  6,  0,  0,  0,  0},
  { 3,  6,  0,  0,  0,  0,  0,  0}, { 0,  3,  6,  0,  0,  0,  0,  0}, { 1,  3,  6,  0,  0,  0,  0,  0}, { 0,  1,  3,  6,  0,  0,  0,  0},
  { 2,  3,  6,  0,  0,  0,  0,  0}, { 0,  2,  3,  6,  0,  0,  0,  0}, { 1,  2,  3,  6,  0,  0,  0,  0}, { 0,  1,  2,  3,  6,  0,  0,  0},
  { 4,  6,  0,  0,  0,  0,  0,  0}, { 0,  4,  6,  0,  0,  0,  0,  0}, { 1,  4,  6,  0,  0,  0,  0,  0}, { 0,  1,  4,  6,  0,  0,  0,  0},
  { 2,  4,  6,  0,  0,  0,  0,  0}, { 0,  2,  4,  6,  0,  0,  0,  0}, { 1,  2,  4,  6,  0,  0,  0,  0}, { 0,  1,  2,  4,  6,  0,  0,  0},
  { 3,  4,  6,  0,  0,  0,  0,  0}, { 0,  3,  4,  6,  0,  0,  0,  0}, { 1,  3,  4,  6,  0,  0,  0,  0}, { 0,  1,  3,  4,  6,  0,  0,  0},
  { 2,  3,  4,  6,  0,  0,  0,  0}, { 0,  2,  3,  4,  6,  0,  0,  0}, { 1,  2,  3,  4,  6,  0,  0,  0}, { 0,  1,  2,  3,  4,  6,  0,  0},
  { 5,  6,  0,  0,  0,  0,  0,  0}, { 0,  5,  6,  0,  0,  0,  0,  0}, { 1,  5,  6,  0,  0,  0,  0,  0}, { 0,  1,  5,  6,  0,  0,  0,  0},
  { 2,  5,  6,  0,  0,  0,  0,  0}, { 0,  2,  5,  6,  0,  0,  0,  0}, { 1,  2,  5,  6,  0,  0,  0,  0}, { 0,  1,  2,  5,  6,  0,  0,  0},
  { 3,  5,  6,  0,  0,  0,  0,  0}, { 0,  3,  5,  6,  0,  0,  0,  0}, { 1,  3,  5,  6,  0,  0,  0,  0}, { 0,  1,  3,  5,  6,  0,  0,  0},
  { 2,  3,  5,  6,  0,  0,  0,  0}, { 0,  2,  3,  5,  6,  0,  0,  0}, { 1,  2,  3,  5,  6,  0,  0,  0}, { 0,  1,  2,  3,  5,  6,  0,  0},
  { 4,  5,  6,  0,  0,  0,  0,  0}, { 0,  4,  5,  6,  0,  0,  0,  0}, { 1,  4,  5,  6,  0,  0,  0,  0}, { 0,  1,  4,  5,  6,  0,  0,  0},
  { 2,  4,  5,  6,  0,  0,  0,  0}, { 0,  2,  4,  5,  6,  0,  0,  0}, { 1,  2,  4,  5,  6,  0,  0,  0}, { 0,  1,  2,  4,  5,  6,  0,  0},
  { 3,  4,  5,  6,  0,  0,  0,  0}, { 0,  3,  4,  5,  6,  0,  0,  0}, { 1,  3,  4,  5,  6,  0,  0,  0}, { 0,  1,  3,  4,  5,  6,  0,  0},
  { 2,  3,  4,  5,  6,  0,  0,  0}, { 0,  2,  3,  4,  5,  6,  0,  0}, { 1,  2,  3,  4,  5,  6,  0,  0}, { 0,  1,  2,  3,  4,  5,  6,  0},
  { 7,  0,  0,  0,  0,  0,  0,  0}, { 0,  7,  0,  0,  0,  0,  0,  0}, { 1,  7,  0,  0,  0,  0,  0,  0}, { 0,  1,  7,  0,  0,  0,  0,  0},
  { 2,  7,  0,  0,  0,  0,  0,  0}, { 0,  2,  7,  0,  0,  0,  0,  0}, { 1,  2,  7,  0,  0,  0,  0,  0}, { 0,  1,  2,  7,  0,  0,  0,  0},
  { 3,  7,  0,  0,  0,  0,  0,  0}, { 0,  3,  7,  0,  0,  0,  0,  0}, { 1,  3,  7,  0,  0,  0,  0,  0}, { 0,  1,  3,  7,  0,  0,  0,  0},
  { 2,  3,  7,  0,  0,  0,  0,  0}, { 0,  2,  3,  7,  0,  0,  0,  0}, { 1,  2,  3,  7,  0,  0,  0,  0}, { 0,  1,  2,  3,  7,  0,  0,  0},
  { 4,  7,  0,  0,  0,  0,  0,  0}, { 0,  4,  7,  0,  0,  0,  0,  0}, { 1,  4,  7,  0,  0,  0,  0,  0}, { 0,  1,  4,  7,  0,  0,  0,  0},
  { 2,  4,  7,  0,  0,  0,  0,  0}, { 0,  2,  4,  7,  0,  0,  0,  0}, { 1,  2,  4,  7,  0,  0,  0,  0}, { 0,  1,  2,  4,  7,  0,  0,  0},
  { 3,  4,  7,  0,  0,  0,  0,  0}, { 0,  3,  4,  7,  0,  0,  0,  0}, { 1,  3,  4,  7,  0,  0,  0,  0}, { 0,  1,  3,  4,  7,  0,  0,  0},
  { 2,  3,  4,  7,  0,  0,  0,  0}, { 0,  2,  3,  4,  7,  0,  0,  0}, { 1,  2,  3,  4,  7,  0,  0,  0}, { 0,  1,  2,  3,  4,  7,  0,  0},
  { 5,  7,  0,  0,  0,  0,  0,  0}, { 0,  5,  7,  0,  0,  0,  0,  0}, { 1,  5,  7,  0,  0,  0,  0,  0}, { 0,  1,  5,  7,  0,  0,  0,  0},
  { 2,  5,  7,  0,  0,  0,  0,  0}, { 0,  2,  5,  7,  0,  0,  0,  0}, { 1,  2,  5,  7,  0,  0,  0,  0}, { 0,  1,  2,  5,  7,  0,  0,  0},
  { 3,  5,  7,  0,  0,  0,  0,  0}, { 0,  3,  5,  7,  0,  0,  0,  0}, { 1,  3,  5,  7,  0,  0,  0,  0}, { 0,  1,  3,  5,  7,  0,  0,  0},
  { 2,  3,  5,  7,  0,  0,  0,  0}, { 0,  2,  3,  5,  7,  0,  0,  0}, { 1,  2,  3,  5,  7,  0,  0,  0}, { 0,  1,  2,  3,  5,  7,  0,  0},
  { 4,  5,  7,  0,  0,  0,  0,  0}, { 0,  4,  5,  7,  0,  0,  0,  0}, { 1,  4,  5,  7,  0,  0,  0,  0}, { 0,  1,  4,  5,  7,  0,  0,  0},
  { 2,  4,  5,  7,  0,  0,  0,  0}, { 0,  2,  4,  5,  7,  0,  0,  0}, { 1,  2,  4,  5,  7,  0,  0,  0}, { 0,  1,  2,  4,  5,  7,  0,  0},
  { 3,  4,  5,  7,  0,  0,  0,  0}, { 0,  3,  4,  5,  7,  0,  0,  0}, { 1,  3,  4,  5,  7,  0,  0,  0}, { 0,  1,  3,  4,  5,  7,  0,  0},
  { 2,  3,  4,  5,  7,  0,  0,  0}, { 0,  2,  3,  4,  5,  7,  0,  0}, { 1,  2,  3,  4,  5,  7,  0,  0}, { 0,  1,  2,  3,  4,  5,  7,  0},
  { 6,  7,  0,  0,  0,  0,  0,  0}, { 0,  6,  7,  0,  0,  0,  0,  0}, { 1,  6,  7,  0,  0,  0,  0,  0}, { 0,  1,  6,  7,  0,  0,  0,  0},
  { 2,  6,  7,  0,  0,  0,  0,  0}, { 0,  2,  6,  7,  0,  0,  0,  0}, { 1,  2,  6,  7,  0,  0,  0,  0}, { 0,  1,  2,  6,  7,  0,  0,  0},
  { 3,  6,  7,  0,  0,  0,  0,  0}, { 0,  3,  6,  7,  0,  0,  0,  0}, { 1,  3,  6,  7,  0,  0,  0,  0}, { 0,  1,  3,  6,  7,  0,  0,  0},
  { 2,  3,  6,  7,  0,  0,  0,  0}, { 0,  2,  3,  6,  7,  0,  0,  0}, { 1,  2,  3,  6,  7,  0,  0,  0}, { 0,  1,  2,  3,  6,  7,  0,  0},
  { 4,  6,  7,  0,  0,  0,  0,  0}, { 0,  4,  6,  7,  0,  0,  0,  0}, { 1,  4,  6,  7,  0,  0,  0,  0}, { 0,  1,  4,  6,  7,  0,  0,  0},
  { 2,  4,  6,  7,  0,  0,  0,  0}, { 0,  2,  4,  6,  7,  0,  0,  0}, { 1,  2,  4,  6,  7,  0,  0,  0}, { 0,  1,  2,  4,  6,  7,  0,  0},
  { 3,  4,  6,  7,  0,  0,  0,  0}, { 0,  3,  4,  6,  7,  0,  0,  0}, { 1,  3,  4,  6,  7,  0,  0,  0}, { 0,  1,  3,  4,  6,  7,  0,  0},
  { 2,  3,  4,  6,  7,  0,  0,  0}, { 0,  2,  3,  4,  6,  7,  0,  0}, { 1,  2,  3,  4,  6,  7,  0,  0}, { 0,  1,  2,  3,  4,  6,  7,  0},
  { 5,  6,  7,  0,  0,  0,  0,  0}, { 0,  5,  6,  7,  0,  0,  0,  0}, { 1,  5,  6,  7,  0,  0,  0,  0}, { 0,  1,  5,  6,  7,  0,  0,  0},
  { 2,  5,  6,  7,  0,  0,  0,  0}, { 0,  2,  5,  6,  7,  0,  0,  0}, { 1,  2,  5,  6,  7,  0,  0,  0}, { 0,  1,  2,  5,  6,  7,  0,  0},
  { 3,  5,  6,  7,  0,  0,  0,  0}, { 0,  3,  5,  6,  7,  0,  0,  0}, { 1,  3,  5,  6,  7,  0,  0,  0}, { 0,  1,  3,  5,  6,  7,  0,  0},
  { 2,  3,  5,  6,  7,  0,  0,  0}, { 0,  2,  3,  5,  6,  7,  0,  0}, { 1,  2,  3,  5,  6,  7,  0,  0}, { 0,  1,  2,  3,  5,  6,  7,  0},
  { 4,  5,  6,  7,  0,  0,  0,  0}, { 0,  4,  5,  6,  7,  0,  0,  0}, { 1,  4,  5,  6,  7,  0,  0,  0}, { 0,  1,  4,  5,  6,  7,  0,  0},
  { 2,  4,  5,  6,  7,  0,  0,  0}, { 0,  2,  4,  5,  6,  7,  0,  0}, { 1,  2,  4,  5,  6,  7,  0,  0}, { 0,  1,  2,  4,  5,  6,  7,  0},
  { 3,  4,  5,  6,  7,  0,  0,  0}, { 0,  3,  4,  5,  6,  7,  0,  0}, { 1,  3,  4,  5,  6,  7,  0,  0}, { 0,  1,  3,  4,  5,  6,  7,  0},
  { 2,  3,  4,  5,  6,  7,  0,  0}, { 0,  2,  3,  4,  5,  6,  7,  0}, { 1,  2,  3,  4,  5,  6,  7,  0}, { 0,  1,  2,  3,  4,  5,  6,  7}
};

static const int32_t dilithium_zetas[DILITHIUM_N] =
{
            0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
    1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
    2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
    2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
    -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
    -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
    -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
    3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
    -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
    -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
    -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
    1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
    2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
    -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
    2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
    -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
    -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
    -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
    -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
    -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
    -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
    -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
    -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
    -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

static dilithium_q_avx2[8] = { DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q,
    DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q };
static dilithium_qinv_avx2[8] = { DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV,
    DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_Q };

#define _mm256_blendv_epi32(a,b,mask) \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), \
                                       _mm256_castsi256_ps(b), \
                                       _mm256_castsi256_ps(mask)))

/* rounding.c */

static void dilithium_avx2_power2round(int32_t* restrict a1, int32_t* restrict a0, const int32_t* restrict a)
{
    __m256i f;
    __m256i f0;
    __m256i f1;
    const __m256i mask = _mm256_set1_epi32(-(int32_t)(1U << DILITHIUM_D));
    const __m256i half = _mm256_set1_epi32((1U << (DILITHIUM_D - 1)) - 1);

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        f = _mm256_load_si256((__m256i*)&a[8 * i]);
        f1 = _mm256_add_epi32(f, half);
        f0 = _mm256_and_si256(f1, mask);
        f1 = _mm256_srli_epi32(f1, DILITHIUM_D);
        f0 = _mm256_sub_epi32(f, f0);
        _mm256_store_si256((__m256i*)&a1[8 * i], f1);
        _mm256_store_si256((__m256i*)&a0[8 * i], f0);
    }
}

#if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32
static void dilithium_avx2_decompose(int32_t* restrict a1, int32_t* restrict a0, const int32_t* restrict a)
{
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0]);
    const __m256i hq = _mm256_srli_epi32(q, 1);
    const __m256i v = _mm256_set1_epi32(1025);
    const __m256i alpha = _mm256_set1_epi32(2 * DILITHIUM_GAMMA2);
    const __m256i off = _mm256_set1_epi32(127);
    const __m256i shift = _mm256_set1_epi32(512);
    const __m256i mask = _mm256_set1_epi32(15);
    __m256i f;
    __m256i f0;
    __m256i f1;

    for (size_t i = 0; i < DILITHIUM_N / 8; i++)
    {
        f = _mm256_load_si256((__m256i*)&a[8 * i]);
        f1 = _mm256_add_epi32(f, off);
        f1 = _mm256_srli_epi32(f1, 7);
        f1 = _mm256_mulhi_epu16(f1, v);
        f1 = _mm256_mulhrs_epi16(f1, shift);
        f1 = _mm256_and_si256(f1, mask);
        f0 = _mm256_mullo_epi32(f1, alpha);
        f0 = _mm256_sub_epi32(f, f0);
        f = _mm256_cmpgt_epi32(f0, hq);
        f = _mm256_and_si256(f, q);
        f0 = _mm256_sub_epi32(f0, f);
        _mm256_store_si256((__m256i*)&a1[8 * i], f1);
        _mm256_store_si256((__m256i*)&a0[8 * i], f0);
    }
}
#elif DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88
static void dilithium_avx2_decompose(int32_t* restrict a1, int32_t* restrict a0, const int32_t* restrict a)
{
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0]);
    const __m256i hq = _mm256_srli_epi32(q, 1);
    const __m256i v = _mm256_set1_epi32(11275);
    const __m256i alpha = _mm256_set1_epi32(2 * DILITHIUM_GAMMA2);
    const __m256i off = _mm256_set1_epi32(127);
    const __m256i shift = _mm256_set1_epi32(128);
    const __m256i max = _mm256_set1_epi32(43);
    const __m256i zero = _mm256_setzero_si256();
    __m256i f;
    __m256i f0;
    __m256i f1;
    __m256i t;

    for (size_t i = 0; i < DILITHIUM_N / 8; i++)
    {
        f = _mm256_load_si256((__m256i*)&a[8 * i]);
        f1 = _mm256_add_epi32(f, off);
        f1 = _mm256_srli_epi32(f1, 7);
        f1 = _mm256_mulhi_epu16(f1, v);
        f1 = _mm256_mulhrs_epi16(f1, shift);
        t = _mm256_cmpgt_epi32(f1, max);
        f1 = _mm256_blendv_epi8(f1, zero, t);
        f0 = _mm256_mullo_epi32(f1, alpha);
        f0 = _mm256_sub_epi32(f, f0);
        f = _mm256_cmpgt_epi32(f0, hq);
        f = _mm256_and_si256(f, q);
        f0 = _mm256_sub_epi32(f0, f);
        _mm256_store_si256((__m256i*)&a1[8 * i], f1);
        _mm256_store_si256((__m256i*)&a0[8 * i], f0);
    }
}
#endif

static uint32_t dilithium_avx2_make_hint(uint8_t hint[DILITHIUM_N], const dilithium_poly* restrict a0, const dilithium_poly* restrict a1)
{
    uint32_t i, n = 0;
    __m256i f0, f1, g0, g1;
    uint32_t bad;
    uint64_t idx;
    const __m256i low = _mm256_set1_epi32(-DILITHIUM_GAMMA2);
    const __m256i high = _mm256_set1_epi32(DILITHIUM_GAMMA2);

    for (i = 0; i < DILITHIUM_N / 8; ++i)
    {
        f0 = _mm256_load_si256((const __m256i*)&a0->coeffs[i * sizeof(__m256i) / sizeof(int32_t)]);
        f1 = _mm256_load_si256((const __m256i*)&a1->coeffs[i * sizeof(__m256i) / sizeof(int32_t)]);
        g0 = _mm256_abs_epi32(f0);
        g0 = _mm256_cmpgt_epi32(g0, high);
        g1 = _mm256_cmpeq_epi32(f0, low);
        g1 = _mm256_sign_epi32(g1, f1);
        g0 = _mm256_or_si256(g0, g1);

        bad = _mm256_movemask_ps(_mm256_castsi256_ps(g0));
        memcpy(&idx, dilithium_rej_avx2[bad], 8);
        idx += (uint64_t)0x0808080808080808 * i;
        memcpy(&hint[n], &idx, 8);
        n += _mm_popcnt_u32(bad);
    }

    return n;
}

//static void dilithium_avx2_use_hint(int32_t* restrict b, const int32_t* restrict a, const int32_t* restrict hint)
//{
//    QSC_ALIGN(32) int32_t a0[DILITHIUM_N];
//    __m256i f;
//    __m256i g;
//    __m256i h;
//    __m256i t;
//    const __m256i zero = _mm256_setzero_si256();
//#if DILITHIUM_GAMMA2 == (DILITHIUM_Q -1 ) / 32
//    const __m256i mask = _mm256_set1_epi32(15);
//#elif DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88
//    const __m256i max = _mm256_set1_epi32(43);
//#endif
//
//    dilithium_avx2_decompose(b, a0, a);
//
//    for (size_t i = 0; i < DILITHIUM_N / 8; i++)
//    {
//        f = _mm256_load_si256((__m256i*)&a0[8 * i]);
//        g = _mm256_load_si256((__m256i*)&b[8 * i]);
//        h = _mm256_load_si256((__m256i*)&hint[8 * i]);
//        t = _mm256_blendv_epi32(zero, h, f);
//        t = _mm256_slli_epi32(t, 1);
//        h = _mm256_sub_epi32(h, t);
//        g = _mm256_add_epi32(g, h);
//#if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32
//        g = _mm256_and_si256(g, mask);
//#elif DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88
//        g = _mm256_blendv_epi32(g, max, g);
//        f = _mm256_cmpgt_epi32(g, max);
//        g = _mm256_blendv_epi32(g, zero, f);
//#endif
//        _mm256_store_si256((__m256i*)&b[8 * i], g);
//    }
//}

static void dilithium_avx2_use_hint(int32_t* b, const int32_t* a, const int32_t* restrict hint)
{
    int32_t a0[DILITHIUM_N];
    __m256i f;
    __m256i g;
    __m256i h;
    __m256i t;
    const __m256i zero = _mm256_setzero_si256();

#if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32
    const __m256i mask = _mm256_set1_epi32(15);
#elif DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88
    const __m256i max = _mm256_set1_epi32(43);
#endif

    dilithium_avx2_decompose(b, a0, a);

    for (size_t i = 0; i < DILITHIUM_N / 8; i++)
    {
        f = _mm256_load_si256((const __m256i*)&a0[i * 8]);
        g = _mm256_load_si256((const __m256i*)&b[i * 8]);
        h = _mm256_load_si256((const __m256i*)&hint[i * 8]);
        t = _mm256_blendv_epi32(zero, h, f);
        t = _mm256_slli_epi32(t, 1);
        h = _mm256_sub_epi32(h, t);
        g = _mm256_add_epi32(g, h);
#if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32
        g = _mm256_and_si256(g, mask);
#elif DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88
        g = _mm256_blendv_epi32(g, max, g);
        f = _mm256_cmpgt_epi32(g, max);
        g = _mm256_blendv_epi32(g, zero, f);
#endif
        _mm256_store_si256((__m256i*)&b[i * 8], g);
    }
}

/* rejsample.c */

static uint32_t dilithium_rej_eta(int32_t* a, size_t len, const uint8_t* buf, size_t buflen)
{
    size_t pos;
    uint32_t ctr;
    uint32_t t0;
    uint32_t t1;

    ctr = 0;
    pos = 0;

    while (ctr < len && pos < buflen)
    {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos] >> 4;
        ++pos;

#if (DILITHIUM_ETA == 2)
        if (t0 < 15)
        {
            t0 = t0 - (205 * t0 >> 10) * 5;
            a[ctr] = 2 - t0;
            ++ctr;
        }

        if (t1 < 15 && ctr < len)
        {
            t1 = t1 - (205 * t1 >> 10) * 5;
            a[ctr] = 2 - t1;
            ++ctr;
        }
#elif (DILITHIUM_ETA == 4)
        if (t0 < 9)
        {
            a[ctr] = 4 - t0;
            ++ctr;
        }

        if (t1 < 9 && ctr < len)
        {
            a[ctr] = 4 - t1;
            ++ctr;
        }
#endif
    }

    return ctr;
}

#if DILITHIUM_ETA == 2

uint32_t dilithium_rej_eta_avx(int32_t * restrict r, const uint8_t buf[DILITHIUM_REJ_UNIFORM_ETA_BUFLEN])
{
    const __m256i mask = _mm256_set1_epi8(15);
    const __m256i eta = _mm256_set1_epi8(DILITHIUM_ETA);
    const __m256i bound = mask;
    const __m256i v = _mm256_set1_epi32(-6560);
    const __m256i p = _mm256_set1_epi32(5);
    __m256i f0;
    __m256i  f1;
    __m256i  f2;
    __m128i g0;
    __m128i g1;
    uint32_t ctr;
    uint32_t good;
    uint32_t pos;
    uint32_t t0;
    uint32_t t1;

    ctr = 0;
    pos = 0;

    while (ctr <= DILITHIUM_N - 8 && pos <= DILITHIUM_REJ_UNIFORM_ETA_BUFLEN - 16)
    {
        f0 = _mm256_cvtepu8_epi16(_mm_loadu_si128((__m128i*)&buf[pos]));
        f1 = _mm256_slli_epi16(f0, 4);
        f0 = _mm256_or_si256(f0, f1);
        f0 = _mm256_and_si256(f0, mask);

        f1 = _mm256_sub_epi8(f0, bound);
        f0 = _mm256_sub_epi8(eta, f0);
        good = _mm256_movemask_epi8(f1);

        g0 = _mm256_castsi256_si128(f0);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        f2 = _mm256_mulhrs_epi16(f1, v);
        f2 = _mm256_mullo_epi16(f2, p);
        f1 = _mm256_add_epi32(f1, f2);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }

        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        f2 = _mm256_mulhrs_epi16(f1, v);
        f2 = _mm256_mullo_epi16(f2, p);
        f1 = _mm256_add_epi32(f1, f2);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }

        g0 = _mm256_extracti128_si256(f0, 1);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        f2 = _mm256_mulhrs_epi16(f1, v);
        f2 = _mm256_mullo_epi16(f2, p);
        f1 = _mm256_add_epi32(f1, f2);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }

        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        f2 = _mm256_mulhrs_epi16(f1, v);
        f2 = _mm256_mullo_epi16(f2, p);
        f1 = _mm256_add_epi32(f1, f2);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good);
        pos += 4;
    }

    while (ctr < DILITHIUM_N && pos < DILITHIUM_REJ_UNIFORM_ETA_BUFLEN)
    {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos] >> 4;
        ++pos;

        if (t0 < 15)
        {
            t0 = t0 - (205 * t0 >> 10) * 5;
            r[ctr] = 2 - t0;
            ++ctr;
        }

        if (t1 < 15 && ctr < DILITHIUM_N) 
        {
            t1 = t1 - (205 * t1 >> 10) * 5;
            r[ctr] = 2 - t1;
            ++ctr;
        }
    }

    return ctr;
}

#elif DILITHIUM_ETA == 4

uint32_t dilithium_rej_eta_avx(int32_t * restrict r, const uint8_t buf[DILITHIUM_REJ_UNIFORM_ETA_BUFLEN])
{
    __m256i f0;
    __m256i f1;
    __m128i g0;
    __m128i g1;  // Changed from __m256i to __m128i
    const __m256i mask = _mm256_set1_epi8(15);
    const __m256i eta = _mm256_set1_epi8(4);
    const __m256i bound = _mm256_set1_epi8(9);
    uint32_t ctr;
    uint32_t good;
    uint32_t pos;
    uint32_t t0;
    uint32_t t1;

    ctr = 0;
    pos = 0;

    while (ctr <= DILITHIUM_N - 8 && pos <= DILITHIUM_REJ_UNIFORM_ETA_BUFLEN - 16) 
    {
        f0 = _mm256_cvtepu8_epi16(_mm_loadu_si128((__m128i *)&buf[pos]));
        f1 = _mm256_slli_epi16(f0, 4);
        f0 = _mm256_or_si256(f0, f1);
        f0 = _mm256_and_si256(f0, mask);

        f1 = _mm256_sub_epi8(f0, bound);
        f0 = _mm256_sub_epi8(eta, f0);
        good = _mm256_movemask_epi8(f1);

        g0 = _mm256_extracti128_si256(f0, 0);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }

        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }

        g0 = _mm256_extracti128_si256(f0, 1);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8;
        pos += 4;

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }

        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good);
        pos += 4;
    }

    while (ctr < DILITHIUM_N && pos < DILITHIUM_REJ_UNIFORM_ETA_BUFLEN) 
    {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos] >> 4;
        ++pos;

        if (t0 < 9)
        {
            r[ctr] = 4 - t0;
            ++ctr;
        }
        if (t1 < 9 && ctr < DILITHIUM_N)
        {
            r[ctr] = 4 - t1;
            ++ctr;
        }
    }

    return ctr;
}

#endif

static uint32_t dilithium_rej_uniform(int32_t* a, size_t len, const uint8_t* buf, size_t buflen)
{
    size_t pos;
    uint32_t ctr;
    uint32_t t;

    ctr = 0;
    pos = 0;

    while (ctr < len && pos + 3 <= buflen)
    {
        t = buf[pos];
        ++pos;
        t |= (uint32_t)buf[pos] << 8;
        ++pos;
        t |= (uint32_t)buf[pos] << 16;
        ++pos;
        t &= 0x007FFFFF;

        if (t < DILITHIUM_Q)
        {
            a[ctr] = t;
            ++ctr;
        }
    }

    return ctr;
}

static uint32_t dilithium_avx2_rej_uniform(int32_t* restrict r, const uint8_t* restrict buf)
{
    const __m256i bound = _mm256_set1_epi32(DILITHIUM_Q);
    const __m256i mask = _mm256_set1_epi32(0x7FFFFF);
    const __m256i idx8 = _mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10, -1, 9, 8, 7, -1, 6, 5, 4,
        -1, 11, 10, 9, -1, 8, 7, 6, -1, 5, 4, 3, -1, 2, 1, 0);
    __m256i d;
    __m256i tmp;
    size_t pos;
    uint32_t ctr;
    uint32_t good;
    uint32_t t;

    ctr = 0;
    pos = 0;

    while (pos <= DILITHIUM_REJ_UNIFORM_BUFLEN - 24)
    {
        d = _mm256_loadu_si256((__m256i*)&buf[pos]);
        d = _mm256_permute4x64_epi64(d, 0x94);
        d = _mm256_shuffle_epi8(d, idx8);
        d = _mm256_and_si256(d, mask);
        pos += 24;

        tmp = _mm256_sub_epi32(d, bound);
        good = _mm256_movemask_ps(_mm256_castsi256_ps(tmp));
        tmp = _mm256_cvtepu8_epi32(_mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good]));
        d = _mm256_permutevar8x32_epi32(d, tmp);
        _mm256_storeu_si256((__m256i*)&r[ctr], d);
        ctr += _mm_popcnt_u32(good);

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }
    }

    while (ctr < DILITHIUM_N && pos <= DILITHIUM_REJ_UNIFORM_BUFLEN - 3)
    {
        t = buf[pos];
        ++pos;
        t |= (uint32_t)buf[pos] << 8;
        ++pos;
        t |= (uint32_t)buf[pos] << 16;
        ++pos;
        t &= 0x7FFFFF;

        if (t < DILITHIUM_Q)
        {
            r[ctr] = t;
            ++ctr;
        }
    }

    return ctr;
}

/* poly.c */

static void dilithium_avx2_poly_reduce(dilithium_poly* a)
{
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0]);
    const __m256i off = _mm256_set1_epi32(1 << 22);
    __m256i f;
    __m256i g;

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        f = _mm256_load_si256((__m256i*)&a->coeffs[8 * i]);
        g = _mm256_add_epi32(f, off);
        g = _mm256_srai_epi32(g, 23);
        g = _mm256_mullo_epi32(g, q);
        f = _mm256_sub_epi32(f, g);
        _mm256_store_si256((__m256i*)&a->coeffs[8 * i], f);
    }
}

static void dilithium_avx2_poly_caddq(dilithium_poly* a)
{
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0]);
    const __m256i zero = _mm256_setzero_si256();
    __m256i f;
    __m256i g;

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        f = _mm256_load_si256((__m256i*)&a->coeffs[8 * i]);
        g = _mm256_blendv_epi32(zero, q, f);
        f = _mm256_add_epi32(f, g);
        _mm256_store_si256((__m256i*)&a->coeffs[8 * i], f);
    }
}

static void dilithium_avx2_poly_add(dilithium_poly* c, const dilithium_poly* a, const dilithium_poly* b)
{
    __m256i vec0;
    __m256i vec1;

    for (size_t i = 0; i < DILITHIUM_N; i += 8)
    {
        vec0 = _mm256_load_si256((__m256i*)&a->coeffs[i]);
        vec1 = _mm256_load_si256((__m256i*)&b->coeffs[i]);
        vec0 = _mm256_add_epi32(vec0, vec1);
        _mm256_store_si256((__m256i*)&c->coeffs[i], vec0);
    }
}

static void dilithium_avx2_poly_sub(dilithium_poly* c, const dilithium_poly* a, const dilithium_poly* b)
{
    __m256i vec0;
    __m256i vec1;

    for (size_t i = 0; i < DILITHIUM_N; i += 8)
    {
        vec0 = _mm256_load_si256((__m256i*)&a->coeffs[i]);
        vec1 = _mm256_load_si256((__m256i*)&b->coeffs[i]);
        vec0 = _mm256_sub_epi32(vec0, vec1);
        _mm256_store_si256((__m256i*)&c->coeffs[i], vec0);
    }
}

static void dilithium_avx2_poly_shiftl(dilithium_poly* a)
{
    __m256i vec;

    for (size_t i = 0; i < DILITHIUM_N; i += 8)
    {
        vec = _mm256_load_si256((__m256i*)&a->coeffs[i]);
        vec = _mm256_slli_epi32(vec, DILITHIUM_D);
        _mm256_store_si256((__m256i*)&a->coeffs[i], vec);
    }
}

static void dilithium_avx2_poly_power2round(dilithium_poly* a1, dilithium_poly* a0, const dilithium_poly* a)
{
    dilithium_avx2_power2round(a1->coeffs, a0->coeffs, a->coeffs);
}

static void dilithium_avx2_poly_decompose(dilithium_poly* a1, dilithium_poly* a0, const dilithium_poly* a)
{
    dilithium_avx2_decompose(a1->coeffs, a0->coeffs, a->coeffs);
}

static void dilithium_avx2_poly_use_hint(dilithium_poly* b, const dilithium_poly* a, const dilithium_poly* h)
{
    dilithium_avx2_use_hint(b->coeffs, a->coeffs, h->coeffs);
}

static int32_t dilithium_avx2_poly_chknorm(const dilithium_poly* a, int32_t B)
{
    const __m256i bound = _mm256_set1_epi32(B - 1);
    __m256i f;
    __m256i t;
    int32_t r;

    if (B > (DILITHIUM_Q - 1) / 8)
    {
        r = 1;
    }
    else
    {
        t = _mm256_setzero_si256();

        for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
        {
            f = _mm256_load_si256((__m256i*)&a->coeffs[8 * i]);
            f = _mm256_abs_epi32(f);
            f = _mm256_cmpgt_epi32(f, bound);
            t = _mm256_or_si256(t, f);
        }

        r = !_mm256_testz_si256(t, t);
    }

    return r;
}

static void dilithium_avx2_poly_uniform_eta_4x(dilithium_poly* a0, dilithium_poly* a1, dilithium_poly* a2, dilithium_poly* a3, 
    const uint8_t seed[64], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3)
{

    QSC_ALIGN(32) uint8_t buf[4][DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_256_RATE];
    __m256i ksi[QSC_KECCAK_STATE_SIZE] = { 0 };
    size_t buflen;
    uint32_t ctr0;
    uint32_t ctr1; 
    uint32_t ctr2;
    uint32_t ctr3;

    buflen = DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_256_RATE;
    qsc_memutils_copy(buf[0], seed, 64);
    qsc_memutils_copy(buf[1], seed, 64);
    qsc_memutils_copy(buf[2], seed, 64);
    qsc_memutils_copy(buf[3], seed, 64);

    buf[0][DILITHIUM_CRHBYTES] = (uint8_t)nonce0;
    buf[0][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce0 >> 8);
    buf[1][DILITHIUM_CRHBYTES] = (uint8_t)nonce1;
    buf[1][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce1 >> 8);
    buf[2][DILITHIUM_CRHBYTES] = (uint8_t)nonce2;
    buf[2][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce2 >> 8);
    buf[3][DILITHIUM_CRHBYTES] = (uint8_t)nonce3;
    buf[3][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce3 >> 8);

    qsc_keccakx4_absorb(ksi, qsc_keccak_rate_256, buf[0], buf[1], buf[2], buf[3], (DILITHIUM_SEEDBYTES * 2) + 2, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_256, buf[0], buf[1], buf[2], buf[3], DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS);

    ctr0 = dilithium_rej_eta_avx(a0->coeffs, buf[0]);
    ctr1 = dilithium_rej_eta_avx(a1->coeffs, buf[1]);
    ctr2 = dilithium_rej_eta_avx(a2->coeffs, buf[2]);
    ctr3 = dilithium_rej_eta_avx(a3->coeffs, buf[3]);

    while (ctr0 < DILITHIUM_N || ctr1 < DILITHIUM_N || ctr2 < DILITHIUM_N || ctr3 < DILITHIUM_N)
    {
        qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_256, buf[0], buf[1], buf[2], buf[3], 1);

        ctr0 += dilithium_rej_eta(a0->coeffs + ctr0, DILITHIUM_N - ctr0, buf[0], QSC_KECCAK_256_RATE);
        ctr1 += dilithium_rej_eta(a1->coeffs + ctr1, DILITHIUM_N - ctr1, buf[1], QSC_KECCAK_256_RATE);
        ctr2 += dilithium_rej_eta(a2->coeffs + ctr2, DILITHIUM_N - ctr2, buf[2], QSC_KECCAK_256_RATE);
        ctr3 += dilithium_rej_eta(a3->coeffs + ctr3, DILITHIUM_N - ctr3, buf[3], QSC_KECCAK_256_RATE);
    }
}

static void dilithium_polyz_unpack(dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4 * i] = a[9 * i];
        r->coeffs[4 * i] |= (uint32_t)a[(9 * i) + 1] << 8;
        r->coeffs[4 * i] |= (uint32_t)a[(9 * i) + 2] << 16;
        r->coeffs[4 * i] &= 0x0003FFFF;

        r->coeffs[(4 * i) + 1] = a[(9 * i) + 2] >> 2;
        r->coeffs[(4 * i) + 1] |= (uint32_t)a[(9 * i) + 3] << 6;
        r->coeffs[(4 * i) + 1] |= (uint32_t)a[(9 * i) + 4] << 14;
        r->coeffs[(4 * i) + 1] &= 0x0003FFFF;

        r->coeffs[(4 * i) + 2] = a[(9 * i) + 4] >> 4;
        r->coeffs[(4 * i) + 2] |= (uint32_t)a[(9 * i) + 5] << 4;
        r->coeffs[(4 * i) + 2] |= (uint32_t)a[(9 * i) + 6] << 12;
        r->coeffs[(4 * i) + 2] &= 0x0003FFFF;

        r->coeffs[(4 * i) + 3] = a[(9 * i) + 6] >> 6;
        r->coeffs[(4 * i) + 3] |= (uint32_t)a[(9 * i) + 7] << 2;
        r->coeffs[(4 * i) + 3] |= (uint32_t)a[(9 * i) + 8] << 10;
        r->coeffs[(4 * i) + 3] &= 0x0003FFFF;

        r->coeffs[4 * i] = DILITHIUM_GAMMA1 - r->coeffs[4 * i];
        r->coeffs[(4 * i) + 1] = DILITHIUM_GAMMA1 - r->coeffs[(4 * i) + 1];
        r->coeffs[(4 * i) + 2] = DILITHIUM_GAMMA1 - r->coeffs[(4 * i) + 2];
        r->coeffs[(4 * i) + 3] = DILITHIUM_GAMMA1 - r->coeffs[(4 * i) + 3];
    }
#elif (DILITHIUM_GAMMA1 == (1 << 19))
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        r->coeffs[2 * i] = a[5 * i];
        r->coeffs[2 * i] |= (uint32_t)a[(5 * i) + 1] << 8;
        r->coeffs[2 * i] |= (uint32_t)a[(5 * i) + 2] << 16;
        r->coeffs[2 * i] &= 0x000FFFFFL;

        r->coeffs[(2 * i) + 1] = a[(5 * i) + 2] >> 4;
        r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 3] << 4;
        r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 4] << 12;
        r->coeffs[2 * i] &= 0x000FFFFFL;

        r->coeffs[2 * i] = DILITHIUM_GAMMA1 - r->coeffs[2 * i];
        r->coeffs[(2 * i) + 1] = DILITHIUM_GAMMA1 - r->coeffs[(2 * i) + 1];
    }
#endif
}

static void dilithium_avx2_poly_uniform_gamma1_4x(dilithium_poly* a0, dilithium_poly* a1, dilithium_poly* a2, dilithium_poly* a3,
    const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3)
{
    QSC_ALIGN(32) uint8_t buf[4][DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS * QSC_KECCAK_256_RATE + 14];
    __m256i ksi[QSC_KECCAK_STATE_SIZE] = { 0 };
    __m256i f;

    f = _mm256_load_si256((__m256i*)seed);
    _mm256_store_si256((__m256i*)buf[0], f);
    _mm256_store_si256((__m256i*)buf[1], f);
    _mm256_store_si256((__m256i*)buf[2], f);
    _mm256_store_si256((__m256i*)buf[3], f);
    f = _mm256_load_si256((__m256i*)&seed[32]);
    _mm256_store_si256((__m256i*)&buf[0][32], f);
    _mm256_store_si256((__m256i*)&buf[1][32], f);
    _mm256_store_si256((__m256i*)&buf[2][32], f);
    _mm256_store_si256((__m256i*)&buf[3][32], f);

    buf[0][DILITHIUM_CRHBYTES] = (uint8_t)nonce0;
    buf[0][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce0 >> 8);
    buf[1][DILITHIUM_CRHBYTES] = (uint8_t)nonce1;
    buf[1][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce1 >> 8);
    buf[2][DILITHIUM_CRHBYTES] = (uint8_t)nonce2;
    buf[2][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce2 >> 8);
    buf[3][DILITHIUM_CRHBYTES] = (uint8_t)nonce3;
    buf[3][DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce3 >> 8);

    qsc_keccakx4_absorb(ksi, qsc_keccak_rate_256, buf[0], buf[1], buf[2], buf[3], DILITHIUM_CRHBYTES + 2, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_256, buf[0], buf[1], buf[2], buf[3], DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS);

    dilithium_polyz_unpack(a0, buf[0]);
    dilithium_polyz_unpack(a1, buf[1]);
    dilithium_polyz_unpack(a2, buf[2]);
    dilithium_polyz_unpack(a3, buf[3]);
}

#if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88
void dilithium_avx2_polyw1_pack(uint8_t *r, const dilithium_poly * restrict a)
{
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m256i f3;
    const __m256i shift1 = _mm256_set1_epi16((64 << 8) + 1);
    const __m256i shift2 = _mm256_set1_epi32((4096 << 16) + 1);
    const __m256i shufdidx1 = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);
    const __m256i shufdidx2 = _mm256_set_epi32(-1, -1, 6, 5, 4, 2, 1, 0);
    const __m256i shufbidx = _mm256_set_epi8(-1, -1, -1, -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0,
        -1, -1, -1, -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0);

    for (size_t i = 0; i < DILITHIUM_N / 32; i++) 
    {
        f0 = _mm256_load_si256((__m256i*)&a->coeffs[32 * i]);
        f1 = _mm256_load_si256((__m256i*)&a->coeffs[32 * i + 8]);
        f2 = _mm256_load_si256((__m256i*)&a->coeffs[32 * i + 16]);
        f3 = _mm256_load_si256((__m256i*)&a->coeffs[32 * i + 24]);
        f0 = _mm256_packus_epi32(f0, f1);
        f1 = _mm256_packus_epi32(f2, f3);
        f0 = _mm256_packus_epi16(f0, f1);
        f0 = _mm256_maddubs_epi16(f0, shift1);
        f0 = _mm256_madd_epi16(f0, shift2);
        f0 = _mm256_permutevar8x32_epi32(f0, shufdidx1);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);
        f0 = _mm256_permutevar8x32_epi32(f0, shufdidx2);
        _mm256_storeu_si256((__m256i*)&r[24 * i], f0);
    }
}

#elif DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32
void dilithium_avx2_polyw1_pack(uint8_t *r, const dilithium_poly * restrict a)
{
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m256i f3;
    __m256i f4;
    __m256i f5;
    __m256i f6;
    __m256i f7;

    const __m256i shift = _mm256_set1_epi16((16 << 8) + 1);
    const __m256i shufbidx = _mm256_set_epi8(15, 14, 7, 6, 13, 12, 5, 4, 11, 10, 3, 2, 9, 8, 1, 0,
        15, 14, 7, 6, 13, 12, 5, 4, 11, 10, 3, 2, 9, 8, 1, 0);

    for (size_t i = 0; i < DILITHIUM_N / 64; ++i)
    {
        f0 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i]);
        f1 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i + 8]);
        f2 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i + 16]);
        f3 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i + 24]);
        f4 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i + 32]);
        f5 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i + 40]);
        f6 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i + 48]);
        f7 = _mm256_load_si256((__m256i*)&a->coeffs[64 * i + 56]);
        f0 = _mm256_packus_epi32(f0, f1);
        f1 = _mm256_packus_epi32(f2, f3);
        f2 = _mm256_packus_epi32(f4, f5);
        f3 = _mm256_packus_epi32(f6, f7);
        f0 = _mm256_packus_epi16(f0, f1);
        f1 = _mm256_packus_epi16(f2, f3);
        f0 = _mm256_maddubs_epi16(f0, shift);
        f1 = _mm256_maddubs_epi16(f1, shift);
        f0 = _mm256_packus_epi16(f0, f1);
        f0 = _mm256_permute4x64_epi64(f0, 0xD8);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);
        _mm256_storeu_si256((__m256i*)&r[32 * i], f0);
    }
}
#endif

/* reduce.c */

static int32_t dilithium_montgomery_reduce(int64_t a)
{
    int32_t t;

    t = (int64_t)(int32_t)a * DILITHIUM_QINV;
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;

    return t;
}

/* ntt.c */

static void dilithium_ntt(int32_t a[DILITHIUM_N])
{
    size_t j;
    size_t k;
    int32_t zeta;
    int32_t t;

    k = 0;

    for (size_t len = 128; len > 0; len >>= 1)
    {
        for (size_t start = 0; start < DILITHIUM_N; start = j + len)
        {
            ++k;
            zeta = dilithium_zetas[k];

            for (j = start; j < start + len; ++j)
            {
                t = dilithium_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

static void dilithium_invntt_to_mont(int32_t a[DILITHIUM_N])
{
    size_t j;
    size_t k;
    int32_t t;
    int32_t zeta;
    const int32_t F = 41978; /* mont ^ 2 / 256 */

    k = 256;

    for (size_t len = 1; len < DILITHIUM_N; len <<= 1)
    {
        for (size_t start = 0; start < DILITHIUM_N; start = j + len)
        {
            --k;
            zeta = -dilithium_zetas[k];

            for (j = start; j < start + len; ++j)
            {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = dilithium_montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < DILITHIUM_N; ++j)
    {
        a[j] = dilithium_montgomery_reduce((int64_t)F * a[j]);
    }
}

/* poly.c */

static void dilithium_poly_ntt(dilithium_poly* a)
{
    dilithium_ntt(a->coeffs);
}

static void dilithium_poly_invntt_to_mont(dilithium_poly* a)
{
    dilithium_invntt_to_mont(a->coeffs);
}

static void dilithium_poly_pointwise_montgomery(dilithium_poly* c, const dilithium_poly* a, const dilithium_poly* b)
{
    for (size_t i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = dilithium_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

static void dilithium_poly_challenge(dilithium_poly* c, const uint8_t seed[DILITHIUM_CTILDEBYTES])
{
    uint8_t buf[QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;
    uint64_t signs;
    size_t i;
    size_t b;
    size_t pos;

    qsc_keccak_initialize_state(&kctx);

    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, DILITHIUM_CTILDEBYTES);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_squeezeblocks(&kctx, buf, 1, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    signs = 0;
    pos = 8;

    for (i = 0; i < 8; ++i)
    {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = 0;
    }

    for (i = DILITHIUM_N - DILITHIUM_TAU; i < DILITHIUM_N; ++i)
    {
        do
        {
            if (pos >= QSC_KECCAK_256_RATE)
            {
                qsc_keccak_squeezeblocks(&kctx, buf, 1, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
                pos = 0;
            }

            b = buf[pos];
            ++pos;
        } 
        while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - (2 * (signs & 1));
        signs >>= 1;
    }
}

static void dilithium_polyeta_pack(uint8_t* r, const dilithium_poly* a)
{
    uint8_t t[8];

#if DILITHIUM_ETA == 2
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        t[0] = DILITHIUM_ETA - a->coeffs[8 * i];
        t[1] = DILITHIUM_ETA - a->coeffs[8 * i + 1];
        t[2] = DILITHIUM_ETA - a->coeffs[8 * i + 2];
        t[3] = DILITHIUM_ETA - a->coeffs[8 * i + 3];
        t[4] = DILITHIUM_ETA - a->coeffs[8 * i + 4];
        t[5] = DILITHIUM_ETA - a->coeffs[8 * i + 5];
        t[6] = DILITHIUM_ETA - a->coeffs[8 * i + 6];
        t[7] = DILITHIUM_ETA - a->coeffs[8 * i + 7];

        r[3 * i] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
        r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
#elif DILITHIUM_ETA == 4
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        t[0] = DILITHIUM_ETA - a->coeffs[2 * i];
        t[1] = DILITHIUM_ETA - a->coeffs[2 * i + 1];
        r[i] = t[0] | (t[1] << 4);
    }
#endif
}

static void dilithium_polyeta_unpack(dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_ETA == 2)
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        r->coeffs[8 * i] = (a[3 * i] >> 0) & 7;
        r->coeffs[(8 * i) + 1] = (a[3 * i] >> 3) & 7;
        r->coeffs[(8 * i) + 2] = ((a[3 * i] >> 6) | (a[(3 * i) + 1] << 2)) & 7;
        r->coeffs[(8 * i) + 3] = (a[(3 * i) + 1] >> 1) & 7;
        r->coeffs[(8 * i) + 4] = (a[(3 * i) + 1] >> 4) & 7;
        r->coeffs[(8 * i) + 5] = ((a[(3 * i) + 1] >> 7) | (a[(3 * i) + 2] << 1)) & 7;
        r->coeffs[(8 * i) + 6] = (a[(3 * i) + 2] >> 2) & 7;
        r->coeffs[(8 * i) + 7] = (a[(3 * i) + 2] >> 5) & 7;

        r->coeffs[8 * i] = DILITHIUM_ETA - r->coeffs[8 * i];
        r->coeffs[(8 * i) + 1] = DILITHIUM_ETA - r->coeffs[(8 * i) + 1];
        r->coeffs[(8 * i) + 2] = DILITHIUM_ETA - r->coeffs[(8 * i) + 2];
        r->coeffs[(8 * i) + 3] = DILITHIUM_ETA - r->coeffs[(8 * i) + 3];
        r->coeffs[(8 * i) + 4] = DILITHIUM_ETA - r->coeffs[(8 * i) + 4];
        r->coeffs[(8 * i) + 5] = DILITHIUM_ETA - r->coeffs[(8 * i) + 5];
        r->coeffs[(8 * i) + 6] = DILITHIUM_ETA - r->coeffs[(8 * i) + 6];
        r->coeffs[(8 * i) + 7] = DILITHIUM_ETA - r->coeffs[(8 * i) + 7];
    }
#elif (DILITHIUM_ETA == 4)
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        r->coeffs[2 * i] = a[i] & 0x0F;
        r->coeffs[(2 * i) + 1] = a[i] >> 4;
        r->coeffs[2 * i] = DILITHIUM_ETA - r->coeffs[2 * i];
        r->coeffs[(2 * i) + 1] = DILITHIUM_ETA - r->coeffs[(2 * i) + 1];
    }
#endif
}

static void dilithium_polyt1_pack(uint8_t* r, const dilithium_poly* a)
{
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r[5 * i] = (uint8_t)(a->coeffs[4 * i] >> 0);
        r[(5 * i) + 1] = (uint8_t)((a->coeffs[4 * i] >> 8) | (a->coeffs[(4 * i) + 1] << 2));
        r[(5 * i) + 2] = (uint8_t)((a->coeffs[(4 * i) + 1] >> 6) | (a->coeffs[(4 * i) + 2] << 4));
        r[(5 * i) + 3] = (uint8_t)((a->coeffs[(4 * i) + 2] >> 4) | (a->coeffs[(4 * i) + 3] << 6));
        r[(5 * i) + 4] = (uint8_t)(a->coeffs[(4 * i) + 3] >> 2);
    }
}

static void dilithium_polyt1_unpack(dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4 * i] = ((a[5 * i] >> 0) | ((uint32_t)a[(5 * i) + 1] << 8)) & 0x000003FF;
        r->coeffs[(4 * i) + 1] = ((a[(5 * i) + 1] >> 2) | ((uint32_t)a[(5 * i) + 2] << 6)) & 0x000003FF;
        r->coeffs[(4 * i) + 2] = ((a[(5 * i) + 2] >> 4) | ((uint32_t)a[(5 * i) + 3] << 4)) & 0x000003FF;
        r->coeffs[(4 * i) + 3] = ((a[(5 * i) + 3] >> 6) | ((uint32_t)a[(5 * i) + 4] << 2)) & 0x000003FF;
    }
}

static void dilithium_polyt0_pack(uint8_t* r, const dilithium_poly* a)
{
    uint32_t t[8];

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        t[0] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i];
        t[1] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 1];
        t[2] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 2];
        t[3] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 3];
        t[4] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 4];
        t[5] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 5];
        t[6] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 6];
        t[7] = (1 << (DILITHIUM_D - 1)) - a->coeffs[(8 * i) + 7];

        r[13 * i] = (uint8_t)t[0];
        r[(13 * i) + 1] = (uint8_t)(t[0] >> 8);
        r[(13 * i) + 1] |= (uint8_t)(t[1] << 5);
        r[(13 * i) + 2] = (uint8_t)(t[1] >> 3);
        r[(13 * i) + 3] = (uint8_t)(t[1] >> 11);
        r[(13 * i) + 3] |= (uint8_t)(t[2] << 2);
        r[(13 * i) + 4] = (uint8_t)(t[2] >> 6);
        r[(13 * i) + 4] |= (uint8_t)(t[3] << 7);
        r[(13 * i) + 5] = (uint8_t)(t[3] >> 1);
        r[(13 * i) + 6] = (uint8_t)(t[3] >> 9);
        r[(13 * i) + 6] |= (uint8_t)(t[4] << 4);
        r[(13 * i) + 7] = (uint8_t)(t[4] >> 4);
        r[(13 * i) + 8] = (uint8_t)(t[4] >> 12);
        r[(13 * i) + 8] |= (uint8_t)(t[5] << 1);
        r[(13 * i) + 9] = (uint8_t)(t[5] >> 7);
        r[(13 * i) + 9] |= (uint8_t)(t[6] << 6);
        r[(13 * i) + 10] = (uint8_t)(t[6] >> 2);
        r[(13 * i) + 11] = (uint8_t)(t[6] >> 10);
        r[(13 * i) + 11] |= (uint8_t)(t[7] << 3);
        r[(13 * i) + 12] = (uint8_t)(t[7] >> 5);
    }
}

static void dilithium_polyt0_unpack(dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        r->coeffs[8 * i] = a[13 * i];
        r->coeffs[8 * i] |= (uint32_t)a[(13 * i) + 1] << 8;
        r->coeffs[8 * i] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 1] = a[(13 * i) + 1] >> 5;
        r->coeffs[(8 * i) + 1] |= (uint32_t)a[(13 * i) + 2] << 3;
        r->coeffs[(8 * i) + 1] |= (uint32_t)a[(13 * i) + 3] << 11;
        r->coeffs[(8 * i) + 1] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 2] = a[(13 * i) + 3] >> 2;
        r->coeffs[(8 * i) + 2] |= (uint32_t)a[(13 * i) + 4] << 6;
        r->coeffs[(8 * i) + 2] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 3] = a[(13 * i) + 4] >> 7;
        r->coeffs[(8 * i) + 3] |= (uint32_t)a[(13 * i) + 5] << 1;
        r->coeffs[(8 * i) + 3] |= (uint32_t)a[(13 * i) + 6] << 9;
        r->coeffs[(8 * i) + 3] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 4] = a[(13 * i) + 6] >> 4;
        r->coeffs[(8 * i) + 4] |= (uint32_t)a[(13 * i) + 7] << 4;
        r->coeffs[(8 * i) + 4] |= (uint32_t)a[(13 * i) + 8] << 12;
        r->coeffs[(8 * i) + 4] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 5] = a[(13 * i) + 8] >> 1;
        r->coeffs[(8 * i) + 5] |= (uint32_t)a[(13 * i) + 9] << 7;
        r->coeffs[(8 * i) + 5] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 6] = a[(13 * i) + 9] >> 6;
        r->coeffs[(8 * i) + 6] |= (uint32_t)a[(13 * i) + 10] << 2;
        r->coeffs[(8 * i) + 6] |= (uint32_t)a[(13 * i) + 11] << 10;
        r->coeffs[(8 * i) + 6] &= 0x00001FFFL;

        r->coeffs[(8 * i) + 7] = a[(13 * i) + 11] >> 3;
        r->coeffs[(8 * i) + 7] |= (uint32_t)a[(13 * i) + 12] << 5;
        r->coeffs[(8 * i) + 7] &= 0x00001FFFL;

        r->coeffs[8 * i] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i];
        r->coeffs[(8 * i) + 1] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 1];
        r->coeffs[(8 * i) + 2] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 2];
        r->coeffs[(8 * i) + 3] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 3];
        r->coeffs[(8 * i) + 4] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 4];
        r->coeffs[(8 * i) + 5] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 5];
        r->coeffs[(8 * i) + 6] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 6];
        r->coeffs[(8 * i) + 7] = (1 << (DILITHIUM_D - 1)) - r->coeffs[(8 * i) + 7];
    }
}

static void dilithium_polyz_pack(uint8_t* r, const dilithium_poly* a)
{
    uint32_t t[4];

#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        t[0] = DILITHIUM_GAMMA1 - a->coeffs[4 * i];
        t[1] = DILITHIUM_GAMMA1 - a->coeffs[(4 * i) + 1];
        t[2] = DILITHIUM_GAMMA1 - a->coeffs[(4 * i) + 2];
        t[3] = DILITHIUM_GAMMA1 - a->coeffs[(4 * i) + 3];

        r[9 * i] = (uint8_t)t[0];
        r[(9 * i) + 1] = (uint8_t)(t[0] >> 8);
        r[(9 * i) + 2] = (uint8_t)(t[0] >> 16);
        r[(9 * i) + 2] |= (uint8_t)(t[1] << 2);
        r[(9 * i) + 3] = (uint8_t)(t[1] >> 6);
        r[(9 * i) + 4] = (uint8_t)(t[1] >> 14);
        r[(9 * i) + 4] |= (uint8_t)(t[2] << 4);
        r[(9 * i) + 5] = (uint8_t)(t[2] >> 4);
        r[(9 * i) + 6] = (uint8_t)(t[2] >> 12);
        r[(9 * i) + 6] |= (uint8_t)(t[3] << 6);
        r[(9 * i) + 7] = (uint8_t)(t[3] >> 2);
        r[(9 * i) + 8] = (uint8_t)(t[3] >> 10);
    }
#elif (DILITHIUM_GAMMA1 == (1 << 19))
    for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
    {
        t[0] = DILITHIUM_GAMMA1 - a->coeffs[2 * i];
        t[1] = DILITHIUM_GAMMA1 - a->coeffs[(2 * i) + 1];

        r[5 * i] = (uint8_t)t[0];
        r[(5 * i) + 1] = (uint8_t)(t[0] >> 8);
        r[(5 * i) + 2] = (uint8_t)(t[0] >> 16);
        r[(5 * i) + 2] |= (uint8_t)(t[1] << 4);
        r[(5 * i) + 3] = (uint8_t)(t[1] >> 4);
        r[(5 * i) + 4] = (uint8_t)(t[1] >> 12);
    }
#endif
}

static void dilithium_avx2_poly_uniform_4x(dilithium_poly* a0, dilithium_poly* a1, dilithium_poly* a2, dilithium_poly* a3,
    const uint8_t seed[32], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3)
{
    QSC_ALIGN(32) uint8_t buf[4][DILITHIUM_REJ_UNIFORM_BUFLEN + 8];
    __m256i ksi[QSC_KECCAK_STATE_SIZE] = { 0 };
    __m256i f;
    uint32_t ctr0;
    uint32_t ctr1;
    uint32_t ctr2;
    uint32_t ctr3;

    f = _mm256_loadu_si256((__m256i*)seed);
    _mm256_store_si256((__m256i*)buf[0], f);
    _mm256_store_si256((__m256i*)buf[1], f);
    _mm256_store_si256((__m256i*)buf[2], f);
    _mm256_store_si256((__m256i*)buf[3], f);

    buf[0][DILITHIUM_SEEDBYTES] = (uint8_t)nonce0;
    buf[0][DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce0 >> 8);
    buf[1][DILITHIUM_SEEDBYTES] = (uint8_t)nonce1;
    buf[1][DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce1 >> 8);
    buf[2][DILITHIUM_SEEDBYTES] = (uint8_t)nonce2;
    buf[2][DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce2 >> 8);
    buf[3][DILITHIUM_SEEDBYTES] = (uint8_t)nonce3;
    buf[3][DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce3 >> 8);

    qsc_keccakx4_absorb(ksi, qsc_keccak_rate_128, buf[0], buf[1], buf[2], buf[3], DILITHIUM_SEEDBYTES + 2, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_128, buf[0], buf[1], buf[2], buf[3], 5);

    ctr0 = dilithium_avx2_rej_uniform(a0->coeffs, buf[0]);
    ctr1 = dilithium_avx2_rej_uniform(a1->coeffs, buf[1]);
    ctr2 = dilithium_avx2_rej_uniform(a2->coeffs, buf[2]);
    ctr3 = dilithium_avx2_rej_uniform(a3->coeffs, buf[3]);

    while (ctr0 < DILITHIUM_N || ctr1 < DILITHIUM_N || ctr2 < DILITHIUM_N || ctr3 < DILITHIUM_N)
    {
        qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_128, buf[0], buf[1], buf[2], buf[3], 1);

        ctr0 += dilithium_rej_uniform(a0->coeffs + ctr0, DILITHIUM_N - ctr0, buf[0], QSC_KECCAK_128_RATE);
        ctr1 += dilithium_rej_uniform(a1->coeffs + ctr1, DILITHIUM_N - ctr1, buf[1], QSC_KECCAK_128_RATE);
        ctr2 += dilithium_rej_uniform(a2->coeffs + ctr2, DILITHIUM_N - ctr2, buf[2], QSC_KECCAK_128_RATE);
        ctr3 += dilithium_rej_uniform(a3->coeffs + ctr3, DILITHIUM_N - ctr3, buf[3], QSC_KECCAK_128_RATE);
    }
}

static void dilithium_poly_uniform_gamma1(dilithium_poly* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    uint8_t buf[DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS * QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;
    uint8_t tn[2];

    tn[0] = (uint8_t)nonce;
    tn[1] = nonce >> 8;

    qsc_keccak_initialize_state(&kctx);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, DILITHIUM_CRHBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, tn, sizeof(tn));
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_squeezeblocks(&kctx, buf, DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    dilithium_polyz_unpack(a, buf);
}

/* polyvec.c */

static void dilithium_avx2_polyvec_matrix_expand(dilithium_polyvecl mat[DILITHIUM_K], const uint8_t rho[DILITHIUM_SEEDBYTES])
{
#if DILITHIUM_K == 4 && DILITHIUM_L == 4
    dilithium_avx2_poly_uniform_4x(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
    dilithium_avx2_poly_uniform_4x(&mat[1].vec[0], &mat[1].vec[1], &mat[1].vec[2], &mat[1].vec[3], rho, 256, 257, 258, 259);
    dilithium_avx2_poly_uniform_4x(&mat[2].vec[0], &mat[2].vec[1], &mat[2].vec[2], &mat[2].vec[3], rho, 512, 513, 514, 515);
    dilithium_avx2_poly_uniform_4x(&mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], &mat[3].vec[3], rho, 768, 769, 770, 771);
#elif DILITHIUM_K == 6 && DILITHIUM_L == 5
    dilithium_poly t0;
    dilithium_poly t1;
    dilithium_avx2_poly_uniform_4x(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
    dilithium_avx2_poly_uniform_4x(&mat[0].vec[4], &mat[1].vec[0], &mat[1].vec[1], &mat[1].vec[2], rho, 4, 256, 257, 258);
    dilithium_avx2_poly_uniform_4x(&mat[1].vec[3], &mat[1].vec[4], &mat[2].vec[0], &mat[2].vec[1], rho, 259, 260, 512, 513);
    dilithium_avx2_poly_uniform_4x(&mat[2].vec[2], &mat[2].vec[3], &mat[2].vec[4], &mat[3].vec[0], rho, 514, 515, 516, 768);
    dilithium_avx2_poly_uniform_4x(&mat[3].vec[1], &mat[3].vec[2], &mat[3].vec[3], &mat[3].vec[4], rho, 769, 770, 771, 772);
    dilithium_avx2_poly_uniform_4x(&mat[4].vec[0], &mat[4].vec[1], &mat[4].vec[2], &mat[4].vec[3], rho, 1024, 1025, 1026, 1027);
    dilithium_avx2_poly_uniform_4x(&mat[4].vec[4], &mat[5].vec[0], &mat[5].vec[1], &mat[5].vec[2], rho, 1028, 1280, 1281, 1282);
    dilithium_avx2_poly_uniform_4x(&mat[5].vec[3], &mat[5].vec[4], &t0, &t1, rho, 1283, 1284, 0, 0);
#elif DILITHIUM_K == 8 && DILITHIUM_L == 7
    dilithium_avx2_poly_uniform_4x(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
    dilithium_avx2_poly_uniform_4x(&mat[0].vec[4], &mat[0].vec[5], &mat[0].vec[6], &mat[1].vec[0], rho, 4, 5, 6, 256);
    dilithium_avx2_poly_uniform_4x(&mat[1].vec[1], &mat[1].vec[2], &mat[1].vec[3], &mat[1].vec[4], rho, 257, 258, 259, 260);
    dilithium_avx2_poly_uniform_4x(&mat[1].vec[5], &mat[1].vec[6], &mat[2].vec[0], &mat[2].vec[1], rho, 261, 262, 512, 513);
    dilithium_avx2_poly_uniform_4x(&mat[2].vec[2], &mat[2].vec[3], &mat[2].vec[4], &mat[2].vec[5], rho, 514, 515, 516, 517);
    dilithium_avx2_poly_uniform_4x(&mat[2].vec[6], &mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], rho, 518, 768, 769, 770);
    dilithium_avx2_poly_uniform_4x(&mat[3].vec[3], &mat[3].vec[4], &mat[3].vec[5], &mat[3].vec[6], rho, 771, 772, 773, 774);
    dilithium_avx2_poly_uniform_4x(&mat[4].vec[0], &mat[4].vec[1], &mat[4].vec[2], &mat[4].vec[3], rho, 1024, 1025, 1026, 1027);
    dilithium_avx2_poly_uniform_4x(&mat[4].vec[4], &mat[4].vec[5], &mat[4].vec[6], &mat[5].vec[0], rho, 1028, 1029, 1030, 1280);
    dilithium_avx2_poly_uniform_4x(&mat[5].vec[1], &mat[5].vec[2], &mat[5].vec[3], &mat[5].vec[4], rho, 1281, 1282, 1283, 1284);
    dilithium_avx2_poly_uniform_4x(&mat[5].vec[5], &mat[5].vec[6], &mat[6].vec[0], &mat[6].vec[1], rho, 1285, 1286, 1536, 1537);
    dilithium_avx2_poly_uniform_4x(&mat[6].vec[2], &mat[6].vec[3], &mat[6].vec[4], &mat[6].vec[5], rho, 1538, 1539, 1540, 1541);
    dilithium_avx2_poly_uniform_4x(&mat[6].vec[6], &mat[7].vec[0], &mat[7].vec[1], &mat[7].vec[2], rho, 1542, 1792, 1793, 1794);
    dilithium_avx2_poly_uniform_4x(&mat[7].vec[3], &mat[7].vec[4], &mat[7].vec[5], &mat[7].vec[6], rho, 1795, 1796, 1797, 1798);
#endif
}

static void dilithium_avx2_polyvec_matrix_expand_row(dilithium_polyvecl mat[DILITHIUM_K], const uint8_t rho[DILITHIUM_SEEDBYTES], size_t idx)
{
#if DILITHIUM_K == 4 && DILITHIUM_L == 4
    if (idx == 0)
    {
        dilithium_avx2_poly_uniform_4x(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
    }
    if (idx == 1)
    {
        dilithium_avx2_poly_uniform_4x(&mat[1].vec[0], &mat[1].vec[1], &mat[1].vec[2], &mat[1].vec[3], rho, 256, 257, 258, 259);
    }
    if (idx == 2)
    {
        dilithium_avx2_poly_uniform_4x(&mat[2].vec[0], &mat[2].vec[1], &mat[2].vec[2], &mat[2].vec[3], rho, 512, 513, 514, 515);
    }
    if (idx == 3)
    {
        dilithium_avx2_poly_uniform_4x(&mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], &mat[3].vec[3], rho, 768, 769, 770, 771);
    }
#elif DILITHIUM_K == 6 && DILITHIUM_L == 5
    if (idx == 0)
    {
        dilithium_avx2_poly_uniform_4x(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
        dilithium_avx2_poly_uniform_4x(&mat[0].vec[4], &mat[1].vec[0], &mat[1].vec[1], &mat[1].vec[2], rho, 4, 256, 257, 258);
    }
    if (idx == 1)
    {
        dilithium_avx2_poly_uniform_4x(&mat[1].vec[3], &mat[1].vec[4], &mat[2].vec[0], &mat[2].vec[1], rho, 259, 260, 512, 513);
    }
    if (idx == 2)
    {
        dilithium_avx2_poly_uniform_4x(&mat[2].vec[2], &mat[2].vec[3], &mat[2].vec[4], &mat[3].vec[0], rho, 514, 515, 516, 768);
    }
    if (idx == 3)
    {
        dilithium_avx2_poly_uniform_4x(&mat[3].vec[1], &mat[3].vec[2], &mat[3].vec[3], &mat[3].vec[4], rho, 769, 770, 771, 772);
    }
    if (idx == 4)
    {
        dilithium_avx2_poly_uniform_4x(&mat[4].vec[0], &mat[4].vec[1], &mat[4].vec[2], &mat[4].vec[3], rho, 1024, 1025, 1026, 1027);
        dilithium_avx2_poly_uniform_4x(&mat[4].vec[4], &mat[5].vec[0], &mat[5].vec[1], &mat[5].vec[2], rho, 1028, 1280, 1281, 1282);
    }
    if (idx == 5)
    {
        dilithium_poly t0;
        dilithium_poly t1;

        dilithium_avx2_poly_uniform_4x(&mat[5].vec[3], &mat[5].vec[4], &t0, &t1, rho, 1283, 1284, 0, 0);
    }
#elif DILITHIUM_K == 8 && DILITHIUM_L == 7
    if (idx == 0)
    {
        dilithium_avx2_poly_uniform_4x(&mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], &mat[0].vec[3], rho, 0, 1, 2, 3);
        dilithium_avx2_poly_uniform_4x(&mat[0].vec[4], &mat[0].vec[5], &mat[0].vec[6], &mat[1].vec[0], rho, 4, 5, 6, 256);
    }
    if (idx == 1)
    {
        dilithium_avx2_poly_uniform_4x(&mat[1].vec[1], &mat[1].vec[2], &mat[1].vec[3], &mat[1].vec[4], rho, 257, 258, 259, 260);
        dilithium_avx2_poly_uniform_4x(&mat[1].vec[5], &mat[1].vec[6], &mat[2].vec[0], &mat[2].vec[1], rho, 261, 262, 512, 513);
    }
    if (idx == 2)
    {
        dilithium_avx2_poly_uniform_4x(&mat[2].vec[2], &mat[2].vec[3], &mat[2].vec[4], &mat[2].vec[5], rho, 514, 515, 516, 517);
        dilithium_avx2_poly_uniform_4x(&mat[2].vec[6], &mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], rho, 518, 768, 769, 770);
    }
    if (idx == 3)
    {
        dilithium_avx2_poly_uniform_4x(&mat[3].vec[3], &mat[3].vec[4], &mat[3].vec[5], &mat[3].vec[6], rho, 771, 772, 773, 774);
    }
    if (idx == 4)
    {
        dilithium_avx2_poly_uniform_4x(&mat[4].vec[0], &mat[4].vec[1], &mat[4].vec[2], &mat[4].vec[3], rho, 1024, 1025, 1026, 1027);
        dilithium_avx2_poly_uniform_4x(&mat[4].vec[4], &mat[4].vec[5], &mat[4].vec[6], &mat[5].vec[0], rho, 1028, 1029, 1030, 1280);
    }
    if (idx == 5)
    {
        dilithium_avx2_poly_uniform_4x(&mat[5].vec[1], &mat[5].vec[2], &mat[5].vec[3], &mat[5].vec[4], rho, 1281, 1282, 1283, 1284);
        dilithium_avx2_poly_uniform_4x(&mat[5].vec[5], &mat[5].vec[6], &mat[6].vec[0], &mat[6].vec[1], rho, 1285, 1286, 1536, 1537);
    }
    if (idx == 6)
    {
        dilithium_avx2_poly_uniform_4x(&mat[6].vec[2], &mat[6].vec[3], &mat[6].vec[4], &mat[6].vec[5], rho, 1538, 1539, 1540, 1541);
        dilithium_avx2_poly_uniform_4x(&mat[6].vec[6], &mat[7].vec[0], &mat[7].vec[1], &mat[7].vec[2], rho, 1542, 1792, 1793, 1794);
    }
    if (idx == 7)
    {
        dilithium_avx2_poly_uniform_4x(&mat[7].vec[3], &mat[7].vec[4], &mat[7].vec[5], &mat[7].vec[6], rho, 1795, 1796, 1797, 1798);
    }

#endif
}

static void dilithium_polyvecl_pointwise_acc_montgomery(dilithium_poly* w, const dilithium_polyvecl* u, const dilithium_polyvecl* v)
{
    dilithium_poly t;

    dilithium_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);

    for (size_t i = 1; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        dilithium_avx2_poly_add(w, w, &t);
    }
}

static void dilithium_polyvecl_ntt(dilithium_polyvecl* v)
{
    for (size_t i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void dilithium_polyveck_ntt(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

/* packing.c */

static void dilithium_unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES], uint8_t tr[DILITHIUM_CRHBYTES], uint8_t key[DILITHIUM_SEEDBYTES],
    dilithium_polyveck* t0, dilithium_polyvecl* s1, dilithium_polyveck* s2, const uint8_t sk[DILITHIUM_PRIVATEKEY_SIZE])
{
    size_t  i;

    qsc_memutils_copy(rho, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(key, sk, DILITHIUM_SEEDBYTES);
    sk += DILITHIUM_SEEDBYTES;

    qsc_memutils_copy(tr, sk, DILITHIUM_TRBYTES);
    sk += DILITHIUM_TRBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        dilithium_polyeta_unpack(&s1->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyeta_unpack(&s2->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_polyt0_unpack(&t0->vec[i], sk + i * DILITHIUM_POLYT0_PACKEDBYTES);
    }
}

void polyvec_matrix_pointwise_montgomery(dilithium_polyveck* t, const dilithium_polyvecl mat[DILITHIUM_K], const dilithium_polyvecl* v)
{
  for (size_t i = 0; i < DILITHIUM_K; ++i)
  {
      dilithium_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
  }
}

static void dilithium_polyveck_invntt_to_mont(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_invntt_to_mont(&v->vec[i]);
    }
}

static void dilithium_avx2_polyveck_caddq(dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_avx2_poly_caddq(&v->vec[i]);
    }
}

static void dilithium_avx2_polyveck_decompose(dilithium_polyveck* v1, dilithium_polyveck* v0, const dilithium_polyveck* v)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_avx2_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static void dilithium_avx2_polyveck_pack_w1(uint8_t r[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES], const dilithium_polyveck* w1)
{
    for (size_t i = 0; i < DILITHIUM_K; ++i)
    {
        dilithium_avx2_polyw1_pack(&r[i * DILITHIUM_POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}

/* sign.c */

void qsc_dilithium_avx2_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1;
    dilithium_polyveck s2;
    dilithium_poly t0;
    dilithium_poly t1;
    QSC_ALIGN(32)uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    const uint8_t* key;
    const uint8_t* rho;
    const uint8_t* rhoprime;
    size_t i;

    /* Get randomness for rho, rhoprime and key */
    rng_generate(seedbuf, DILITHIUM_SEEDBYTES);
    seedbuf[DILITHIUM_SEEDBYTES] = DILITHIUM_K;
    seedbuf[DILITHIUM_SEEDBYTES + 1] = DILITHIUM_L;
    qsc_shake256_compute(seedbuf, 2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES, seedbuf, DILITHIUM_SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + DILITHIUM_SEEDBYTES;
    key = rhoprime + DILITHIUM_CRHBYTES;

    /* Store rho, key */
    qsc_memutils_copy(pk, rho, DILITHIUM_SEEDBYTES);
    qsc_memutils_copy(sk, rho, DILITHIUM_SEEDBYTES);
    qsc_memutils_copy(sk + DILITHIUM_SEEDBYTES, key, DILITHIUM_SEEDBYTES);

    /* Sample short vectors s1 and s2 */
#if DILITHIUM_K == 4 && DILITHIUM_L == 4
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[0], &s2.vec[1], &s2.vec[2], &s2.vec[3], rhoprime, 4, 5, 6, 7);
#elif DILITHIUM_K == 6 && DILITHIUM_L == 5
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[4], &s2.vec[0], &s2.vec[1], &s2.vec[2], rhoprime, 4, 5, 6, 7);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[3], &s2.vec[4], &s2.vec[5], &t0, rhoprime, 8, 9, 10, 11);
#elif DILITHIUM_K == 8 && DILITHIUM_L == 7
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[4], &s1.vec[5], &s1.vec[6], &s2.vec[0], rhoprime, 4, 5, 6, 7);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[1], &s2.vec[2], &s2.vec[3], &s2.vec[4], rhoprime, 8, 9, 10, 11);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[5], &s2.vec[6], &s2.vec[7], &t0, rhoprime, 12, 13, 14, 15);
#else
#   error
#endif

    /* Pack secret vectors */
    for (i = 0; i < DILITHIUM_L; i++)
    {
        dilithium_polyeta_pack(sk + (2 * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (i * DILITHIUM_POLYETA_PACKEDBYTES), &s1.vec[i]);
    }

    for (i = 0; i < DILITHIUM_K; i++)
    {
        dilithium_polyeta_pack(sk + (2 * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (DILITHIUM_L + i) * DILITHIUM_POLYETA_PACKEDBYTES, &s2.vec[i]);
    }

    /* Transform s1 */
    dilithium_polyvecl_ntt(&s1);

    for (i = 0; i < DILITHIUM_K; i++)
    {
        dilithium_avx2_polyvec_matrix_expand_row(mat, rho, i);
        /* Compute inner-product */
        dilithium_polyvecl_pointwise_acc_montgomery(&t1, &mat[i], &s1);
        dilithium_poly_invntt_to_mont(&t1);
        /* Add error polynomial */
        dilithium_avx2_poly_add(&t1, &t1, &s2.vec[i]);
        /* Round t and pack t1, t0 */
        dilithium_avx2_poly_caddq(&t1);
        dilithium_avx2_poly_power2round(&t1, &t0, &t1);
        dilithium_polyt1_pack(pk + DILITHIUM_SEEDBYTES + (i * DILITHIUM_POLYT1_PACKEDBYTES), &t1);
        dilithium_polyt0_pack(sk + (2 * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (DILITHIUM_L + DILITHIUM_K) * DILITHIUM_POLYETA_PACKEDBYTES + (i * DILITHIUM_POLYT0_PACKEDBYTES), &t0);
    }

    /* Compute CRH(rho, t1) and store in secret key */
    qsc_shake256_compute(sk + (2 * DILITHIUM_SEEDBYTES), DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);
}

void qsc_dilithium_avx2_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1;
    dilithium_polyvecl y;
    dilithium_polyvecl z;
    dilithium_polyveck t0;
    dilithium_polyveck s2;
    dilithium_polyveck w1;
    dilithium_polyveck w0;
    dilithium_poly cp;
    dilithium_poly tmph;
    qsc_keccak_state kctx = { 0 };
    uint8_t hintbuf[DILITHIUM_N];
    QSC_ALIGN(32) uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + 3 * DILITHIUM_CRHBYTES];
    uint8_t rnd[DILITHIUM_RNDBYTES] = { 0 };
    uint8_t* hint;
    uint8_t* key;
    uint8_t* mu;
    uint8_t* rho;
    uint8_t* rhoprime;
    uint8_t* tr;
    size_t i;
    size_t n;
    size_t pos;
    uint16_t nonce;
    bool res;
    
    nonce = 0;
    rho = seedbuf;
    tr = rho + DILITHIUM_SEEDBYTES;
    key = tr + DILITHIUM_CRHBYTES;
    mu = key + DILITHIUM_SEEDBYTES;
    rhoprime = mu + DILITHIUM_CRHBYTES;
    hint = sig + DILITHIUM_CTILDEBYTES + (DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES);

    dilithium_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute CRH(tr, msg) */
    qsc_keccak_initialize_state(&kctx);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, tr, DILITHIUM_TRBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, context, contextlen);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
    rng_generate(rnd, DILITHIUM_CRHBYTES);
#endif

    /* compute rhoprime = CRH(key, rnd, mu) */
    qsc_keccak_initialize_state(&kctx);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, key, DILITHIUM_SEEDBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, rnd, DILITHIUM_RNDBYTES);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, rhoprime, DILITHIUM_CRHBYTES);

    /* Expand matrix and transform vectors */
    dilithium_avx2_polyvec_matrix_expand(mat, rho);
    dilithium_polyvecl_ntt(&s1);
    dilithium_polyveck_ntt(&s2);
    dilithium_polyveck_ntt(&t0);

    while (true)
    {
        res = true;
        /* Sample intermediate vector y */
#if DILITHIUM_L == 4
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[0], &y.vec[1], &y.vec[2], &y.vec[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
        nonce += 4;
#elif DILITHIUM_L == 5
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[0], &y.vec[1], &y.vec[2], &y.vec[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
        dilithium_poly_uniform_gamma1(&y.vec[4], rhoprime, nonce + 4);
        nonce += 5;
#elif DILITHIUM_L == 7
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[0], &y.vec[1], &y.vec[2], &y.vec[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[4], &y.vec[5], &y.vec[6], &tmph, rhoprime, nonce + 4, nonce + 5, nonce + 6, 0);
        nonce += 7;
#else
#   error
#endif

        /* Save y and transform it */
        z = y;
        dilithium_polyvecl_ntt(&y);
        polyvec_matrix_pointwise_montgomery(&w1, mat, &y);
        dilithium_polyveck_invntt_to_mont(&w1);

        dilithium_avx2_polyveck_caddq(&w1);
        dilithium_avx2_polyveck_decompose(&w1, &w0, &w1);
        dilithium_avx2_polyveck_pack_w1(sig, &w1);

        /* Call the random oracle */
        qsc_keccak_initialize_state(&kctx);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, sig, DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
        qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
        qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, sig, DILITHIUM_CTILDEBYTES);

        dilithium_poly_challenge(&cp, sig);
        dilithium_poly_ntt(&cp);

        /* Compute z, reject if it reveals secret */
        for (i = 0; i < DILITHIUM_L; i++)
        {
            dilithium_poly_pointwise_montgomery(&tmph, &cp, &s1.vec[i]);
            dilithium_poly_invntt_to_mont(&tmph);
            dilithium_avx2_poly_add(&z.vec[i], &z.vec[i], &tmph);
            dilithium_avx2_poly_reduce(&z.vec[i]);

            if (dilithium_avx2_poly_chknorm(&z.vec[i], DILITHIUM_GAMMA1 - DILITHIUM_BETA))
            {
                res = false;
                break;
            }
        }

        if (res == true)
        {
            /* Zero hint in signature */
            n = 0;
            pos = 0;
            qsc_memutils_clear(hint, DILITHIUM_OMEGA + DILITHIUM_K);

            for (i = 0; i < DILITHIUM_K; i++)
            {
                /* Check that subtracting cs2 does not change high bits of w and low bits
                 * do not reveal secret information */
                dilithium_poly_pointwise_montgomery(&tmph, &cp, &s2.vec[i]);
                dilithium_poly_invntt_to_mont(&tmph);
                dilithium_avx2_poly_sub(&w0.vec[i], &w0.vec[i], &tmph);
                dilithium_avx2_poly_reduce(&w0.vec[i]);

                if (dilithium_avx2_poly_chknorm(&w0.vec[i], DILITHIUM_GAMMA2 - DILITHIUM_BETA))
                {
                    res = false;
                    break;
                }

                /* Compute hints */
                dilithium_poly_pointwise_montgomery(&tmph, &cp, &t0.vec[i]);
                dilithium_poly_invntt_to_mont(&tmph);
                dilithium_avx2_poly_reduce(&tmph);

                if (dilithium_avx2_poly_chknorm(&tmph, DILITHIUM_GAMMA2))
                {
                    res = false;
                    break;
                }

                dilithium_avx2_poly_add(&w0.vec[i], &w0.vec[i], &tmph);
                n = dilithium_avx2_make_hint(hintbuf, &w0.vec[i], &w1.vec[i]);

                if (pos + n > DILITHIUM_OMEGA)
                {
                    res = false;
                    break;
                }

                /* Store hints in signature */
                qsc_memutils_copy(&hint[pos], hintbuf, n);
                pos += n;
                hint[DILITHIUM_OMEGA + i] = (uint8_t)pos;
            }
        }

        if (res == false)
        {
            continue;
        }
        
        /* Pack z into signature */
        for (i = 0; i < DILITHIUM_L; ++i)
        {
            dilithium_polyz_pack(sig + DILITHIUM_CTILDEBYTES + (i * DILITHIUM_POLYZ_PACKEDBYTES), &z.vec[i]);
        }

        break;
    }
    
    *siglen = DILITHIUM_SIGNATURE_SIZE;
}

void qsc_dilithium_avx2_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    if (contextlen <= 255)
    {
        uint8_t prec[DILITHIUM_CONTEXT_SIZE] = { 0 };

        /* prepare pre = (0, contextlen, ctx) */
        prec[0] = 0;
        prec[1] = (uint8_t)contextlen;

        if (context != NULL)
        {
            qsc_memutils_copy(prec + 2, context, contextlen);
        }

        for (size_t i = 0; i < mlen; ++i)
        {
            sm[DILITHIUM_SIGNATURE_SIZE + mlen - 1 - i] = m[mlen - 1 - i];
        }

        qsc_dilithium_avx2_sign_signature(sm, smlen, sm + DILITHIUM_SIGNATURE_SIZE, mlen, prec, contextlen + 2, sk, rng_generate);
        *smlen += mlen;
    }
}

bool qsc_dilithium_avx2_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* pk)
{
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl z;
    dilithium_poly cp;
    dilithium_poly t1;
    dilithium_poly w1;
    dilithium_poly h;
    qsc_keccak_state kctx = { 0 };
    /* polyw1_pack writes additional 14 bytes */
    QSC_ALIGN(32) uint8_t buf[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES + 14];
    uint8_t c[DILITHIUM_CTILDEBYTES];
    uint8_t mu[DILITHIUM_CRHBYTES];
    const uint8_t* hint = sig + DILITHIUM_CTILDEBYTES + DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;
    size_t i;
    size_t j;
    size_t pos;
    bool res;

    res = true;
    pos = 0;

    if (siglen == DILITHIUM_SIGNATURE_SIZE)
    {
        /* Compute CRH(H(rho, t1), pre, msg) */
        qsc_shake256_compute(mu, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);

        qsc_keccak_initialize_state(&kctx);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, context, contextlen);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
        qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
        qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

        /* Expand challenge */
        dilithium_poly_challenge(&cp, sig);
        dilithium_poly_ntt(&cp);

        /* Unpack z; shortness follows from unpacking */
        for (i = 0; i < DILITHIUM_L; i++)
        {
            dilithium_polyz_unpack(&z.vec[i], sig + DILITHIUM_CTILDEBYTES + i * DILITHIUM_POLYZ_PACKEDBYTES);
            dilithium_poly_ntt(&z.vec[i]);
        }

        pos = 0; // NOTE: t1 is h now

        for (i = 0; i < DILITHIUM_K; i++)
        {
            /* Expand matrix row */
            dilithium_avx2_polyvec_matrix_expand_row(mat, pk, i);

            /* Compute i-th row of Az - c2^Dt1 */
            dilithium_polyvecl_pointwise_acc_montgomery(&w1, &mat[i], &z);

            dilithium_polyt1_unpack(&t1, pk + DILITHIUM_SEEDBYTES + i * DILITHIUM_POLYT1_PACKEDBYTES);
            dilithium_avx2_poly_shiftl(&t1);
            dilithium_poly_ntt(&t1);
            dilithium_poly_pointwise_montgomery(&t1, &cp, &t1);

            dilithium_avx2_poly_sub(&w1, &w1, &t1);
            dilithium_avx2_poly_reduce(&w1);
            dilithium_poly_invntt_to_mont(&w1);

            /* Get hint polynomial and reconstruct w1 */
            qsc_memutils_clear(h.coeffs, DILITHIUM_N);

            /* Get hint polynomial and reconstruct w1 */
            qsc_memutils_clear(h.coeffs, sizeof(dilithium_poly));

            if(hint[DILITHIUM_OMEGA + i] < pos || hint[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA)
            {
                res = false;
                break;
            }

            for(j = pos; j < hint[DILITHIUM_OMEGA + i]; ++j)
            {
                /* Coefficients are ordered for strong unforgeability */
                if(j > pos && hint[j] <= hint[j - 1]) 
                {
                    res = false;
                    break;
                }

                h.coeffs[hint[j]] = 1;
            }

            pos = hint[DILITHIUM_OMEGA + i];

            if (res == false)
            {
                break;
            }

            pos = hint[DILITHIUM_OMEGA + i];

            dilithium_avx2_poly_caddq(&w1);
            dilithium_avx2_poly_use_hint(&w1, &w1, &h);
            dilithium_avx2_polyw1_pack(buf + i * DILITHIUM_POLYW1_PACKEDBYTES, &w1);
        }

        if (res == true)
        {
            /* Extra indices are zero for strong unforgeability */
            for (j = pos; j < DILITHIUM_OMEGA; ++j)
            {
                if (hint[j])
                {
                    res = false;
                    break;
                }
            }

            if (res == true)
            {
                /* Call random oracle and verify challenge */
                qsc_keccak_initialize_state(&kctx);
                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
                qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, buf, DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
                qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
                qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, c, DILITHIUM_CTILDEBYTES);

                if (qsc_intutils_verify(c, sig, DILITHIUM_CTILDEBYTES) != 0)
                {
                    res = false;
                }
            }
        }
    }

    return res;
}

bool qsc_dilithium_avx2_open(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* context, size_t contextlen, const uint8_t* pk)
{
    bool res;

    *mlen = 0;
    res = false;

    if (contextlen <= 255)
    {
        uint8_t prec[DILITHIUM_CONTEXT_SIZE] = { 0 };

        /* prepare pre = (0, ctxlen, ctx) */
        prec[0] = 0;
        prec[1] = (uint8_t)contextlen;

        if (context != NULL)
        {
            qsc_memutils_copy(prec + 2, context, contextlen);
        }

        if (smlen >= DILITHIUM_SIGNATURE_SIZE)
        {
            *mlen = smlen - DILITHIUM_SIGNATURE_SIZE;
            res = qsc_dilithium_avx2_verify(sm, DILITHIUM_SIGNATURE_SIZE, sm + DILITHIUM_SIGNATURE_SIZE, *mlen, prec, contextlen + 2, pk);

            if (res == true)
            {
                /* All good, copy msg, return 0 */
                qsc_memutils_copy(m, sm + DILITHIUM_SIGNATURE_SIZE, *mlen);
            }
        }
    }

    if (res == false)
    {
        qsc_memutils_clear(m, smlen - DILITHIUM_SIGNATURE_SIZE);
    }

    return res;
}

#endif
