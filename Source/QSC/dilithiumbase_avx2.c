#include "dilithiumbase_avx2.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/* params.h */
#if defined(QSC_SYSTEM_HAS_AVX2)

#if defined(QSC_DILITHIUM_S1P44)
#   define DILITHIUM_MODE 2
#elif defined(QSC_DILITHIUM_S3P65) 
#   define DILITHIUM_MODE 3
#elif defined(QSC_DILITHIUM_S5P87)
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

#define DILITHIUM_CRHBYTES 64U
#define DILITHIUM_CONTEXT_SIZE 257
#define DILITHIUM_D 13
#define DILITHIUM_Q 8380417
#define DILITHIUM_MONT -4186625 /* 2^32 % DILITHIUM_Q */
#define DILITHIUM_N 256LL
#define DILITHIUM_QINV 58728449 /* q^(-1) mod 2^32 */
#define DILITHIUM_RNDBYTES 32U
#define DILITHIUM_ROOT_OF_UNITY 1753
#define DILITHIUM_SEEDBYTES 32U
#define DILITHIUM_TRBYTES 64U

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

#define DILITHIUM_POLYT1_PACKEDBYTES  320U
#define DILITHIUM_POLYT0_PACKEDBYTES  416U
#define DILITHIUM_POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + DILITHIUM_K)

#if (DILITHIUM_GAMMA1 == (1 << 17))
#   define DILITHIUM_POLYZ_PACKEDBYTES 576
#elif (DILITHIUM_GAMMA1 == (1 << 19))
#   define DILITHIUM_POLYZ_PACKEDBYTES 640U
#endif

#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 88)
#   define DILITHIUM_POLYW1_PACKEDBYTES 192U
#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 32)
#   define DILITHIUM_POLYW1_PACKEDBYTES  128U
#endif

#if (DILITHIUM_ETA == 2)
#   define DILITHIUM_POLYETA_PACKEDBYTES 96U
#elif (DILITHIUM_ETA == 4)
#   define DILITHIUM_POLYETA_PACKEDBYTES 128U
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
    QSC_ALIGN(32) int32_t coeffs[DILITHIUM_N];            /*!< The coefficients  */
} dilithium_poly;

/*!
* \struct dilithium_polyvecl
* \brief Vectors of polynomials of length L
*/
typedef struct
{
    QSC_ALIGN(32) dilithium_poly vec[DILITHIUM_L];    /*!< The poly vector of L  */
} dilithium_polyvecl;

/*!
* \struct dilithium_polyveck
* \brief Vectors of polynomials of length K
*/
typedef struct
{
    QSC_ALIGN(32) dilithium_poly vec[DILITHIUM_K];    /*!< The poly vector of K  */
} dilithium_polyveck;

static const QSC_ALIGN(32) uint8_t dilithium_rej_avx2[256U][8U] = {
  { 0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 1U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  0U,  0U,  0U,  0U,  0U,  0U},
  { 2U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  0U,  0U,  0U,  0U,  0U,  0U}, { 1U,  2U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  0U,  0U,  0U,  0U,  0U},
  { 3U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  0U,  0U,  0U,  0U,  0U,  0U}, { 1U,  3U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  0U,  0U,  0U,  0U,  0U},
  { 2U,  3U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  0U,  0U,  0U,  0U,  0U}, { 1U,  2U,  3U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  0U,  0U,  0U,  0U},
  { 4U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  4U,  0U,  0U,  0U,  0U,  0U,  0U}, { 1U,  4U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  4U,  0U,  0U,  0U,  0U,  0U},
  { 2U,  4U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  4U,  0U,  0U,  0U,  0U,  0U}, { 1U,  2U,  4U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  4U,  0U,  0U,  0U,  0U},
  { 3U,  4U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  4U,  0U,  0U,  0U,  0U,  0U}, { 1U,  3U,  4U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  4U,  0U,  0U,  0U,  0U},
  { 2U,  3U,  4U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  4U,  0U,  0U,  0U,  0U}, { 1U,  2U,  3U,  4U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  4U,  0U,  0U,  0U},
  { 5U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  5U,  0U,  0U,  0U,  0U,  0U,  0U}, { 1U,  5U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  5U,  0U,  0U,  0U,  0U,  0U},
  { 2U,  5U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  5U,  0U,  0U,  0U,  0U,  0U}, { 1U,  2U,  5U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  5U,  0U,  0U,  0U,  0U},
  { 3U,  5U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  5U,  0U,  0U,  0U,  0U,  0U}, { 1U,  3U,  5U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  5U,  0U,  0U,  0U,  0U},
  { 2U,  3U,  5U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  5U,  0U,  0U,  0U,  0U}, { 1U,  2U,  3U,  5U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  5U,  0U,  0U,  0U},
  { 4U,  5U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  4U,  5U,  0U,  0U,  0U,  0U,  0U}, { 1U,  4U,  5U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  4U,  5U,  0U,  0U,  0U,  0U},
  { 2U,  4U,  5U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  4U,  5U,  0U,  0U,  0U,  0U}, { 1U,  2U,  4U,  5U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  4U,  5U,  0U,  0U,  0U},
  { 3U,  4U,  5U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  4U,  5U,  0U,  0U,  0U,  0U}, { 1U,  3U,  4U,  5U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  4U,  5U,  0U,  0U,  0U},
  { 2U,  3U,  4U,  5U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  4U,  5U,  0U,  0U,  0U}, { 1U,  2U,  3U,  4U,  5U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  4U,  5U,  0U,  0U},
  { 6U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  6U,  0U,  0U,  0U,  0U,  0U,  0U}, { 1U,  6U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  6U,  0U,  0U,  0U,  0U,  0U},
  { 2U,  6U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  6U,  0U,  0U,  0U,  0U,  0U}, { 1U,  2U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  6U,  0U,  0U,  0U,  0U},
  { 3U,  6U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  6U,  0U,  0U,  0U,  0U,  0U}, { 1U,  3U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  6U,  0U,  0U,  0U,  0U},
  { 2U,  3U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  6U,  0U,  0U,  0U,  0U}, { 1U,  2U,  3U,  6U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  6U,  0U,  0U,  0U},
  { 4U,  6U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  4U,  6U,  0U,  0U,  0U,  0U,  0U}, { 1U,  4U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  4U,  6U,  0U,  0U,  0U,  0U},
  { 2U,  4U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  4U,  6U,  0U,  0U,  0U,  0U}, { 1U,  2U,  4U,  6U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  4U,  6U,  0U,  0U,  0U},
  { 3U,  4U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  4U,  6U,  0U,  0U,  0U,  0U}, { 1U,  3U,  4U,  6U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  4U,  6U,  0U,  0U,  0U},
  { 2U,  3U,  4U,  6U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  4U,  6U,  0U,  0U,  0U}, { 1U,  2U,  3U,  4U,  6U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  4U,  6U,  0U,  0U},
  { 5U,  6U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  5U,  6U,  0U,  0U,  0U,  0U,  0U}, { 1U,  5U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  5U,  6U,  0U,  0U,  0U,  0U},
  { 2U,  5U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  5U,  6U,  0U,  0U,  0U,  0U}, { 1U,  2U,  5U,  6U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  5U,  6U,  0U,  0U,  0U},
  { 3U,  5U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  5U,  6U,  0U,  0U,  0U,  0U}, { 1U,  3U,  5U,  6U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  5U,  6U,  0U,  0U,  0U},
  { 2U,  3U,  5U,  6U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  5U,  6U,  0U,  0U,  0U}, { 1U,  2U,  3U,  5U,  6U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  5U,  6U,  0U,  0U},
  { 4U,  5U,  6U,  0U,  0U,  0U,  0U,  0U}, { 0U,  4U,  5U,  6U,  0U,  0U,  0U,  0U}, { 1U,  4U,  5U,  6U,  0U,  0U,  0U,  0U}, { 0U,  1U,  4U,  5U,  6U,  0U,  0U,  0U},
  { 2U,  4U,  5U,  6U,  0U,  0U,  0U,  0U}, { 0U,  2U,  4U,  5U,  6U,  0U,  0U,  0U}, { 1U,  2U,  4U,  5U,  6U,  0U,  0U,  0U}, { 0U,  1U,  2U,  4U,  5U,  6U,  0U,  0U},
  { 3U,  4U,  5U,  6U,  0U,  0U,  0U,  0U}, { 0U,  3U,  4U,  5U,  6U,  0U,  0U,  0U}, { 1U,  3U,  4U,  5U,  6U,  0U,  0U,  0U}, { 0U,  1U,  3U,  4U,  5U,  6U,  0U,  0U},
  { 2U,  3U,  4U,  5U,  6U,  0U,  0U,  0U}, { 0U,  2U,  3U,  4U,  5U,  6U,  0U,  0U}, { 1U,  2U,  3U,  4U,  5U,  6U,  0U,  0U}, { 0U,  1U,  2U,  3U,  4U,  5U,  6U,  0U},
  { 7U,  0U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  7U,  0U,  0U,  0U,  0U,  0U,  0U}, { 1U,  7U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  7U,  0U,  0U,  0U,  0U,  0U},
  { 2U,  7U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  7U,  0U,  0U,  0U,  0U,  0U}, { 1U,  2U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  7U,  0U,  0U,  0U,  0U},
  { 3U,  7U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  7U,  0U,  0U,  0U,  0U,  0U}, { 1U,  3U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  7U,  0U,  0U,  0U,  0U},
  { 2U,  3U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  7U,  0U,  0U,  0U,  0U}, { 1U,  2U,  3U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  7U,  0U,  0U,  0U},
  { 4U,  7U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  4U,  7U,  0U,  0U,  0U,  0U,  0U}, { 1U,  4U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  4U,  7U,  0U,  0U,  0U,  0U},
  { 2U,  4U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  4U,  7U,  0U,  0U,  0U,  0U}, { 1U,  2U,  4U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  4U,  7U,  0U,  0U,  0U},
  { 3U,  4U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  4U,  7U,  0U,  0U,  0U,  0U}, { 1U,  3U,  4U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  4U,  7U,  0U,  0U,  0U},
  { 2U,  3U,  4U,  7U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  4U,  7U,  0U,  0U,  0U}, { 1U,  2U,  3U,  4U,  7U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  4U,  7U,  0U,  0U},
  { 5U,  7U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  5U,  7U,  0U,  0U,  0U,  0U,  0U}, { 1U,  5U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  5U,  7U,  0U,  0U,  0U,  0U},
  { 2U,  5U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  5U,  7U,  0U,  0U,  0U,  0U}, { 1U,  2U,  5U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  5U,  7U,  0U,  0U,  0U},
  { 3U,  5U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  5U,  7U,  0U,  0U,  0U,  0U}, { 1U,  3U,  5U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  5U,  7U,  0U,  0U,  0U},
  { 2U,  3U,  5U,  7U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  5U,  7U,  0U,  0U,  0U}, { 1U,  2U,  3U,  5U,  7U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  5U,  7U,  0U,  0U},
  { 4U,  5U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  4U,  5U,  7U,  0U,  0U,  0U,  0U}, { 1U,  4U,  5U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  4U,  5U,  7U,  0U,  0U,  0U},
  { 2U,  4U,  5U,  7U,  0U,  0U,  0U,  0U}, { 0U,  2U,  4U,  5U,  7U,  0U,  0U,  0U}, { 1U,  2U,  4U,  5U,  7U,  0U,  0U,  0U}, { 0U,  1U,  2U,  4U,  5U,  7U,  0U,  0U},
  { 3U,  4U,  5U,  7U,  0U,  0U,  0U,  0U}, { 0U,  3U,  4U,  5U,  7U,  0U,  0U,  0U}, { 1U,  3U,  4U,  5U,  7U,  0U,  0U,  0U}, { 0U,  1U,  3U,  4U,  5U,  7U,  0U,  0U},
  { 2U,  3U,  4U,  5U,  7U,  0U,  0U,  0U}, { 0U,  2U,  3U,  4U,  5U,  7U,  0U,  0U}, { 1U,  2U,  3U,  4U,  5U,  7U,  0U,  0U}, { 0U,  1U,  2U,  3U,  4U,  5U,  7U,  0U},
  { 6U,  7U,  0U,  0U,  0U,  0U,  0U,  0U}, { 0U,  6U,  7U,  0U,  0U,  0U,  0U,  0U}, { 1U,  6U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  1U,  6U,  7U,  0U,  0U,  0U,  0U},
  { 2U,  6U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  2U,  6U,  7U,  0U,  0U,  0U,  0U}, { 1U,  2U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  2U,  6U,  7U,  0U,  0U,  0U},
  { 3U,  6U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  3U,  6U,  7U,  0U,  0U,  0U,  0U}, { 1U,  3U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  3U,  6U,  7U,  0U,  0U,  0U},
  { 2U,  3U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  2U,  3U,  6U,  7U,  0U,  0U,  0U}, { 1U,  2U,  3U,  6U,  7U,  0U,  0U,  0U}, { 0U,  1U,  2U,  3U,  6U,  7U,  0U,  0U},
  { 4U,  6U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  4U,  6U,  7U,  0U,  0U,  0U,  0U}, { 1U,  4U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  4U,  6U,  7U,  0U,  0U,  0U},
  { 2U,  4U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  2U,  4U,  6U,  7U,  0U,  0U,  0U}, { 1U,  2U,  4U,  6U,  7U,  0U,  0U,  0U}, { 0U,  1U,  2U,  4U,  6U,  7U,  0U,  0U},
  { 3U,  4U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  3U,  4U,  6U,  7U,  0U,  0U,  0U}, { 1U,  3U,  4U,  6U,  7U,  0U,  0U,  0U}, { 0U,  1U,  3U,  4U,  6U,  7U,  0U,  0U},
  { 2U,  3U,  4U,  6U,  7U,  0U,  0U,  0U}, { 0U,  2U,  3U,  4U,  6U,  7U,  0U,  0U}, { 1U,  2U,  3U,  4U,  6U,  7U,  0U,  0U}, { 0U,  1U,  2U,  3U,  4U,  6U,  7U,  0U},
  { 5U,  6U,  7U,  0U,  0U,  0U,  0U,  0U}, { 0U,  5U,  6U,  7U,  0U,  0U,  0U,  0U}, { 1U,  5U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  1U,  5U,  6U,  7U,  0U,  0U,  0U},
  { 2U,  5U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  2U,  5U,  6U,  7U,  0U,  0U,  0U}, { 1U,  2U,  5U,  6U,  7U,  0U,  0U,  0U}, { 0U,  1U,  2U,  5U,  6U,  7U,  0U,  0U},
  { 3U,  5U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  3U,  5U,  6U,  7U,  0U,  0U,  0U}, { 1U,  3U,  5U,  6U,  7U,  0U,  0U,  0U}, { 0U,  1U,  3U,  5U,  6U,  7U,  0U,  0U},
  { 2U,  3U,  5U,  6U,  7U,  0U,  0U,  0U}, { 0U,  2U,  3U,  5U,  6U,  7U,  0U,  0U}, { 1U,  2U,  3U,  5U,  6U,  7U,  0U,  0U}, { 0U,  1U,  2U,  3U,  5U,  6U,  7U,  0U},
  { 4U,  5U,  6U,  7U,  0U,  0U,  0U,  0U}, { 0U,  4U,  5U,  6U,  7U,  0U,  0U,  0U}, { 1U,  4U,  5U,  6U,  7U,  0U,  0U,  0U}, { 0U,  1U,  4U,  5U,  6U,  7U,  0U,  0U},
  { 2U,  4U,  5U,  6U,  7U,  0U,  0U,  0U}, { 0U,  2U,  4U,  5U,  6U,  7U,  0U,  0U}, { 1U,  2U,  4U,  5U,  6U,  7U,  0U,  0U}, { 0U,  1U,  2U,  4U,  5U,  6U,  7U,  0U},
  { 3U,  4U,  5U,  6U,  7U,  0U,  0U,  0U}, { 0U,  3U,  4U,  5U,  6U,  7U,  0U,  0U}, { 1U,  3U,  4U,  5U,  6U,  7U,  0U,  0U}, { 0U,  1U,  3U,  4U,  5U,  6U,  7U,  0U},
  { 2U,  3U,  4U,  5U,  6U,  7U,  0U,  0U}, { 0U,  2U,  3U,  4U,  5U,  6U,  7U,  0U}, { 1U,  2U,  3U,  4U,  5U,  6U,  7U,  0U}, { 0U,  1U,  2U,  3U,  4U,  5U,  6U,  7U}
};

static const QSC_ALIGN(32) int32_t dilithium_zetas[DILITHIUM_N] =
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

static QSC_ALIGN(32) int32_t dilithium_q_avx2[8U] = { DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q,
		DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q };
//static dilithium_qinv_avx2[8U] = { DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV,
//    DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_Q };

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
    const __m256i half = _mm256_set1_epi32((1U << (DILITHIUM_D - 1)) - 1U);

    for (size_t i = 0U; i < DILITHIUM_N / 8U; ++i)
    {
        f = _mm256_load_si256((__m256i*)&a[8U * i]);
        f1 = _mm256_add_epi32(f, half);
        f0 = _mm256_and_si256(f1, mask);
        f1 = _mm256_srli_epi32(f1, DILITHIUM_D);
        f0 = _mm256_sub_epi32(f, f0);
        _mm256_store_si256((__m256i*)&a1[8U * i], f1);
        _mm256_store_si256((__m256i*)&a0[8U * i], f0);
    }
}

#if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32
static void dilithium_avx2_decompose(int32_t* restrict a1, int32_t* restrict a0, const int32_t* restrict a)
{
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0U]);
    const __m256i hq = _mm256_srli_epi32(q, 1);
    const __m256i v = _mm256_set1_epi32(1025);
    const __m256i alpha = _mm256_set1_epi32(2 * DILITHIUM_GAMMA2);
    const __m256i off = _mm256_set1_epi32(127);
    const __m256i shift = _mm256_set1_epi32(512);
    const __m256i mask = _mm256_set1_epi32(15);
    __m256i f;
    __m256i f0;
    __m256i f1;

    for (size_t i = 0U; i < DILITHIUM_N / 8; i++)
    {
        f = _mm256_load_si256((__m256i*)&a[8U * i]);
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
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0U]);
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

    for (size_t i = 0U; i < DILITHIUM_N / 8U; i++)
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
        _mm256_store_si256((__m256i*)&a1[8U * i], f1);
        _mm256_store_si256((__m256i*)&a0[8U * i], f0);
    }
}
#endif

static uint32_t dilithium_avx2_make_hint(uint8_t hint[DILITHIUM_N], const dilithium_poly* restrict a0, const dilithium_poly* restrict a1)
{
    uint32_t i;
    uint32_t n;
    __m256i f0;
    __m256i f1;
    __m256i g0;
    __m256i g1;
    uint32_t bad;
    uint64_t idx;
    const __m256i low = _mm256_set1_epi32(-DILITHIUM_GAMMA2);
    const __m256i high = _mm256_set1_epi32(DILITHIUM_GAMMA2);

    n = 0U;

    for (i = 0U; i < DILITHIUM_N / 8U; ++i)
    {
        f0 = _mm256_load_si256((const __m256i*)&a0->coeffs[i * sizeof(__m256i) / sizeof(int32_t)]);
        f1 = _mm256_load_si256((const __m256i*)&a1->coeffs[i * sizeof(__m256i) / sizeof(int32_t)]);
        g0 = _mm256_abs_epi32(f0);
        g0 = _mm256_cmpgt_epi32(g0, high);
        g1 = _mm256_cmpeq_epi32(f0, low);
        g1 = _mm256_sign_epi32(g1, f1);
        g0 = _mm256_or_si256(g0, g1);

        bad = _mm256_movemask_ps(_mm256_castsi256_ps(g0));
        qsc_memutils_copy(&idx, dilithium_rej_avx2[bad], 8);
        idx += (uint64_t)0x0808080808080808 * i;
        qsc_memutils_copy(&hint[n], &idx, 8);
        n += _mm_popcnt_u32(bad);
    }

    return n;
}

static void dilithium_avx2_use_hint(int32_t* b, const int32_t* a, const int32_t* restrict hint)
{
    QSC_ALIGN(32) int32_t a0[DILITHIUM_N];
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

    for (size_t i = 0U; i < DILITHIUM_N / 8U; i++)
    {
        f = _mm256_load_si256((const __m256i*)&a0[i * 8U]);
        g = _mm256_load_si256((const __m256i*)&b[i * 8U]);
        h = _mm256_load_si256((const __m256i*)&hint[i * 8U]);
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
        _mm256_store_si256((__m256i*)&b[i * 8U], g);
    }
}

/* rejsample.c */

static uint32_t dilithium_rej_eta(int32_t* a, size_t len, const uint8_t* buf, size_t buflen)
{
    size_t pos;
    uint32_t ctr;
    uint32_t t0;
    uint32_t t1;

    ctr = 0U;
    pos = 0U;

    while (ctr < len && pos < buflen)
    {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos] >> 4;
        ++pos;

#if (DILITHIUM_ETA == 2)
        if (t0 < 15)
        {
            t0 = t0 - (205U * t0 >> 10) * 5U;
            a[ctr] = 2 - t0;
            ++ctr;
        }

        if (t1 < 15 && ctr < len)
        {
            t1 = t1 - (205 * t1 >> 10) * 5U;
            a[ctr] = 2 - t1;
            ++ctr;
        }
#elif (DILITHIUM_ETA == 4)
        if (t0 < 9U)
        {
            a[ctr] = 4 - t0;
            ++ctr;
        }

        if (t1 < 9U && ctr < len)
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

    ctr = 0U;
    pos = 0U;

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
        ctr += _mm_popcnt_u32(good & 0xFFU);
        good >>= 8U;
        pos += 4U;

        if (ctr > DILITHIUM_N - 8U)
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
        good >>= 8U;
        pos += 4U;

        if (ctr > DILITHIUM_N - 8U)
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
        good >>= 8U;
        pos += 4U;

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
        pos += 4U;
    }

    while (ctr < DILITHIUM_N && pos < DILITHIUM_REJ_UNIFORM_ETA_BUFLEN)
    {
        t0 = buf[pos] & 0x0FU;
        t1 = buf[pos] >> 4U;
        ++pos;

        if (t0 < 15)
        {
            t0 = t0 - (205 * t0 >> 10) * 5U;
            r[ctr] = 2 - t0;
            ++ctr;
        }

        if (t1 < 15 && ctr < DILITHIUM_N) 
        {
            t1 = t1 - (205 * t1 >> 10) * 5U;
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

    ctr = 0U;
    pos = 0U;

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
        good >>= 8U;
        pos += 4U;

        if (ctr > DILITHIUM_N - 8U)
        {
            break;
        }

        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8U;
        pos += 4U;

        if (ctr > DILITHIUM_N - 8U)
        {
            break;
        }

        g0 = _mm256_extracti128_si256(f0, 1);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good & 0xFF]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good & 0xFF);
        good >>= 8U;
        pos += 4U;

        if (ctr > DILITHIUM_N - 8U)
        {
            break;
        }

        g0 = _mm_bsrli_si128(g0, 8);
        g1 = _mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good]);
        g1 = _mm_shuffle_epi8(g0, g1);
        f1 = _mm256_cvtepi8_epi32(g1);
        _mm256_storeu_si256((__m256i*)&r[ctr], f1);
        ctr += _mm_popcnt_u32(good);
        pos += 4U;
    }

    while (ctr < DILITHIUM_N && pos < DILITHIUM_REJ_UNIFORM_ETA_BUFLEN) 
    {
        t0 = buf[pos] & 0x0FU;
        t1 = buf[pos] >> 4U;
        ++pos;

        if (t0 < 9U)
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

    ctr = 0U;
    pos = 0U;

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

    ctr = 0U;
    pos = 0U;

    while (pos <= DILITHIUM_REJ_UNIFORM_BUFLEN - 24U)
    {
        d = _mm256_loadu_si256((__m256i*)&buf[pos]);
        d = _mm256_permute4x64_epi64(d, 0x94);
        d = _mm256_shuffle_epi8(d, idx8);
        d = _mm256_and_si256(d, mask);
        pos += 24U;

        tmp = _mm256_sub_epi32(d, bound);
        good = _mm256_movemask_ps(_mm256_castsi256_ps(tmp));
        tmp = _mm256_cvtepu8_epi32(_mm_loadl_epi64((__m128i*)&dilithium_rej_avx2[good]));
        d = _mm256_permutevar8x32_epi32(d, tmp);
        _mm256_storeu_si256((__m256i*)&r[ctr], d);
        ctr += _mm_popcnt_u32(good);

        if (ctr > DILITHIUM_N - 8U)
        {
            break;
        }
    }

    while (ctr < DILITHIUM_N && pos <= DILITHIUM_REJ_UNIFORM_BUFLEN - 3U)
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
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0U]);
    const __m256i off = _mm256_set1_epi32(1 << 22);
    __m256i f;
    __m256i g;

    for (size_t i = 0U; i < DILITHIUM_N / 8U; ++i)
    {
        f = _mm256_load_si256((__m256i*)&a->coeffs[8U * i]);
        g = _mm256_add_epi32(f, off);
        g = _mm256_srai_epi32(g, 23);
        g = _mm256_mullo_epi32(g, q);
        f = _mm256_sub_epi32(f, g);
        _mm256_store_si256((__m256i*)&a->coeffs[8U * i], f);
    }
}

static void dilithium_avx2_poly_caddq(dilithium_poly* a)
{
    const __m256i q = _mm256_load_si256((__m256i*)&dilithium_q_avx2[0U]);
    const __m256i zero = _mm256_setzero_si256();
    __m256i f;
    __m256i g;

    for (size_t i = 0U; i < DILITHIUM_N / 8U; ++i)
    {
        f = _mm256_load_si256((__m256i*)&a->coeffs[8U * i]);
        g = _mm256_blendv_epi32(zero, q, f);
        f = _mm256_add_epi32(f, g);
        _mm256_store_si256((__m256i*)&a->coeffs[8U * i], f);
    }
}

static void dilithium_avx2_poly_add(dilithium_poly* c, const dilithium_poly* a, const dilithium_poly* b)
{
    __m256i vec0;
    __m256i vec1;

    for (size_t i = 0U; i < DILITHIUM_N; i += 8U)
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

    for (size_t i = 0U; i < DILITHIUM_N; i += 8U)
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

    for (size_t i = 0U; i < DILITHIUM_N; i += 8U)
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

        for (size_t i = 0U; i < DILITHIUM_N / 8U; ++i)
        {
            f = _mm256_load_si256((__m256i*)&a->coeffs[8U * i]);
            f = _mm256_abs_epi32(f);
            f = _mm256_cmpgt_epi32(f, bound);
            t = _mm256_or_si256(t, f);
        }

        r = !_mm256_testz_si256(t, t);
    }

    return r;
}

static void dilithium_avx2_poly_uniform_eta_4x(dilithium_poly* a0, dilithium_poly* a1, dilithium_poly* a2, dilithium_poly* a3, 
    const uint8_t seed[64U], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3)
{

    QSC_ALIGN(32) uint8_t buf[4U][DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QSC_KECCAK_256_RATE];
    __m256i ksi[QSC_KECCAK_STATE_SIZE] = { 0U };
    uint32_t ctr0;
    uint32_t ctr1; 
    uint32_t ctr2;
    uint32_t ctr3;

    qsc_memutils_copy(buf[0U], seed, 64U);
    qsc_memutils_copy(buf[1U], seed, 64U);
    qsc_memutils_copy(buf[2U], seed, 64U);
    qsc_memutils_copy(buf[3U], seed, 64U);

    buf[0U][DILITHIUM_CRHBYTES] = (uint8_t)nonce0;
    buf[0U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce0 >> 8);
    buf[1U][DILITHIUM_CRHBYTES] = (uint8_t)nonce1;
    buf[1U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce1 >> 8);
    buf[2U][DILITHIUM_CRHBYTES] = (uint8_t)nonce2;
    buf[2U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce2 >> 8);
    buf[3U][DILITHIUM_CRHBYTES] = (uint8_t)nonce3;
    buf[3U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce3 >> 8);

    qsc_keccakx4_absorb(ksi, qsc_keccak_rate_256, buf[0U], buf[1U], buf[2U], buf[3U], (DILITHIUM_SEEDBYTES * 2U) + 2U, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_256, buf[0U], buf[1U], buf[2U], buf[3U], DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS);

    ctr0 = dilithium_rej_eta_avx(a0->coeffs, buf[0U]);
    ctr1 = dilithium_rej_eta_avx(a1->coeffs, buf[1U]);
    ctr2 = dilithium_rej_eta_avx(a2->coeffs, buf[2U]);
    ctr3 = dilithium_rej_eta_avx(a3->coeffs, buf[3U]);

    while (ctr0 < DILITHIUM_N || ctr1 < DILITHIUM_N || ctr2 < DILITHIUM_N || ctr3 < DILITHIUM_N)
    {
        qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_256, buf[0U], buf[1U], buf[2U], buf[3U], 1U);

        ctr0 += dilithium_rej_eta(a0->coeffs + ctr0, DILITHIUM_N - ctr0, buf[0U], QSC_KECCAK_256_RATE);
        ctr1 += dilithium_rej_eta(a1->coeffs + ctr1, DILITHIUM_N - ctr1, buf[1U], QSC_KECCAK_256_RATE);
        ctr2 += dilithium_rej_eta(a2->coeffs + ctr2, DILITHIUM_N - ctr2, buf[2U], QSC_KECCAK_256_RATE);
        ctr3 += dilithium_rej_eta(a3->coeffs + ctr3, DILITHIUM_N - ctr3, buf[3U], QSC_KECCAK_256_RATE);
    }
}

static void dilithium_polyz_unpack(dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0U; i < DILITHIUM_N / 4U; ++i)
    {
        r->coeffs[4U * i] = a[9 * i];
        r->coeffs[4U * i] |= (uint32_t)a[(9U * i) + 1U] << 8;
        r->coeffs[4U * i] |= (uint32_t)a[(9U * i) + 2U] << 16;
        r->coeffs[4U * i] &= 0x0003FFFF;

        r->coeffs[(4U * i) + 1U] = a[(9U * i) + 2U] >> 2;
        r->coeffs[(4U * i) + 1U] |= (uint32_t)a[(9U * i) + 3U] << 6;
        r->coeffs[(4U * i) + 1U] |= (uint32_t)a[(9U * i) + 4U] << 14;
        r->coeffs[(4U * i) + 1U] &= 0x0003FFFF;

        r->coeffs[(4U * i) + 2U] = a[(9U * i) + 4U] >> 4;
        r->coeffs[(4U * i) + 2U] |= (uint32_t)a[(9U * i) + 5U] << 4;
        r->coeffs[(4U * i) + 2U] |= (uint32_t)a[(9U * i) + 6U] << 12;
        r->coeffs[(4U * i) + 2U] &= 0x0003FFFF;

        r->coeffs[(4U * i) + 3U] = a[(9U * i) + 6U] >> 6;
        r->coeffs[(4U * i) + 3U] |= (uint32_t)a[(9U * i) + 7U] << 2;
        r->coeffs[(4U * i) + 3U] |= (uint32_t)a[(9U * i) + 8U] << 10;
        r->coeffs[(4U * i) + 3U] &= 0x0003FFFF;

        r->coeffs[4U * i] = DILITHIUM_GAMMA1 - r->coeffs[4U * i];
        r->coeffs[(4U * i) + 1U] = DILITHIUM_GAMMA1 - r->coeffs[(4U * i) + 1U];
        r->coeffs[(4U * i) + 2U] = DILITHIUM_GAMMA1 - r->coeffs[(4U * i) + 2U];
        r->coeffs[(4U * i) + 3U] = DILITHIUM_GAMMA1 - r->coeffs[(4U * i) + 3U];
    }
#elif (DILITHIUM_GAMMA1 == (1 << 19))
    for (size_t i = 0U; i < DILITHIUM_N / 2U; ++i)
    {
        r->coeffs[2U * i] = a[5U * i];
        r->coeffs[2U * i] |= (uint32_t)a[(5U * i) + 1U] << 8;
        r->coeffs[2U * i] |= (uint32_t)a[(5U * i) + 2U] << 16;
        r->coeffs[2U * i] &= 0x000FFFFFL;

        r->coeffs[(2U * i) + 1U] = a[(5U * i) + 2U] >> 4;
        r->coeffs[(2U * i) + 1U] |= (uint32_t)a[(5U * i) + 3U] << 4;
        r->coeffs[(2U * i) + 1U] |= (uint32_t)a[(5U * i) + 4U] << 12;
        r->coeffs[2U * i] &= 0x000FFFFFL;

        r->coeffs[2U * i] = DILITHIUM_GAMMA1 - r->coeffs[2U * i];
        r->coeffs[(2U * i) + 1U] = DILITHIUM_GAMMA1 - r->coeffs[(2U * i) + 1U];
    }
#endif
}

static void dilithium_avx2_poly_uniform_gamma1_4x(dilithium_poly* a0, dilithium_poly* a1, dilithium_poly* a2, dilithium_poly* a3,
    const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3)
{
    QSC_ALIGN(32) uint8_t buf[4U][DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS * QSC_KECCAK_256_RATE + 14U];
    __m256i ksi[QSC_KECCAK_STATE_SIZE] = { 0U };
    __m256i f;

    f = _mm256_loadu_si256((__m256i*)seed);
    _mm256_store_si256((__m256i*)buf[0U], f);
    _mm256_store_si256((__m256i*)buf[1U], f);
    _mm256_store_si256((__m256i*)buf[2U], f);
    _mm256_store_si256((__m256i*)buf[3U], f);
    f = _mm256_loadu_si256((__m256i*)&seed[32U]);
    _mm256_store_si256((__m256i*)&buf[0U][32U], f);
    _mm256_store_si256((__m256i*)&buf[1U][32U], f);
    _mm256_store_si256((__m256i*)&buf[2U][32U], f);
    _mm256_store_si256((__m256i*)&buf[3U][32U], f);

    buf[0U][DILITHIUM_CRHBYTES] = (uint8_t)nonce0;
    buf[0U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce0 >> 8);
    buf[1U][DILITHIUM_CRHBYTES] = (uint8_t)nonce1;
    buf[1U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce1 >> 8);
    buf[2U][DILITHIUM_CRHBYTES] = (uint8_t)nonce2;
    buf[2U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce2 >> 8);
    buf[3U][DILITHIUM_CRHBYTES] = (uint8_t)nonce3;
    buf[3U][DILITHIUM_CRHBYTES + 1U] = (uint8_t)(nonce3 >> 8);

    qsc_keccakx4_absorb(ksi, qsc_keccak_rate_256, buf[0U], buf[1U], buf[2U], buf[3U], DILITHIUM_CRHBYTES + 2U, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_256, buf[0U], buf[1U], buf[2U], buf[3U], DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS);

    dilithium_polyz_unpack(a0, buf[0U]);
    dilithium_polyz_unpack(a1, buf[1U]);
    dilithium_polyz_unpack(a2, buf[2U]);
    dilithium_polyz_unpack(a3, buf[3U]);
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

    for (size_t i = 0U; i < DILITHIUM_N / 32U; i++) 
    {
        f0 = _mm256_load_si256((__m256i*)&a->coeffs[32U * i]);
        f1 = _mm256_load_si256((__m256i*)&a->coeffs[32U * i + 8U]);
        f2 = _mm256_load_si256((__m256i*)&a->coeffs[32U * i + 16U]);
        f3 = _mm256_load_si256((__m256i*)&a->coeffs[32U * i + 24U]);
        f0 = _mm256_packus_epi32(f0, f1);
        f1 = _mm256_packus_epi32(f2, f3);
        f0 = _mm256_packus_epi16(f0, f1);
        f0 = _mm256_maddubs_epi16(f0, shift1);
        f0 = _mm256_madd_epi16(f0, shift2);
        f0 = _mm256_permutevar8x32_epi32(f0, shufdidx1);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);
        f0 = _mm256_permutevar8x32_epi32(f0, shufdidx2);
        _mm256_storeu_si256((__m256i*)&r[24U * i], f0);
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

    for (size_t i = 0U; i < DILITHIUM_N / 64U; ++i)
    {
        f0 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i]);
        f1 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i + 8U]);
        f2 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i + 16U]);
        f3 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i + 24U]);
        f4 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i + 32U]);
        f5 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i + 40U]);
        f6 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i + 48U]);
        f7 = _mm256_load_si256((__m256i*)&a->coeffs[64U * i + 56U]);
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
        _mm256_storeu_si256((__m256i*)&r[32U * i], f0);
    }
}
#endif

/* reduce.c */

static int32_t dilithium_montgomery_reduce(int64_t a)
{
    int32_t t;

    t = (int64_t)(int32_t)a * DILITHIUM_QINV;
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;

    return (int32_t)t;
}

/* ntt.c */

static void dilithium_ntt(int32_t a[DILITHIUM_N])
{
    size_t j;
    size_t k;
    int32_t zeta;
    int32_t t;

    k = 0U;

    for (size_t len = 128U; len > 0U; len >>= 1U)
    {
        for (size_t start = 0U; start < DILITHIUM_N; start = j + len)
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

    k = 256U;

    for (size_t len = 1U; len < DILITHIUM_N; len <<= 1U)
    {
        for (size_t start = 0U; start < DILITHIUM_N; start = j + len)
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

    for (j = 0U; j < DILITHIUM_N; ++j)
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
    for (size_t i = 0U; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = dilithium_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

static void dilithium_poly_challenge(dilithium_poly* c, const uint8_t seed[DILITHIUM_CTILDEBYTES])
{
    QSC_ALIGN(32) uint8_t buf[QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;
    uint64_t signs;
    size_t i;
    size_t b;
    size_t pos;

    qsc_keccak_initialize_state(&kctx);

    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, DILITHIUM_CTILDEBYTES);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_squeezeblocks(&kctx, buf, 1U, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
    signs = 0U;
    pos = 8U;

    for (i = 0U; i < 8U; ++i)
    {
        signs |= (uint64_t)buf[i] << (8U * i);
    }

    for (i = 0U; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = 0;
    }

    for (i = DILITHIUM_N - DILITHIUM_TAU; i < DILITHIUM_N; ++i)
    {
        do
        {
            if (pos >= QSC_KECCAK_256_RATE)
            {
                qsc_keccak_squeezeblocks(&kctx, buf, 1U, QSC_KECCAK_256_RATE, QSC_KECCAK_PERMUTATION_ROUNDS);
                pos = 0U;
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
    QSC_ALIGN(32) uint8_t t[8U];

#if DILITHIUM_ETA == 2
    for (size_t i = 0U; i < DILITHIUM_N / 8U; ++i)
    {
        t[0U] = DILITHIUM_ETA - a->coeffs[8U * i];
        t[1U] = DILITHIUM_ETA - a->coeffs[8U * i + 1U];
        t[2U] = DILITHIUM_ETA - a->coeffs[8U * i + 2U];
        t[3U] = DILITHIUM_ETA - a->coeffs[8U * i + 3U];
        t[4U] = DILITHIUM_ETA - a->coeffs[8U * i + 4U];
        t[5U] = DILITHIUM_ETA - a->coeffs[8U * i + 5U];
        t[6U] = DILITHIUM_ETA - a->coeffs[8U * i + 6U];
        t[7U] = DILITHIUM_ETA - a->coeffs[8U * i + 7U];

        r[3U * i] = (t[0U] >> 0) | (t[1U] << 3) | (t[2U] << 6);
        r[3U * i + 1U] = (t[2U] >> 2) | (t[3U] << 1) | (t[4U] << 4) | (t[5U] << 7);
        r[3U * i + 2U] = (t[5U] >> 1) | (t[6U] << 2) | (t[7U] << 5);
    }
#elif DILITHIUM_ETA == 4
    for (size_t i = 0U; i < DILITHIUM_N / 2U; ++i)
    {
        t[0U] = DILITHIUM_ETA - a->coeffs[2U * i];
        t[1U] = DILITHIUM_ETA - a->coeffs[2U * i + 1U];
        r[i] = t[0U] | (t[1U] << 4);
    }
#endif
}

static void dilithium_polyeta_unpack(dilithium_poly* r, const uint8_t* a)
{
#if (DILITHIUM_ETA == 2)
    for (size_t i = 0U; i < DILITHIUM_N / 8; ++i)
    {
        r->coeffs[8U * i] = (a[3U * i] >> 0) & 7;
        r->coeffs[(8U * i) + 1U] = (a[3U * i] >> 3) & 7;
        r->coeffs[(8U * i) + 2U] = ((a[3U * i] >> 6) | (a[(3U * i) + 1U] << 2)) & 7;
        r->coeffs[(8U * i) + 3U] = (a[(3U * i) + 1U] >> 1) & 7;
        r->coeffs[(8U * i) + 4U] = (a[(3U * i) + 1U] >> 4) & 7;
        r->coeffs[(8U * i) + 5U] = ((a[(3U * i) + 1U] >> 7) | (a[(3U * i) + 2U] << 1)) & 7;
        r->coeffs[(8U * i) + 6U] = (a[(3U * i) + 2U] >> 2) & 7;
        r->coeffs[(8U * i) + 7U] = (a[(3U * i) + 2U] >> 5) & 7;

        r->coeffs[8U * i] = DILITHIUM_ETA - r->coeffs[8 * i];
        r->coeffs[(8U * i) + 1U] = DILITHIUM_ETA - r->coeffs[(8U * i) + 1U];
        r->coeffs[(8U * i) + 2U] = DILITHIUM_ETA - r->coeffs[(8U * i) + 2U];
        r->coeffs[(8U * i) + 3U] = DILITHIUM_ETA - r->coeffs[(8U * i) + 3U];
        r->coeffs[(8U * i) + 4U] = DILITHIUM_ETA - r->coeffs[(8U * i) + 4U];
        r->coeffs[(8U * i) + 5U] = DILITHIUM_ETA - r->coeffs[(8U * i) + 5U];
        r->coeffs[(8U * i) + 6U] = DILITHIUM_ETA - r->coeffs[(8U * i) + 6U];
        r->coeffs[(8U * i) + 7U] = DILITHIUM_ETA - r->coeffs[(8U * i) + 7U];
    }
#elif (DILITHIUM_ETA == 4)
    for (size_t i = 0U; i < DILITHIUM_N / 2U; ++i)
    {
        r->coeffs[2U * i] = a[i] & 0x0F;
        r->coeffs[(2U * i) + 1U] = a[i] >> 4;
        r->coeffs[2U * i] = DILITHIUM_ETA - r->coeffs[2U * i];
        r->coeffs[(2U * i) + 1U] = DILITHIUM_ETA - r->coeffs[(2U * i) + 1U];
    }
#endif
}

static void dilithium_polyt1_pack(uint8_t* r, const dilithium_poly* a)
{
    for (size_t i = 0U; i < DILITHIUM_N / 4U; ++i)
    {
        r[5U * i] = (uint8_t)(a->coeffs[4 * i] >> 0);
        r[(5U * i) + 1U] = (uint8_t)((a->coeffs[4U * i] >> 8) | (a->coeffs[(4U * i) + 1U] << 2));
        r[(5U * i) + 2U] = (uint8_t)((a->coeffs[(4U * i) + 1U] >> 6) | (a->coeffs[(4U * i) + 2U] << 4));
        r[(5U * i) + 3U] = (uint8_t)((a->coeffs[(4U * i) + 2U] >> 4) | (a->coeffs[(4U * i) + 3U] << 6));
        r[(5U * i) + 4U] = (uint8_t)(a->coeffs[(4U * i) + 3U] >> 2);
    }
}

static void dilithium_polyt1_unpack(dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0U; i < DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4U * i] = ((a[5U * i] >> 0) | ((uint32_t)a[(5U * i) + 1U] << 8)) & 0x000003FF;
        r->coeffs[(4U * i) + 1U] = ((a[(5U * i) + 1U] >> 2) | ((uint32_t)a[(5U * i) + 2U] << 6)) & 0x000003FF;
        r->coeffs[(4U * i) + 2U] = ((a[(5U * i) + 2U] >> 4) | ((uint32_t)a[(5U * i) + 3U] << 4)) & 0x000003FF;
        r->coeffs[(4U * i) + 3U] = ((a[(5U * i) + 3U] >> 6) | ((uint32_t)a[(5U * i) + 4U] << 2)) & 0x000003FF;
    }
}

static void dilithium_polyt0_pack(uint8_t* r, const dilithium_poly* a)
{
    QSC_ALIGN(32) uint32_t t[8U];

    for (size_t i = 0U; i < DILITHIUM_N / 8U; ++i)
    {
        t[0U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[8U * i];
        t[1U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[(8U * i) + 1U];
        t[2U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[(8U * i) + 2U];
        t[3U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[(8U * i) + 3U];
        t[4U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[(8U * i) + 4U];
        t[5U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[(8U * i) + 5U];
        t[6U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[(8U * i) + 6U];
        t[7U] = (1 << (DILITHIUM_D - 1U)) - a->coeffs[(8U * i) + 7U];

        r[13U * i] = (uint8_t)t[0U];
        r[(13U * i) + 1U] = (uint8_t)(t[0U] >> 8);
        r[(13U * i) + 1U] |= (uint8_t)(t[1U] << 5);
        r[(13U * i) + 2U] = (uint8_t)(t[1U] >> 3);
        r[(13U * i) + 3U] = (uint8_t)(t[1U] >> 11);
        r[(13U * i) + 3U] |= (uint8_t)(t[2U] << 2);
        r[(13U * i) + 4U] = (uint8_t)(t[2U] >> 6);
        r[(13U * i) + 4U] |= (uint8_t)(t[3U] << 7);
        r[(13U * i) + 5U] = (uint8_t)(t[3U] >> 1);
        r[(13U * i) + 6U] = (uint8_t)(t[3U] >> 9);
        r[(13U * i) + 6U] |= (uint8_t)(t[4U] << 4);
        r[(13U * i) + 7U] = (uint8_t)(t[4U] >> 4);
        r[(13U * i) + 8U] = (uint8_t)(t[4U] >> 12);
        r[(13U * i) + 8U] |= (uint8_t)(t[5U] << 1);
        r[(13U * i) + 9U] = (uint8_t)(t[5U] >> 7);
        r[(13U * i) + 9U] |= (uint8_t)(t[6U] << 6);
        r[(13U * i) + 10U] = (uint8_t)(t[6U] >> 2);
        r[(13U * i) + 11U] = (uint8_t)(t[6U] >> 10);
        r[(13U * i) + 11U] |= (uint8_t)(t[7U] << 3);
        r[(13U * i) + 12U] = (uint8_t)(t[7U] >> 5);
    }
}

static void dilithium_polyt0_unpack(dilithium_poly* r, const uint8_t* a)
{
    for (size_t i = 0U; i < DILITHIUM_N / 8U; ++i)
    {
        r->coeffs[8U * i] = a[13U * i];
        r->coeffs[8U * i] |= (uint32_t)a[(13U * i) + 1U] << 8;
        r->coeffs[8U * i] &= 0x00001FFFL;

        r->coeffs[(8U * i) + 1U] = a[(13U * i) + 1U] >> 5;
        r->coeffs[(8U * i) + 1U] |= (uint32_t)a[(13U * i) + 2U] << 3;
        r->coeffs[(8U * i) + 1U] |= (uint32_t)a[(13U * i) + 3U] << 11;
        r->coeffs[(8U * i) + 1U] &= 0x00001FFFL;

        r->coeffs[(8U * i) + 2U] = a[(13U * i) + 3U] >> 2;
        r->coeffs[(8U * i) + 2U] |= (uint32_t)a[(13U * i) + 4U] << 6;
        r->coeffs[(8U * i) + 2U] &= 0x00001FFFL;

        r->coeffs[(8U * i) + 3U] = a[(13U * i) + 4U] >> 7;
        r->coeffs[(8U * i) + 3U] |= (uint32_t)a[(13U * i) + 5U] << 1;
        r->coeffs[(8U * i) + 3U] |= (uint32_t)a[(13U * i) + 6U] << 9;
        r->coeffs[(8U * i) + 3U] &= 0x00001FFFL;

        r->coeffs[(8U * i) + 4U] = a[(13U * i) + 6U] >> 4;
        r->coeffs[(8U * i) + 4U] |= (uint32_t)a[(13U * i) + 7U] << 4;
        r->coeffs[(8U * i) + 4U] |= (uint32_t)a[(13U * i) + 8U] << 12;
        r->coeffs[(8U * i) + 4U] &= 0x00001FFFL;

        r->coeffs[(8U * i) + 5U] = a[(13U * i) + 8U] >> 1;
        r->coeffs[(8U * i) + 5U] |= (uint32_t)a[(13U * i) + 9U] << 7;
        r->coeffs[(8U * i) + 5U] &= 0x00001FFFL;

        r->coeffs[(8U * i) + 6U] = a[(13U * i) + 9U] >> 6;
        r->coeffs[(8U * i) + 6U] |= (uint32_t)a[(13U * i) + 10U] << 2;
        r->coeffs[(8U * i) + 6U] |= (uint32_t)a[(13U * i) + 11U] << 10;
        r->coeffs[(8U * i) + 6U] &= 0x00001FFFL;

        r->coeffs[(8U * i) + 7U] = a[(13U * i) + 11U] >> 3;
        r->coeffs[(8U * i) + 7U] |= (uint32_t)a[(13U * i) + 12U] << 5;
        r->coeffs[(8U * i) + 7U] &= 0x00001FFFL;

        r->coeffs[8U * i] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[8U * i];
        r->coeffs[(8U * i) + 1U] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[(8U * i) + 1U];
        r->coeffs[(8U * i) + 2U] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[(8U * i) + 2U];
        r->coeffs[(8U * i) + 3U] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[(8U * i) + 3U];
        r->coeffs[(8U * i) + 4U] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[(8U * i) + 4U];
        r->coeffs[(8U * i) + 5U] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[(8U * i) + 5U];
        r->coeffs[(8U * i) + 6U] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[(8U * i) + 6U];
        r->coeffs[(8U * i) + 7U] = (1 << (DILITHIUM_D - 1U)) - r->coeffs[(8U * i) + 7U];
    }
}

static void dilithium_polyz_pack(uint8_t* r, const dilithium_poly* a)
{
    QSC_ALIGN(32) uint32_t t[4U];

#if (DILITHIUM_GAMMA1 == (1 << 17))
    for (size_t i = 0U; i < DILITHIUM_N / 4U; ++i)
    {
        t[0U] = DILITHIUM_GAMMA1 - a->coeffs[4U * i];
        t[1U] = DILITHIUM_GAMMA1 - a->coeffs[(4U * i) + 1U];
        t[2U] = DILITHIUM_GAMMA1 - a->coeffs[(4U * i) + 2U];
        t[3U] = DILITHIUM_GAMMA1 - a->coeffs[(4U * i) + 3U];

        r[9U * i] = (uint8_t)t[0U];
        r[(9U * i) + 1U] = (uint8_t)(t[0U] >> 8);
        r[(9U * i) + 2U] = (uint8_t)(t[0U] >> 16);
        r[(9U * i) + 2U] |= (uint8_t)(t[1U] << 2);
        r[(9U * i) + 3U] = (uint8_t)(t[1U] >> 6);
        r[(9U * i) + 4U] = (uint8_t)(t[1U] >> 14);
        r[(9U * i) + 4U] |= (uint8_t)(t[2U] << 4);
        r[(9U * i) + 5U] = (uint8_t)(t[2U] >> 4);
        r[(9U * i) + 6U] = (uint8_t)(t[2U] >> 12);
        r[(9U * i) + 6U] |= (uint8_t)(t[3U] << 6);
        r[(9U * i) + 7U] = (uint8_t)(t[3U] >> 2);
        r[(9U * i) + 8U] = (uint8_t)(t[3U] >> 10);
    }
#elif (DILITHIUM_GAMMA1 == (1 << 19))
    for (size_t i = 0U; i < DILITHIUM_N / 2U; ++i)
    {
        t[0U] = DILITHIUM_GAMMA1 - a->coeffs[2U * i];
        t[1U] = DILITHIUM_GAMMA1 - a->coeffs[(2U * i) + 1U];

        r[5U * i] = (uint8_t)t[0U];
        r[(5U * i) + 1U] = (uint8_t)(t[0U] >> 8);
        r[(5U * i) + 2U] = (uint8_t)(t[0U] >> 16);
        r[(5U * i) + 2U] |= (uint8_t)(t[1U] << 4);
        r[(5U * i) + 3U] = (uint8_t)(t[1U] >> 4);
        r[(5U * i) + 4U] = (uint8_t)(t[1U] >> 12);
    }
#endif
}

static void dilithium_avx2_poly_uniform_4x(dilithium_poly* a0, dilithium_poly* a1, dilithium_poly* a2, dilithium_poly* a3,
    const uint8_t seed[32U], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t nonce3)
{
    QSC_ALIGN(32) uint8_t buf[4U][DILITHIUM_REJ_UNIFORM_BUFLEN + 8U];
    __m256i ksi[QSC_KECCAK_STATE_SIZE] = { 0U };
    __m256i f;
    uint32_t ctr0;
    uint32_t ctr1;
    uint32_t ctr2;
    uint32_t ctr3;

    f = _mm256_loadu_si256((__m256i*)seed);
    _mm256_store_si256((__m256i*)buf[0U], f);
    _mm256_store_si256((__m256i*)buf[1U], f);
    _mm256_store_si256((__m256i*)buf[2U], f);
    _mm256_store_si256((__m256i*)buf[3U], f);

    buf[0U][DILITHIUM_SEEDBYTES] = (uint8_t)nonce0;
    buf[0U][DILITHIUM_SEEDBYTES + 1U] = (uint8_t)(nonce0 >> 8);
    buf[1U][DILITHIUM_SEEDBYTES] = (uint8_t)nonce1;
    buf[1U][DILITHIUM_SEEDBYTES + 1U] = (uint8_t)(nonce1 >> 8);
    buf[2U][DILITHIUM_SEEDBYTES] = (uint8_t)nonce2;
    buf[2U][DILITHIUM_SEEDBYTES + 1U] = (uint8_t)(nonce2 >> 8);
    buf[3U][DILITHIUM_SEEDBYTES] = (uint8_t)nonce3;
    buf[3U][DILITHIUM_SEEDBYTES + 1U] = (uint8_t)(nonce3 >> 8);

    qsc_keccakx4_absorb(ksi, qsc_keccak_rate_128, buf[0U], buf[1U], buf[2U], buf[3U], DILITHIUM_SEEDBYTES + 2U, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_128, buf[0U], buf[1U], buf[2U], buf[3U], 5U);

    ctr0 = dilithium_avx2_rej_uniform(a0->coeffs, buf[0U]);
    ctr1 = dilithium_avx2_rej_uniform(a1->coeffs, buf[1U]);
    ctr2 = dilithium_avx2_rej_uniform(a2->coeffs, buf[2U]);
    ctr3 = dilithium_avx2_rej_uniform(a3->coeffs, buf[3U]);

    while (ctr0 < DILITHIUM_N || ctr1 < DILITHIUM_N || ctr2 < DILITHIUM_N || ctr3 < DILITHIUM_N)
    {
        qsc_keccakx4_squeezeblocks(ksi, qsc_keccak_rate_128, buf[0U], buf[1U], buf[2U], buf[3U], 1U);

        ctr0 += dilithium_rej_uniform(a0->coeffs + ctr0, DILITHIUM_N - ctr0, buf[0U], QSC_KECCAK_128_RATE);
        ctr1 += dilithium_rej_uniform(a1->coeffs + ctr1, DILITHIUM_N - ctr1, buf[1U], QSC_KECCAK_128_RATE);
        ctr2 += dilithium_rej_uniform(a2->coeffs + ctr2, DILITHIUM_N - ctr2, buf[2U], QSC_KECCAK_128_RATE);
        ctr3 += dilithium_rej_uniform(a3->coeffs + ctr3, DILITHIUM_N - ctr3, buf[3U], QSC_KECCAK_128_RATE);
    }
}

static void dilithium_poly_uniform_gamma1(dilithium_poly* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
    QSC_ALIGN(32) uint8_t buf[DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS * QSC_KECCAK_256_RATE];
    qsc_keccak_state kctx;
    QSC_ALIGN(32) uint8_t tn[2U];

    tn[0U] = (uint8_t)nonce;
    tn[1U] = nonce >> 8;

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
    dilithium_avx2_poly_uniform_4x(&mat[0U].vec[0U], &mat[0U].vec[1U], &mat[0U].vec[2U], &mat[0U].vec[3U], rho, 0U, 1U, 2U, 3U);
    dilithium_avx2_poly_uniform_4x(&mat[1U].vec[0U], &mat[1U].vec[1U], &mat[1U].vec[2U], &mat[1U].vec[3U], rho, 256U, 257U, 258U, 259U);
    dilithium_avx2_poly_uniform_4x(&mat[2U].vec[0U], &mat[2U].vec[1U], &mat[2U].vec[2U], &mat[2U].vec[3U], rho, 512U, 513U, 514U, 515U);
    dilithium_avx2_poly_uniform_4x(&mat[3U].vec[0U], &mat[3U].vec[1U], &mat[3U].vec[2U], &mat[3U].vec[3U], rho, 768U, 769U, 770U, 771U);
#elif DILITHIUM_K == 6 && DILITHIUM_L == 5
    dilithium_poly t0;
    dilithium_poly t1;
    dilithium_avx2_poly_uniform_4x(&mat[0U].vec[0U], &mat[0U].vec[1U], &mat[0U].vec[2U], &mat[0U].vec[3U], rho, 0U, 1U, 2U, 3U);
    dilithium_avx2_poly_uniform_4x(&mat[0U].vec[4U], &mat[1U].vec[0U], &mat[1U].vec[1U], &mat[1U].vec[2U], rho, 4U, 256U, 257U, 258U);
    dilithium_avx2_poly_uniform_4x(&mat[1U].vec[3U], &mat[1U].vec[4U], &mat[2U].vec[0U], &mat[2U].vec[1U], rho, 259U, 260U, 512U, 513U);
    dilithium_avx2_poly_uniform_4x(&mat[2U].vec[2U], &mat[2U].vec[3U], &mat[2U].vec[4U], &mat[3U].vec[0U], rho, 514U, 515U, 516U, 768U);
    dilithium_avx2_poly_uniform_4x(&mat[3U].vec[1U], &mat[3U].vec[2U], &mat[3U].vec[3U], &mat[3U].vec[4U], rho, 769U, 770U, 771U, 772U);
    dilithium_avx2_poly_uniform_4x(&mat[4U].vec[0U], &mat[4U].vec[1U], &mat[4U].vec[2U], &mat[4U].vec[3U], rho, 1024U, 1025U, 1026U, 1027U);
    dilithium_avx2_poly_uniform_4x(&mat[4U].vec[4U], &mat[5U].vec[0U], &mat[5U].vec[1U], &mat[5U].vec[2U], rho, 1028U, 1280U, 1281U, 1282U);
    dilithium_avx2_poly_uniform_4x(&mat[5U].vec[3U], &mat[5U].vec[4U], &t0, &t1, rho, 1283, 1284, 0U, 0U);
#elif DILITHIUM_K == 8 && DILITHIUM_L == 7
    dilithium_avx2_poly_uniform_4x(&mat[0U].vec[0U], &mat[0U].vec[1U], &mat[0U].vec[2U], &mat[0U].vec[3U], rho, 0U, 1U, 2U, 3U);
    dilithium_avx2_poly_uniform_4x(&mat[0U].vec[4U], &mat[0U].vec[5U], &mat[0U].vec[6U], &mat[1U].vec[0U], rho, 4U, 5U, 6U, 256U);
    dilithium_avx2_poly_uniform_4x(&mat[1U].vec[1U], &mat[1U].vec[2U], &mat[1U].vec[3U], &mat[1U].vec[4U], rho, 257U, 258U, 259U, 260U);
    dilithium_avx2_poly_uniform_4x(&mat[1U].vec[5U], &mat[1U].vec[6U], &mat[2U].vec[0U], &mat[2U].vec[1U], rho, 261U, 262U, 512U, 513U);
    dilithium_avx2_poly_uniform_4x(&mat[2U].vec[2U], &mat[2U].vec[3U], &mat[2U].vec[4U], &mat[2U].vec[5U], rho, 514U, 515U, 516U, 517U);
    dilithium_avx2_poly_uniform_4x(&mat[2U].vec[6U], &mat[3U].vec[0U], &mat[3U].vec[1U], &mat[3U].vec[2U], rho, 518U, 768U, 769U, 770U);
    dilithium_avx2_poly_uniform_4x(&mat[3U].vec[3U], &mat[3U].vec[4U], &mat[3U].vec[5U], &mat[3U].vec[6U], rho, 771U, 772U, 773U, 774U);
    dilithium_avx2_poly_uniform_4x(&mat[4U].vec[0U], &mat[4U].vec[1U], &mat[4U].vec[2U], &mat[4U].vec[3U], rho, 1024U, 1025U, 1026U, 1027U);
    dilithium_avx2_poly_uniform_4x(&mat[4U].vec[4U], &mat[4U].vec[5U], &mat[4U].vec[6U], &mat[5U].vec[0U], rho, 1028U, 1029U, 1030U, 1280U);
    dilithium_avx2_poly_uniform_4x(&mat[5U].vec[1U], &mat[5U].vec[2U], &mat[5U].vec[3U], &mat[5U].vec[4U], rho, 1281U, 1282U, 1283U, 1284U);
    dilithium_avx2_poly_uniform_4x(&mat[5U].vec[5U], &mat[5U].vec[6U], &mat[6U].vec[0U], &mat[6U].vec[1U], rho, 1285U, 1286U, 1536U, 1537U);
    dilithium_avx2_poly_uniform_4x(&mat[6U].vec[2U], &mat[6U].vec[3U], &mat[6U].vec[4U], &mat[6U].vec[5U], rho, 1538U, 1539U, 1540U, 1541U);
    dilithium_avx2_poly_uniform_4x(&mat[6U].vec[6U], &mat[7U].vec[0U], &mat[7U].vec[1U], &mat[7U].vec[2U], rho, 1542U, 1792U, 1793U, 1794U);
    dilithium_avx2_poly_uniform_4x(&mat[7U].vec[3U], &mat[7U].vec[4U], &mat[7U].vec[5U], &mat[7U].vec[6U], rho, 1795U, 1796U, 1797U, 1798U);
#endif
}

static void dilithium_avx2_polyvec_matrix_expand_row(dilithium_polyvecl mat[DILITHIUM_K], const uint8_t rho[DILITHIUM_SEEDBYTES], size_t idx)
{
#if DILITHIUM_K == 4 && DILITHIUM_L == 4
    if (idx == 0U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[0U].vec[0U], &mat[0U].vec[1U], &mat[0U].vec[2U], &mat[0U].vec[3U], rho, 0U, 1U, 2U, 3U);
    }
    if (idx == 1U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[1U].vec[0U], &mat[1U].vec[1U], &mat[1U].vec[2U], &mat[1U].vec[3U], rho, 256U, 257U, 258U, 259U);
    }
    if (idx == 2U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[2U].vec[0U], &mat[2U].vec[1U], &mat[2U].vec[2U], &mat[2U].vec[3U], rho, 512U, 513U, 514U, 515U);
    }
    if (idx == 3U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[3U].vec[0U], &mat[3U].vec[1U], &mat[3U].vec[2U], &mat[3U].vec[3U], rho, 768U, 769U, 770U, 771U);
    }
#elif DILITHIUM_K == 6 && DILITHIUM_L == 5
    if (idx == 0U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[0U].vec[0U], &mat[0U].vec[1U], &mat[0U].vec[2U], &mat[0U].vec[3U], rho, 0U, 1U, 2U, 3U);
        dilithium_avx2_poly_uniform_4x(&mat[0U].vec[4U], &mat[1U].vec[0U], &mat[1U].vec[1U], &mat[1U].vec[2U], rho, 4U, 256U, 257U, 258U);
    }
    if (idx == 1U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[1U].vec[3U], &mat[1U].vec[4U], &mat[2U].vec[0U], &mat[2U].vec[1U], rho, 259U, 260U, 512U, 513U);
    }
    if (idx == 2U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[2U].vec[2U], &mat[2U].vec[3U], &mat[2U].vec[4U], &mat[3U].vec[0U], rho, 514U, 515U, 516U, 768U);
    }
    if (idx == 3U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[3U].vec[1U], &mat[3U].vec[2U], &mat[3U].vec[3U], &mat[3U].vec[4U], rho, 769U, 770U, 771U, 772U);
    }
    if (idx == 4U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[4U].vec[0U], &mat[4U].vec[1U], &mat[4U].vec[2U], &mat[4U].vec[3U], rho, 1024U, 1025U, 1026U, 1027U);
        dilithium_avx2_poly_uniform_4x(&mat[4U].vec[4U], &mat[5U].vec[0U], &mat[5U].vec[1U], &mat[5U].vec[2U], rho, 1028U, 1280U, 1281U, 1282U);
    }
    if (idx == 5U)
    {
        dilithium_poly t0;
        dilithium_poly t1;

        dilithium_avx2_poly_uniform_4x(&mat[5U].vec[3U], &mat[5U].vec[4U], &t0, &t1, rho, 1283U, 1284U, 0U, 0U);
    }
#elif DILITHIUM_K == 8 && DILITHIUM_L == 7
    if (idx == 0U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[0U].vec[0U], &mat[0U].vec[1U], &mat[0U].vec[2U], &mat[0U].vec[3U], rho, 0U, 1U, 2U, 3U);
        dilithium_avx2_poly_uniform_4x(&mat[0U].vec[4U], &mat[0U].vec[5U], &mat[0U].vec[6U], &mat[1U].vec[0U], rho, 4U, 5U, 6U, 256U);
    }
    if (idx == 1U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[1U].vec[1U], &mat[1U].vec[2U], &mat[1U].vec[3U], &mat[1U].vec[4U], rho, 257U, 258U, 259U, 260U);
        dilithium_avx2_poly_uniform_4x(&mat[1U].vec[5U], &mat[1U].vec[6U], &mat[2U].vec[0U], &mat[2U].vec[1U], rho, 261U, 262U, 512U, 513U);
    }
    if (idx == 2U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[2U].vec[2U], &mat[2U].vec[3U], &mat[2U].vec[4U], &mat[2U].vec[5U], rho, 514U, 515U, 516U, 517U);
        dilithium_avx2_poly_uniform_4x(&mat[2U].vec[6U], &mat[3U].vec[0U], &mat[3U].vec[1U], &mat[3U].vec[2U], rho, 518U, 768U, 769U, 770U);
    }
    if (idx == 3U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[3U].vec[3U], &mat[3U].vec[4U], &mat[3U].vec[5U], &mat[3U].vec[6U], rho, 771U, 772U, 773U, 774U);
    }
    if (idx == 4U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[4U].vec[0U], &mat[4U].vec[1U], &mat[4U].vec[2U], &mat[4U].vec[3U], rho, 1024U, 1025U, 1026U, 1027U);
        dilithium_avx2_poly_uniform_4x(&mat[4U].vec[4U], &mat[4U].vec[5U], &mat[4U].vec[6U], &mat[5U].vec[0U], rho, 1028U, 1029U, 1030U, 1280U);
    }
    if (idx == 5U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[5U].vec[1U], &mat[5U].vec[2U], &mat[5U].vec[3U], &mat[5U].vec[4U], rho, 1281U, 1282U, 1283U, 1284U);
        dilithium_avx2_poly_uniform_4x(&mat[5U].vec[5U], &mat[5U].vec[6U], &mat[6U].vec[0U], &mat[6U].vec[1U], rho, 1285U, 1286U, 1536U, 1537U);
    }
    if (idx == 6U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[6U].vec[2U], &mat[6U].vec[3U], &mat[6U].vec[4U], &mat[6U].vec[5U], rho, 1538U, 1539U, 1540U, 1541U);
        dilithium_avx2_poly_uniform_4x(&mat[6U].vec[6U], &mat[7U].vec[0U], &mat[7U].vec[1U], &mat[7U].vec[2U], rho, 1542U, 1792U, 1793U, 1794U);
    }
    if (idx == 7U)
    {
        dilithium_avx2_poly_uniform_4x(&mat[7U].vec[3U], &mat[7U].vec[4U], &mat[7U].vec[5U], &mat[7U].vec[6U], rho, 1795U, 1796U, 1797U, 1798U);
    }

#endif
}

static void dilithium_polyvecl_pointwise_acc_montgomery(dilithium_poly* w, const dilithium_polyvecl* u, const dilithium_polyvecl* v)
{
    dilithium_poly t;

    dilithium_poly_pointwise_montgomery(w, &u->vec[0U], &v->vec[0U]);

    for (size_t i = 1U; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        dilithium_avx2_poly_add(w, w, &t);
    }
}

static void dilithium_polyvecl_ntt(dilithium_polyvecl* v)
{
    for (size_t i = 0U; i < DILITHIUM_L; ++i)
    {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

static void dilithium_polyveck_ntt(dilithium_polyveck* v)
{
    for (size_t i = 0U; i < DILITHIUM_K; ++i)
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

    for (i = 0U; i < DILITHIUM_L; ++i)
    {
        dilithium_polyeta_unpack(&s1->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0U; i < DILITHIUM_K; ++i)
    {
        dilithium_polyeta_unpack(&s2->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
    }

    sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

    for (i = 0U; i < DILITHIUM_K; ++i)
    {
        dilithium_polyt0_unpack(&t0->vec[i], sk + i * DILITHIUM_POLYT0_PACKEDBYTES);
    }
}

void polyvec_matrix_pointwise_montgomery(dilithium_polyveck* t, const dilithium_polyvecl mat[DILITHIUM_K], const dilithium_polyvecl* v)
{
  for (size_t i = 0U; i < DILITHIUM_K; ++i)
  {
      dilithium_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
  }
}

static void dilithium_polyveck_invntt_to_mont(dilithium_polyveck* v)
{
    for (size_t i = 0U; i < DILITHIUM_K; ++i)
    {
        dilithium_poly_invntt_to_mont(&v->vec[i]);
    }
}

static void dilithium_avx2_polyveck_caddq(dilithium_polyveck* v)
{
    for (size_t i = 0U; i < DILITHIUM_K; ++i)
    {
        dilithium_avx2_poly_caddq(&v->vec[i]);
    }
}

static void dilithium_avx2_polyveck_decompose(dilithium_polyveck* v1, dilithium_polyveck* v0, const dilithium_polyveck* v)
{
    for (size_t i = 0U; i < DILITHIUM_K; ++i)
    {
        dilithium_avx2_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

static void dilithium_avx2_polyveck_pack_w1(uint8_t r[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES], const dilithium_polyveck* w1)
{
    for (size_t i = 0U; i < DILITHIUM_K; ++i)
    {
        dilithium_avx2_polyw1_pack(&r[i * DILITHIUM_POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}

/* sign.c */

bool qsc_dilithium_avx2_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ALIGN(32) dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1;
    dilithium_polyveck s2;
    dilithium_poly t0;
    dilithium_poly t1;
    QSC_ALIGN(32) uint8_t seedbuf[(2U * DILITHIUM_SEEDBYTES) + DILITHIUM_CRHBYTES];
    const uint8_t* key;
    const uint8_t* rho;
    const uint8_t* rhoprime;
    size_t i;
    bool res;

    /* Get randomness for rho, rhoprime and key */
    res = rng_generate(seedbuf, DILITHIUM_SEEDBYTES);

    if (res)
    {
        seedbuf[DILITHIUM_SEEDBYTES] = DILITHIUM_K;
        seedbuf[DILITHIUM_SEEDBYTES + 1U] = DILITHIUM_L;
        qsc_shake256_compute(seedbuf, 2U * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES, seedbuf, DILITHIUM_SEEDBYTES + 2U);
        rho = seedbuf;
        rhoprime = rho + DILITHIUM_SEEDBYTES;
        key = rhoprime + DILITHIUM_CRHBYTES;

        /* Store rho, key */
        qsc_memutils_copy(pk, rho, DILITHIUM_SEEDBYTES);
        qsc_memutils_copy(sk, rho, DILITHIUM_SEEDBYTES);
        qsc_memutils_copy(sk + DILITHIUM_SEEDBYTES, key, DILITHIUM_SEEDBYTES);

        /* Sample short vectors s1 and s2 */
#if DILITHIUM_K == 4 && DILITHIUM_L == 4
        dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0U], &s1.vec[1U], &s1.vec[2U], &s1.vec[3U], rhoprime, 0U, 1U, 2U, 3U);
        dilithium_avx2_poly_uniform_eta_4x(&s2.vec[0U], &s2.vec[1U], &s2.vec[2U], &s2.vec[3U], rhoprime, 4U, 5U, 6U, 7U);
#elif DILITHIUM_K == 6 && DILITHIUM_L == 5
        dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0U], &s1.vec[1U], &s1.vec[2U], &s1.vec[3U], rhoprime, 0U, 1U, 2U, 3U);
        dilithium_avx2_poly_uniform_eta_4x(&s1.vec[4U], &s2.vec[0U], &s2.vec[1U], &s2.vec[2U], rhoprime, 4U, 5U, 6U, 7U);
        dilithium_avx2_poly_uniform_eta_4x(&s2.vec[3U], &s2.vec[4U], &s2.vec[5U], &t0, rhoprime, 8U, 9U, 10U, 11U);
#elif DILITHIUM_K == 8 && DILITHIUM_L == 7
        dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0U], &s1.vec[1U], &s1.vec[2U], &s1.vec[3U], rhoprime, 0U, 1U, 2U, 3U);
        dilithium_avx2_poly_uniform_eta_4x(&s1.vec[4U], &s1.vec[5U], &s1.vec[6U], &s2.vec[0U], rhoprime, 4U, 5U, 6U, 7U);
        dilithium_avx2_poly_uniform_eta_4x(&s2.vec[1U], &s2.vec[2U], &s2.vec[3U], &s2.vec[4U], rhoprime, 8U, 9U, 10U, 11U);
        dilithium_avx2_poly_uniform_eta_4x(&s2.vec[5U], &s2.vec[6U], &s2.vec[7U], &t0, rhoprime, 12U, 13U, 14U, 15U);
#else
#   error
#endif

    /* Pack secret vectors */
        for (i = 0U; i < DILITHIUM_L; i++)
        {
            dilithium_polyeta_pack(sk + (2U * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (i * DILITHIUM_POLYETA_PACKEDBYTES), &s1.vec[i]);
        }

        for (i = 0U; i < DILITHIUM_K; i++)
        {
            dilithium_polyeta_pack(sk + (2U * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (DILITHIUM_L + i) * DILITHIUM_POLYETA_PACKEDBYTES, &s2.vec[i]);
        }

        /* Transform s1 */
        dilithium_polyvecl_ntt(&s1);

        for (i = 0U; i < DILITHIUM_K; i++)
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
            dilithium_polyt0_pack(sk + (2U * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (DILITHIUM_L + DILITHIUM_K) * DILITHIUM_POLYETA_PACKEDBYTES + (i * DILITHIUM_POLYT0_PACKEDBYTES), &t0);
        }

        /* Compute CRH(rho, t1) and store in secret key */
        qsc_shake256_compute(sk + (2U * DILITHIUM_SEEDBYTES), DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);
        qsc_memutils_clear(seedbuf, sizeof(seedbuf));
    }

    return res;
}

void qsc_dilithium_avx2_seeded_generate_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed)
{
    QSC_ALIGN(32) dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1;
    dilithium_polyveck s2;
    dilithium_poly t0;
    dilithium_poly t1;
    QSC_ALIGN(32) uint8_t seedbuf[(2U * DILITHIUM_SEEDBYTES) + DILITHIUM_CRHBYTES];
    const uint8_t* key;
    const uint8_t* rho;
    const uint8_t* rhoprime;
    size_t i;

    /* Get randomness for rho, rhoprime and key */
    qsc_memutils_copy(seedbuf, seed, DILITHIUM_SEEDBYTES);

    seedbuf[DILITHIUM_SEEDBYTES] = DILITHIUM_K;
    seedbuf[DILITHIUM_SEEDBYTES + 1U] = DILITHIUM_L;
    qsc_shake256_compute(seedbuf, 2U * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES, seedbuf, DILITHIUM_SEEDBYTES + 2U);
    rho = seedbuf;
    rhoprime = rho + DILITHIUM_SEEDBYTES;
    key = rhoprime + DILITHIUM_CRHBYTES;

    /* Store rho, key */
    qsc_memutils_copy(pk, rho, DILITHIUM_SEEDBYTES);
    qsc_memutils_copy(sk, rho, DILITHIUM_SEEDBYTES);
    qsc_memutils_copy(sk + DILITHIUM_SEEDBYTES, key, DILITHIUM_SEEDBYTES);

    /* Sample short vectors s1 and s2 */
#if DILITHIUM_K == 4 && DILITHIUM_L == 4
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0U], &s1.vec[1U], &s1.vec[2U], &s1.vec[3U], rhoprime, 0U, 1U, 2U, 3U);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[0U], &s2.vec[1U], &s2.vec[2U], &s2.vec[3U], rhoprime, 4U, 5U, 6U, 7U);
#elif DILITHIUM_K == 6 && DILITHIUM_L == 5
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0U], &s1.vec[1U], &s1.vec[2U], &s1.vec[3U], rhoprime, 0U, 1U, 2U, 3U);
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[4U], &s2.vec[0U], &s2.vec[1U], &s2.vec[2U], rhoprime, 4U, 5U, 6U, 7U);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[3U], &s2.vec[4U], &s2.vec[5U], &t0, rhoprime, 8U, 9U, 10U, 11U);
#elif DILITHIUM_K == 8 && DILITHIUM_L == 7
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[0U], &s1.vec[1U], &s1.vec[2U], &s1.vec[3U], rhoprime, 0U, 1U, 2U, 3U);
    dilithium_avx2_poly_uniform_eta_4x(&s1.vec[4U], &s1.vec[5U], &s1.vec[6U], &s2.vec[0U], rhoprime, 4U, 5U, 6U, 7U);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[1U], &s2.vec[2U], &s2.vec[3U], &s2.vec[4U], rhoprime, 8U, 9U, 10U, 11U);
    dilithium_avx2_poly_uniform_eta_4x(&s2.vec[5U], &s2.vec[6U], &s2.vec[7U], &t0, rhoprime, 12U, 13U, 14U, 15U);
#else
#   error
#endif

    /* Pack secret vectors */
    for (i = 0U; i < DILITHIUM_L; i++)
    {
        dilithium_polyeta_pack(sk + (2U * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (i * DILITHIUM_POLYETA_PACKEDBYTES), &s1.vec[i]);
    }

    for (i = 0U; i < DILITHIUM_K; i++)
    {
        dilithium_polyeta_pack(sk + (2U * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (DILITHIUM_L + i) * DILITHIUM_POLYETA_PACKEDBYTES, &s2.vec[i]);
    }

    /* Transform s1 */
    dilithium_polyvecl_ntt(&s1);

    for (i = 0U; i < DILITHIUM_K; i++)
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
        dilithium_polyt0_pack(sk + (2U * DILITHIUM_SEEDBYTES) + DILITHIUM_TRBYTES + (DILITHIUM_L + DILITHIUM_K) * DILITHIUM_POLYETA_PACKEDBYTES + (i * DILITHIUM_POLYT0_PACKEDBYTES), &t0);
    }

    /* Compute CRH(rho, t1) and store in secret key */
    qsc_shake256_compute(sk + (2U * DILITHIUM_SEEDBYTES), DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);
    qsc_memutils_clear(seedbuf, sizeof(seedbuf));
}

bool qsc_dilithium_avx2_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ALIGN(32) dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl s1;
    dilithium_polyvecl y;
    dilithium_polyvecl z;
    dilithium_polyveck t0;
    dilithium_polyveck s2;
    dilithium_polyveck w1;
    dilithium_polyveck w0;
    dilithium_poly cp;
    dilithium_poly tmph;
    qsc_keccak_state kctx = { 0U };
    QSC_ALIGN(32) uint8_t hintbuf[DILITHIUM_N];
    QSC_ALIGN(32) uint8_t seedbuf[2U * DILITHIUM_SEEDBYTES + 3 * DILITHIUM_CRHBYTES];
    QSC_ALIGN(32) uint8_t rnd[DILITHIUM_RNDBYTES] = { 0U };
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
    bool ret;
    bool res;

    nonce = 0U;
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
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, context, ctxlen);
    qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, message, msglen);
    qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
    res = rng_generate(rnd, DILITHIUM_CRHBYTES);
#else
    res = true;
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
        ret = true;
        /* Sample intermediate vector y */
#if DILITHIUM_L == 4
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[0U], &y.vec[1U], &y.vec[2U], &y.vec[3U], rhoprime, nonce, nonce + 1U, nonce + 2U, nonce + 3U);
        nonce += 4U;
#elif DILITHIUM_L == 5
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[0U], &y.vec[1U], &y.vec[2U], &y.vec[3U], rhoprime, nonce, nonce + 1U, nonce + 2U, nonce + 3U);
        dilithium_poly_uniform_gamma1(&y.vec[4U], rhoprime, nonce + 4U);
        nonce += 5U;
#elif DILITHIUM_L == 7
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[0U], &y.vec[1U], &y.vec[2U], &y.vec[3U], rhoprime, nonce, nonce + 1U, nonce + 2U, nonce + 3U);
        dilithium_avx2_poly_uniform_gamma1_4x(&y.vec[4U], &y.vec[5U], &y.vec[6U], &tmph, rhoprime, nonce + 4U, nonce + 5U, nonce + 6U, 0U);
        nonce += 7U;
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
        for (i = 0U; i < DILITHIUM_L; i++)
        {
            dilithium_poly_pointwise_montgomery(&tmph, &cp, &s1.vec[i]);
            dilithium_poly_invntt_to_mont(&tmph);
            dilithium_avx2_poly_add(&z.vec[i], &z.vec[i], &tmph);
            dilithium_avx2_poly_reduce(&z.vec[i]);

            if (dilithium_avx2_poly_chknorm(&z.vec[i], DILITHIUM_GAMMA1 - DILITHIUM_BETA))
            {
                ret = false;
                break;
            }
        }

        if (ret == true)
        {
            /* Zero hint in signature */
            n = 0U;
            pos = 0U;
            qsc_memutils_clear(hint, DILITHIUM_OMEGA + DILITHIUM_K);

            for (i = 0U; i < DILITHIUM_K; i++)
            {
                /* Check that subtracting cs2 does not change high bits of w and low bits
                 * do not reveal secret information */
                dilithium_poly_pointwise_montgomery(&tmph, &cp, &s2.vec[i]);
                dilithium_poly_invntt_to_mont(&tmph);
                dilithium_avx2_poly_sub(&w0.vec[i], &w0.vec[i], &tmph);
                dilithium_avx2_poly_reduce(&w0.vec[i]);

                if (dilithium_avx2_poly_chknorm(&w0.vec[i], DILITHIUM_GAMMA2 - DILITHIUM_BETA))
                {
                    ret = false;
                    break;
                }

                /* Compute hints */
                dilithium_poly_pointwise_montgomery(&tmph, &cp, &t0.vec[i]);
                dilithium_poly_invntt_to_mont(&tmph);
                dilithium_avx2_poly_reduce(&tmph);

                if (dilithium_avx2_poly_chknorm(&tmph, DILITHIUM_GAMMA2))
                {
                    ret = false;
                    break;
                }

                dilithium_avx2_poly_add(&w0.vec[i], &w0.vec[i], &tmph);
                n = dilithium_avx2_make_hint(hintbuf, &w0.vec[i], &w1.vec[i]);

                if (pos + n > DILITHIUM_OMEGA)
                {
                    ret = false;
                    break;
                }

                /* Store hints in signature */
                qsc_memutils_copy(&hint[pos], hintbuf, n);
                pos += n;
                hint[DILITHIUM_OMEGA + i] = (uint8_t)pos;
            }
        }

        if (ret == false)
        {
            continue;
        }
        
        /* Pack z into signature */
        for (i = 0U; i < DILITHIUM_L; ++i)
        {
            dilithium_polyz_pack(sig + DILITHIUM_CTILDEBYTES + (i * DILITHIUM_POLYZ_PACKEDBYTES), &z.vec[i]);
        }

        break;
    }
    
    *siglen = DILITHIUM_SIGNATURE_SIZE;
    qsc_memutils_clear(seedbuf, sizeof(seedbuf));

    return res;
}

bool qsc_dilithium_avx2_sign(uint8_t* sm, size_t* smlen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
    bool res;

    res = false;

    if (ctxlen <= 255U)
    {
        QSC_ALIGN(32) uint8_t prec[DILITHIUM_CONTEXT_SIZE] = { 0U };

        /* prepare pre = (0, contextlen, ctx) */
        prec[0U] = 0U;
        prec[1U] = (uint8_t)ctxlen;

        if (context != NULL && ctxlen != 0)
        {
            qsc_memutils_copy(prec + 2U, context, ctxlen);
        }

        for (size_t i = 0U; i < msglen; ++i)
        {
            sm[DILITHIUM_SIGNATURE_SIZE + msglen - 1U - i] = message[msglen - 1U - i];
        }

        res = qsc_dilithium_avx2_sign_signature(sm, smlen, sm + DILITHIUM_SIGNATURE_SIZE, msglen, prec, ctxlen + 2U, sk, rng_generate);
        *smlen += msglen;
    }

    return res;
}

bool qsc_dilithium_avx2_verify(const uint8_t* sig, size_t siglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* pk)
{
    dilithium_polyvecl mat[DILITHIUM_K];
    dilithium_polyvecl z;
    dilithium_poly cp;
    dilithium_poly t1;
    dilithium_poly w1;
    dilithium_poly h;
    qsc_keccak_state kctx = { 0U };
    /* polyw1_pack writes additional 14 bytes */
    QSC_ALIGN(32) uint8_t buf[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES + 14U];
    QSC_ALIGN(32) uint8_t c[DILITHIUM_CTILDEBYTES];
    QSC_ALIGN(32) uint8_t mu[DILITHIUM_CRHBYTES];
    const uint8_t* hint = sig + DILITHIUM_CTILDEBYTES + DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;
    size_t i;
    size_t j;
    size_t pos;
    bool res;

    res = true;

    if (siglen == DILITHIUM_SIGNATURE_SIZE)
    {
        /* Compute CRH(H(rho, t1), pre, msg) */
        qsc_shake256_compute(mu, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);

        qsc_keccak_initialize_state(&kctx);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, context, ctxlen);
        qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, message, msglen);
        qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
        qsc_keccak_incremental_squeeze(&kctx, QSC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

        /* Expand challenge */
        dilithium_poly_challenge(&cp, sig);
        dilithium_poly_ntt(&cp);

        /* Unpack z; shortness follows from unpacking */
        for (i = 0U; i < DILITHIUM_L; i++)
        {
            dilithium_polyz_unpack(&z.vec[i], sig + DILITHIUM_CTILDEBYTES + i * DILITHIUM_POLYZ_PACKEDBYTES);
            dilithium_poly_ntt(&z.vec[i]);
        }

        pos = 0U; // NOTE: t1 is h now

        for (i = 0U; i < DILITHIUM_K; i++)
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
                if(j > pos && hint[j] <= hint[j - 1U]) 
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

bool qsc_dilithium_avx2_open(uint8_t* message, size_t* msglen, const uint8_t* context, size_t ctxlen, const uint8_t* sm, size_t smlen, const uint8_t* pk)
{
    bool res;

    *msglen = 0U;
    res = false;

    if (ctxlen <= 255)
    {
        QSC_ALIGN(32) uint8_t prec[DILITHIUM_CONTEXT_SIZE] = { 0U };

        /* prepare pre = (0, ctxlen, ctx) */
        prec[0U] = 0U;
        prec[1U] = (uint8_t)ctxlen;

        if (context != NULL && ctxlen != 0)
        {
            qsc_memutils_copy(prec + 2U, context, ctxlen);
        }

        if (smlen >= DILITHIUM_SIGNATURE_SIZE)
        {
            *msglen = smlen - DILITHIUM_SIGNATURE_SIZE;
            res = qsc_dilithium_avx2_verify(sm, DILITHIUM_SIGNATURE_SIZE, sm + DILITHIUM_SIGNATURE_SIZE, *msglen, prec, ctxlen + 2U, pk);

            if (res == true)
            {
                /* All good, copy msg, return 0 */
                qsc_memutils_copy(message, sm + DILITHIUM_SIGNATURE_SIZE, *msglen);
            }
        }
    }

    if (res == false)
    {
        qsc_memutils_clear(message, smlen - DILITHIUM_SIGNATURE_SIZE);
    }

    return res;
}

#endif
