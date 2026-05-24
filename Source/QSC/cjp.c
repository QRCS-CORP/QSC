/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * See cjp.h for license and usage restrictions.
 */

#include "cjp.h"
#include "cpuidex.h"
#include "csp.h"
#include "memutils.h"
#include "rdp.h"
#include "sha3.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   include <windows.h>
#elif defined(QSC_SYSTEM_OS_MAC)
#   include <mach/mach_time.h>
#elif defined(QSC_SYSTEM_OS_POSIX)
#   include <time.h>
#endif

#define QSC_CJP_ACC_LOOP_BIT_MAX 7ULL
#define QSC_CJP_ACC_LOOP_BIT_MIN 0ULL
#define QSC_CJP_ADAPTIVE_WINDOW_SIZE 512U
#define QSC_CJP_ADAPTIVE_WINDOW_MAX 496U
#define QSC_CJP_AUXILIARY_SIZE 64U
#define QSC_CJP_CLEARCACHE 100U
#define QSC_CJP_DATA_SIZE_BITS 64U
#define QSC_CJP_DOMAIN_SIZE 32U
#define QSC_CJP_LOOP_TEST_COUNT 300U
#define QSC_CJP_MEMORY_ACCESSLOOPS 256U
#define QSC_CJP_MEMORY_BLOCKS 512U
#define QSC_CJP_MEMORY_BLOCKSIZE 32U
#define QSC_CJP_MEMORY_SIZE (QSC_CJP_MEMORY_BLOCKS * QSC_CJP_MEMORY_BLOCKSIZE)
#define QSC_CJP_REPETITION_COUNT_MAX 32U
#define QSC_CJP_SAMPLE_ATTEMPT_MAX 8192U
#define QSC_CJP_SAMPLE_COUNT 512U
#define QSC_CJP_SAMPLE_ENCODED_SIZE 40U
#define QSC_CJP_SEED_SIZE ((QSC_CJP_SAMPLE_COUNT * QSC_CJP_SAMPLE_ENCODED_SIZE) + (QSC_CJP_AUXILIARY_SIZE * 2U) + QSC_CJP_DOMAIN_SIZE)

static const uint8_t CJP_DOMAIN[QSC_CJP_DOMAIN_SIZE] =
{
    0x51U, 0x53U, 0x43U, 0x2DU, 0x43U, 0x4AU, 0x50U, 0x2DU,
    0x53U, 0x48U, 0x41U, 0x4BU, 0x45U, 0x35U, 0x31U, 0x32U,
    0x2DU, 0x43U, 0x50U, 0x55U, 0x2DU, 0x4AU, 0x49U, 0x54U,
    0x54U, 0x45U, 0x52U, 0x2DU, 0x56U, 0x30U, 0x31U, 0x00U
};

typedef struct
{
    uint8_t* memory_state;
    uint64_t last_delta;
    uint64_t last_delta2;
    uint64_t previous_time;
    uint64_t shuffle_state;
    uint64_t sample_count;
    uint64_t rejected_count;
    uint64_t health_failures;
    uint64_t rct_previous;
    size_t rct_count;
    uint8_t apt_symbol;
    size_t apt_count;
    size_t apt_index;
    size_t memory_blocks;
    size_t memory_block_size;
    size_t memory_iterations;
    size_t memory_position;
    size_t memory_total_size;
    bool initialized;
} qsc_cjp_state;

static bool qsc_cjp_health_check(qsc_cjp_state* ctx, uint64_t delta, uint64_t delta2, uint64_t delta3);
static bool qsc_cjp_initialize(qsc_cjp_state* ctx);
static bool qsc_cjp_measure_jitter(qsc_cjp_state* ctx, uint8_t* seed, size_t* offset, size_t seedlen);
static void qsc_cjp_memory_jitter(qsc_cjp_state* ctx);
static void qsc_cjp_seed_auxiliary(uint8_t* seed, size_t* offset, size_t seedlen);
static void qsc_cjp_seed_encode(uint8_t* seed, size_t* offset, size_t seedlen, uint64_t value);
static bool qsc_cjp_seed_generate(qsc_cjp_state* ctx, uint8_t* seed, size_t seedlen);
static size_t qsc_cjp_shuffle_loop(qsc_cjp_state* ctx, size_t lowbits, size_t minshift);
static bool qsc_cjp_stuck_check(qsc_cjp_state* ctx, uint64_t current_delta, uint64_t* delta2, uint64_t* delta3);
static bool qsc_cjp_timer_check(qsc_cjp_state* ctx);
static bool qsc_cjp_timestamp(uint64_t* output);

static bool qsc_cjp_timestamp(uint64_t* output)
{
    bool res;

    res = false;

    if (output != NULL)
    {
        *output = 0ULL;

#if defined(QSC_SYSTEM_OS_WINDOWS)
        {
            LARGE_INTEGER ctr;

            if (QueryPerformanceCounter(&ctr) != 0)
            {
                *output = (uint64_t)ctr.QuadPart;
                res = (*output != 0ULL);
            }
        }
#elif defined(QSC_SYSTEM_OS_MAC)
        *output = (uint64_t)mach_absolute_time();
        res = (*output != 0ULL);
#elif defined(QSC_SYSTEM_OS_POSIX)
        {
            struct timespec ts;
            int32_t ret;

#   if defined(CLOCK_MONOTONIC_RAW)
            ret = clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#   else
            ret = clock_gettime(CLOCK_MONOTONIC, &ts);
#   endif

            if (ret == 0)
            {
                *output = (((uint64_t)ts.tv_sec) * 1000000000ULL) + (uint64_t)ts.tv_nsec;
                res = (*output != 0ULL);
            }
        }
#else
        res = false;
#endif
    }

    return res;
}

static void qsc_cjp_dispose(qsc_cjp_state* ctx)
{
    if (ctx != NULL)
    {
        if (ctx->memory_state != NULL)
        {
            qsc_memutils_secure_erase(ctx->memory_state, ctx->memory_total_size);
            qsc_memutils_alloc_free(ctx->memory_state);
        }

        qsc_memutils_secure_erase(ctx, sizeof(qsc_cjp_state));
    }
}

bool qsc_cjp_available(void)
{
    qsc_cjp_state st;
    bool res;

    res = false;
    qsc_memutils_clear(&st, sizeof(st));

    if (qsc_cjp_initialize(&st) == true)
    {
        res = qsc_cjp_timer_check(&st);
        qsc_cjp_dispose(&st);
    }

    return res;
}

bool qsc_cjp_generate(uint8_t* output, size_t length)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(length != 0U);
    QSC_ASSERT(length <= QSC_CJP_SEED_MAX);

    qsc_cjp_state st;
    uint8_t* seed;
    bool res;

    seed = NULL;
    res = false;
    qsc_memutils_clear(&st, sizeof(st));

    if (output != NULL && length != 0U && length <= QSC_CJP_SEED_MAX)
    {
        seed = (uint8_t*)qsc_memutils_malloc(QSC_CJP_SEED_SIZE);

        if (seed != NULL)
        {
            qsc_memutils_clear(seed, QSC_CJP_SEED_SIZE);

            if (qsc_cjp_initialize(&st) == true)
            {
                if (qsc_cjp_timer_check(&st) == true && qsc_cjp_seed_generate(&st, seed, QSC_CJP_SEED_SIZE) == true)
                {
                    qsc_shake512_compute(output, length, seed, QSC_CJP_SEED_SIZE);
                    res = true;
                }

                qsc_cjp_dispose(&st);
            }

            qsc_memutils_secure_erase(seed, QSC_CJP_SEED_SIZE);
            qsc_memutils_alloc_free(seed);
        }
    }

    if (res == false && output != NULL && length != 0U && length <= QSC_CJP_SEED_MAX)
    {
        qsc_memutils_clear(output, length);
    }

    return res;
}

static bool qsc_cjp_initialize(qsc_cjp_state* ctx)
{
#if defined(QSC_HAS_CPUID)
    qsc_cpuidex_cpu_features cpu;
#endif
    size_t blockcount;
    size_t blocksize;
    size_t total;
    bool res;

    res = false;

    if (ctx != NULL)
    {
        qsc_memutils_clear(ctx, sizeof(qsc_cjp_state));

        blocksize = QSC_CJP_MEMORY_BLOCKSIZE;
        blockcount = QSC_CJP_MEMORY_BLOCKS;

#if defined(QSC_HAS_CPUID)
        qsc_memutils_clear(&cpu, sizeof(cpu));

        if (qsc_cpuidex_features_set(&cpu) == true)
        {
            if (cpu.l1cacheline != 0U)
            {
                blocksize = (size_t)cpu.l1cacheline;
            }

            if (cpu.l1cache != 0U && cpu.cpus != 0U && blocksize != 0U)
            {
                blockcount = ((size_t)cpu.l1cache / (size_t)cpu.cpus) / blocksize;

                if (blockcount == 0U)
                {
                    blockcount = QSC_CJP_MEMORY_BLOCKS;
                }
            }
        }
#endif

        total = blockcount * blocksize;

        if (total == 0U)
        {
            total = QSC_CJP_MEMORY_SIZE;
            blockcount = QSC_CJP_MEMORY_BLOCKS;
            blocksize = QSC_CJP_MEMORY_BLOCKSIZE;
        }

        ctx->memory_state = (uint8_t*)qsc_memutils_malloc(total);

        if (ctx->memory_state != NULL)
        {
            qsc_memutils_clear(ctx->memory_state, total);
            ctx->memory_blocks = blockcount;
            ctx->memory_block_size = blocksize;
            ctx->memory_iterations = (total / blocksize) * 2U;
            ctx->memory_total_size = total;
            ctx->initialized = true;
            res = true;
        }
    }

    return res;
}

static void qsc_cjp_seed_encode(uint8_t* seed, size_t* offset, size_t seedlen, uint64_t value)
{
    if (seed != NULL && offset != NULL && (*offset + sizeof(uint64_t)) <= seedlen)
    {
        seed[*offset] = (uint8_t)value;
        seed[*offset + 1U] = (uint8_t)(value >> 8U);
        seed[*offset + 2U] = (uint8_t)(value >> 16U);
        seed[*offset + 3U] = (uint8_t)(value >> 24U);
        seed[*offset + 4U] = (uint8_t)(value >> 32U);
        seed[*offset + 5U] = (uint8_t)(value >> 40U);
        seed[*offset + 6U] = (uint8_t)(value >> 48U);
        seed[*offset + 7U] = (uint8_t)(value >> 56U);
        *offset += sizeof(uint64_t);
    }
}

static void qsc_cjp_seed_auxiliary(uint8_t* seed, size_t* offset, size_t seedlen)
{
    uint8_t aux[QSC_CJP_AUXILIARY_SIZE] = { 0U };

    if (seed != NULL && offset != NULL)
    {
        qsc_memutils_copy(seed + *offset, CJP_DOMAIN, QSC_CJP_DOMAIN_SIZE);
        *offset += QSC_CJP_DOMAIN_SIZE;

        if ((*offset + sizeof(aux)) <= seedlen && qsc_rdp_generate(aux, sizeof(aux)) == true)
        {
            qsc_memutils_copy(seed + *offset, aux, sizeof(aux));
            *offset += sizeof(aux);
            qsc_memutils_secure_erase(aux, sizeof(aux));
        }

        if ((*offset + sizeof(aux)) <= seedlen && qsc_csp_generate(aux, sizeof(aux)) == true)
        {
            qsc_memutils_copy(seed + *offset, aux, sizeof(aux));
            *offset += sizeof(aux);
            qsc_memutils_secure_erase(aux, sizeof(aux));
        }
    }
}

static bool qsc_cjp_seed_generate(qsc_cjp_state* ctx, uint8_t* seed, size_t seedlen)
{
    size_t attempts;
    size_t accepted;
    size_t offset;
    bool res;

    attempts = 0U;
    accepted = 0U;
    offset = 0U;
    res = false;

    if (ctx != NULL && seed != NULL && seedlen >= QSC_CJP_SEED_SIZE)
    {
        qsc_cjp_seed_auxiliary(seed, &offset, seedlen);

        while (accepted < QSC_CJP_SAMPLE_COUNT && attempts < QSC_CJP_SAMPLE_ATTEMPT_MAX)
        {
            if (qsc_cjp_measure_jitter(ctx, seed, &offset, seedlen) == true)
            {
                ++accepted;
            }
            else
            {
                ++ctx->rejected_count;
            }

            ++attempts;
        }

        if (accepted == QSC_CJP_SAMPLE_COUNT && ctx->health_failures == 0U)
        {
            res = true;
        }
    }

    return res;
}

static bool qsc_cjp_measure_jitter(qsc_cjp_state* ctx, uint8_t* seed, size_t* offset, size_t seedlen)
{
    uint64_t delta;
    uint64_t delta2;
    uint64_t delta3;
    uint64_t tm;
    bool res;

    res = false;

    if (ctx != NULL && seed != NULL && offset != NULL)
    {
        qsc_cjp_memory_jitter(ctx);

        if (qsc_cjp_timestamp(&tm) == true)
        {
            if (ctx->previous_time != 0ULL && tm > ctx->previous_time)
            {
                delta = tm - ctx->previous_time;

                if (qsc_cjp_stuck_check(ctx, delta, &delta2, &delta3) == false &&
                    qsc_cjp_health_check(ctx, delta, delta2, delta3) == true)
                {
                    qsc_cjp_seed_encode(seed, offset, seedlen, tm);
                    qsc_cjp_seed_encode(seed, offset, seedlen, delta);
                    qsc_cjp_seed_encode(seed, offset, seedlen, delta2);
                    qsc_cjp_seed_encode(seed, offset, seedlen, delta3);
                    qsc_cjp_seed_encode(seed, offset, seedlen, ctx->shuffle_state);
                    ++ctx->sample_count;
                    res = true;
                }
            }

            ctx->previous_time = tm;
        }
    }

    return res;
}

QSC_SYSTEM_OPTIMIZE_IGNORE
static void qsc_cjp_memory_jitter(qsc_cjp_state* ctx)
{
    size_t access_count;
    size_t i;
    size_t wraplen;
    uint8_t tmp;

    if (ctx != NULL && ctx->memory_state != NULL && ctx->memory_block_size != 0U && ctx->memory_blocks != 0U)
    {
        wraplen = ctx->memory_block_size * ctx->memory_blocks;
        access_count = ctx->memory_iterations + qsc_cjp_shuffle_loop(ctx, QSC_CJP_ACC_LOOP_BIT_MAX, QSC_CJP_ACC_LOOP_BIT_MIN);

        for (i = 0U; i < access_count; ++i)
        {
            tmp = ctx->memory_state[ctx->memory_position];
            tmp = (uint8_t)((tmp + 1U) & 0xFFU);
            ctx->memory_state[ctx->memory_position] = tmp;
            ctx->memory_position = ctx->memory_position + ctx->memory_block_size - 1U;
            ctx->memory_position %= wraplen;
        }
    }
}
QSC_SYSTEM_OPTIMIZE_RESUME

static size_t qsc_cjp_shuffle_loop(qsc_cjp_state* ctx, size_t lowbits, size_t minshift)
{
    uint64_t mask;
    uint64_t shuffle;
    uint64_t tm;
    size_t i;
    size_t res;

    res = (size_t)1U << minshift;

    if (ctx != NULL && lowbits != 0U && lowbits < QSC_CJP_DATA_SIZE_BITS)
    {
        mask = (1ULL << lowbits) - 1ULL;

        if (qsc_cjp_timestamp(&tm) == true)
        {
            tm ^= ctx->shuffle_state;
            shuffle = 0ULL;

            for (i = 0U; i < (QSC_CJP_DATA_SIZE_BITS / lowbits); ++i)
            {
                shuffle ^= (tm & mask);
                tm >>= lowbits;
            }

            ctx->shuffle_state ^= (tm + shuffle + ctx->sample_count + ctx->rejected_count);
            res = (size_t)shuffle + ((size_t)1U << minshift);
        }
    }

    return res;
}

static bool qsc_cjp_stuck_check(qsc_cjp_state* ctx, uint64_t current_delta, uint64_t* delta2, uint64_t* delta3)
{
    bool ret;

    ret = true;

    if (ctx != NULL && delta2 != NULL && delta3 != NULL)
    {
        *delta2 = ctx->last_delta - current_delta;
        *delta3 = *delta2 - ctx->last_delta2;
        ctx->last_delta = current_delta;
        ctx->last_delta2 = *delta2;

        ret = (current_delta == 0ULL || *delta2 == 0ULL || *delta3 == 0ULL);
    }

    return ret;
}

static bool qsc_cjp_health_check(qsc_cjp_state* ctx, uint64_t delta, uint64_t delta2, uint64_t delta3)
{
    uint8_t symbol;
    bool res;

    res = false;

    if (ctx != NULL)
    {
        symbol = (uint8_t)(delta ^ delta2 ^ delta3);

        if (ctx->sample_count == 0U)
        {
            ctx->rct_previous = delta;
            ctx->rct_count = 1U;
            ctx->apt_symbol = symbol;
            ctx->apt_count = 1U;
            ctx->apt_index = 1U;
            res = true;
        }
        else
        {
            if (delta == ctx->rct_previous)
            {
                ++ctx->rct_count;
            }
            else
            {
                ctx->rct_previous = delta;
                ctx->rct_count = 1U;
            }

            if (ctx->rct_count >= QSC_CJP_REPETITION_COUNT_MAX)
            {
                ++ctx->health_failures;
            }

            if (ctx->apt_index == 0U)
            {
                ctx->apt_symbol = symbol;
                ctx->apt_count = 1U;
                ctx->apt_index = 1U;
            }
            else
            {
                if (symbol == ctx->apt_symbol)
                {
                    ++ctx->apt_count;
                }

                ++ctx->apt_index;
            }

            if (ctx->apt_index >= QSC_CJP_ADAPTIVE_WINDOW_SIZE)
            {
                if (ctx->apt_count >= QSC_CJP_ADAPTIVE_WINDOW_MAX)
                {
                    ++ctx->health_failures;
                }

                ctx->apt_index = 0U;
                ctx->apt_count = 0U;
            }

            res = (ctx->health_failures == 0U);
        }
    }

    return res;
}

static bool qsc_cjp_timer_check(qsc_cjp_state* ctx)
{
    uint64_t delta;
    uint64_t olddelta;
    uint64_t sumdelta;
    uint64_t tm1;
    uint64_t tm2;
    size_t backctr;
    size_t i;
    size_t modctr;
    bool res;

    olddelta = 0ULL;
    sumdelta = 0ULL;
    backctr = 0U;
    modctr = 0U;
    res = false;

    if (ctx != NULL)
    {
        for (i = 0U; i < (QSC_CJP_LOOP_TEST_COUNT + QSC_CJP_CLEARCACHE); ++i)
        {
            if (qsc_cjp_timestamp(&tm1) == false)
            {
                break;
            }

            qsc_cjp_memory_jitter(ctx);

            if (qsc_cjp_timestamp(&tm2) == false)
            {
                break;
            }

            if (tm2 <= tm1)
            {
                ++backctr;
                continue;
            }

            delta = tm2 - tm1;

            if (delta == 0ULL)
            {
                break;
            }

            if (i < QSC_CJP_CLEARCACHE)
            {
                continue;
            }

            if ((delta % 100ULL) == 0ULL)
            {
                ++modctr;
            }

            if (delta > olddelta)
            {
                sumdelta += (delta - olddelta);
            }
            else
            {
                sumdelta += (olddelta - delta);
            }

            olddelta = delta;
        }

        if (backctr <= 3U && sumdelta > 1ULL && modctr <= ((QSC_CJP_LOOP_TEST_COUNT / 10U) * 9U))
        {
            res = true;
        }
    }

    return res;
}

uint16_t qsc_cjp_uint16(void)
{
    uint8_t arr[sizeof(uint16_t)] = { 0U };
    uint16_t num;

    num = 0U;

    if (qsc_cjp_generate(arr, sizeof(arr)) == true)
    {
        num = (((uint16_t)arr[1U]) | (uint16_t)((uint16_t)arr[0U] << 8U));
        qsc_memutils_secure_erase(arr, sizeof(arr));
    }

    return num;
}

uint32_t qsc_cjp_uint32(void)
{
    uint8_t arr[sizeof(uint32_t)] = { 0U };
    uint32_t num;

    num = 0U;

    if (qsc_cjp_generate(arr, sizeof(arr)) == true)
    {
        num = (uint32_t)(arr[3U]) |
            (((uint32_t)(arr[2U])) << 8U) |
            (((uint32_t)(arr[1U])) << 16U) |
            (((uint32_t)(arr[0U])) << 24U);

        qsc_memutils_secure_erase(arr, sizeof(arr));
    }

    return num;
}

uint64_t qsc_cjp_uint64(void)
{
    uint8_t arr[sizeof(uint64_t)] = { 0U };
    uint64_t num;

    num = 0U;

    if (qsc_cjp_generate(arr, sizeof(arr)) == true)
    {
        num = (uint64_t)(arr[7U]) |
            (((uint64_t)(arr[6U])) << 8U) |
            (((uint64_t)(arr[5U])) << 16U) |
            (((uint64_t)(arr[4U])) << 24U) |
            (((uint64_t)(arr[3U])) << 32U) |
            (((uint64_t)(arr[2U])) << 40U) |
            (((uint64_t)(arr[1U])) << 48U) |
            (((uint64_t)(arr[0U])) << 56U);

        qsc_memutils_secure_erase(arr, sizeof(arr));
    }

    return num;
}
