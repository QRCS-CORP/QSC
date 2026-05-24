#include "acp.h"
#include "csp.h"
#include "intrinsics.h"
#include "memutils.h"
#include "rdp.h"
#include "sha3.h"
#include "sysutils.h"

#define ACP_PRESEED_SIZE 64U

static void acp_add_computer_name(qsc_keccak_state* kstate)
{
	char snm[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0U };
	size_t nlen;

	nlen = qsc_sysutils_computer_name(snm);

	if (nlen > 0U)
	{
		qsc_sha3_update(kstate, qsc_keccak_rate_512, (const uint8_t*)snm, nlen);
		qsc_memutils_secure_erase(snm, nlen);
	}
}

static void acp_drive_statistics(qsc_keccak_state* kstate)
{
	uint8_t sds[sizeof(qsc_sysutils_drive_space_state)] = { 0U };
	qsc_sysutils_drive_space_state dst;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	char drv[3U] = { 0 };

	drv[0U] = qsc_sysutils_get_os_drive_letter();
	drv[1U] = ':';
	qsc_sysutils_drive_space(drv, &dst);
#elif defined(QSC_SYSTEM_OS_POSIX)
	qsc_sysutils_drive_space("/", &dst);
#else
	qsc_memutils_clear(&dst, sizeof(dst));
#endif

	qsc_memutils_copy(sds, (const uint8_t*)&dst, sizeof(sds));
	qsc_sha3_update(kstate, qsc_keccak_rate_512, sds, sizeof(sds));
	qsc_memutils_secure_erase(sds, sizeof(sds));
}

static void acp_add_memory_statistics(qsc_keccak_state* kstate)
{
	qsc_sysutils_memory_statistics_state mst;
	uint8_t sms[sizeof(qsc_sysutils_memory_statistics_state)] = { 0U };

	qsc_sysutils_memory_statistics(&mst);
	qsc_memutils_copy(sms, (const uint8_t*)&mst, sizeof(sms));
	qsc_sha3_update(kstate, qsc_keccak_rate_512, sms, sizeof(sms));
	qsc_memutils_secure_erase(sms, sizeof(sms));
}

static void acp_add_pid(qsc_keccak_state* kstate)
{
	uint8_t spd[sizeof(uint32_t)] = { 0U };
	uint32_t pid;

	pid = qsc_sysutils_process_id();
	qsc_memutils_copy(spd, (const uint8_t*)&pid, sizeof(spd));
	qsc_sha3_update(kstate, qsc_keccak_rate_512, spd, sizeof(spd));
	pid = 0U;
}

static void acp_add_timestamp(qsc_keccak_state* kstate)
{
	uint8_t sts[sizeof(uint64_t)] = { 0U };
	uint64_t ts;

	ts = qsc_sysutils_system_timestamp();
	qsc_memutils_copy(sts, (const uint8_t*)&ts, sizeof(uint64_t));
	qsc_sha3_update(kstate, qsc_keccak_rate_512, sts, sizeof(sts));
	qsc_memutils_secure_erase(sts, sizeof(sts));
	ts = 0U;
}

static void acp_add_user_name(qsc_keccak_state* kstate)
{
	char snm[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0U };
	size_t nlen;

	nlen = qsc_sysutils_user_name(snm);

	if (nlen > 0U)
	{
		qsc_sha3_update(kstate, qsc_keccak_rate_512, (const uint8_t*)snm, nlen);
		qsc_memutils_secure_erase(snm, nlen);
	}
}

static void acp_collect_statistics(uint8_t* output)
{
	qsc_keccak_state kstate = { 0U };

	acp_add_timestamp(&kstate);
	acp_add_computer_name(&kstate);
	acp_drive_statistics(&kstate);
	acp_add_memory_statistics(&kstate);
	acp_add_pid(&kstate);
	acp_add_user_name(&kstate);
	acp_add_timestamp(&kstate);

	/* compress the statistics */
	qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, output);
	qsc_keccak_dispose(&kstate);
}

static void acp_squeeze_output(qsc_keccak_state* kstate, uint8_t* output, size_t length)
{
	size_t pos;

	pos = 0U;

	while (length >= QSC_KECCAK_512_RATE)
	{
		qsc_keccak_squeezeblocks(kstate, output + pos, 1U, qsc_keccak_rate_512, QSC_KECCAK_PERMUTATION_ROUNDS);
		length -= QSC_KECCAK_512_RATE;
		pos += QSC_KECCAK_512_RATE;
	}

	if (length > 0U)
	{
		uint8_t kbuff[QSC_KECCAK_512_RATE] = { 0U };

		qsc_keccak_squeezeblocks(kstate, kbuff, 1U, qsc_keccak_rate_512, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_memutils_copy(output + pos, kbuff, length);
		qsc_memutils_secure_erase(kbuff, sizeof(kbuff));
	}
}

bool qsc_acp_generate(uint8_t* output, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);
	QSC_ASSERT(length <= QSC_ACP_SEED_MAX);

	qsc_keccak_state kstate = { 0U };
	uint8_t seed[ACP_PRESEED_SIZE] = { 0U };
	bool res;

	res = false;

	if (output != NULL && length != 0U && length <= QSC_ACP_SEED_MAX)
	{
		/* collect non-cryptographic system statistics only as supplemental input */
		acp_collect_statistics(seed);
		qsc_keccak_update(&kstate, qsc_keccak_rate_512, seed, sizeof(seed), QSC_KECCAK_PERMUTATION_ROUNDS);

		/* mix hardware random data if available; failure is not fatal if CSP succeeds */
		if (qsc_rdrand_available() == true)
		{
			if (qsc_rdp_generate(seed, sizeof(seed)) == true)
			{
				qsc_keccak_update(&kstate, qsc_keccak_rate_512, seed, sizeof(seed), QSC_KECCAK_PERMUTATION_ROUNDS);
			}
		}

		/* the operating-system CSPRNG is mandatory.
		 * host statistics and RDRAND are supplemental and must never be treated
		 * as sufficient standalone entropy for ACP output. */
		if (qsc_csp_generate(seed, sizeof(seed)) == true)
		{
			qsc_keccak_update(&kstate, qsc_keccak_rate_512, seed, sizeof(seed), QSC_KECCAK_PERMUTATION_ROUNDS);
			acp_squeeze_output(&kstate, output, length);
			res = true;
		}
		else
		{
			qsc_memutils_clear(output, length);
		}

		qsc_keccak_dispose(&kstate);
		qsc_memutils_secure_erase(seed, sizeof(seed));
	}

	return res;
}

uint16_t qsc_acp_uint16(void)
{
	uint8_t arr[sizeof(uint16_t)] = { 0U };
	uint16_t num;

	num = 0U;

	if (qsc_acp_generate(arr, sizeof(arr)) == true)
	{
		num = (((uint16_t)arr[1U]) | (uint16_t)((uint16_t)arr[0U] << 8U));

		qsc_memutils_secure_erase(arr, sizeof(arr));
	}

	return num;
}

uint32_t qsc_acp_uint32(void)
{
	uint8_t arr[sizeof(uint32_t)] = { 0U };
	uint32_t num;

	num = 0U;

	if (qsc_acp_generate(arr, sizeof(arr)) == true)
	{
		num = (uint32_t)(arr[3U]) |
			(((uint32_t)(arr[2U])) << 8U) |
			(((uint32_t)(arr[1U])) << 16U) |
			(((uint32_t)(arr[0U])) << 24U);

		qsc_memutils_secure_erase(arr, sizeof(arr));
	}

	return num;
}

uint64_t qsc_acp_uint64(void)
{
	uint8_t arr[sizeof(uint64_t)] = { 0U };
	uint64_t num;

	num = 0U;

	if (qsc_acp_generate(arr, sizeof(arr)) == true)
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
