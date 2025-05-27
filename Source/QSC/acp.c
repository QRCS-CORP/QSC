#include "acp.h"
#include "csp.h"
#include "memutils.h"
#include "rdp.h"
#include "sha3.h"
#include "sysutils.h"

#define ACP_PRESEED_SIZE 64

static void acp_collect_statistics(uint8_t stat[ACP_PRESEED_SIZE])
{
	uint8_t buffer[1024U] = { 0U };
	char tname[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0U };
	qsc_sysutils_drive_space_state dstate;
	qsc_sysutils_memory_statistics_state mstate;
	uint64_t ts;
	size_t len;
	size_t oft;
	uint32_t id;

	/* add user statistics */
	ts = qsc_sysutils_system_timestamp();

	/* interspersed with time-stamps, as return from system calls has some entropy variability */
	qsc_memutils_copy(buffer, (const uint8_t*)&ts, sizeof(uint64_t));
	oft = sizeof(uint64_t);
	len = qsc_sysutils_computer_name(tname);

	if ((oft + len) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, tname, len);
		oft += len;
	}

	id = qsc_sysutils_process_id();

	if ((oft + sizeof(uint32_t)) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, (const uint8_t*)&id, sizeof(uint32_t));
		oft += sizeof(uint32_t);
	}

	len = qsc_sysutils_user_name(tname);

	if ((oft + len) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, tname, len);
		oft += len;
	}

	ts = qsc_sysutils_system_uptime();

	if ((oft + sizeof(uint64_t)) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, (const uint8_t*)&ts, sizeof(uint64_t));
		oft += sizeof(uint64_t);
	}

	/* add drive statistics */
	ts = qsc_sysutils_system_timestamp();

	if ((oft + sizeof(uint64_t)) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, (const uint8_t*)&ts, sizeof(uint64_t));
		oft += sizeof(uint64_t);
	}

#if defined(QSC_SYSTEM_OS_WINDOWS)
	char drv[3U] = { 0 };

	drv[0U] = qsc_sysutils_get_os_drive_letter();
	drv[1U] = ':';
	qsc_sysutils_drive_space(drv, &dstate);
#elif defined(QSC_SYSTEM_OS_POSIX)
	qsc_sysutils_drive_space("/", &dstate);
#endif

	if ((oft + sizeof(dstate)) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, (const uint8_t*)&dstate, sizeof(dstate));
		oft += sizeof(dstate);
	}

	/* add memory statistics */
	ts = qsc_sysutils_system_timestamp();

	if ((oft + sizeof(uint64_t)) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, (const uint8_t*)&ts, sizeof(uint64_t));
		oft += sizeof(uint64_t);
	}

	qsc_sysutils_memory_statistics(&mstate);

	if ((oft + sizeof(mstate)) <= sizeof(buffer))
	{
		qsc_memutils_copy(buffer + oft, (const uint8_t*)&mstate, sizeof(mstate));
		len = oft + sizeof(mstate);
	}

	/* compress the statistics */
	qsc_sha3_compute512(stat, buffer, len);
	qsc_memutils_clear(buffer, sizeof(buffer));
}

bool qsc_acp_generate(uint8_t* output, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);
	QSC_ASSERT(length <= QSC_ACP_SEED_MAX);

	uint8_t cust[64U] = { 0U };
	uint8_t key[64U] = { 0U };
	uint8_t stat[ACP_PRESEED_SIZE] = { 0U };
	bool res;

	res = false;

	if (output != NULL && length != 0U && length <= QSC_ACP_SEED_MAX)
	{
		/* collect timers and system stats, compressed as tertiary seed */
		acp_collect_statistics(stat);

		/* add a seed using RDRAND used as cSHAKE custom parameter */
		res = qsc_rdp_generate(cust, sizeof(cust));

		if (res == false)
		{
			/* fall-back to system provider */
			res = qsc_csp_generate(cust, sizeof(cust));
		}

		if (res == true)
		{
			/* generate primary key using system random provider */
			res = qsc_csp_generate(key, sizeof(key));
		}

		if (res == true)
		{
			/* key cSHAKE-512 to generate the pseudo-random output, using all three entropy sources */
			qsc_cshake512_compute(output, length, key, sizeof(key), stat, sizeof(stat), cust, sizeof(cust));
			qsc_memutils_clear(key, sizeof(key));
			qsc_memutils_clear(stat, sizeof(stat));
		}
	}

	if (!res)
	{
		qsc_memutils_clear(output, length);
	}

	return res;
}

uint16_t qsc_acp_uint16()
{
	uint8_t arr[sizeof(uint16_t)] = { 0U };
	uint16_t num;

	num = 0U;

	if (qsc_acp_generate(arr, sizeof(arr)))
	{
		num = (((uint16_t)arr[1U]) | (uint16_t)((uint16_t)arr[0U] << 8U));
	}

	return num;
}

uint32_t qsc_acp_uint32()
{
	uint8_t arr[sizeof(uint32_t)] = { 0U };
	uint32_t num;

	num = 0U;

	if (qsc_acp_generate(arr, sizeof(arr)))
	{
		num = (uint32_t)(arr[3U]) |
			(((uint32_t)(arr[2U])) << 8U) |
			(((uint32_t)(arr[1U])) << 16U) |
			(((uint32_t)(arr[0U])) << 24U);
	}

	return num;
}

uint64_t qsc_acp_uint64()
{
	uint8_t arr[sizeof(uint64_t)] = { 0U };
	uint64_t num;

	num = 0U;

	if (qsc_acp_generate(arr, sizeof(arr)))
	{
		num = (uint64_t)(arr[7U]) |
			(((uint64_t)(arr[6U])) << 8U) |
			(((uint64_t)(arr[5U])) << 16U) |
			(((uint64_t)(arr[4U])) << 24U) |
			(((uint64_t)(arr[3U])) << 32U) |
			(((uint64_t)(arr[2U])) << 40U) |
			(((uint64_t)(arr[1U])) << 48U) |
			(((uint64_t)(arr[0U])) << 56U);
	}

	return num;
}
