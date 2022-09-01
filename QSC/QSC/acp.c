#include "acp.h"
#include "csp.h"
#include "memutils.h"
#include "rdp.h"
#include "sha3.h"
#include "sysutils.h"

static void acp_collect_statistics(uint8_t* seed)
{
	const char* drv = "C:";
	uint8_t buffer[1024] = { 0 };
	char tname[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0 };
	qsc_sysutils_drive_space_state dstate;
	qsc_sysutils_memory_statistics_state mstate;
	uint64_t ts;
	size_t len;
	size_t oft;
	uint32_t id;

	/* add user statistics */
	ts = qsc_sysutils_system_timestamp();
	/* interspersed with time-stamps, as return from system calls has some entropy variability */
	qsc_memutils_copy(buffer, &ts, sizeof(uint64_t));
	oft = sizeof(uint64_t);
	len = qsc_sysutils_computer_name(tname);
	qsc_memutils_copy(buffer + oft, tname, len);
	oft += len;
	id = qsc_sysutils_process_id();
	qsc_memutils_copy(buffer + oft, &id, sizeof(uint32_t));
	oft += sizeof(uint32_t);
	len = qsc_sysutils_user_name(tname);
	qsc_memutils_copy(buffer + oft, tname, len);
	oft += len;
	ts = qsc_sysutils_system_uptime();
	qsc_memutils_copy(buffer + oft, &ts, sizeof(uint64_t));
	oft += sizeof(uint64_t);

	/* add drive statistics */
	ts = qsc_sysutils_system_timestamp();
	qsc_memutils_copy(buffer + oft, &ts, sizeof(uint64_t));
	oft += sizeof(uint64_t);
	qsc_sysutils_drive_space(drv, &dstate);
	qsc_memutils_copy(buffer + oft, &dstate, sizeof(dstate));
	oft += sizeof(dstate);

	/* add memory statistics */
	ts = qsc_sysutils_system_timestamp();
	qsc_memutils_copy(buffer + oft, &ts, sizeof(uint64_t));
	oft += sizeof(uint64_t);
	qsc_sysutils_memory_statistics(&mstate);
	qsc_memutils_copy(buffer + oft, &mstate, sizeof(mstate));
	len = oft + sizeof(mstate);

	/* compress the statistics */
	qsc_sha3_compute512(seed, buffer, len);
}

bool qsc_acp_generate(uint8_t* output, size_t length)
{
	assert(output != 0);
	assert(length <= QSC_ACP_SEED_MAX);

	uint8_t cust[64] = { 0 };
	uint8_t key[64] = { 0 };
	uint8_t stat[64] = { 0 };
	bool res;

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
	}

	return res;
}
