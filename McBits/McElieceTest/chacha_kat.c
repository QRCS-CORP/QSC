#include "chacha_kat.h"
#include "testutils.h"
#include "..\McEliece\chacha20.h"
#include "..\McEliece\sysrand.h"
#include "..\McEliece\util.h"
#include <stdio.h>
#include <string.h>

#if defined(__AVX512__)
#	define CHACHA_SIMD_TSIZE ((CHACHA_AVX512BLOCK_SIZE * 2) + 32)
#elif defined(__AVX2__)
#	define CHACHA_SIMD_TSIZE ((CHACHA_AVX2BLOCK_SIZE * 2) + 32)
#elif defined(__AVX__)
#	define CHACHA_SIMD_TSIZE ((CHACHA_AVXBLOCK_SIZE * 2) + 32)
#else
#	define CHACHA_SIMD_TSIZE ((CHACHA_BLOCK_SIZE * 2) + 32)
#endif

bool chacha128_kat_test()
{
	uint8_t exp[2][64];
	uint8_t msg[64];
	uint8_t out[64];
	uint8_t key[2][16];
	uint8_t nonce[8];
	bool status;

	status = true;
	clear8(msg, 64);
	clear8(nonce, 8);
	clear8(out, 64);

	hex_to_bin("FBB87FBB8395E05DAA3B1D683C422046F913985C2AD9B23CFC06C1D8D04FF213D44A7A7CDB84929F915420A8A3DC58BF0F7ECB4B1F167BB1A5E6153FDAF4493D", exp[0], 64);
	hex_to_bin("A276339F99316A913885A0A4BE870F0691E72B00F1B3F2239F714FE81E88E00CBBE52B4EBBE1EA15894E29658C4CB145E6F89EE4ABB045A78514482CE75AFB7C", exp[1], 64);

	hex_to_bin("80000000000000000000000000000000", key[0], 16);
	hex_to_bin("00400000000000000000000000000000", key[1], 16);

	chacha_state ctx;

	chacha_initialize(&ctx, key[0], 16, nonce);
	chacha_transform(&ctx, out, msg, 64);

	if (are_equal8(out, exp[0], 64) == false)
	{
		status = false;
	}

	clear8(out, 64);

	chacha_initialize(&ctx, key[1], 16, nonce);
	chacha_transform(&ctx, out, msg, 64);

	if (are_equal8(out, exp[1], 64) == false)
	{
		status = false;
	}

	return status;
}

bool chacha256_kat_test()
{
	uint8_t exp[2][64];
	uint8_t msg[64];
	uint8_t out[64];
	uint8_t key[2][32];
	uint8_t nonce[2][8];
	bool status;

	status = true;
	clear8(msg, 64);
	clear8(out, 64);

	hex_to_bin("57459975BC46799394788DE80B928387862985A269B9E8E77801DE9D874B3F51AC4610B9F9BEE8CF8CACD8B5AD0BF17D3DDF23FD7424887EB3F81405BD498CC3", exp[0], 64);
	hex_to_bin("92A2508E2C4084567195F2A1005E552B4874EC0504A9CD5E4DAF739AB553D2E783D79C5BA11E0653BEBB5C116651302E8D381CB728CA627B0B246E83942A2B99", exp[1], 64);

	hex_to_bin("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D", key[0], 32);
	hex_to_bin("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", key[1], 32);

	hex_to_bin("0D74DB42A91077DE", nonce[0], 8);
	hex_to_bin("167DE44BB21980E7", nonce[1], 8);

	chacha_state ctx;

	chacha_initialize(&ctx, key[0], 32, nonce[0]);
	chacha_transform(&ctx, out, msg, 64);

	if (are_equal8(out, exp[0], 64) == false)
	{
		status = false;
	}

	clear8(out, 64);

	chacha_initialize(&ctx, key[1], 32, nonce[1]);
	chacha_transform(&ctx, out, msg, 64);

	if (are_equal8(out, exp[1], 64) == false)
	{
		status = false;
	}

	return status;
}

bool chacha_avx_equivalence()
{
	chacha_state ctx;
	uint8_t msg[CHACHA_SIMD_TSIZE];
	uint8_t dec[CHACHA_SIMD_TSIZE];
	uint8_t enc[CHACHA_SIMD_TSIZE];
	uint8_t key[32];
	uint8_t nonce[8];
	size_t i;
	size_t pos;
	bool status;

	clear8(dec, CHACHA_SIMD_TSIZE);
	clear8(enc, CHACHA_SIMD_TSIZE);
	clear8(msg, CHACHA_SIMD_TSIZE);
	status = true;

	/*lint -e534 */
	sysrand_getbytes(msg, CHACHA_SIMD_TSIZE);

	hex_to_bin("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", key, 32);
	hex_to_bin("0D74DB42A91077DE", nonce, 8);

	/* encrypt with natural block size for sequential mode */
	clear32(ctx.state, CHACHA_STATE_SIZE);
	chacha_initialize(&ctx, key, 32, nonce);
	pos = 0;

	for (i = 0; i < (CHACHA_SIMD_TSIZE / CHACHA_BLOCK_SIZE); ++i)
	{
		chacha_transform(&ctx, enc + pos, msg + pos, CHACHA_BLOCK_SIZE);
		pos += CHACHA_BLOCK_SIZE;
	}

	if (pos != CHACHA_SIMD_TSIZE)
	{
		chacha_transform(&ctx, enc + pos, msg + pos, CHACHA_SIMD_TSIZE % CHACHA_BLOCK_SIZE);
	}

	/* decrypt with a large block to call avx */
	clear32(ctx.state, CHACHA_STATE_SIZE);
	chacha_initialize(&ctx, key, 32, nonce);
	chacha_transform(&ctx, dec, enc, CHACHA_SIMD_TSIZE);

	if (are_equal8(msg, dec, CHACHA_SIMD_TSIZE) == false)
	{
		status = false;
	}

	/*** reverse test ***/

	clear8(dec, CHACHA_SIMD_TSIZE);
	clear8(enc, CHACHA_SIMD_TSIZE);
	clear32(ctx.state, CHACHA_STATE_SIZE);

	/* encrypt with avx */
	chacha_initialize(&ctx, key, 32, nonce);
	chacha_transform(&ctx, enc, msg, CHACHA_SIMD_TSIZE);

	/* decrypt with sequential mode */
	clear32(ctx.state, CHACHA_STATE_SIZE);
	chacha_initialize(&ctx, key, 32, nonce);
	pos = 0;

	for (i = 0; i < (CHACHA_SIMD_TSIZE / CHACHA_BLOCK_SIZE); ++i)
	{
		chacha_transform(&ctx, dec + pos, enc + pos, CHACHA_BLOCK_SIZE);
		pos += CHACHA_BLOCK_SIZE;
	}

	if (pos != CHACHA_SIMD_TSIZE)
	{
		chacha_transform(&ctx, dec + pos, enc + pos, CHACHA_SIMD_TSIZE % CHACHA_BLOCK_SIZE);
	}

	if (are_equal8(msg, dec, CHACHA_SIMD_TSIZE) == false)
	{
		status = false;
	}

	return status;
}