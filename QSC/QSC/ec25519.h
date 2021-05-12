/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
* Reference implementations:
* LibSodium by Frank Denis
* https://github.com/jedisct1/libsodium
*
* curve25519-donna by Adam Langley
* https://github.com/agl/curve25519-donna
*
* NaCI by Daniel J. Bernstein, Tanja Lange, Peter Schwabe
* https://nacl.cr.yp.to
*
* Rewritten for Misra compliance and optimizations by John G. Underhill
* September 21, 2020
*/

#ifndef QSC_EC25519_H
#define QSC_EC25519_H

#include "common.h"

#define EC25519_SEED_SIZE 32
#define EC25519_SIGNATURE_SIZE 64
#define EC25519_PUBLICKEY_SIZE 32
#define EC25519_PRIVATEKEY_SIZE 64
#define EC25519_CURVE_SIZE 32U

/* fe */

#if defined(QSC_SYSTEM_NATIVE_UINT128)
typedef uint64_t fe25519[5];
#else
typedef int32_t fe25519[10];
#endif

void fe25519_0(fe25519 h);
void fe25519_1(fe25519 h);
void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g);
void fe25519_cswap(fe25519 f, fe25519 g, uint32_t b);
void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g);
void fe25519_neg(fe25519 h, const fe25519 f);
void fe25519_cmov(fe25519 f, const fe25519 g, uint32_t b);
void fe25519_copy(fe25519 h, const fe25519 f);
int32_t fe25519_isnegative(const fe25519 f);
int32_t fe25519_iszero(const fe25519 f);
void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g);
void fe25519_mul32(fe25519 h, const fe25519 f, uint32_t n);
void fe25519_sq(fe25519 h, const fe25519 f);
void fe25519_sq2(fe25519 h, const fe25519 f);
void fe25519_reduce(fe25519 h, const fe25519 f);
void fe25519_tobytes(uint8_t* s, const fe25519 h);
void fe25519_invert(fe25519 out, const fe25519 z);
void fe25519_frombytes(fe25519 h, const uint8_t* s);

/* ge */

typedef struct
{
	fe25519 x;
	fe25519 y;
	fe25519 z;
} ge25519_p2;

typedef struct
{
	fe25519 x;
	fe25519 y;
	fe25519 z;
	fe25519 t;
} ge25519_p3;

typedef struct
{
	fe25519 x;
	fe25519 y;
	fe25519 z;
	fe25519 t;
} ge25519_p1p1;

typedef struct
{
	fe25519 yplusx;
	fe25519 yminusx;
	fe25519 xy2d;
} ge25519_precomp;

typedef struct
{
	fe25519 yplusx;
	fe25519 yminusx;
	fe25519 z;
	fe25519 t2d;
} ge25519_cached;

void ge25519_p1p1_to_p3(ge25519_p3* r, const ge25519_p1p1* p);
void ge25519_p1p1_to_p2(ge25519_p2* r, const ge25519_p1p1* p);
void ge25519_scalarmult_base(ge25519_p3* h, const uint8_t* a);
void ge25519_p3_tobytes(uint8_t* s, const ge25519_p3* h);
int32_t ge25519_is_canonical(const uint8_t* s);
int32_t ge25519_has_small_order(const uint8_t s[32]);
int32_t ge25519_frombytes_negate_vartime(ge25519_p3* h, const uint8_t* s);
void ge25519_p3_to_cached(ge25519_cached* r, const ge25519_p3* p);
void ge25519_add_cached(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_cached* q);
void ge25519_double_scalarmult_vartime(ge25519_p2* r, const uint8_t* a, const ge25519_p3* A, const uint8_t* b);
void ge25519_sub_cached(ge25519_p1p1* r, const ge25519_p3* p, const ge25519_cached* q);
void ge25519_tobytes(uint8_t* s, const ge25519_p2* h);

/* sc */

void sc25519_clamp(uint8_t* k);
int32_t sc25519_is_canonical(const uint8_t s[32]);
void sc25519_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]);
void sc25519_reduce(uint8_t s[64]);
int32_t qsc_sc25519_verify(const uint8_t* x, const uint8_t* y, const size_t n);
int ed25519_small_order(const uint8_t s[32]);

#endif

