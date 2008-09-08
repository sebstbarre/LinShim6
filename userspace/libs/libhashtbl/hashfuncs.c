/*
 * Copyright © 2006, DoCoMo Communications Laboratories USA, Inc.,
 *   the DoCoMo SEND Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of DoCoMo Communications Laboratories USA, Inc., its
 *    parents, affiliates, subsidiaries, theDoCoMo SEND Project nor the names
 *    of the Project's contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL DOCOMO COMMUNICATIONS LABORATORIES USA,
 *  INC., ITS PARENTS, AFFILIATES, SUBSIDIARIES, THE PROJECT OR THE PROJECT'S
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

#include "config.h"

#ifndef	s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

uint32_t
hash_string(const char *p, int sz)
{
	uint32_t h;
	int a = 31415, b = 27183;

	for (h = 0; *p != 0; p++, a = a * b % (sz - 1)) {
		h = (a * h + *p) % sz;
	}

	return (h);
}

uint32_t
hash_l2addr(const uint8_t *l2a, int l2len, int sz)
{
	uint32_t h;
	const uint8_t *p;
	uint8_t *hp;
	int i;

	h = 0;
	hp = (uint8_t *)&h;
	for (i = 0; i < l2len; i++) {
		p = l2a + i;
		hp[i % sizeof(h)] += *p;
	}

	return (h % sz);
}

uint32_t
hash_in6_addr(void *v, int sz)
{
	struct in6_addr *a = v;

        uint32_t h =
                a->s6_addr32[0] ^ a->s6_addr32[1] ^
                a->s6_addr32[2] ^ a->s6_addr32[3];

        return (h % sz);
}

uint32_t
hash_in_addr(void *v, int sz)
{
	struct in_addr *a = v;

        return (a->s_addr % sz);
}
