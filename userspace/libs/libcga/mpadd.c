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
#include <string.h>

#include "config.h"
#include "cga.h"
#include "cga_local.h"

static void
hexdump(unsigned char *b, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		int v = b[i] & 0xff;
		printf("%.2x ", v);
		if (((i + 1) % CGA_MODLEN) == 0) {
			printf("\n");
		}
	}
	printf("\n");
}

int
main(int argc, char **argv)
{
	uint8_t mod[CGA_MODLEN], cmp[CGA_MODLEN];
	int i;

	memset(mod, 0, CGA_MODLEN);
	memset(cmp, 0, CGA_MODLEN);
	cmp[CGA_MODLEN - 1] = 0x00;
	cmp[CGA_MODLEN - 2] = 0x00;
	cmp[CGA_MODLEN - 3] = 0x00;
	cmp[CGA_MODLEN - 4] = 0x01;

	for (i = 0; i < (1 << 24); i++) {
		incr_mod(mod);
	}

	hexdump(mod, CGA_MODLEN);
	hexdump(cmp, CGA_MODLEN);
	if (memcmp(mod, cmp, CGA_MODLEN) != 0) {
		printf("failed\n");
		return (1);
	}

	memset(mod, 0xff, CGA_MODLEN);
	mod[CGA_MODLEN - 1] = 0xfe;
	memset(cmp, 0, CGA_MODLEN);
	cmp[CGA_MODLEN - 1] = 0x01;

	incr_mod(mod);
	incr_mod(mod);
	incr_mod(mod);

	hexdump(mod, CGA_MODLEN);
	hexdump(cmp, CGA_MODLEN);

	if (memcmp(mod, cmp, CGA_MODLEN) != 0) {
		printf("failed\n");
		return (1);
	}

	return (0);
}
