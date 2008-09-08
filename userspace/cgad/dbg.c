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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <applog.h>

#include "dbg.h"

const char *cgad_dbgs;

#ifdef DEBUGGING

int
cgad_applog_register(struct dlog_desc **descs)
{
	struct dlog_desc *d;
	int i, len;
	char *str;

	if (applog_register(descs) < 0) {
		return (-1);
	}

	if (cgad_dbgs == NULL && cgad_dbg < CGAD_DBG_LOCAL) {
		return (0);
	}

	for (i = 0;; i++) {
		d = descs[i];
		if (!d) {
			return (0);
		}
		if (cgad_dbg >= CGAD_DBG_LOCAL) {
			applog_enable_level(d->ctx, d->desc);
			// DBG(&dbg_cgad, "enabling %s", d->desc);
			continue;
		}
		if (cgad_dbgs == NULL) {
			continue;
		}

		len = strlen(d->ctx) + 1 + strlen(d->desc) + 1;
		if ((str = malloc(len)) == NULL) {
			APPLOG_NOMEM();
			return (-1);
		}
		snprintf(str, len, "%s:%s", d->ctx, d->desc);
		if (strstr(cgad_dbgs, str) != NULL) {
			applog_enable_level(d->ctx, d->desc);
			// DBG(&dbg_cgad, "enabling %s", str);
		}
		free(str);
	}

	return (0);
}

#endif
