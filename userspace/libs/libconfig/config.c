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
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

#include <config.h>
#include <hashtbl.h>

#include "libconfig.h"

static htbl_t *cfgtbl;
static pthread_mutex_t cfglock = PTHREAD_MUTEX_INITIALIZER;
static char *buf;

struct cfgent {
	const char *k, *v;
	struct htbl_item hti;
};

static uint32_t
hash_cfgent(void *k, int sz)
{
	struct cfgent *ce = k;

	return (hash_string(ce->k, sz));
}

static int
match_cfgent(void *a, void *b)
{
	struct cfgent *ce1 = a;
	struct cfgent *ce2 = b;

	return (strcmp(ce1->k, ce2->k));
}

const char *
config_get(const char *k, const char *dflt) {
	struct cfgent cek[1], *ce;
	const char *rv = dflt;

	cek->k = k;
	pthread_mutex_lock(&cfglock);

	if (cfgtbl && (ce = htbl_find(cfgtbl, cek)) != NULL) {
		rv = ce->v;
	}

	pthread_mutex_unlock(&cfglock);

	return (rv);
}

int
config_init(const char *file)
{
	char *bp, *k, *v, *p;
	size_t tr, nr, sz = LIBCONFIG_BUFSZ;
	FILE *fp = NULL;
	int rv = 0;
	struct cfgent *ce;

	pthread_mutex_lock(&cfglock);

	if (cfgtbl != NULL) {
		htbl_destroy(cfgtbl, NULL);
		assert(buf != NULL);
		free(buf);
	}
	buf = NULL;

	/* create config table */
	if ((cfgtbl = htbl_create(LIBCONFIG_HTBL_SZ, hash_cfgent,
	    match_cfgent)) == NULL) {
		return (-ENOMEM);
	}

	/* read in config file */
	if (file == NULL) {
		rv = -EINVAL;
		goto done;
	}

	if ((fp = fopen(file, "r")) == NULL) {
		rv = -ENOENT;
		goto done;
	}

	if ((buf = malloc(sz)) == NULL) {
		rv = -ENOMEM;
		goto done;
	}

	bp = buf;
	tr = 0;
	while ((nr = fread(bp, 1, sz, fp)) == sz) {
		sz *= 2;
		if ((buf = realloc(buf, sz)) == NULL) {
			rv = -ENOMEM;
			goto done;
		}
		bp += nr;
		tr += nr;
	}
	tr += nr;
	buf[tr] = 0;

#define	EATSPACE(c) while (isspace(*(c))) *c++ = 0
#define EATSPACEBACK(c) while (isspace(*(c))) *c-- = 0;
#define	CHECKNULL(c) if (*c == 0) goto done

	/* parse config */
	k = buf;
	for (;;) {
		EATSPACE(k);
		CHECKNULL(k);
		if (*k == '#') {
			/* comment; skip this line */
			k = strchr(k, '\n');
			if (k == NULL) {
				goto done;
			}
			continue;
		}

		/* sanity checks */
		v = strchr(k, '=');
		if (v == NULL) {
			goto done;
		}
		if ((p = strchr(k, '\n')) != NULL && p < v) {
			k = p++;
			continue;
		}

		p = v - 1;
		EATSPACEBACK(p);
		*v++ = 0;
		/* allow properties with no values */
		while (isspace(*v) && *v != '\n') {
			*v++ = 0;
		}

		if ((p = strchr(v, '\n')) != NULL) {
			*p++ = 0;
		}

		if ((ce = malloc(sizeof (*ce))) == NULL) {
			rv = -ENOMEM;
			goto done;
		}
		ce->k = k;
		ce->v = v;

		htbl_add(cfgtbl, ce, &ce->hti);

		if (p == NULL) {
			break;
		}
		k = p;
	}

done:
	if (fp != NULL) {
		fclose(fp);
	}

	pthread_mutex_unlock(&cfglock);

	return (rv);
}

void
config_fini(void)
{
	htbl_destroy(cfgtbl, free);
	free(buf);
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
