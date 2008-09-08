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
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include "config.h"
#include <applog.h>

#include "cga.h"
#include "cga_local.h"

#define	CGA_MAXMOD_BUFLEN	2048

struct {
	pthread_mutex_t	lock;
	uint32_t	batchsize;
	int		done;
	struct timeval	end;
	uint8_t		*buf;
	uint8_t		*mod;
	int		blen;
	int		sec;
} state[1];

static int active, cancelled;

#ifdef	CGA_SPIN_WAIT

static char spin[] = { '-', '\\', '|', '/' };
static int spinpos;

static inline void
SPIN(void)
{
	printf("\r%c", spin[spinpos++ % (sizeof (spin) / sizeof (*spin))]);
	fflush(stdout);
}
#endif

static int
add_mod(uint8_t *m, uint32_t s)
{
	BIGNUM bn[1], *bnp;
	int blen;

	BN_init(bn);
	if ((bnp = BN_bin2bn(m, CGA_MODLEN, bn)) == NULL) {
		ssl_err(__FUNCTION__, "BN_bin2bin failed");
		return (-1);
	}
	BN_add_word(bnp, s);
	blen = BN_num_bytes(bnp);
	BN_bn2bin(bnp, m + (CGA_MODLEN - blen));

	return (0);
}

static void *
cga_findmod_thr(void *a)
{
	uint32_t i, bs;
	int blen, sec;
	uint8_t b[CGA_MAXMOD_BUFLEN], *m;
	uint8_t hash[SHA_DIGEST_LENGTH];

	DBG(&dbg_mt, "0x%x starting", pthread_self());

again:
	pthread_mutex_lock(&state->lock);

	if (state->done) {
		DBG(&dbg_mt, "%d someone else finished", pthread_self());
		pthread_mutex_unlock(&state->lock);
		goto done;
	}

	memcpy(b, state->buf, state->blen);
	m = b + (state->mod - state->buf);

	blen = state->blen;
	bs = state->batchsize;
	sec = state->sec;

	/* Set mod for the next thread */
	if (add_mod(state->mod, state->batchsize) < 0) {
		pthread_mutex_unlock(&state->lock);
		goto done;
	}

	pthread_mutex_unlock(&state->lock);

	/*
	 * This loop is where the heavy lifting takes place. All functions
	 * except for digest generation are inlined. Profiling shows
	 * that about 95% of time is spent in the digest code.
	 */
	for (i = 0; i < bs; i++) {
		SHA1(b, blen, hash);
		if (cga_cmp(hash, sec * CGA_SECMULT) == 1) {
			/* found it */
			pthread_mutex_lock(&state->lock);
			if (state->done) {
				DBG(&dbg_mt, "0x%x: someone else also "
				     "found it", pthread_self());
				pthread_mutex_unlock(&state->lock);
				goto done;
			}

			memcpy(state->mod, m, CGA_MODLEN);
			state->done = 1;
			gettimeofday(&state->end, NULL);

			DBG(&dbg_mt, "0x%x found modifier", pthread_self());
			DBG_HEXDUMP(&dbg_mt, "hash2: ",
			    hash, CGA_MODLEN * 7 / 8);

			pthread_mutex_unlock(&state->lock);

			goto done;
		}
		incr_mod(m);

#ifdef	CGA_SPIN_WAIT
		if ((i % 500000) == 0) {
			SPIN();
		}
#endif
	}
	goto again;

done:
	DBG(&dbg_mt, "%d exiting", pthread_self());

#ifndef	NOTHREADS
	pthread_exit(NULL);
#endif
	return (NULL);
}

static void
opssec(struct timeval *start, uint8_t *startmod)
{
	BIGNUM sm[1], em[1], ops[1], t[1], dv[1];
	BN_CTX *bc;
	struct timeval tv[1];
	char *dec;

	BN_init(sm); BN_init(em); BN_init(ops); BN_init(t); BN_init(dv);
	BN_bin2bn(startmod, CGA_MODLEN, sm);
	BN_bin2bn(state->mod, CGA_MODLEN, em);
	BN_sub(ops, em, sm);
	dec = BN_bn2dec(ops);

	timersub(&state->end, start, tv);

	DBG(&dbg_stats, "took %6ld.%.6ld seconds (%s ops)",
	     tv->tv_sec, tv->tv_usec, dec);
	OPENSSL_free(dec);

	if ((bc = BN_CTX_new()) == NULL) {
		DBG(&dbg_mt, "BN_CTX_new() failed");
		return;
	}

	BN_add_word(t, tv->tv_sec);
	BN_mul_word(t, 1000000);
	BN_add_word(t, tv->tv_usec);

	BN_mul_word(ops, 1000000);
	BN_div(dv, NULL, ops, t, bc);
	dec = BN_bn2dec(dv);
	DBG(&dbg_stats, "%s ops per second", dec);

	OPENSSL_free(dec);
	BN_CTX_free(bc);
}

void
cga_findmod_cancel(void)
{
	if (!active) {
		return;
	}
	state->done = 1;
	cancelled = 1;
	DBG(&dbg_mt, "generation cancelled; waiting for all threads "
	     "to come home");
}

int
cga_findmod_mt(uint32_t bs, uint8_t *b, uint8_t *m, int blen, int sec,
    int thrcnt)
{
#ifndef	NOTHREADS
	int i;
#endif
	pthread_t *tids;
	uint8_t startmod[CGA_MODLEN];
	struct timeval start[1];

	if (blen > CGA_MAXMOD_BUFLEN) {
		DBG(&dbg_mt, "buffer too long (change CGA_MAXMOD_BUFLEN)");
		return (-1);
	}

	if ((tids = malloc(thrcnt * sizeof (*tids))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}

	memcpy(startmod, m, CGA_MODLEN);

	memset(state, 0, sizeof (*state));
	pthread_mutex_init(&state->lock, NULL);
	state->batchsize = bs;
	state->buf = b;
	state->mod = m;
	state->blen = blen;
	state->sec = sec;

	gettimeofday(start, NULL);

	active = 1;
#ifdef	NOTHREADS
	cga_findmod_thr(NULL);
#else
	for (i = 0; i < thrcnt; i++) {
		if (pthread_create(tids + i, NULL, cga_findmod_thr, NULL)
		    != 0) {
			applog(LOG_CRIT, "%s: pthread_create() failed",
			    __FUNCTION__);
		}
	}

	for (i = 0; i < thrcnt; i++) {
		pthread_join(tids[i], NULL);
	}
#endif	/* NOTHREADS */
	free(tids);
	active = 0;
	if (cancelled) {
		DBG(&dbg_mt, "cancelled");
		gettimeofday(&state->end, NULL);
	}

	opssec(start, startmod);

	if (cancelled) {
		cancelled = 0;
		return (-1);
	}

	return (0);
}
