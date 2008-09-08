/*
 * This file comes from the DoCoMo SEND project
 *
 * Adapted by Sébastien Barré - sebastien.barre@uclouvain.be
 *
 *
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
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include <config.h>
#include <utils/debug.h>

#ifdef	APPLOG_DEBUG
static struct dlog_desc dbg = {
	.desc =	"crypto",
	.ctx =	PACKAGE
};
struct dlog_desc dbg_cryptox = {
	.desc =	"crypto_extra",
	.ctx =	PACKAGE
};
#endif

static pthread_mutex_t *lock_cs;
static int numlocks;

static void
ssl_locking_callback(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(lock_cs + n);
	} else {
		pthread_mutex_unlock(lock_cs + n);
	}
}

static int
ssl_thread_init(void)
{
	int i;

	numlocks = CRYPTO_num_locks();
	if ((lock_cs = malloc(numlocks * sizeof (*lock_cs))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}

	for (i = 0; i < numlocks; i++) {
		pthread_mutex_init(lock_cs + i, NULL);
	}

	CRYPTO_set_locking_callback(ssl_locking_callback);

	return (0);
}

#if 0
/* not used for now */
static void
ssl_thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < numlocks; i++) {
		pthread_mutex_destroy(lock_cs + i);
	}

	free(lock_cs);
}
#endif

/**
 * Converts the most recent SSL error message(s) into normal log
 * format.
 *
 * func: the name of the calling function
 * context: a message providing context for the error
 */
void
openssl_err(const char *func, const char *context) {
#ifdef	APPLOG_DEBUG
	char buf[512];
	unsigned int err;

	err = ERR_get_error();
	ERR_error_string_n(err, buf, sizeof (buf));
	DBGF(&dbg, (char *)func, "%s: %s", context, buf);
	     
#endif
}


int
openssl_init(void)
{
#ifdef	APPLOG_DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};
	struct dlog_desc *dbgsx[] = {
		&dbg_cryptox,
		NULL
	};

	if (applog_register(dbgs) < 0 ||
	    applog_register(dbgsx) < 0) {
		return (-1);
	}
	
#endif

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	if (ssl_thread_init() < 0) {
		return (-1);
	}
	return (0);
}

void
openssl_fini(void)
{
	DBG(&dbg, "");
	free(lock_cs);
}
