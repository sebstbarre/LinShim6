/*
 * Portions of this source adapted from radvd:
 *
 *   Authors:
 *    Pedro Roque		<roque@di.fc.ul.pt>
 *    Lars Fenneberg		<lf@elemental.net>	 
 *
 *   This software is Copyright 1996-2000 by the above mentioned author(s), 
 *   All Rights Reserved.
 *
 *   The license which is distributed with this software in the file COPYRIGHT
 *   applies to this software. If your distribution is missing this file, you
 *   may request it from <lutchann@litech.org>.
 *
 */

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
#include <stdarg.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#ifdef	LOG_BACKTRACE
#include <execinfo.h>
#endif

#include "applog.h"

#define	MAXL2ADDRLEN	16
#define	LOG_TIME_FORMAT "%b %d %H:%M:%S"

uint32_t debug_mask;

#ifdef	LOG_TIMESTAMP
int _g_applog_timestamp_nest_level = 1;
#endif

static int log_method = L_STDERR;
static char *log_ident = "";

static const char *log_methods[] = { "none", "stderr", "syslog", NULL };

static void
vlog_func(int prio, const char *f, char *ctx, char *format, va_list ap)
{
	char tstamp[64], buff[1024];
	struct tm *tm;
	time_t current;
	int nr, nw, r;

	nr = sizeof (buff);

	switch (log_method) {
	case L_NONE:
		break;
	case L_SYSLOG:
		nw = 0;
		if (ctx && strcmp(ctx, log_ident)) {
			r = snprintf(buff, nr, "%s: ", ctx);
			nw += r;
			nr -= r;
		}
		if (f) {
			r = snprintf(buff + nw, nr, "%s: ", f);
			nw += r;
			nr -= r;
		}
		vsnprintf(buff + nw, nr, format, ap);
		syslog(prio, "%s", buff);
		break;
	case L_STDERR:
		current = time(NULL);
		tm = localtime(&current);
		(void) strftime(tstamp, sizeof(tstamp), LOG_TIME_FORMAT, tm);

		fprintf(stderr, "[%s] %s: ", tstamp, log_ident);
		if (ctx && strcmp(ctx, log_ident)) {
			fprintf(stderr, "%s: ", ctx);
		}
		if (f) {
			fprintf(stderr, "%s: ", f);
		}
		vfprintf(stderr, format, ap);
		fputs("\n", stderr);
		fflush(stderr);
		break;
	default:
		break;
	}
}


static void
vlog(int prio, char *format, va_list ap)
{
	vlog_func(prio, NULL, NULL, format, ap);
}

void
applog(int prio, char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vlog(prio, format, ap);
	va_end(ap);
}

void
dlog(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vlog(LOG_DEBUG, format, ap);
	va_end(ap);
}

static uint32_t liblog_mask[LIBLOG_MAX_MASK];
static struct dlog_desc liblog_descs[LIBLOG_MAX_MASK * 32];
static int nextbit;
uint32_t log_all_on[LIBLOG_MAX_MASK];

static inline int
log_is_bit_set(uint32_t *bit)
{
	int i;
	for (i = 0; i < LIBLOG_MAX_MASK; i++) {
		if (liblog_mask[i] & bit[i]) {
			return (1);
		}
	}

	return (0);
}

void
applog_dbg(struct dlog_desc *d, const char *func, char *format, ...)
{
	int i;
	va_list ap;
	
	for (i = 0; i < LIBLOG_MAX_MASK; i++) {
		if (log_is_bit_set(d->bit)) {
			va_start(ap, format);
			vlog_func(LOG_DEBUG, func, d->ctx, format, ap);
			va_end(ap);
			return;
		}
	}
}

int
applog_register(struct dlog_desc **descs)
{
	struct dlog_desc *d;
	int byte, bit, i;

	for (i = 0;; i++) {
		d = descs[i];
		if (!d) {
			return (0);
		}

		byte = nextbit / 32;
		bit = nextbit % 32;
		if (byte >= LIBLOG_MAX_MASK) {
			fprintf(stderr, "not enough space in bitmask\n");
			return (-1);
		}

		memset(d->bit, 0, LIBLOG_MAX_MASK);
		d->bit[byte] |= (1 << bit);

		liblog_descs[nextbit] = *d;
		nextbit++;
	}

	return (0);
}

void
applog_addlevel(uint32_t *bits)
{
	int i;
	for (i = 0; i < LIBLOG_MAX_MASK; i++) {
		liblog_mask[i] |= bits[i];
	}
}

void
applog_clearlevel(uint32_t *bits)
{
	int i;

	for (i = 0; i < LIBLOG_MAX_MASK; i++) {
		liblog_mask[i] &= ~bits[i];
	}
}

int
applog_enable_level(const char *ctx, const char *desc)
{
	int i;
	for (i = 0; i < LIBLOG_MAX_MASK * 32; i++) {
		if (liblog_descs[i].ctx == NULL) {
			continue;
		}
		if (strcmp(liblog_descs[i].ctx, ctx) == 0 &&
		    strcmp(liblog_descs[i].desc, desc) == 0) {
			applog_addlevel(liblog_descs[i].bit);
			return (0);
		}
	}

	return (-1);
}

int
applog_disable_level(const char *ctx, const char *desc)
{
	int i;

	for (i = 0; i < LIBLOG_MAX_MASK * 32; i++) {
		if (strcmp(liblog_descs[i].ctx, ctx) == 0 &&
		    strcmp(liblog_descs[i].desc, desc) == 0) {
			applog_clearlevel(liblog_descs[i].bit);
			return (0);
		}
	}

	return (-1);
}

void
applog_printlevels(void)
{
	int i, j;

	for (i = 0; i < LIBLOG_MAX_MASK * 32; i++) {
		if (liblog_descs[i].ctx == NULL) {
			return;
		}

		printf("%20s: %20s:\t", liblog_descs[i].ctx,
		       liblog_descs[i].desc);
		for (j = LIBLOG_MAX_MASK - 1; j >= 0; j--) {
			printf("%.8x", liblog_descs[i].bit[j]);
		}
		printf("\n");
	}
}

void
applog_print_curlevels(void)
{
	int i, pr = 0;

	for (i = 0; i < LIBLOG_MAX_MASK * 32; i++) {
		if (log_is_bit_set(liblog_descs[i].bit)) {
			printf("%s:%s ", liblog_descs[i].ctx,
			       liblog_descs[i].desc);
			pr = 1;
		}
	}

	if (pr) printf("\n");
}

const char *
mac2str_r(uint8_t *a, int len, char *buf)
{
        int i;
	char *p;

	if (!a) {
		sprintf(buf, "<NULL>");
		return (buf);
	}
	p = buf;
	for (i = 0; i < len; i++) {
		if (i == 0) {
			sprintf(p, "%02x", a[i]);
			p += 2;
		} else {
                        sprintf(p, ":%02x", a[i]);
			p += 3;
                }
        }
	*p = 0;

	return (buf);
}

const char *
mac2str(uint8_t *a, int len)
{
	static char buf[MAXL2ADDRLEN * 3 + 1];

	return (mac2str_r(a, len, buf));
}

int
applog_open(int method, char *ident)
{
	int i;

	if (ident == NULL) {
		return (-1);
	}

	switch (method) {
	case L_NONE:
	case L_STDERR:
	case L_SYSLOG:
		break;
	default:
		return (-1);
	}

	for (i = 0; i < LIBLOG_MAX_MASK; i++) {
		log_all_on[i] = 0xffffffff;
	}

	log_method = method;
	log_ident = ident;

	return (0);
}

/*
 * 'as' is a string containing the L2 address.
 * 'a' is a buffer provided by the caller into which the L2 address
 * bytes will be placed.
 * len is IN/OUT: on in, contains the length of the buffer 'a'; on out,
 * contains the length of the parsed L2 address, in bytes.
 */
int
str2mac(const char *as, uint8_t *a, int *len)
{
	char *str = strdup(as);
	int i, j;
	char *p, *pp;

	if (str == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}

	/* count the number of ':'s in the L2 address */
	for (i = 0, p = str; (p = strchr(p, ':')) != NULL; i++, p++)
		;
	i++;
	if (i > *len) {
		free(str);
		return (-1);
	}

	p = str;
	for (j = 0; j < i; j++) {
		pp = p;
		p = strchr(p, ':');
		if (p) {
			*p++ = 0;
		}
		a[j] = strtol(pp, NULL, 16);
	}

	free(str);
	*len = i;
	return (0);
}

void
applog_hexdump(uint8_t *b, int len, const char *f, const char *msg)
{
	int i, rem, np;
	char *str, *p;

	rem = len * 3 + len / 8 * 3 + 2;
	if ((str = malloc(rem)) == NULL) {
		applog(LOG_CRIT, "%s: no memory (called from %s)",
		       __FUNCTION__, f);
		return;
	}
	p = str;
	*p++ = '\t';
	rem--;

	for (i = 0; i < len; i++) {
		int v = b[i] & 0xff;
		np = snprintf(p, rem, "%.2x ", v);
		rem -= np;
		p += np;

		if (((i + 1) % 16) == 0) {
			*p++ = '\n';
			*p++ = '\t';
			rem -= 2;
		} else if (((i + 1) % 8) == 0) {
			*p++ = ' ';
			rem--;
		}
	}
	*p = 0;

	dlog("%s: %s\n%s", f, msg, str);

	free(str);
}

void
applog_dhexdump(struct dlog_desc *d, const char *func, uint8_t *buf, int len,
    const char *msg)
{
	int i;

	for (i = 0; i < LIBLOG_MAX_MASK; i++) {
		if (log_is_bit_set(d->bit)) {
			applog_hexdump(buf, len, func, msg);
			return;
		}
	}
}

const char **
applog_get_methods(void)
{
	return (log_methods);
}

int
applog_str2method(const char *m)
{
	if (m == NULL) {
		return (L_STDERR);
	}

	if (strncasecmp(m, log_methods[L_NONE], strlen(log_methods[L_NONE]))
	    == 0) {
		return (L_NONE);
	}
	if (strncasecmp(m, log_methods[L_STDERR],
			strlen(log_methods[L_STDERR])) == 0) {
		return (L_STDERR);
	}
	if (strncasecmp(m, log_methods[L_SYSLOG],
			strlen(log_methods[L_SYSLOG])) == 0) {
		return (L_SYSLOG);
	}

	return (L_STDERR);
}

int
applog_set_method(int meth)
{
	switch (meth) {
	case L_NONE:
	case L_STDERR:
	case L_SYSLOG:
		log_method = meth;
		return (0);
	default:
		return (-1);
	}
}

#ifdef	LOG_BACKTRACE
void
applog_stacktrace(struct dlog_desc *d, char *msg)
{
	void *array[LIBLOG_MAX_STACK_DEPTH];
	size_t size, i;
	char **strings, tstamp[64];
	struct tm *tm;
	time_t current;

	for (i = 0; i < LIBLOG_MAX_MASK; i++) {
		if (log_is_bit_set(d->bit)) {
			goto ok;
		}
	}

	return;

ok:
	switch (log_method) {
	case L_SYSLOG:
		syslog(LOG_DEBUG, "%s: %s", d->ctx ? d->ctx : "",
		       msg ? msg : "");
		break;
	case L_STDERR:
		current = time(NULL);
		tm = localtime(&current);
		(void) strftime(tstamp, sizeof(tstamp), LOG_TIME_FORMAT, tm);

		fprintf(stderr, "[%s] %s: ", tstamp, log_ident);
		if (d->ctx && strcmp(d->ctx, log_ident)) {
			fprintf(stderr, "%s: ", d->ctx);
		}
		if (msg) fprintf(stderr, msg);
		fprintf(stderr, "\n");
		break;
	case L_NONE:
	default:
		return;
	}

	size = backtrace(array, LIBLOG_MAX_STACK_DEPTH);
	strings = backtrace_symbols(array, size);

	for (i = 0; i < size; i++) {
		switch (log_method) {
		case L_SYSLOG:
			syslog(LOG_DEBUG, "\t%s", strings[i]);
			break;
		case L_STDERR:
			fprintf(stderr, "\t%s\n", strings[i]);
			break;
		}
	}

	free(strings);
}
#endif
