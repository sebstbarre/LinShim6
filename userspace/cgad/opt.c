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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/time.h>
#include <openssl/x509.h>

#include <applog.h>
#include <sbuff.h>

#include "cgad_local.h"
#include "cgad_proto.h"
#include "os_defines.h"
#include "dbg.h"

#ifdef	APPLOG_DEBUG
static struct dlog_desc dbg = {
	.desc = "opt",
	.ctx = CGAD_NAME
};
#endif	/* APPLOG_DEBUG */

int
cgad_parse_opts(struct ndopts *ndopts, uint8_t *opts, int len)
{
	uint8_t *opt = opts;
	int olen;

	memset(ndopts, 0, sizeof (*ndopts));
	while (len > 0) {
		if (len < 2) {
			return (-1);
		}
		olen = opt[1] << 3;
		if (olen > len || olen == 0 || *opt > ND_OPT_MAX) {
			DBG(&dbg_cgad, "invalid option; olen %d len %d type %d",
			    olen, len, *opt);
			return (-1);
		}
		if (ndopts->opt[*opt]) {
			/*
			 * Callers can process multiple opts re-calling
			 * parse_opts with a new start, so leave the
			 * first instance in place.
			 */
			goto next;
		}
		ndopts->opt[*opt] = opt;
next:
		len -= olen;
		opt += olen;
	}

	return (0);
}

uint8_t *
cgad_get_opt(uint8_t *opts, int olen, int type)
{
	struct ndopts ndopts[1];

	memset(ndopts, 0, sizeof (*ndopts));
	if (cgad_parse_opts(ndopts, opts, olen) < 0) {
		DBG(&dbg_cgad, "invalid option format");
		return (NULL);
	}

	return (ndopts->opt[type]);
}

static void
ndisc_fill_option(uint8_t *opt, int type, void *data, int data_len, int space)
{
	opt[0] = type;
	opt[1] = space >> 3;
	if (data)
		memcpy(opt+2, data, data_len);
	data_len += 2;
	opt += data_len;
	if ((space -= data_len) > 0) {
		memset(opt, 0, space);
	}
}

int
cgad_add_cert_opt(struct sbuff *b, void *xp)
{
	struct cgad_opt_cert *co;
	int clen, olen;
	X509 *x = xp;
	uint8_t *p;

	if ((clen = i2d_X509(x, NULL)) <= 0) {
		DBG(&dbg_cgad, "X509_i2d() returned %d", clen);
		return (-1);
	}
	olen = clen + sizeof (*co);
	olen = NDISC_OPT_SPACE(olen - 2);
	DBG(&dbg, "DER cert len=%d, opt len=%d", clen, olen);

	p = sbuff_data(b);
	if (sbuff_advance(b, olen) < 0) {
		DBG(&dbg_cgad, "not enough space");
		return (-1);
	}

	memset(p + olen - 8, 0, 8);
	co = (struct cgad_opt_cert *)p;
	co->type = ND_OPT_CERTIFICATE;
	co->cert_type = 1;
	co->len = olen >> 3;
	co->reserved = 0;

	p += sizeof (*co);
	i2d_X509(x, &p);

	DBG(&dbg, "added certificate option");
	return (0);
}

int
cgad_add_cga_opt(struct sbuff *b, uint8_t *cga_params, int cgalen)
{
	uint8_t *p;
	int olen = NDISC_OPT_SPACE(2 + cgalen); /* +2 for pad len + resrvd */

	p = sbuff_data(b);
	if (sbuff_advance(b, olen) < 0) {
		DBG(&dbg_cgad, "not enough space");
		return (-1);
	}
	ndisc_fill_option(p, ND_OPT_CGA, NULL, cgalen + 2, olen);
	p[2] = olen - /* calculate pad length */
		(2 + /* subtract opt type and length */
		 2 + /* subtract pad len and reserved */
		 cgalen);
	p[3] = 0; /* reserved */
	memcpy(p + 4, cga_params, cgalen);

	DBG(&dbg, "added CGA params option");
	return (0);
}

int
cgad_add_nonce_opt(struct sbuff *b, uint8_t *nonce, int nlen)
{
	uint8_t *p;
	int olen = NDISC_OPT_SPACE(nlen);

	p = sbuff_data(b);
	if (sbuff_advance(b, olen) < 0) {
		DBG(&dbg_cgad, "not enough space");
		return (-1);
	}
	ndisc_fill_option(p, ND_OPT_NONCE, NULL, nlen, olen);
	memcpy(p + 2, nonce, nlen);

	DBG(&dbg, "added nonce option");
	return (0);
}

int
cgad_add_sig_opt(struct sbuff *b, uint8_t *kh, uint8_t *sig, int slen,
    uint8_t type)
{
	uint8_t *p;
	int olen;
	struct cgad_opt_sig *so;

	so = sbuff_data(b);
	p = (uint8_t *)so;
	olen = NDISC_OPT_SPACE(sizeof (*so) + slen);
	if (sbuff_advance(b, olen) < 0) {
		DBG(&dbg_cgad, "not enough space");
		return (-1);
	}

	ndisc_fill_option(p, type, NULL, sizeof (*so) + slen, olen);
	p[2] = p[3] = 0; /* reserved */
	memcpy(so->keyhash, kh, sizeof (so->keyhash));
	memcpy(so->sig, sig, slen);

	DBG(&dbg, "added signature option");
	return (0);
}

int
cgad_add_timestamp_opt(struct sbuff *b)
{
	struct timeval now[1];
	uint64_t ts;
	uint16_t fr;
	struct cgad_opt_timestamp *to;
	
	to = sbuff_data(b);
	if (sbuff_advance(b, sizeof (*to)) < 0) {
		DBG(&dbg_cgad, "not enough space");
		return (-1);
	}

	gettimeofday(now, NULL);

	/* first 48 bits are integer number of seconds since epoch time */
	ts = now->tv_sec;
	ts <<= 16;
	/* last 16 bits are fractions of a second */
	fr = now->tv_usec >> 4;
	ts += fr;

	memset(to, 0, sizeof (*to));
	to->type = ND_OPT_TIMESTAMP;
	to->len = 2;
	to->ts = hton64(ts);

	DBG(&dbg, "added timestamp option");
	return (0);
}

int
cgad_init_opt(void)
{
#ifdef	APPLOG_DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};

	if (cgad_applog_register(dbgs) < 0) {
		return (-1);
	}
#endif
	return (0);
}
