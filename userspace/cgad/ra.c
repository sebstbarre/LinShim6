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
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <applog.h>
#include <timer.h>
#include <cryptoshim6/cga.h>
#include <utils/util.h>

#include "cgad_local.h"
#include "cgad_proto.h"
#include "cgad_config.h"
#include "os_specific.h"
#include "dbg.h"

#ifdef	APPLOG_DEBUG
static struct dlog_desc dbg = {
	.desc = "ra",
	.ctx = CGAD_NAME
};
static char abuf[INET6_ADDRSTRLEN];
#endif

static timer_item_t gc_timer_item;

#ifdef	LOG_TIMESTAMP
static struct timeval deferred_ts[1];
#endif

static LIST_HEAD(pfxlist);
struct cgad_pfx {
	struct list_head list;
	struct in6_addr	pfx;
	int		ifidx;
	uint32_t	valid_time;
	uint32_t	pref_time;
	time_t		exp;
	uint8_t		plen;
	uint8_t		flags;
};

static void set_gc_timer(void);

static void
del_pfx(struct cgad_pfx *p)
{
	DBG(&dbg, "%s/%d",
	    inet_ntop(AF_INET6, &p->pfx, abuf, sizeof (abuf)), p->plen);

	list_del(&p->list);
	free(p);
}

static void
pfx_gc_timer(void *a)
{
	struct timeval now[1];
	struct cgad_pfx *p, *n;

	DBG(&dbg, "");

	gettimeofday(now, NULL);

	list_for_each_entry_safe(p, n, &pfxlist, list) {
		DBG(&dbg, "%s/%d",
		    inet_ntop(AF_INET6, &p->pfx, abuf, sizeof (abuf)),
		    p->plen);

		if (p->exp < now->tv_sec) {
			del_pfx(p);
			DBG(&dbg, "expired");
		}
	}

	if (!list_empty(&pfxlist)) {
		set_gc_timer();
		return;
	}
	timerclear(&gc_timer_item.tv);
	DBG(&dbg, "idling");
}

static void
set_gc_timer(void)
{
	struct timeval tv[1];

	if (timerisset(&gc_timer_item.tv)) {
		return;
	}

	tv->tv_sec = cgad_conf_get_int(cgad_pfx_cache_gc_intvl);
	tv->tv_usec = 0;
	timer_set(tv, pfx_gc_timer, NULL, &gc_timer_item);
	DBG(&dbg, "next gc in %d seconds",
	    cgad_conf_get_int(cgad_pfx_cache_gc_intvl));
}

static void
add_addr(struct nd_opt_prefix_info *pfxinfo, int ifidx)
{
	struct in6_addr a[1];
	struct cga_params* p;

	if (!(pfxinfo->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) ||
	    !cgad_conf_get_int(cgad_addr_autoconf)) {
		return;
	}

	if (pfxinfo->nd_opt_pi_prefix_len != 64) {
		DBG(&dbg, "prefix len != 64; can't create a cga");
		return;
	}

	memcpy(a, &pfxinfo->nd_opt_pi_prefix, sizeof (*a));
	p=find_params_byifidx(ifidx);
	if (p->hs) {
		if (hba_gen(a,p) < 0) {
			DBG(&dbg_cgad, "hba_gen() failed");
			return;
		}
	}
	else if (cga_gen(a, p) < 0) {
		DBG(&dbg_cgad, "cga_gen() failed");
		return;
	}
	
	DBG(&dbg, "CGA/HBA: %s",
	    inet_ntop(AF_INET6, a, abuf, sizeof (abuf)));

	os_specific_add_addr(a, ifidx, 64,
			     ntohl(pfxinfo->nd_opt_pi_valid_time),
			     ntohl(pfxinfo->nd_opt_pi_preferred_time));
}

static inline int
prefix_match(void *a, struct cgad_pfx *p)
{
	int bytes, bits, plen = p->plen;
	uint8_t abits, pbits, m, v;

	bytes = plen / 8;
	bits = plen % 8;

	if (bytes && memcmp(a, &p->pfx, bytes) != 0) {
		return (0);
	}
	if (bits == 0) {
		return (1);
	}

	for (m = 0, v = 0x80; plen; plen--) {
		m += v;
		v /= 2;
	}

	abits = ((uint8_t *)a)[bytes];
	abits &= m;
	pbits = *(((uint8_t *)&p->pfx) + bytes);
	pbits &= m;

	if (abits == pbits) {
		return (1);
	}
	return (0);
}

static struct cgad_pfx *
find_pfx(struct in6_addr *p1, int ifidx)
{
	struct cgad_pfx *p2;

	list_for_each_entry(p2, &pfxlist, list) {
		if (ifidx == p2->ifidx && prefix_match(p1, p2)) {
			return (p2);
		}
	}

	return (NULL);
}

static int
process_pfx(struct nd_opt_prefix_info *pi, int ifidx, int secure)
{
	struct cgad_pfx *p;
	uint32_t vlife = ntohl(pi->nd_opt_pi_valid_time);
	uint32_t plife = ntohl(pi->nd_opt_pi_preferred_time);
	struct timeval tv[1];

	if (plife > vlife) {
		DBG(&dbg_cgad, "pref life > valid life; ignoring");
		return (0);
	}

	p = find_pfx(&pi->nd_opt_pi_prefix, ifidx);

	/* Ensure that an unsecured RA can't override a secured RA */
	if (!secure) {
		if (p) {
			return (-1);
		}
		/* else no override; autoconf, but don't add any state */
		add_addr(pi, ifidx);
		return (0);
	}

	if (vlife == 0) {
		if (p) {
			del_pfx(p);
		}
		return (0);
	}

	if (p) {
		DBG(&dbg, "Already have prefix; refreshing");
		goto refresh;
	}

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}

	memset(p, 0, sizeof (*p));
	p->pfx = pi->nd_opt_pi_prefix;
	p->ifidx = ifidx;
	p->plen = pi->nd_opt_pi_prefix_len;
	p->flags = pi->nd_opt_pi_flags_reserved;

	list_add_tail(&p->list, &pfxlist);

refresh:
	add_addr(pi, ifidx);

	p->valid_time = vlife;
	p->pref_time = plife;

	/* set expiration */
	gettimeofday(tv, NULL);
	if (vlife == 0xffffffff) {
		/* never expires */
		p->exp = vlife;
	} else {
		p->exp = tv->tv_sec + vlife;
	}
	set_gc_timer();

	return (0);
}

/*
 * Called in two different scenarios: First when checking an unsecured
 * RA (via the IP filter), second when an RA is received on the icmp6
 * socket.
 * When checking an unsecured RA, this just ensures that the RA would
 * not override any prefix info generated by a secured RA. No state is
 * updated.
 * When processing a secured RA from the icmp6 socket, this caches the
 * prefix info.
 * The prefix list (pfxlist) only contains information from secured RAs.
 */
int
cgad_process_ra(uint8_t *raw, int ralen, int ifidx, struct in6_addr *from)
{
	struct ndopts ndopts[1];
	struct nd_router_advert *ra;
	struct nd_opt_prefix_info *pfxinfo;
	uint8_t *nopt;
	int len;
	int secure = 0;

	DBG(&dbg, "");

	if (!cgad_iface_ok(ifidx)) {
		DBG(&dbg, "Addr6SecD not active on this interface");
		return (0);
	}

	if (get_valid_method(from, ifidx,NULL)) {
		DBG(&dbg, "is local; don't need to process");
		return (0);
	}

	ra = (struct nd_router_advert *)raw;
	if (ra->nd_ra_router_lifetime == 0) {
		DBG(&dbg, "router lifetime is 0");
		return (0);
	}

	nopt = (uint8_t *)(ra + 1);
	len = ralen - sizeof (*ra);

	while (len > 0) {
		if (cgad_parse_opts(ndopts, nopt, len) < 0) {
			DBG(&dbg_cgad, "invalid option format");
			return (-1);
		}
		if (ndopts->opt[ND_OPT_CGA]) {
			/* really only happens once */
			DBG(&dbg, "secured RA");
			secure = 1;
		}

		if (!ndopts->opt[ND_OPT_PREFIX_INFORMATION]) {
			break;
		}
		pfxinfo = (struct nd_opt_prefix_info *)
			ndopts->opt[ND_OPT_PREFIX_INFORMATION];
		nopt = (uint8_t *)(pfxinfo + 1);
		len = ralen - (nopt - raw);

		DBG(&dbg, "prefix: %s/%d",
		    inet_ntop(AF_INET6, &pfxinfo->nd_opt_pi_prefix, abuf,
			      sizeof (abuf)), pfxinfo->nd_opt_pi_prefix_len);

		if (process_pfx(pfxinfo, ifidx, secure) < 0) {
			return (-1);
		}
	}

	return (0);
}

#ifdef	USE_CONSOLE
void
dump_pfx_cache(void)
{
	struct cgad_pfx *p;
	char abuf[INET6_ADDRSTRLEN];

	list_for_each_entry(p, &pfxlist, list) {
		printf("\t%s/%d (ifidx %d)\n\t\tvalid %u pref %u\n",
		       inet_ntop(AF_INET6, &p->pfx, abuf, sizeof (abuf)),
		       p->plen, p->ifidx, p->valid_time, p->pref_time);
		printf("\t\texp %s", ctime(&p->exp));
	}
}
#endif

int
cgad_ra_init(void)
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

void
cgad_ra_fini(void)
{
	struct cgad_pfx *p, *n;

	DBG(&dbg, "");
	list_for_each_entry_safe(p, n, &pfxlist, list) {
		del_pfx(p);
	}
}
