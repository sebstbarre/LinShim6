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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <utils/rtnl.h>

#include <applog.h>
#include <cryptoshim6/cga_params.h>
#include <cryptoshim6/cga.h>
#include <utils/debug.h>

#include "cgad_local.h"
#include "cgad_config.h"
#include "os_specific.h"
#include "os_defines.h"
#include "dbg.h"

#ifdef	APPLOG_DEBUG
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN];

static struct dlog_desc dbg = {
	.desc = "addrtbl",
	.ctx = CGAD_NAME
};
#endif

static LIST_HEAD(cgad_non_cga_linklocals);

struct cgad_ll_addr {
	struct in6_addr	addr;
	int		ifidx;
	struct list_head list;
};

int do_replace_address(struct in6_addr *old, struct in6_addr *new, int ifidx)
{
	DBG(&dbg, "replacing %s",
	    inet_ntop(AF_INET6, old, abuf, sizeof (abuf)));

	if (addr_del(old, 64, ifidx) < 0 ||
	    addr_add(new, 64, 0, 0, ifidx, CGAD_LIFE_INF, CGAD_LIFE_INF)
	    < 0) {
		return (-1);
	}

	return (0);
}

static int
gen_linklocal_cga(struct in6_addr *addr, int ifidx)
{
	struct cga_params *p;

	if ((p = find_params_byifidx(ifidx)) == NULL) {
		return (-1);
	}

	/* set link local prefix */
	memset(addr, 0, sizeof (*addr));
	addr->s6_addr32[0] = htonl(0xfe800000);

	/* Generate same link-local for all interfaces, unless it is 
	   explicitly asked to make an HBA (in the config files)*/
	if (!p->hs) {
		if (cga_gen(addr, p) < 0) {
			DBG(&dbg, "cga_gen() failed");
			return (-1);
		}
	}
	else {
		int i;
		ASSERT(p->hs->computed);
		for (i=0;i<p->hs->length;i++) {
			if (!memcmp(addr,&p->hs->set_addr[i],8)) {
				ipv6_addr_copy(addr,&p->hs->set_addr[i]);
				goto success;
			}
		}
		if (p->hs->cgacompat && cga_gen(addr,p)<0) {
			DBG(&dbg, "cga_gen() failed");
			return (-1);
		}
		else if (!p->hs->cgacompat) {
			syslog(LOG_ERR,"Configured to generate link-local "
			       "CGAs/HBAs, but no parameters are defined for"
			       " the link local prefix. You should either "
			       " disable link-local replacement in cgad.conf,"
			       " or define parameters for them in params.conf");
			return -1;
		}
	}
success:
	DBG(&dbg, "generated address: %s",
	    inet_ntop(AF_INET6, addr, abuf, sizeof (abuf)));

	return (0);
}

/**
 * Since this is a user-space only implementation, we can't modify
 * how the kernel forms link-locals when it initializes the IPv6
 * stack. Instead, when this daemon starts up, we replace all non-CGA
 * link-locals with a CGA link-local. We re-use the same one so that
 * we won't need to find a new modifier for each address (this is the
 * same as for address autoconfiguration).
 */
static int
replace_linklocals(void)
{
	struct cgad_ll_addr *ap, *n;
	struct in6_addr addr[1];

	list_for_each_entry_safe(ap, n, &cgad_non_cga_linklocals, list) {
		if (gen_linklocal_cga(addr, ap->ifidx) < 0) {
			return (-1);
		}
		do_replace_address(&ap->addr, addr, ap->ifidx);
		list_del(&ap->list);
		free(ap);
	}

	return (0);
}

static void
add_ll_addr(struct in6_addr *a, int ifidx)
{
	struct cgad_ll_addr *ap;

	if ((ap = malloc(sizeof (*ap))) == NULL) {
		APPLOG_NOMEM();
		return;
	}
	memcpy(&ap->addr, a, sizeof (ap->addr));
	ap->ifidx = ifidx;
	list_add(&ap->list, &cgad_non_cga_linklocals);
}

int
cgad_replace_this_non_cga_linklocal(struct in6_addr *a, int ifidx)
{
	struct in6_addr addr[1];

	if (!cgad_conf_get_int(replace_linklocal_addresses)) {
		return (0);
	}
	if (gen_linklocal_cga(addr, ifidx) < 0 ||
	    do_replace_address(a, addr, ifidx) < 0) {
		return (-1);
	}

	return (0);
}

int
cgad_replace_non_cga_linklocals(void)
{
	if (cgad_conf_get_int(replace_linklocal_addresses) &&
	    !list_empty(&cgad_non_cga_linklocals)) {
		return (replace_linklocals());
	}
	return (0);
}

static void
cgad_cfg_addr(struct in6_addr *a, int plen, int ifidx)
{
	DBG(&dbg, "%s/%d (%d)",
	    inet_ntop(AF_INET6, a, abuf, sizeof (abuf)), plen, ifidx);

	if (IN6_IS_ADDR_LOOPBACK(a)) {
		DBG(&dbg, "skipping loopback");
		return;
	}

	if (plen != 64) {
		DBG(&dbg, "prefix length != 64 bits; skipping");
		return;
	}

	if (!get_valid_method(a, ifidx,NULL)) {
		DBG(&dbg, "not CGA");
		if (cgad_conf_get_int(replace_linklocal_addresses) &&
		    IN6_IS_ADDR_LINKLOCAL(a)) {
			add_ll_addr(a, ifidx);
		}
		return;
	} 
}

/*
 * libdnet (1.11) is currently broken on Linux - intf_loop fails on SUSE 10.0.
 * Until it is fixed, we use this workaround instead.
 */

static int
get_addrs(void)
{
	FILE *fp;
	struct in6_addr a;
	uint32_t ifidx, plen, scope, flags;
	char buf[128], ifname[32];
	int i, off, digit;

	if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL) {
		applog(LOG_ERR, "%s: fopen(/proc/net/if_inet6): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		for (i = off = 0; i < 16; i++, off += 2) {
			sscanf(buf + off, "%02x", &digit);
			a.s6_addr[i] = digit;
		}
		sscanf(buf + off, "%02x %02x %02x %02x %32s\n",
		       &ifidx, &plen, &scope, &flags, ifname);
		cgad_cfg_addr(&a, plen, ifidx);
	}

	fclose(fp);
	return (0);
}

int
cgad_addr_init(void)
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

	return (get_addrs());
}
