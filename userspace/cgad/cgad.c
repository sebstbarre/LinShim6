/*
 * Coyright 2008, Université catholique de Louvain
 * Now maintained by Sébastien Barré - sebastien.barre@uclouvain.be
 *  last modified : Feb 2008
 *
 *
 * Original code from :
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
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <applog.h>
#include <appconsole.h>
#include <thrpool.h>
#include <timer.h>
#include <utils/util.h>
#include <cryptoshim6/sigmeth.h>
#include <cryptoshim6/openssl.h>
#include <cryptoshim6/cga.h>
#include <cga.h>
#include <utils/debug.h>

#include "cgad_local.h"
#include "cgad_config.h"
#include "os_specific.h"
#include "dbg.h"

#ifdef	APPLOG_DEBUG
enum cgad_dbg_lvl cgad_dbg;
struct dlog_desc dbg_cgad = {
	.desc = "cgad",
	.ctx = CGAD_NAME
};
#endif

static struct timeval *
get_next_wait(struct timeval *tvb)
{
	struct timeval now[1], tctv[1];

	if (timer_check(tctv) == NULL) {
		return (NULL);
	}

	/* Calculate next wait period */
	gettimeofday(now, NULL);
	timersub(tctv, now, tvb);
	// DBG(&dbg_cgad, "next wake: %ld.%.6ld", tvb->tv_sec, tvb->tv_usec);

	return (tvb);
}

static int
do_select(int icmps)
{
	fd_set fds[1];
	int maxfd = -1;
	struct timeval *tv, tvb[1];

	applog(LOG_DEBUG,"Entering in %s",__FUNCTION__);

	maxfd = icmps; /*Currently only one fd is defined*/

	for (;;) {
		FD_ZERO(fds);
		FD_SET(icmps, fds);

		tv = get_next_wait(tvb);
		if (select(maxfd + 1, fds, NULL, NULL, tv) < 0) {
			applog(LOG_DEBUG,"error in select");
			if (errno == EINTR) {
				continue;
			}
			applog(LOG_ERR, "%s: select: %s", __FUNCTION__,
			       strerror(errno));
			return (-1);
		}
		applog(LOG_DEBUG,"select : success");

		if (FD_ISSET(icmps, fds)) {
			applog(LOG_DEBUG,"Received ICMP message\n");
			cgad_icmp_sock_read();
		}
		cgad_replace_non_cga_linklocals();
	}
}

static void
sighandler(int sig)
{
	cgad_cleanup();
	exit(0);
}

void
cgad_cleanup(void)
{
	os_specific_fini();
	cgad_ra_fini();
	cgad_proto_fini();
	sigmeth_fini();
	openssl_fini();
	cgad_params_fini();
	cgad_config_fini();
}

static void
usage(const char *this)
{
	const char **lm = applog_get_methods();

	fprintf(stderr, "Usage: %s [-fV] [-i <iface>] "
		"[-l <log method>]\n", this);
	fprintf(stderr, "  log methods: ");
	for (; *lm; lm++) {
		fprintf(stderr, "%s ", *lm);
	}
	fprintf(stderr, "\n");
}


/**
 * Tries to remove all non-cga global unicast addresses
 * and replace them with the corresponding CGA/HBA (depending on
 * config file)
 * Only /64 addresses are taken into account.
 */

void replace_non_cgas(void)
{
	struct ifaddrs* addrlist_head=NULL; /*head*/
	struct ifaddrs* addrlist_it; /*iterator*/
	struct cga_params *p;
	struct in6_addr newcga[1];
	struct in6_addr netmask64={
		.s6_addr32={0xFFFFFFFF,0xFFFFFFFF,0,0}
	}; /*/64 netmask*/

	
	/*Get all addresses from the system*/
	if (getifaddrs(&addrlist_head)<0) {
		DBG(&dbg_cgad,"getifaddrs failed : %m\n");
		return;
	}

	/*Build the local locator table*/
	for (addrlist_it=addrlist_head; addrlist_it;
	     addrlist_it=addrlist_it->ifa_next) {
		struct sockaddr_in6* sa6=(struct sockaddr_in6*)
			addrlist_it->ifa_addr;
		struct sockaddr_in6* nm=(struct sockaddr_in6*)
			addrlist_it->ifa_netmask;
		int ifidx=if_nametoindex(addrlist_it->ifa_name);
		ASSERT(ifidx!=0);

		/*We do not consider link local, loopback or multicast*/
		if (sa6->sin6_family != AF_INET6 ||
		    IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) ||
		    IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr) ||
		    IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr))
			continue;
		/*only consider /64*/
		if (!ipv6_addr_equal(&nm->sin6_addr,&netmask64)) {
			PDEBUG("Prefix of address %s is not /64. Skipping\n",
			       addrtostr(&sa6->sin6_addr));
			continue;
		}
		
		if (get_valid_method(&sa6->sin6_addr,ifidx,NULL)) {
			PDEBUG("Address %s is a CGA or HBA. Skipping\n",
			       addrtostr(&sa6->sin6_addr));
			continue;
		}
		
		/*OK, let's replace that address*/
		if ((p = find_params_byifidx(ifidx)) == NULL)
			continue;
		/* set prefix */
		memset(newcga, 0, sizeof (struct in6_addr));
		memcpy(newcga,&sa6->sin6_addr,8);
		if (p->hs) {
			if (hba_gen(newcga,p) < 0) {
				DBG(&dbg_cgad, "hba_gen() failed");
				continue;
			}
		}
		else if (cga_gen(newcga, p) < 0) {
			DBG(&dbg_cgad, "cga_gen() failed");
			continue;
		}
		do_replace_address(&sa6->sin6_addr, newcga, ifidx);
	}
}

int
main(int argc, char **argv)
{
	int r, c, icmps, do_daemon = 1;
	char *cfile = CGAD_CONF_FILE;

#ifdef	APPLOG_DEBUG
	if (applog_open(L_STDERR, CGAD_NAME) < 0) {
		exit(1);
	}
#else
	if (applog_open(L_SYSLOG, CGAD_NAME) < 0) {
		exit(1);
	}
#endif

	while (argc > 1 && (c = getopt(argc, argv, "fdc:i:l:V")) != -1) {
		switch (c) {
		case 'f':
			do_daemon = 0;
			break;
		case 'i':
			if (cgad_add_iface(optarg) < 0) {
				exit(1);
			}
			break;
		case 'd':
#ifdef	APPLOG_DEBUG
			cgad_dbg++;
#endif
			break;
		case 'l':
			applog_set_method(applog_str2method(optarg));
			break;
		case 'V':
			printf("CGA daemon, part of the LinShim6 package "
			       " version %s\n", PACKAGE_VERSION);
			exit(0);
		case 'h':
		default:
			usage(*argv);
			exit(1);
		}
	}

#ifdef	APPLOG_DEBUG
	if (cgad_dbg >= CGAD_DBG_ERR) {
		struct dlog_desc *dbgs[] = {
			&dbg_cgad,
			NULL
		};

		if (applog_register(dbgs) < 0) {
			exit(1);
		}
		applog_enable_level(dbg_cgad.ctx, dbg_cgad.desc);
	}
	if (cgad_dbg >= CGAD_DBG_ALL) {
		applog_addlevel(log_all_on);
	}
#endif

	if (signal(SIGINT, sighandler) < 0 ||
	    signal(SIGTERM, sighandler) < 0) {
		applog(LOG_CRIT, "signal: %s", strerror(errno));
		exit(1);
	}
	
	thrpool_init();

	if (timer_init() < 0 ||
	    cgad_read_config(cfile) < 0 ||
	    openssl_init() < 0 ||
	    cga_init() < 0 ||
	    sigmeth_init() < 0 ||
	    cgad_params_init() < 0 ||
	    (icmps = cgad_net_init()) < 0 ||
	    cgad_proto_init() < 0 ||
	    cgad_ra_init() < 0 ||
	    cgad_addr_init() < 0 ||
	    os_specific_init() < 0 ||
	    cgad_replace_non_cga_linklocals() < 0) {
		cgad_cleanup();
		exit(1);
	}
	thrpool_set_max(cgad_conf_get_int(cgad_thrpool_max));

	if (do_daemon) {
		daemon(0, 0);
	}

	if (system("disable_autoconf")<0) {
		syslog(LOG_ERR, "disable-autoconf failed : %m");
		syslog(LOG_ERR, "You should disable autoconf manually");
	}

	replace_non_cgas();

	r = do_select(icmps);

	cgad_cleanup();
	exit(r);
}
