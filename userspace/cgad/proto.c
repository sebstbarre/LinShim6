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

/*
 *
 * Threading model:
 * One main thread handles all I/O, and does some initial packet processing
 * that is not CPU-intensive. Once a packet passes the basic checks, it
 * is handed off to a thread pool with thrpool_req, where cryptographic tasks
 * are performed.
 * There are two sources of packets: the OS-specific packet intercept
 * mechanism, and an ICMPv6 socket. This file handles the intercepted
 * ND packets. The ICMPv6 packets of interest are RA, CPS, and CPA,
 * which are handled by their respective files.
 * If sendd is built withouth multi-threading support, thrpool_req
 * simply calls the function directly.
 */

#include <config.h>
#include <string.h>
#include <sys/socket.h>

#include <applog.h>
#include <thrpool.h>
#include <cga.h>
#include <utils/util.h>

#include "cgad_local.h"
#include "os_specific.h"
#include "os_defines.h"
#include "cgad_proto.h"
#include "cgad_config.h"
#include "dbg.h"

#ifdef	APPLOG_DEBUG
#include <arpa/inet.h>
static struct dlog_desc dbg = {
	.desc = "proto",
	.ctx = CGAD_NAME
};
#endif

struct cgad_pkt_info {
	struct sbuff	*b;
	struct ip6_hdr	*iph;
	struct icmp6_hdr *icmp;
	struct in6_addr	*cga;
	void		*start;
	void		*os_pkt;
	struct cgad_sig_method *sigmeth;  // for incoming pkts
	struct cgad_cga_params *params;   // for outgoing pkts
	uint8_t		*key;
	int		klen;
	int		ifidx;
	uint64_t	ts;
	uint64_t	now;
	struct ndopts	ndopts;
};

enum cgad_pkt_decision {
	CGAD_STOLEN,
	CGAD_ACCEPT_CHANGED,
	CGAD_ACCEPT_NOTCHANGED,
	CGAD_DROP,
};

static inline void
ipv6_addr_all_routers(struct in6_addr *addr)
{
	ipv6_addr_set(addr, htonl(0xFF020000), 0, 0, htonl(0x2));
}

/*
 * Walk the supported signature method list until we find one that
 * matches a signature option in the incoming packet.
 */
struct sigmeth_info {
	struct cgad_sig_method *m;
	struct ndopts *ndopts;
};


struct cgad_sig_method *
cgad_packetinfo_sigmeth(void *p)
{
	struct cgad_pkt_info *pi = p;
	return (pi->sigmeth);
}

int
cgad_proto_init(void)
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
cgad_proto_fini(void)
{
}
