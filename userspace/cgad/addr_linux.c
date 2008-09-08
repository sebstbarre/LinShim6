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
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <applog.h>

#include "os_specific.h"
#include "cgad_linux.h"

/* Is this defined in any user headers? */
struct in6_ifreq {
	struct in6_addr	ifr6_addr;
	uint32_t	ifr6_prefixlen;
	int		ifr6_ifindex; 
};

/*
 * Linux kernel ignores valid and pref life when configuring an address
 * from userspace, so we also ignore them (for now, at least...)
 */
static int
addr_common(struct in6_addr *a, int ifidx, int plen, int add, uint32_t vlife,
    uint32_t plife)
{
	struct in6_ifreq req;
	int cmd, s, r = -1;

	memset(&req, 0, sizeof (req));
	req.ifr6_addr = *a;
	req.ifr6_prefixlen = plen;
	req.ifr6_ifindex = ifidx;

	cmd = add ? SIOCSIFADDR : SIOCDIFADDR;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		applog(LOG_ERR, "%s: socket(): %s", __FUNCTION__,
		       strerror(errno));
		goto done;
	}

	if (ioctl(s, cmd, &req) < 0) {
		applog(LOG_ERR, "%s: ioctl(): %s", __FUNCTION__,
		       strerror(errno));
		goto done;
	}
	r = 0;

done:
	close(s);
	return (r);
}

int
os_specific_add_addr(struct in6_addr *a, int ifidx, int plen, uint32_t vlife,
    uint32_t plife)
{
	return (addr_common(a, ifidx, plen, 1, vlife, plife));
}

int
os_specific_del_addr(struct in6_addr *a, int ifidx, int plen)
{
	return (addr_common(a, ifidx, plen, 0, 0, 0));
}
