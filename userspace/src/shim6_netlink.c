/*
 *	Shim6 daemon - netlink communication with kernel space.
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Based on draft-ietf-shim6-proto-09
 *
 *      date : December 2007
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bits/sockaddr.h>
#include <linux/shim6_netlink.h>
#include <libnetlink.h>

#include <utils/debug.h>
#include <utils/rtnl.h>

int nlsd=-1;
struct sockaddr_nl nladdr;
	
/*Allocate memory for reception from the kernel
 * @size is the only parameter to know in advance
 * @nlhdr is a pointer which will be set to the allocated memory
 * @msg and @iov point to empty structures. They will be filled in.
 */
int netlink_alloc_rcv(int size, struct nlmsghdr** nlhdr, struct msghdr* msg,
		      struct iovec* iov)
{	
	struct nlmsghdr* hdr=malloc(NLMSG_SPACE(size));
	if (!hdr) return -1;
	iov->iov_base=(void*)hdr;
	iov->iov_len=NLMSG_SPACE(size);
	memset(msg,0,sizeof(struct msghdr));
	msg->msg_name = (void*)&nladdr;
	msg->msg_namelen = sizeof(nladdr);
	msg->msg_iov=iov;
	msg->msg_iovlen=1;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	*nlhdr=hdr;
	return 0;
}


int netlink_init(void)
{
	int val=SHIM6NLGRP_DEFAULT;
	struct rtnl_handle shim6_rth;

	if (rtnl_ext_open(&shim6_rth, NETLINK_SHIM6,0) < 0) {
		syslog(LOG_ERR, "%s: rtnl_xfrm_open:%m\n",__FUNCTION__);
		return -1;
	}
	nlsd=shim6_rth.fd;

	/*Opening the netlink socket*/
	
	if (setsockopt(nlsd, SOL_NETLINK,
		       NETLINK_ADD_MEMBERSHIP, &val, sizeof(val)) < 0) {
		syslog(LOG_ERR,"%s:setsockopt:%m\n",
		       __FUNCTION__);
		return -1;
	}
	
	return 0;
}
