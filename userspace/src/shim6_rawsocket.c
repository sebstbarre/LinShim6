/*
 *	Linux shim6 implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : June 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <config.h>
#include <shim6/shim6d.h>
#include <linux/shim6.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>

#include <utils/debug.h>
#include "shim6_rawsocket.h"

static int shim6sd_send=-1;
int shim6sd_rcv=-1;

/*================*/


/*Alloc @hdr_len + @opt_len bytes in a new shim6 message. 
 * @data is filled with a pointer
 * to the data part of the message; @hdr is filled with a pointer to the
 * message header.
 * @opt may be NULL if we want to send an optionless message.
 * @type is the message type, for example SHIM6_TYPE_I1
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int shim6_alloc_send(int hdr_len, int opt_len, int type, union shim6_msgpp hdr, 
		     void** opt)
{
	struct shim6hdr_ctl* common_hdr;
	int total_size=hdr_len+opt_len;
	
	common_hdr=(struct shim6hdr_ctl*) malloc(total_size);       
	if (!common_hdr) return -1;

	bzero(common_hdr, sizeof(struct shim6hdr_ctl));
	common_hdr->nexthdr=NEXTHDR_NONE;
	common_hdr->hdrlen=(total_size-8)>>3;
	common_hdr->P=SHIM6_MSG_CONTROL;
	common_hdr->type=type;
	common_hdr->csum=0;
	
	if (opt) *opt=(char*)common_hdr+hdr_len;
	
	/*We do here as if the message were always an I1, since all messages
	  start with common_hdr*/
	*hdr.i1=(shim6hdr_i1*)common_hdr;

	return 0;
}


/*Sends a packet with the specified src and destination addresses, 
 * using @ifdx as outgoing interface*/
int shim6_send(void* pkt, int pkt_len, struct in6_addr* src, 
	       struct in6_addr* dest) 
{
	struct msghdr mhdr[1]={{0}};
	struct cmsghdr *cmsg;
	struct in6_pktinfo* pktinfo;
	shim6_loc_l* src_loc;
	char buf[CMSG_SPACE(sizeof(*pktinfo))]; /*ancillary data 
						  buffer*/
	struct sockaddr_in6 dest_addr[1];
	struct iovec iov[1];

	/*Setting src address*/
	
	mhdr->msg_control=buf;
	mhdr->msg_controllen=sizeof(buf);
	cmsg=CMSG_FIRSTHDR(mhdr);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pktinfo));
	
	pktinfo= (struct in6_pktinfo*) CMSG_DATA(cmsg);
	
	src_loc=lookup_loc_l(src,NULL);
	if (!src_loc) {
		syslog(LOG_ERR,"%s :  lookup_loc_l failed\n",__FUNCTION__);
		return -1;
	}


	ipv6_addr_copy(&pktinfo->ipi6_addr,&src_loc->addr);
	
	/*Setting outgoing interface*/
	
	pktinfo->ipi6_ifindex=src_loc->ifidx;
	mhdr->msg_controllen = cmsg->cmsg_len;
	
	PDEBUG("Sending to ifidx %d\n", pktinfo->ipi6_ifindex);

	/*Setting dest address*/
	dest_addr->sin6_family=AF_INET6;
	dest_addr->sin6_flowinfo=0;
	dest_addr->sin6_port=0;
	dest_addr->sin6_scope_id=0;
	ipv6_addr_copy(&dest_addr->sin6_addr,dest);
	mhdr->msg_name=dest_addr;
	mhdr->msg_namelen=sizeof(dest_addr);
	
	/*Setting payload*/
	iov->iov_base=pkt;
	iov->iov_len=pkt_len;
	mhdr->msg_iov=iov;
	mhdr->msg_iovlen=1;

	/*Sending packet*/
	if (sendmsg(shim6sd_send,mhdr,0)<0) {
		syslog(LOG_ERR,"%s, sendmsg : %m\n",__FUNCTION__);
		return -1;
	}
			
	return 0;	
}

/*Should be defined in netinet/in.h, but old versions of this header have the
 * value of 2 (rfc 2292) instead of 50 (rfc 3542)*/
#ifdef IPV6_PKTINFO
#undef IPV6_PKTINFO /*Forget the old value of 2*/
#endif
#define IPV6_PKTINFO            50 

/* Fills the pkt_info structure, that contains the IPv6 
 * dest address for the message mhdr. Returns 0 in case of success, else -1.
 **/
int get_pkt_info(struct msghdr* mhdr, 
		 struct in6_pktinfo** pkt_info)
{
	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(mhdr); cmsg; 
	     cmsg = CMSG_NXTHDR(mhdr, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;
		if(cmsg->cmsg_type==IPV6_PKTINFO) {
			*pkt_info=(struct in6_pktinfo*)CMSG_DATA(cmsg);
			return 0;
		}
	}
	return -1;
}

int shim6_rawsocket_init(void)
{
	struct sockaddr_in6 inaddr = {
		.sin6_family=AF_INET6,
		.sin6_addr=IN6ADDR_ANY_INIT,
	};
	int val=1;

	
	/*Create network sockets (ka/probe messages)
	 * We need a separate socket for reception, which will stay bound
	 * to in6addr_any throughout its lifetime*/
	
	shim6sd_rcv=socket(PF_INET6,SOCK_RAW,IPPROTO_SHIM6);
	if (shim6sd_rcv<0) {
		syslog(LOG_ERR, "socket : %m\n");
		goto failure;
	}
	
	if (setsockopt(shim6sd_rcv, IPPROTO_IPV6, IPV6_RECVPKTINFO, 
		       &val, sizeof(val)) < 0) {
		syslog(LOG_ERR,"setsockopt : %m\n");
		goto failure;
	}      
	
	shim6sd_send=socket(PF_INET6,SOCK_RAW,IPPROTO_SHIM6);
	if (shim6sd_send<0) {
		syslog(LOG_ERR, "socket : %m\n");
		goto failure;
	}
	
	
	if (bind(shim6sd_rcv,(struct sockaddr*)&inaddr,sizeof(inaddr))<0) {
		syslog(LOG_ERR, "bind : %m\n");
		goto failure;
	}
	
	return 0;

 failure:
	if (shim6sd_send!=-1) close(shim6sd_send);
	if (shim6sd_rcv!=-1) close(shim6sd_rcv);
	return -1;
}
