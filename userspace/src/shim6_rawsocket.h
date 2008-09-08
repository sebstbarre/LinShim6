/*
 *	Linux shim6 implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sbarre@info.ucl.ac.be>
 *
 *	date : May 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _SHIM6_RAWSOCKET_H_
#define _SHIM6_RAWSOCKET_H_

#include <shim6/shim6d.h>

/*Special union used to pass the argument to shim6_alloc_send, without
  breaking strict-aliasing rules of gcc.*/
union shim6_msgpp {
	shim6hdr_i1** i1;
	shim6hdr_i2** i2;
	shim6hdr_r1** r1;
	shim6hdr_r2** r2;
	shim6hdr_ur** ur;
	shim6hdr_ua** ua;
	reaphdr_ka**  ka;
	reaphdr_probe** probe;
};

/*raw socket for the shim6 protocol*/
extern int shim6sd_rcv;

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
		     void** opt);

/*Sends a packet with the specified src and destination addresses*/
int shim6_send(void* pkt, int pkt_len, struct in6_addr* src, 
	       struct in6_addr* dest);

/* Fills the pkt_info structure, that contains the IPv6 
 * dest address for the message mhdr. Returns 0 in case of success, else -1.
 **/
int get_pkt_info(struct msghdr* mhdr, 
		 struct in6_pktinfo** pkt_info);

int shim6_rawsocket_init(void);

#endif /*_SHIM6_RAWSOCKET_H_*/
