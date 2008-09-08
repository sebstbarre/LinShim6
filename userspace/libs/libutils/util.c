/*
 *	Linux shim6 implementation - utilities
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : July 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


static char string_addr[INET6_ADDRSTRLEN];

/*writes a string representation of addr and returns a pointer to the
 *  string. This cannot be used in a concurrent environment
 */
const char* addrtostr(const struct in6_addr* addr)
{
	inet_ntop(AF_INET6,addr,string_addr,INET6_ADDRSTRLEN);
	return string_addr;
}
