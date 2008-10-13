/*
 *	Linux shim6 implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *     	date : September 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef __XFRM_H_
#define __XFRM_H_ 1

#include <netinet/in.h>
#include <asm/types.h>
#include <shim6/shim6d.h>

#define NOSHIM6_PRIO_DEFAULT            99 /*Priority for rules used to
					     bypass the shim6 layer*/
#define SHIM6_PRIO_DEFAULT		100


int xfrm_init(void);
int xfrm_add_shim6_ctx(const struct in6_addr* ulid_local, 
		       const struct in6_addr* ulid_peer,
		       __u64 ct_local, __u64 ct_peer,
		       struct shim6_path *paths, int npaths,
		       uint16_t tka);
int xfrm_del_shim6_ctx(const struct in6_addr* ulid_local, 
		       const struct in6_addr* ulid_peer,
		       __u64 ct_local, __u64 ct_peer);
int xfrm_update_shim6_ctx(struct shim6_ctx* ctx,
			  const struct in6_addr* new_loc_p,
			  const struct in6_addr* new_loc_l,
			  struct shim6_path *paths, int npaths);
/*Dumps all kernel xfrm states to the file descriptor @fd*/
int dump_all_kern_states(int fd, char* str);

/*Dumps all kernel xfrm policies to the file descriptor @fd*/
int dump_all_kern_policies(int fd, char* str);

/*To be called by the pipe module*/
void xfrm_handler(void* data);


#endif /* __XFRM_H_ */
