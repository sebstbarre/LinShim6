/*
 *	Linux shim6 implementation (LinShim6) - daemon part
 *
 *      CGA support (inspired from the DoCoMo SEND implementation)
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : November 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _SHIM6_CGA_H
#define _SHIM6_CGA_H

#include <netinet/in.h>
#include <shim6/shim6d.h>
#include "cga_params.h"


struct hba_set {
	struct list_head        list;
	const char *            name;
	union {
		uint64_t*               pfx; /*/64 prefixes*/
		struct in6_addr*        addr; /*Computed addresses*/
	} set;
#define set_pfx set.pfx
#define set_addr set.addr
	char                    computed:1, /*if set to 1, addr must be used
					      instead of pfx in union set*/
	 	                cgacompat:1;
	int                     length;
	void*                   private; /*Private pointer, specific to the 
					   user of that library.*/
};

/*Initialize the CGA module*/
int shim6_cga_init(void);

/**
 * @pre -@a points to a local address.
 * @post if @hs is not NULL and *@a is an HBA, *hs is set to the corresponding
 *       hba set.
 * Returns - false if the address is neither an HBA nor a CGA
 *         - returns SHIM6_HBA if it is an HBA
 *         - returns SHIM6_CGA if it is a CGA
 * 
 */
int get_valid_method(struct in6_addr *a, int ifidx, struct hba_set** hs);

int cga_gen(struct in6_addr *pfx, struct cga_params *p);
int hba_precompute(struct cga_params *p);
int hba_gen(struct in6_addr *pfx, struct cga_params *p);

/**
 * Returns the CGA PDS option, for I2 and R2 messages
 * The CGA PDS is retrieved according to the ulid_local, as stated in draft
 * shim6-proto-09, appendix D.4.*/
struct cga_params* get_cga_pds_option(struct in6_addr* ulid_local, 
					   int ifidx);


extern void cga_set_keyhash(struct cga_params *);

/**
 *  @loclist : The locator list option. This function will parse the option to 
 *            find which locators and locator generation number to use as 
 *            input for the signature algorithm.
 * @size : Will be filled by cga_sign with the length of the signature
 *
 * @returns: a pointer to signature; the caller must free this pointer*/
uint8_t *cga_sign(struct loc_list_opt* loclist, int* slen, 
		  struct cga_params* pds);

/**
 *  This makes the CGA verification for all CGA locators.
 * The result is returned as follows:
 * -if the test for a given CGA succeeds, it stays unchanged
 * -if it fails, its verif method is changed to 0, which causes it
 * to be ignored later.*/
int verify_cga_locators(struct shim6_opt* rll, struct shim6_opt* pds,
			struct shim6_opt* sign);
/**
 * @pds is a dump of the pds option, as sent by the peer
 * @loc is the locator to be verified
 */
int shim6_is_remote_cga(struct shim6_opt* pds, struct in6_addr* loc, int hba);

#endif /*_SHIM6_CGA_H*/
