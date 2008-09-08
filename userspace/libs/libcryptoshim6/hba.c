/*
 *	HBA utilities
 *
 *      This implementation uses the CGA framework from DoCoMo SEND impl.
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : April 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <cryptoshim6/cga.h>
#include <cga.h>
#include <applog.h>
#include <utils/debug.h>

/**
 * @pre : the hs field of @p points to one of the sets maintained by the
 * global hba set list.
 * @post : the hba set is generated. The hs pointer is replaced by a newly
 * malloc'ed area containing the hba addresses. The original hs node is also
 * deleted from the hba list and replaced by the new set. 
 * The original hs pointer is finally freed.
 */
int
hba_precompute(struct cga_params *p)
{
	cga_ctx_t ctx[1];
	struct hba_set* hs=p->hs;

	if (!p->hs) {
		applog(LOG_ERR,"%s: Trying to generate HBAs, but HBA set not "
		       "defined", __FUNCTION__);
		return -1;
	}

	cga_init_ctx(ctx);
	cga_set_der(ctx, p->der, p->dlen);
	cga_set_sec(ctx, p->sec);
	hba_set_prefixes(ctx, p->hs);
	ctx->is_hba_ctx=1;

	if (hba_generate(ctx) != 0) {
		applog(LOG_ERR, "%s: cga_generate() failed", __FUNCTION__);
		return (-1);
	}
	PDEBUG("p->hs:%p,ctx->hba_data:%p",p->hs,ctx->hba_data);
	p->hs=ctx->hba_data; /*Replacing the hba_set/pfx by the new 
			       hba_set/addr*/

	/*Replacing the old hs in the global hba list*/
	list_del(&hs->list);
	list_add(&p->hs->list,&hba_sets);
	free(hs);
	return (0);
}

/**
 * This function does not really generate a new HBA, rather it checks whether 
 * the provided prefix corresponds to one of the precomputed HBAs, in which case
 * the suffix is set to the corresponding HBA suffix. The name has been chosen
 * by similarity to cga_gen().
 */
int
hba_gen(struct in6_addr* pfx, struct cga_params *p)
{
	int i;
	if (!p->hs || !p->hs->computed) {
		applog(LOG_ERR,"%s: no hba set defined or computed",
		       __FUNCTION__);
		return -1;
	}
	for (i=0;i<p->hs->length;i++) {
		if (!memcmp(pfx,&p->hs->set_addr[i],8)) {
			ipv6_addr_copy(pfx,&p->hs->set_addr[i]);
			return 0;
		}
	}
	if (p->hs->cgacompat) return cga_gen(pfx,p);
	else return -1;
}
