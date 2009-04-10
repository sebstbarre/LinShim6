/*
 *
 * This file comes from the DoCoMo SEND project
 *
 * Adapted by Sébastien Barré - sebastien.barre@uclouvain.be
 * Last modified : April 2008
 *
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
#include <string.h>
#include <cga.h>
#include <hashtbl.h>
#include <sys/uio.h>
#include <list.h>
#include <net/if.h>
#include <syslog.h>

#include <cryptoshim6/cga_params.h>
#include <cryptoshim6/sigmeth.h>
#include <shim6/shim6d.h>
#include <utils/debug.h>
#include <utils/util.h>

#define	SHIM6_MSG_TYPE_TAG { \
	0x4a, 0x30, 0x56, 0x62, 0x48, 0x58, 0x57, 0x4b, \
	0x36, 0x55, 0x41, 0x6f, 0x50, 0x6a, 0x6d, 0x48 }

static uint8_t shim6_msg_type_tag[] = SHIM6_MSG_TYPE_TAG;

/*We only use one signature method*/
static struct sig_method *m;

/**
 * @pre p->hs is not NULL
 */
static int is_lcl_hba(struct in6_addr *a, struct cga_params *p, 
		      struct hba_set** hs)
{
	int i;
	ASSERT(p->hs->computed);
	for (i=0;i<p->hs->length;i++) {
		if (ipv6_addr_equal(&p->hs->set_addr[i],a)) {
			if (hs) *hs=p->hs;
			return 1;
		}
	}
	return 0;
}

/**
 * @pre -@a points to a local address.
 * @post -if @hs is not NULL and *@a is an HBA, *@hs is set to the corresponding
 *       hba set.
 *       -if @hs is not NULL and *@a is not an HBA, *@hs is set to NULL.
 * Returns - false if the address is neither an HBA nor a CGA
 *         - returns SHIM6_HBA if it is an HBA
 *         - returns SHIM6_CGA if it is a CGA
 *         - in case of error, returns -1 and if hs is not NULL, 
 *           *@hs is set to NULL
 * 
 */
int get_valid_method(struct in6_addr *a, int ifidx, struct hba_set** hs)
{
	cga_ctx_t ctx[1];
	struct cga_params *p=find_params_byaddr(a, ifidx);
	struct cga_parsed_params ws[1];

	if (!p) {
		if (hs) *hs=NULL;
		return -1;
	}
	
	if (hs) *hs=NULL;
	if (p->hs && is_lcl_hba(a,p, hs)) return SHIM6_HBA;

	cga_init_ctx(ctx);
	cga_set_der(ctx, p->der, p->dlen);
	cga_set_sec(ctx, p->sec);
	cga_set_addr(ctx, a);

	ws->buf = p->der;
	ws->dlen = p->dlen;
	cga_parse_params(ws);

	/* Change prefix to addr's */
	memcpy(ws->pfx, a->s6_addr, 8);

	if (cga_verify(ctx) == 0) {
		return SHIM6_CGA;
	}
	return (0);
}

static int is_hba_in_set(struct cga_multipfx_ext* mpe, struct in6_addr* hba)
{
	uint16_t rem;
	uint64_t* curpfx;
	if (!mpe) return 0;
	curpfx=mpe->pfxs;
	for (rem=ntohs(mpe->hdr.len)-4;rem>=sizeof(uint64_t);
	     rem-=sizeof(uint64_t),curpfx++) {
		if (!memcmp(hba,curpfx,8)) return 1;		
	}
	PDEBUG("%s failed",__FUNCTION__);
	return 0;
}

/*@pds is a dump of the pds option, as sent by the peer
 *@loc is the locator to be verified
 *@hba : 1 if we should verify if the address is an HBA, rather than a CGA.
 */
int shim6_is_remote_cga(struct shim6_opt* pds, struct in6_addr* loc,
			int hba)
{
	cga_ctx_t cga[1];
	struct cga_parsed_params ws[1];
	int ans;
	char pfx[8];
   
	cga_init_ctx(cga);
	cga_set_der(cga, (uint8_t*)(pds+1), ntohs(pds->length));
	cga_set_addr(cga, loc);

	ws->buf = (uint8_t*)(pds+1);
	ws->dlen = ntohs(pds->length);
	cga_parse_params(ws);

	if (ws->mpe && !is_hba_in_set(ws->mpe,loc)) {
		ans=0; goto end;
	}
				
	/* If, HBA, change prefix to addr's */
	if (hba) {
		memcpy(pfx, ws->pfx, 8); /*Save previous prefix*/
		memcpy(ws->pfx, loc->s6_addr, 8);
	}

        ans=(cga_verify(cga)==0);
	if (!ans) PDEBUG("%s : cga_verify failed",__FUNCTION__);

	if (hba) memcpy(ws->pfx,pfx, 8); /*Restore original prefix, this is
					   needed for later possible CGA 
					   checks*/
end:
	cga_cleanup_ctx(cga);
	return ans;
}

void cga_set_keyhash(struct cga_params *p)
{
	struct cga_parsed_params ws[1];

	ws->buf = p->der;
	ws->dlen = p->dlen;
	cga_parse_params(ws);

	SHA1(ws->key, p->dlen - CGA_PARAM_LEN, p->keyhash);
}

int shim6_cga_init(void)
{

	if (cga_init() < 0) {
		return -1;
	}

	if (sigmeth_init()<0) {
		return -1;
	}
	m=find_sig_method_byname("RSASSA-PKCS1-v1_5");
	if (!m) return -1;

	return (0);
}

static struct cga_params *
cga_get_params(struct in6_addr *addr, int ifidx)
{
	struct cga_parsed_params ws[1];
	struct cga_params *p = find_params_byaddr(addr, ifidx);
	
	if (!p) return NULL;

	ws->buf = p->der;
	ws->dlen = p->dlen;
	cga_parse_params(ws);

	/* Change prefix to addr's */
	memcpy(ws->pfx, addr->s6_addr, 8);

	return (p);
}

int
cga_gen(struct in6_addr *pfx, struct cga_params *p)
{
	cga_ctx_t ctx[1];	

	cga_init_ctx(ctx);
	cga_set_der(ctx, p->der, p->dlen);
	cga_set_sec(ctx, p->sec);
	cga_set_prefix(ctx, pfx);

	if (cga_generate(ctx) != 0) {
		applog(LOG_ERR, "%s: cga_generate() failed", __FUNCTION__);
		return (-1);
	}
	memcpy(pfx, &ctx->addr, sizeof (*pfx));
	return (0);
}


/* Returns the CGA PDS option, for I2 and R2 messages
 * The CGA PDS is retrieved according to the ulid_local, as stated in draft
 * shim6-proto-09, appendix D.4.*/
struct cga_params* get_cga_pds_option(struct in6_addr* ulid_local, 
				      int ifidx)
{
	/*Retrieve the CGA structure*/
	struct cga_params *p=cga_get_params(ulid_local, ifidx);
	
	return p;
}

/*Fills the @iov vector for input to the CGA signing/verif algorithm.
 * @loclist : parsed locator list option
 * @buffer : This will be filled either by NULL (fast path) or a malloc'ed 
 *         pointer (slow path), if not NULL, the caller must free @buffer.
 * @return : -1 in case of failure
 *           0 in case of success
 */
static int gen_sign_input(struct loc_list_opt* loclist, 
			   struct iovec iov[3], void** buffer)
{
	int nb_cga=0;
	struct in6_addr* buf=NULL;
	int i;
	
	iov[0].iov_base = shim6_msg_type_tag;
	iov[0].iov_len  = sizeof (shim6_msg_type_tag);
	iov[1].iov_base = loclist->gen_nb;
	iov[1].iov_len  = sizeof(*loclist->gen_nb);
	/*We only look locators with verif method set to CGA*/
	for (i=0;i<*loclist->num_locs;i++) {
		if (loclist->verif_method[i]==SHIM6_CGA) nb_cga++;
	}
	if (nb_cga==0) {
		syslog(LOG_ERR, "Tried to verify a CGA signature, but"
		       " no cga is present in that loc list\n");
		return -1;
	}
			
	iov[2].iov_len=nb_cga*sizeof(struct in6_addr);

	/*Fast path*/
	if (nb_cga==*loclist->num_locs) {
		iov[2].iov_base=loclist->locators;
	}
	else { /*slow path*/
		buf=malloc(nb_cga*sizeof(struct in6_addr));
		if (!buf) {
			APPLOG_NOMEM();
			return -1;
		}
		for (i=0;i<*loclist->num_locs;i++) {
			if (loclist->verif_method[i]==SHIM6_CGA) {
				ipv6_addr_copy(&buf[i],
					       &loclist->locators[i]);
			}
		}
		iov[2].iov_base=buf;
	}
	
	*buffer=buf;
	return 0;
}

/* @loclist : The locator list option. This function will parse the option to 
 *            find which locators and locator generation number to use as 
 *            input for the signature algorithm.
 * @size : Will be filled by cga_sign with the length of the signature
 *
 * @returns: a pointer to signature; the caller must free this pointer
 *           NULL is returned in case of error
 */
uint8_t *cga_sign(struct loc_list_opt* loclist, int* slen, 
		  struct cga_params* pds)
{
	struct iovec iov[3];
	uint8_t* ans;
	void* buf;
	
	if (gen_sign_input(loclist, iov, &buf)<0) return NULL;
	
	ans= m->sign(iov, ARR_SZ(iov), slen, pds->key);
	
	if (buf) free(buf);
	return ans;
}

/*This makes the HBA/CGA verification for all locators.
 * @pre @rll must not be NULL
 * @post -1 is returned is any invalid locator is found.
 *
 */
int verify_cga_locators(struct shim6_opt* rll, struct shim6_opt* pds,
			struct shim6_opt* sign)
{
	struct loc_list_opt rloclist;
	cga_parsed_params_t ws[1];
	struct iovec iov[3];
	void* buf=NULL;
	int ans;
	int i;
	int sign_ok=0;
	
	/*First if loclist option is defined but not pds, 
	 * then any cga is considered invalid*/
	if (!pds) {
		PDEBUG("PDS option expected, but not found "
		       "in control packet\n");
		goto failed;
	}

	set_loc_list_opt(&rloclist,(char*)(rll+1));

	if (sign && gen_sign_input(&rloclist, iov, &buf)<0) goto failed;

	ws->buf = (uint8_t*)(pds+1);
	ws->dlen = ntohs(pds->length);

	if (cga_parse_params(ws)<0) {
		PDEBUG("Bad CGA Parameter Data Structure\n");
		goto failed;
	}
	
	PDEBUG("parse params OK\n");

	if ((!ws->mpe || ws->mpe->P) && sign) {
		/*Verify the signature*/
		ans=m->verify(iov,ARR_SZ(iov),ws->key,ws->klen,
			      (uint8_t*)(sign+1), ntohs(sign->length));
		if (ans<0) {
			PDEBUG("Bad CGA signature\n");
			goto failed;
		}
		sign_ok=1;
		PDEBUG("signature OK\n");
	}

	/*Verify each locator*/
	for (i=0;i<*rloclist.num_locs;i++) {
		/*If the verif method is CGA, we do not need to check
		  it against the PDS, it only needs to be part of the
		  signature (verified above) and the peer ULID is the only
		  address that needs to be verified against the PDS 
		  (call to shim6_is_remote_cga() in shim6d.c)*/
		switch(rloclist.verif_method[i]) {
		case SHIM6_CGA:
			if (!sign_ok) goto failed; 
			break;
		case SHIM6_HBA:
			if (!shim6_is_remote_cga(pds, &rloclist.locators[i], 1))
				goto failed;
			break;
		default: goto failed; /*Unknown verif method*/			
		}
	}

	
	if (buf) free(buf);

	return 1;
failed:
	PDEBUG("%s : At least one locator is invalid, "
	       "rejecting packet\n",__FUNCTION__);
	if (buf) free(buf);
	return -1;
}
