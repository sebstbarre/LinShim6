/*
 *	Linux Shim6 (LinShim6) implementation, options implementation
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : June 2008
 *
 *      TODO : Support CGA signature cache.
 *
 *      Based on draft-ietf-shim6-proto-10
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <config.h>
#include <strings.h>
#include <list.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <list.h>

#include <shim6/shim6d.h>
#include "opt.h"
#include "shim6_local.h"

#include <utils/debug.h>
#include <cryptoshim6/cga.h>
#include <cga.h>

/*For the implementation of options, we must work in two steps :
 * ->Compute the length of all options so that the caller is able to 
 * reserve the right amount of memory, this is done by calling successive
 * "add_xxx" functions. This file creates temporary state to maintain
 * information about these options. For this reason, the first and second steps
 * must be atomic (In this architecture this is ensured by letting only the 
 * main thread access such functions).
 * ->The second step is to write the options
 *
 * Note : - opt_init MUST be called before add_xxx
 *        - since free_all is called in case any error is caused, 
 *          option processing MUST be stopped if any add_xxx function
 *          returns -1 (failing to do that would cause an assertion(ctx!=NULL)
 *          failed.)
 */

/*=================================*/

struct option {
	struct list_head   list;
	int                (*write)(char* buf, struct option* opt);
	int                total_length;
	int                pad_length;
};


/*==================================*/
/*Local state*/
static LIST_HEAD(options);
static struct shim6_ctx* ctx=NULL;
static struct loc_list_opt loclist={.gen_nb=NULL};
static struct cga_params* pds=NULL;
static struct signature sgn={NULL,0};
static int need_signature=0;
static int need_pds=0;

/*==================================*/

/**********************************************************************
 *Code for option writing
 **********************************************************************/

/*Deletes every local state and free the associated memory*/
static void free_all(void)
{
	struct option* it;
	struct option* temp;
	list_for_each_entry_safe(it,temp,&options,list) {
		list_del(&it->list);
		free(it);
	}
	
	ctx=NULL;
	pds=NULL;
/*We do not free loclist and signature, to avoid recomputing the
 * signature if it is not necessary. (that is, the loclist gen number
 * has changed)*/
}

void opt_init(struct shim6_ctx* context)
{
	struct locset* ls;
	if (!list_empty(&options)) {
		syslog(LOG_WARNING,"Options list is not empty at init."
		       " Is it normal ??\n");
		free_all();
	}
	ctx=context;
	
	/*If we are attacking, setting the context is all what needs to be done
	  (since everything is set up in beforehand by attack_set_params()*/
	if (attack) return;
	
	/* In the options we always send the latest version of the locator list
	 * Retrieving the newest locset that may be used with ctx.
	 */
	ls=newest_locset(ctx->ls_localp);

	if ((loclist.gen_nb && 
	     ls->gen_number!=ntohl(*loclist.gen_nb))
#ifdef SHIM6EVAL
	    || nooptcache
#endif
		) {
		free(loclist.gen_nb);
		loclist.gen_nb=NULL;
		if (sgn.sign) {
			free(sgn.sign);
			sgn.sign=NULL;
		}
	}
}

#ifdef SHIM6EVAL
/*Facility to set precomputed params when performing an attack.*/
void attack_set_params(struct parameters *params)
{
	struct cga_parsed_params ws[1];
	set_loc_list_opt(&loclist,params->loclist.gen_nb);
	memcpy(&sgn,&params->sgn,sizeof(sgn));
	pds=params->pds;		
	ws->buf = pds->der;
	ws->dlen = pds->dlen;
	cga_parse_params(ws);
	/* Change prefix to addr's */
	memcpy(ws->pfx, params->ulid.addr.s6_addr, 8);
}
#endif

static int write_vali2_option(char* buf, struct option* opt)
{
	memcpy(buf,ctx->r1_vldt,opt->total_length);
	return 0;
}


/*Validator option field - Message i2*/
int add_vali2_option()
{
	struct option* opt;

	ASSERT(ctx);
	if (!ctx->r1_vldt) return 0;
	
	opt=malloc(sizeof(struct option));
	if (!opt) goto failure;
	list_add_tail(&opt->list,&options);
	opt->write=write_vali2_option;
	opt->total_length=TOTAL_LENGTH(ntohs(ctx->r1_vldt->length));
	return opt->total_length;
failure:
	free_all();
	return -1;
}

static int write_loc_option(char* buf, struct option* opt)
{
	struct shim6_opt* tl;
	
	ASSERT(loclist.gen_nb);

	tl=(struct shim6_opt*) (buf);
	tl->type=htons(SHIM6_TYPEOPT_LOC_LIST);
	/*For loc list option, pad_len must be included in the length field, 
	  according to draft shim6-proto-09 section 5.15.2*/
	tl->length=htons(opt->total_length-sizeof(struct shim6_opt));

	memcpy(tl+1,loclist.gen_nb,opt->total_length-sizeof(struct shim6_opt));
	
	return 0;
}

/**
 * Locator option field
 * Since we are sending locators to the host (with I2,R2, or UR), we
 * use the main locator set to build the list, not the local pointer
 * of the context. The aim is to replace the local pointer with the one 
 * from the system when the loclist will be aknowledged by the peer.
 */
int add_loc_option(void)
{
	struct option* opt;
	int opt_len;
	void* loclistp;
	int nb_locs=0;
	int useall; /*1 if all available locators are sent*/
	int allnonsecure; /*1 if all available locators are sent, without
			      any security (shim6eval only)*/
	struct locset *ls;

	PDEBUG("Adding loc option\n");

	ASSERT(ctx);
	
	if (!attack) {
		nb_locs=get_nb_loc_locs(ctx,TRUE,&allnonsecure,&useall, &ls);
		if (nb_locs<0) goto failure;
	}
	else {
		nb_locs=2; /*Parallel mode in shim6eval supports only 2 locs*/
		need_signature=1;
	}

	if (nb_locs==1) {
		/*If only one locator is available, there is no need for
		  loc option, pds option, nor signature option.*/
		need_pds=0;
		need_signature=0;
		return 0;
	}

	if (ctx->pds_acked) need_pds=0;
	else need_pds=1;

#ifdef SHIM6EVAL
	if (measure_sec==0) need_pds=0;
#endif

	
	opt_len=5+17*nb_locs;
	opt=malloc(sizeof(struct option));
	if (!opt) goto failure;
	list_add_tail(&opt->list,&options);
	opt->write=write_loc_option;
	opt->total_length=TOTAL_LENGTH(opt_len);
	opt->pad_length=PAD_LENGTH(opt_len);

	/*We need to pre-create the option, for future call of
	 * add_cga_sign_option()*/
	
	/*If already created and valid (validity check in opt_init(),
	  just keep the current option*/
	if (loclist.gen_nb) return opt->total_length;
	
	loclistp=malloc(opt->total_length);
	if (!loclistp) goto failure;

	loclist.gen_nb=loclistp;
	loclist.num_locs=(uint8_t*)(loclist.gen_nb+1);
	loclist.verif_method=loclist.num_locs+1;
	loclist.padding=loclist.verif_method+nb_locs;
	loclist.locators=(struct in6_addr*)(loclist.padding+opt->pad_length);

	*loclist.gen_nb=htonl(ls->gen_number);
	*loclist.num_locs=nb_locs;

	memset(loclist.padding,0,opt->pad_length);
	
	if (get_loc_locs_array(ctx,TRUE,loclist.locators,loclist.verif_method,
			       allnonsecure,useall,&need_signature)<0)
		goto failure;
	
	return opt->total_length;
failure:
	syslog(LOG_ERR, "%s: failure", __FUNCTION__);
	free_all();
	return -1;
}

static int write_cga_pds_option(char* buf, struct option* opt)
{
	struct shim6_opt* tl;
	int pad_len=opt->pad_length;
	
	tl=(struct shim6_opt*) (buf);
	tl->type=htons(SHIM6_TYPEOPT_CGA_PDS);
	tl->length=htons(opt->total_length-4-pad_len);
	memcpy(tl+1,pds->der,pds->dlen);
	bzero((char*)(tl+1)+pds->dlen,pad_len); /*padding*/
	return 0;
}

/*CGA PDS option*/
int add_cga_pds_option()
{
	struct option* opt;
	
	ASSERT(ctx);

	PDEBUG("Adding cga pds option\n");
	
	if (!need_pds) return 0;

	pds=get_cga_pds_option(&ctx->ulid_local.addr,ctx->ulid_local.ifidx);
	
	opt=malloc(sizeof(struct option));
	if (!opt) goto failure;
	list_add_tail(&opt->list,&options);
	opt->write=write_cga_pds_option;
	opt->total_length=TOTAL_LENGTH(pds->dlen);
	opt->pad_length=PAD_LENGTH(pds->dlen);

	ctx->pds_sent=1;

	return opt->total_length;
failure:
	free_all();
	return -1;
}

static int write_cga_sign_option(char* buf, struct option* opt)
{
	struct shim6_opt* tl;
	int pad_len=opt->pad_length;
	
	tl=(struct shim6_opt*) (buf);
	tl->type=htons(SHIM6_TYPEOPT_CGA_SIGN);
	tl->length=htons(opt->total_length-4-pad_len);
	memcpy(tl+1,sgn.sign,sgn.slen);
	bzero((char*)(tl+1)+sgn.slen,pad_len); /*padding*/
	return 0;
}

/*CGA signature option*/
int add_cga_sign_option()
{
	struct option* opt;

	PDEBUG("Adding CGA sign option\n");
	
	/*If all addresses are verified with HBA, no signature
	  is needed*/
	if (!need_signature) return 0;

	ASSERT(ctx);
	ASSERT(loclist.gen_nb);		

	if (!pds) {
		/*This happens only in case of sending an ur message.
		 * Indeed, in case of ur, we want to sign the 
		 * locators, but we don't need to insert the cga pds
		 * option*/
		pds=get_cga_pds_option(&ctx->ulid_local.addr,
				       ctx->ulid_local.ifidx);
	}

	opt=malloc(sizeof(struct option));
	if (!opt) goto failure;
	list_add_tail(&opt->list,&options);
	opt->write=write_cga_sign_option;

	if (!sgn.sign) sgn.sign=cga_sign(&loclist,&sgn.slen,pds);
	if (!sgn.sign) goto failure;
	
	opt->total_length=TOTAL_LENGTH(sgn.slen);
	opt->pad_length=PAD_LENGTH(sgn.slen);

	return opt->total_length;
failure:
	free_all();
	return -1;
}

static int write_ka_option(char* buf, struct option* opt)
{
	struct shim6_opt* tl;
	struct ka_opt* v;
	tl=(struct shim6_opt*) (buf);
	v=(struct ka_opt*)(tl+1);
	tl->type=htons(SHIM6_TYPEOPT_KA);
	tl->length=htons(opt->total_length-sizeof(struct shim6_opt));
	
	/*Filling the option*/
	v->reserved=0;
	v->tka=htons(get_tsend());
	
	return 0;
}

/*Keepalive Timeout option*/
int add_ka_option(void)
{
	struct option* opt;
	ASSERT(ctx);

	PDEBUG("Adding ka option\n");
	
	/*If send timer is the default, the option is not
	  necessary*/
	if (get_tsend()==REAP_SEND_TIMEOUT) return 0;
	
	opt=malloc(sizeof(struct option));
	if (!opt) goto failure;
	list_add_tail(&opt->list,&options);
	opt->write=write_ka_option;
	opt->total_length=8;
	
	return opt->total_length;
failure:
	free_all();
	return -1;
}

/*Writes every selected option (with add_xxx), and returns a pointer to the 
 * first byte following
 * the last option*/
char* write_options(char* buf)
{
	struct option* it;
	list_for_each_entry(it,&options,list) {
		if (it->write(buf,it)<0) goto failure;
		buf+=it->total_length;
	}
	free_all();
	return buf;
failure:
	free_all();
	return NULL;
}


/**********************************************************************
 *Code for option reception (parsing)
 **********************************************************************/

struct shim6_opt* psd_opts[PO_MAX];


/**
 * @buf : a pointer to the first option
 * @packet_end : pointer to the first byte following the end of the packet.
 * @msg_type : type of shim6 message, for example SHIM6_TYPE_I1
 * @ctx : pointer to the corresponding context. This is only needed if the
 *   message is an update request (to recuperate the cached CGA PDS).
 *   For other messages, it can be NULL.
 * @return : success : 0, failure : -1
 *
 */
int parse_options(struct shim6_opt* buf, char* packet_end, int msg_type,
		  struct shim6_ctx* ctx)
{
	struct shim6_opt* tl;
	int opt_len;

	/*init psd_opts*/
	bzero(psd_opts,sizeof(psd_opts));
	
	for (tl=buf;
	     (char*)tl+sizeof(struct shim6_opt)<=packet_end;
	     tl=(struct shim6_opt*)((char*)tl+TOTAL_LENGTH(opt_len))) {
		/*Verify that option is not longer than packet*/
		opt_len=ntohs(tl->length);
		if ((char*)tl+TOTAL_LENGTH(opt_len)>packet_end) {
			syslog(LOG_ERR,
			       "%s : error in option length\n", __FUNCTION__);
			return -1;
		}
		switch(ntohs(tl->type)) {
		case SHIM6_TYPEOPT_VALIDATOR:
			psd_opts[PO_VLDT]=tl;
			break;			
		case SHIM6_TYPEOPT_LOC_LIST:
			psd_opts[PO_LOC]=tl;
			break;
		case SHIM6_TYPEOPT_CGA_PDS:
			psd_opts[PO_PDS]=tl;
			break;
		case SHIM6_TYPEOPT_CGA_SIGN:
			psd_opts[PO_SIGN]=tl;
			break;
		case SHIM6_TYPEOPT_KA:
			if (opt_len!=4) break;
			psd_opts[PO_KA]=tl;
			break;
		default:
			syslog(LOG_INFO, 
			       "%s : unknown option field"
			       " : %d\n",__FUNCTION__,ntohs(tl->type));
			/*draft10, sec. 5.15: if the critical bit is set, drop
			  the whole message, if not, just drop the option.
			  TODO : Also send an error message if the C bit is 
			  set*/
			if (ntohs(tl->type)&0xFFFFE) return -1;
		}
	}

	/*Checking for mandatory options*/
	if (msg_type==SHIM6_TYPE_I2 && !psd_opts[PO_VLDT]) {
		PDEBUG("I2 recvd without vldt option\n");
		return -1;
	}

	/*validity checks*/
	if (psd_opts[PO_VLDT] && ntohs(psd_opts[PO_VLDT]->length) != 
	    VAL_LENGTH) {
		PDEBUG("%s:invalid validator length\n",__FUNCTION__);
		return -1;
	}

	/*If the CGA PDS is not present, set it to its cached value*/
	if (!psd_opts[PO_PDS] && ctx)
		psd_opts[PO_PDS]=ctx->pds;
	
	/*Verifying signature*/
	if (psd_opts[PO_LOC]) {
		struct loc_list_opt rloclist;
		set_loc_list_opt(&rloclist,psd_opts[PO_LOC]+1);

		
		
		/*Verifying that we have at least one locator 
		  and all locators fit in the packet.:*/
		if (*rloclist.num_locs==0 || 
		    (char*)rloclist.locators+*rloclist.num_locs*
		    sizeof(struct in6_addr) > packet_end) {
			syslog(LOG_ERR, 
			       "shim6 : bad number of locators\n");
			return -1;
		}
		
#ifndef NO_CGA_CHECK
		if (verify_cga_locators(psd_opts[PO_LOC],psd_opts[PO_PDS],
					psd_opts[PO_SIGN])<0)
			return -1;
#endif
	}

	return 0;
}
