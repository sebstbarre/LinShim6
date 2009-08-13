/*
 *	Linux shim6 implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *  TODO :     - Monitor the state of the addresses (subscribe to 
 *               the kernel events
 *               that notify when an address appears/disappears/...)
 *             - Replace the current way of dealing with the loc list gen
 *               number to replace it with a random number saved in each
 *               context. This is to prevent an attacker from sending false
 *               Locator preferences updates to the peer, by guessing the 
 *               loc list number.
 *             - If for some reason a context never enters the established
 *               state, it is also never destroyed, since the tear-down signal
 *               is given by the kernel, and the kernel gets state only when
 *               entering the established state. We thus need to add a timer 
 *               (or timestamp) on contexts, until they reach established state.
 *  
 *
 *
 *	date : March 2009
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <config.h>

#include <shim6/shim6d.h>
#include <cryptoshim6/cga.h>
#include "shim6_rawsocket.h"
#include "opt.h"
#include "xfrm.h"
#include "shim6_local.h"
#include "idips.h"
#include "random.h"
#include "testparams.h"

#include <linux/shim6_netlink.h>
#include <linux/shim6.h>
#include <linux/xfrm.h>
#include <net/if.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <ifaddrs.h>
#include <list.h>

#include <utils/util.h>
#include <utils/jhash.h>
#include <utils/debug.h>
#include <utils/checksum.h>

/*===============*/

/*Global locator table management*/

struct locset glob_loc_sets; /*This is a rare use of list.h : In this
				circular list, every node has a content
				(there is no content-less head)*/
static int glob_gen_nb=0; /*Even if we have different locator sets working at 
			    the same time, none of them will have the same
			    generation number, because each gen number is 
			    picked from this global variable*/

/*===============*/


static const struct timespec RESP_NONCE_UPDATE = {
	.tv_sec=SHIM6_VALIDATOR_MIN_LIFETIME,
	.tv_nsec=0};
#define RESP_SECRET_UPDATE_FACTOR 10 /*10 times RESP_NONCE_UPDATE*/
static int cur_resp_nonce; /*Responder nonce : 
			    *Incremented every RESP_NONCE_UPDATE
			    * Initialized (in shim6d_init) to a random number
			    * to prevent problems with reboot.
			    */
struct tq_elem resp_nonce_timer; /*Timer for resp. nonce update*/


/*SHA1 variables*/
__u32 prev_resp_secret;
__u32 resp_secret;

struct sha1_input {
	__u32 secret;
	__u32 resp_nonce;
	uint64_t init_ct; /*Initiator context tag*/	
	struct in6_addr ulid_local; /*From the I1 message*/
	struct in6_addr ulid_peer; /*From the I1 message*/
};


/*===============*/
/*Function declarations*/

/**
 * Handler for the I1/I2 retransmit timer
 */
static void shim6_retransmit(struct tq_elem* timer);

static struct shim6_ctx* __init_shim6_ctx(struct shim6_loc_l* ulid_local,
					  struct in6_addr* ulid_peer,
					  int* new);

/*===============*/

struct list_head ulid_hashtable[SHIM6_HASH_SIZE];
struct list_head ct_hashtable[SHIM6_HASH_SIZE];
struct list_head init_list; /*list of contexts in course of initialization.*/

/* Looks up for a context using the context tag hash table
 */
 
struct shim6_ctx* lookup_ct(uint64_t ct) 
{
	int ct_hash;
	struct shim6_ctx* ctx;

	ct_hash=hash_ct(ct);

	list_for_each_entry(ctx,&ct_hashtable[ct_hash],collide_ct) {
		if (ctx->ct_local==ct) {
			return ctx;
		}
	}
	return NULL; /*not found*/
}

/*
 * Returns the context if it exists, else NULL
 */
struct shim6_ctx* lookup_ulid(struct in6_addr* ulid_peer,
			      struct in6_addr* ulid_local) 
{
	struct shim6_ctx* ctx;
	int ulid_hash=hash_ulid(ulid_peer);
	
	/*lookup*/
	list_for_each_entry(ctx,&ulid_hashtable[ulid_hash],
			    collide_ulid) {
		if (ipv6_addr_equal(&ctx->ulid_local.addr,ulid_local) &&
		    ipv6_addr_equal(&ctx->ulid_peer,ulid_peer)) {
			return ctx;
		}
	}
	return NULL;
}

int nb_glob_locs(void)
{
	int nb=0;
	int list_cnt;
	struct locset* ls;

	list_for_each_entry_all(ls,&glob_loc_sets.list,list,list_cnt) {
		nb+=ls->size_not_broken;
	}
	return nb;
}

uint64_t gen_new_ct(void)
{
	uint32_t spi; /*Used for hashtable lookup in the kernel,
		     cannot be zero.*/
	uint32_t high_order;
	uint64_t ct=0;
	int count=0;
	do {
		spi=random_int();
		if (!spi) continue;
		high_order=random_int()&0x7FFF;
		ct=high_order;
		ct<<=32;
		ct+=spi;
		count++;
	} while(lookup_ct(ct) && count < 100);
	if (count==100) {
		syslog(LOG_ERR,"Impossible to generate a new context tag\n"
		       "\t Too many shim6 context states ?\n");
		return 0;
	}
	else return ct;
}

static void resp_nonce_handler(struct tq_elem* timer)
{
	/*update the cur_resp_nonce*/
	/*When arriving at 0x7FFFFFFF (max positive), it will
	 *automatically come back for another cycle at 0x80000000 (min neg.)
	 *so we don't need to care about modulo.
	 */
	cur_resp_nonce++;
	if (cur_resp_nonce%RESP_SECRET_UPDATE_FACTOR==0) {
		/*update resp_secret*/
		prev_resp_secret=resp_secret;
		resp_secret=random_int();
	}
	/*Restart the timer*/
	add_task_rel(&RESP_NONCE_UPDATE,&resp_nonce_timer,resp_nonce_handler);
}

/*Computes the responder hash and put it in dest
 * Warning : dest must be a valid pointer to a 20 bytes place
 * @prev : If TRUE, prev_resp_secret is used instead of resp_secret
 */
static inline void get_resp_hash(unsigned char* dest,__u32 resp_nonce,
				 uint64_t init_ct,
				 struct in6_addr* ulid_local,
				 struct in6_addr* ulid_peer, int prev) {

	struct sha1_input input;
	
	input.secret=(prev)?prev_resp_secret:resp_secret;
	input.resp_nonce=resp_nonce;
	input.init_ct=init_ct;
	ipv6_addr_copy(&input.ulid_local,ulid_local);
	ipv6_addr_copy(&input.ulid_peer,ulid_peer);
	
	SHA1((const unsigned char*)&input,sizeof(input),dest);
}

/* init_nonce is supposed to be already in network byte order
 * (because this is just a copy from the i1 message)
 * src_addr is the source and destination addresses used to send this 
 * R1 packet.
 */
static inline int send_r1( struct in6_addr* src_addr, 
			   struct in6_addr* dst_addr,
			   uint32_t init_nonce, uint64_t ct_peer) 
{
	struct shim6hdr_r1* r1;
	union shim6_msgpp r1_msg={.r1=&r1};
	struct shim6_opt* tl; /*tl part of the tlv option field*/
	int total_length;
	void* optionsp;
	int opts_len=TOTAL_LENGTH(VAL_LENGTH);
	
	PDEBUG("Sending r1 message...\n");	

	if (shim6_alloc_send(sizeof(shim6hdr_r1),opts_len,
			     SHIM6_TYPE_R1, r1_msg, &optionsp)<0) {
		syslog(LOG_ERR, "send_r1:shim6_alloc_send failed\n");
		return -1;
	}

	total_length=sizeof(shim6hdr_r1)+opts_len;
		
	/*Eventually we fill the packet itself*/
		
	r1->reserved=0;
	r1->init_nonce=init_nonce;
	r1->resp_nonce=htonl(cur_resp_nonce);

	/*Filling the validator option field. We do not use the opt.h 
	  interface for this option, because it is short
	  and it needs too many arguments*/
	tl=optionsp;
	tl->type=htons(SHIM6_TYPEOPT_VALIDATOR);
	tl->length=htons(VAL_LENGTH);
	
	get_resp_hash((unsigned char*)(tl+1),ntohl(r1->resp_nonce),ct_peer,
		      src_addr,dst_addr,FALSE);
	memset(((char*)(tl+1))+VAL_LENGTH,0,PAD_LENGTH(VAL_LENGTH));
	
	/*Computing checksum*/
	r1->common.csum=ipsum_calculate((unsigned char*)r1,
					(r1->common.hdrlen+1)*8,NULL);

	/*Sending the packet*/

	if (shim6_send(r1, total_length, src_addr, 
		       dst_addr)<0) return -1;

	return 0;
}


static inline int send_r1bis(struct in6_addr* local_loc, 
			     struct in6_addr* peer_loc,uint64_t pkt_ct) 
{
	shim6hdr_r1bis *r1bis;
	union shim6_msgpp r1bis_msg={.r1bis=&r1bis};
	struct shim6_opt* tl; /*tl part of the tlv option field*/
	int total_length;
	void* optionsp;
	int opts_len=TOTAL_LENGTH(VAL_LENGTH);
	
	PDEBUG("Sending r1bis message...\n");	

	if (shim6_alloc_send(sizeof(shim6hdr_r1bis),opts_len,
			     SHIM6_TYPE_R1BIS,r1bis_msg,&optionsp)<0) {
		syslog(LOG_ERR,"%s:shim6_alloc_send failed\n",__FUNCTION__);
		return -1;
	}
	total_length=sizeof(shim6hdr_r1bis)+opts_len;

	set_ct(pkt_ct,r1bis->ct_1,r1bis->ct_2,r1bis->ct_3);
	r1bis->R=0;
	r1bis->nonce=htonl(cur_resp_nonce);

	/*Filling the validator option field. We do not use the opt.h 
	  interface for this option, because it is short
	  and it needs too many arguments*/
	tl=optionsp;
	tl->type=htons(SHIM6_TYPEOPT_VALIDATOR);
	tl->length=htons(VAL_LENGTH);
	
	get_resp_hash((unsigned char*)(tl+1),ntohl(r1bis->nonce),pkt_ct,
		      local_loc,peer_loc,FALSE);
	memset(((char*)(tl+1))+VAL_LENGTH,0,PAD_LENGTH(VAL_LENGTH));

	/*Computing checksum*/
	r1bis->common.csum=ipsum_calculate((unsigned char*)r1bis,
					(r1bis->common.hdrlen+1)*8,NULL);
	
	/*Sending the packet*/
	
	if (shim6_send(r1bis, total_length, local_loc, 
		       peer_loc)<0) return -1;	
	return 0;
}

static int send_i1(struct shim6_ctx* ctx) 
{
	shim6hdr_i1 *i1;
	union shim6_msgpp i1_msg={.i1=&i1};
	int total_length=sizeof(shim6hdr_i1);
	
	PDEBUG("Sending i1 message...\n");
	
	if (shim6_alloc_send(sizeof(shim6hdr_i1),0,
			     SHIM6_TYPE_I1, i1_msg,NULL)<0) {
		syslog(LOG_ERR, "%s:shim6_alloc_send failed\n",__FUNCTION__);
		return -1;
	}
	
	set_ct(ctx->ct_local,i1->ct_1,i1->ct_2,i1->ct_3);
	
	/*If we are retransmitting, we use the previously computed 
	  nonce.*/
	if (ctx->state!=SHIM6_I1_SENT) ctx->init_nonce=random_int();
	i1->nonce=htonl(ctx->init_nonce);
	i1->R=0;		
	i1->common.csum=ipsum_calculate((unsigned char*)i1,
					(i1->common.hdrlen+1)*8,NULL);
	
	/*Sending the packet*/

	if (shim6_send(i1, total_length, &ctx->lp_local, 
		       &ctx->lp_peer)<0) return -1;

	ctx->state=SHIM6_I1_SENT;

	return 0;
}

static int send_i2(struct shim6_ctx* ctx) 
{
	shim6hdr_i2* i2;
	union shim6_msgpp i2_msg={.i2=&i2};
	int opts_len=0; /*Total length of all options*/
	int total_length;
	int len;
	void* optionsp;

	PDEBUG("Sending i2 message...\n");
	
	/*Preparing options*/
#ifdef SHIM6EVAL
	if (attack)
		attack_set_params(&params[ctx->eval_counter/2]);		
#endif

	opt_init(ctx);
	if ((len=add_vali2_option())<0) return -1;
	opts_len+=len;
	if ((len=add_loc_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_pds_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_sign_option())<0) return -1;
	opts_len+=len;
	if ((len=add_ka_option())<0) return -1;
	opts_len+=len;
	
	
	if (shim6_alloc_send(sizeof(shim6hdr_i2),opts_len,
			     SHIM6_TYPE_I2, i2_msg,&optionsp)<0) {
		syslog(LOG_ERR, "%s:shim6_alloc_send failed\n",__FUNCTION__);
		return -1;
	}

	total_length=sizeof(shim6hdr_i2)+opts_len;	

	/*Writing options. We need to do that before filling the main i2 part
	 * for the checksum to be correct*/
	if (!write_options(optionsp)) return -1;
	
	/*Eventually we fill the packet itself*/

	set_ct(ctx->ct_local,i2->ct_1,i2->ct_2,i2->ct_3);

	i2->init_nonce=htonl(ctx->init_nonce);
	i2->resp_nonce=ctx->resp_nonce; /*Already in network byte order*/
	i2->reserved=0;
	i2->common.csum=ipsum_calculate((unsigned char*)i2,
					(i2->common.hdrlen+1)*8,NULL);
	
	/*Sending the packet*/
	
	if (shim6_send(i2, total_length, &ctx->lp_local, 
		       &ctx->lp_peer)<0) return -1;
	
	ctx->state=SHIM6_I2_SENT;
	
	return 0;
}

static int send_i2bis(struct shim6_ctx* ctx)
{
	shim6hdr_i2bis* i2bis;
	union shim6_msgpp i2bis_msg={.i2bis=&i2bis};
	int opts_len=0; /*Total length of all options*/
	int total_length;
	int len;
	void* optionsp;

	PDEBUG("Sending i2bis message...\n");
	
	/*Preparing options*/
	opt_init(ctx);
	if ((len=add_vali2_option())<0) return -1;
	opts_len+=len;
	if ((len=add_loc_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_pds_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_sign_option())<0) return -1;
	opts_len+=len;
	if ((len=add_ka_option())<0) return -1;
	opts_len+=len;
	if ((len=add_ulid_option())<0) return -1;
	opts_len+=len;
		
	if (shim6_alloc_send(sizeof(shim6hdr_i2bis),opts_len,
			     SHIM6_TYPE_I2BIS, i2bis_msg,&optionsp)<0) {
		syslog(LOG_ERR, "%s:shim6_alloc_send failed\n",__FUNCTION__);
		return -1;
	}

	total_length=sizeof(shim6hdr_i2bis)+opts_len;	

	/*Writing options. We need to do that before filling the main i2 part
	 * for the checksum to be correct*/
	if (!write_options(optionsp)) return -1;
	
	/*Eventually we fill the packet itself*/

	set_ct(ctx->ct_local,i2bis->init_ct_1,i2bis->init_ct_2,
	       i2bis->init_ct_3);

	set_ct(ctx->ct_peer,i2bis->pkt_ct_1,i2bis->pkt_ct_2,i2bis->pkt_ct_3);
	/*If we are retransmitting, we use the previously computed 
	  nonce.*/
	if (ctx->state!=SHIM6_I2BIS_SENT) ctx->init_nonce=random_int();
	i2bis->init_nonce=htonl(ctx->init_nonce);
	i2bis->resp_nonce=ctx->resp_nonce; /*Already in network byte order*/
	i2bis->reserveda=i2bis->reservedb=0;
	i2bis->R=0;
	
	i2bis->common.csum=ipsum_calculate((unsigned char*)i2bis,
					   (i2bis->common.hdrlen+1)*8,NULL);
	
	/*Sending the packet*/
	
	if (shim6_send(i2bis, total_length, &ctx->lp_local, 
		       &ctx->lp_peer)<0) return -1;
	
	ctx->state=SHIM6_I2BIS_SENT;
	
	return 0;
}

static void shim6_holddown_handler(struct tq_elem* timer) 
{
	struct shim6_ctx* ctx=container_of(timer,struct shim6_ctx,
					   retransmit_timer);

	unsigned char random_byte;
	struct timespec timeout;

	/*Maybe we are no more in E_FAILED state*/
	if (ctx->state!=SHIM6_E_FAILED) return;

	PDEBUG("changing state from e-failed to idle\n");

	ctx->state=SHIM6_IDLE;
	send_i1(ctx);

	ctx->nb_retries=0;
	ctx->cur_timeout_val=SHIM6_I1_TIMEOUT; /*back to normal timeout*/
	
	random_byte=(__u8)random_int();
	tssetdsec(timeout, ctx->cur_timeout_val/2.0+
		  (random_byte*ctx->cur_timeout_val)/256.0);
	
	add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);
}


/**
 * @new_request is TRUE if a new request is done because of a change in the
 * locator list. It must be FALSE if this function is called by the 
 * retransmission timer.
 */
static int send_ur(struct shim6_ctx* ctx, int new_request) 
{
	shim6hdr_ur* ur;
	union shim6_msgpp ur_msg={.ur=&ur};
	int opts_len=0;
	int total_length;
	int len;
	void* optionsp;
	
	/*First of all, we must set the ur_pending bit, for correct
	  Initialization in opt_init*/
	ctx->ur_pending=1;

	/*Preparing options*/
	opt_init(ctx);
	if ((len=add_loc_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_pds_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_sign_option())<0) return -1;
	opts_len+=len;
	if ((len=add_ka_option())<0) return -1;
	opts_len+=len;

	
	PDEBUG("Sending update request message...\n");
	
	if (shim6_alloc_send(sizeof(shim6hdr_ur),opts_len,
			     SHIM6_TYPE_UPD_REQ, ur_msg,&optionsp)<0) {
		syslog(LOG_ERR, "%s:shim6_alloc_send failed\n",__FUNCTION__);
		return -1;
	}

	total_length=sizeof(shim6hdr_ur)+opts_len;
	
	/*Writing options. We need to do that before filling the main ur part
	 * for the checksum to be correct*/
	if (!write_options(optionsp)) return -1;
	
	/*Eventually we fill the packet itself*/

	set_ct(ctx->ct_peer,ur->ct_1,ur->ct_2,ur->ct_3);
	
	/*If we are retransmitting, we use the previously computed 
	  nonce.*/
	if (new_request) ctx->update_nonce=random_int();
	ur->nonce=htonl(ctx->update_nonce);
	ur->R=0;		
	ur->common.csum=ipsum_calculate((unsigned char*)ur,
					(ur->common.hdrlen+1)*8,NULL);
	
	/*Sending the packet*/

	if (shim6_send(ur, total_length, &ctx->lp_local, 
		       &ctx->lp_peer)<0) return -1;


	return 0;
}

/**
 * nonce is supposed to be already in network byte order
 * (because this is just a copy from the ur message)
 */
static int send_ua(struct shim6_ctx* ctx, uint32_t nonce)
{
	shim6hdr_ua* ua;
	union shim6_msgpp ua_msg={.ua=&ua};
	int total_length=sizeof(shim6hdr_ua);
	
	if (shim6_alloc_send(sizeof(shim6hdr_ua),0,
			     SHIM6_TYPE_UPD_ACK, ua_msg,NULL)<0) {
		syslog(LOG_ERR, "%s:shim6_alloc_send failed\n",__FUNCTION__);
		return -1;
	}
	set_ct(ctx->ct_peer,ua->ct_1,ua->ct_2,ua->ct_3);	
	ua->nonce=nonce;
	ua->R=0;
	ua->common.csum=ipsum_calculate((unsigned char*)ua,
					(ua->common.hdrlen+1)*8,NULL);
	
	/*Sending the packet*/
	if (shim6_send(ua, total_length, &ctx->lp_local, 
		       &ctx->lp_peer)<0) return -1;
	return 0;
}


/**
 * Handler for the I1/I2/UR retransmit timer
 */
static void shim6_retransmit(struct tq_elem* timer)
{
	int max_retries;
	int (*send_fct)(struct shim6_ctx*);
	struct shim6_ctx* ctx=container_of(timer,struct shim6_ctx,
					   retransmit_timer);
	uint8_t random_byte;
	struct timespec timeout;
    
	if (ctx->ur_pending) {
		PDEBUG("retransmission of ur message...\n");
		/*retransmission*/
		send_ur(ctx,FALSE);
		ctx->nb_retries++;
		/*Preparing next timeout, with exp. backoff and randomization*/
		if ((ctx->cur_timeout_val<<1) <= SHIM6_MAX_UPDATE_TIMEOUT) 
			ctx->cur_timeout_val<<=1;

		random_byte=(__u8)random_int();
		tssetdsec(timeout, ctx->cur_timeout_val/2.0+
			  (random_byte*ctx->cur_timeout_val)/256.0);
		
		add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);
		return;
	}

	PDEBUG("retransmission of i1/i2/i2bis message...\n");
	
	/*Adjusting variables*/
	if (ctx->state==SHIM6_I1_SENT) {
		max_retries=SHIM6_I1_RETRIES_MAX;
		send_fct=send_i1;
	}
	else if (ctx->state==SHIM6_I2_SENT) {
		max_retries=SHIM6_I2_RETRIES_MAX;
		send_fct=send_i2;
	}
	else if (ctx->state==SHIM6_I2BIS_SENT) {
		max_retries=SHIM6_I2BIS_RETRIES_MAX;
		send_fct=send_i2bis;
	}
	else if (!ctx->ur_pending)
		return; /*The state has changed while the timer was running,
			  just do nothing*/
		
	if (ctx->nb_retries<max_retries) 
	{
		/*retransmission*/
		send_fct(ctx);
		ctx->nb_retries++;

		/*Preparing next timeout, with exp. backoff and randomization*/
		ctx->cur_timeout_val<<=1; 
		
		random_byte=(__u8)random_int();
		tssetdsec(timeout, ctx->cur_timeout_val/2.0+
			  (random_byte*ctx->cur_timeout_val)/256.0);
		
		add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);
       
	}
	else if (ctx->state==SHIM6_I1_SENT) {
		/*Do negative caching*/
		ctx->state=SHIM6_E_FAILED;
		
		tssetsec(timeout,SHIM6_NO_R1_HOLDDOWN_TIME);
		add_task_rel(&timeout,&ctx->retransmit_timer,
			     shim6_holddown_handler);
	}
	else { /*state is SHIM6_I2_SENT or SHIM6_I2BIS_SENT*/
		send_i1(ctx); /*Back to I1_SENT state*/
		if (ctx->r1_vldt) {
			free(ctx->r1_vldt);
			ctx->r1_vldt=NULL;
		}
		
		/*Preparing next timeout, with exp. backoff and randomization*/

		ctx->nb_retries=0;
		ctx->cur_timeout_val=SHIM6_I1_TIMEOUT; 
		
		random_byte=(uint8_t)random_int();
		tssetdsec(timeout, ctx->cur_timeout_val/2.0+
			  (random_byte*ctx->cur_timeout_val)/256.0);
		
		add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);
	}
}

/*
 * Since nonce is a copy from an i1/i2 packet, it is supposed to be 
 * in network byte order.
 */
static inline int send_r2(__u32 nonce, struct shim6_ctx* ctx) 
{
	shim6hdr_r2* r2;
	union shim6_msgpp r2_msg={.r2=&r2};
	int total_length;
	int opts_len=0; /*Total length of all options*/
	int len;
	void* optionsp;

	PDEBUG("Sending r2 message...\n");
	

	/*Preparing options*/
	opt_init(ctx);
	if ((len=add_loc_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_pds_option())<0) return -1;
	opts_len+=len;
	if ((len=add_cga_sign_option())<0) return -1;
	opts_len+=len;
	if ((len=add_ka_option())<0) return -1;
	opts_len+=len;



	if (shim6_alloc_send(sizeof(shim6hdr_r2),opts_len,
			     SHIM6_TYPE_R2, r2_msg,&optionsp)<0) {
		syslog(LOG_ERR, "send_r2:shim6_alloc_send failed\n");
		return -1;
	}

	total_length=sizeof(shim6hdr_r2)+opts_len;


	/*Writing options. We need to do that before filling the main R2 part
	 * for the checksum to be correct*/
	if (!write_options(optionsp)) return -1;
	
	/*Eventually we fill the packet itself*/
		
	set_ct(ctx->ct_local,r2->ct_1,r2->ct_2,r2->ct_3);

	r2->R=0;
	
	r2->nonce=nonce; /*already in network byte order*/
	r2->common.csum=ipsum_calculate((unsigned char*)r2,
					(r2->common.hdrlen+1)*8,NULL);
    	
	/*Sending the packet*/
	
	if (shim6_send(r2, total_length, &ctx->lp_local, 
		       &ctx->lp_peer)<0) return -1;

#ifdef SHIM6EVAL
	/*Delete that context, to get prepared for the next trial*/
	if (server_mode)
		shim6_del_ctx(ctx);			
#endif
	
	return 0;
}

/* impl of draft shim6-proto-09 section 7.9
 */
int rcv_i1(shim6hdr_i1* hdr, struct in6_addr* saddr, struct in6_addr* daddr)
{
	struct in6_addr* ulid_local;
	struct in6_addr* ulid_peer;
	struct shim6_ctx* ctx;
	uint64_t ct_peer;
#ifdef LOG_RCV_I2_TIME
	struct timespec start,stop,total_time;
	static double time_array[NB_PARALLEL];
	static int count=0;
	clock_gettime(CLOCK_REALTIME,&start);
#endif


	PDEBUG("receiving i1 message\n");

	if (hdr->common.hdrlen<1) {
		PDEBUG("i1 length < 1\n");
		return -1;
	}
	
	

	/*TODO : verify presence of ulid option field,
	  in which case ulids must be taken from there.*/
	ulid_local=daddr;
	ulid_peer=saddr;
	

	get_ct(&ct_peer,hdr->ct_1,hdr->ct_2,hdr->ct_3);
	
	ctx=lookup_ulid(ulid_peer,ulid_local);
	if (!ctx || ctx->state==SHIM6_IDLE || ctx->state==SHIM6_E_FAILED) {
		send_r1(ulid_local, ulid_peer, hdr->nonce, ct_peer);
		goto finish;
	}
	
	/*TODO : Verify that locators are included in ctx locators set
	  This is necessary only if ulid option is present*/

	switch(ctx->state) {
	case SHIM6_I1_SENT:
	case SHIM6_I2_SENT:
	case SHIM6_I2BIS_SENT:
	case SHIM6_E_FAILED:		
		send_r2(hdr->nonce,ctx);
		break;
	case SHIM6_ESTABLISHED:
		if (ctx->ct_peer==ct_peer)
			send_r2(hdr->nonce,ctx);
		else 
			send_r1(ulid_local, ulid_peer, hdr->nonce, ct_peer);
		break;
	default:
		syslog(LOG_ERR, "shim6 : shim6 context has an unknown state !\n"
		       "Value is %d\n",ctx->state);
	}	

finish:
#ifdef LOG_RCV_I2_TIME
	clock_gettime(CLOCK_REALTIME,&stop);
	tssub(stop,start,total_time);
	time_array[count++]=tstodsec(total_time);
	if (count==NB_PARALLEL) {
		FILE* f;
		int i;
		f=fopen(LOCALSTATE_DIR "/shim6/i1.log", "a");
		if (!f) {
			syslog(LOG_ERR,"open : %m\n");
			return 0;
		}		
		for (i=0;i<NB_PARALLEL;i++) {
			fprintf(f,"%f\n",time_array[i]);
		}
		fclose(f);		
		count=0;
	}	
#endif

	return 0;
}


static inline shim6_loc_p* lookup_loc_p(struct in6_addr* loc, 
					struct shim6_ctx* ctx)
{
	int i;
	for (i=0;i<ctx->ls_peer.size;i++) 
		if (ipv6_addr_equal(loc,&((ctx->ls_peer.psetp+i)->addr)))
			return ctx->ls_peer.psetp+i; 
	return NULL;
}

/**
 * Returns the address of the locator corresponding to @loc, in any
 * set.
 * If @head is NULL, the glob_loc_sets list is searched. If not, 
 * The given list is searched.
 */
shim6_loc_l* lookup_loc_l(struct in6_addr* loc, struct list_head* head)
{
	int j;
	int list_cnt;
#ifdef SHIM6_DEBUG
	int i=0;
#endif	
	struct locset *ls;
	struct list_head* loc_sets=(head!=NULL)?head:&glob_loc_sets.list;
	list_for_each_entry_all(ls,loc_sets,list,list_cnt) {
		PDEBUG("glob loc set %d, size %d",i++,ls->size);
		for (j=0;j<ls->size;j++) 
			if (ipv6_addr_equal(loc,
					    &(ls->lsetp+j)->addr))
				return ls->lsetp+j;		
	}
	return NULL;
}

/**
 * Returns the address of the locator corresponding to @loc if 
 * it belongs to the locator set used by @ctx.
 */
shim6_loc_l* lookup_loc_l_ctx(struct in6_addr* loc, struct shim6_ctx* ctx)
{
	int i;
	ASSERT(ctx->ls_localp);
	/*If ctx uses the main list, then all available locators are part of
	  the set*/
	if (ctx->ls_localp->main) 
		return lookup_loc_l(loc, &ctx->ls_localp->list);
	for (i=0;i<ctx->ls_localp->size;i++) 
		if (ipv6_addr_equal(loc,
				    &ctx->ls_localp->lsetp[i].addr))
			return ctx->ls_localp->lsetp+i;
	return NULL;
}

/*
 * Returns the context if it exists, else NULL
 * This lookup follows the lookup specs for reception of an R1 message
 * (section 7.11)
 *
 */
static struct shim6_ctx* shim6_lookup_r1(uint32_t init_nonce,
				  struct in6_addr* loc_local,
				  struct in6_addr* loc_peer) 
{
	struct shim6_ctx *ctx;
	
	/*lookup*/
	list_for_each_entry(ctx,&init_list,init_list) {
		if (ctx->init_nonce != init_nonce) continue;
		if (!lookup_loc_l(loc_local,NULL)) continue;
		if (!lookup_loc_p(loc_peer,ctx)) continue;

		/*OK, this is the right context*/
		return ctx;
	}
	return NULL;
}

int rcv_r1(shim6hdr_r1* hdr, struct in6_addr* saddr, struct in6_addr* daddr)
{
	struct shim6_ctx *ctx;
	char* packet_end = (char*)hdr + ((hdr->common.hdrlen+1)<<3);
	struct shim6_opt *tl; /*tl part of the tlv option field
				(r1 only supports the validator option)*/
	uint8_t random_byte;
	struct timespec timeout;
#ifdef SHIM6EVAL	
	struct timespec before,after;
	clock_gettime(CLOCK_REALTIME,&before);
#endif
	
	PDEBUG("receiving r1 message\n");

	if (hdr->common.hdrlen<1) {
		PDEBUG("r1 length < 1\n");
		return -1;
	}

	ctx=shim6_lookup_r1(ntohl(hdr->init_nonce),daddr,saddr);
	if (!ctx) {
		PDEBUG("rcv_r1 : no ctx found\n");
		return -1;
	}
	PDEBUG("rcv_r1 : a ctx was found \n");

	if (ctx->state!=SHIM6_I1_SENT) return 0;
	
	tl=(struct shim6_opt*)(hdr+1);

       	/*is there a validator, well given ?*/
	if ((char*)tl+sizeof(struct shim6_opt)<=packet_end && 
	    ntohs(tl->type)==SHIM6_TYPEOPT_VALIDATOR &&
	    (char*)tl+TOTAL_LENGTH(ntohs(tl->length))==
	    packet_end) {
		ctx->r1_vldt=realloc(ctx->r1_vldt,
				     TOTAL_LENGTH(ntohs(tl->length)));
		memcpy(ctx->r1_vldt,tl,TOTAL_LENGTH(ntohs(tl->length)));
	}
	/*If no validator is supplied, the r1 is still considered Ok :
	 * It's up to the responder to guarantee its own security*/
	else if ((char*)tl!=packet_end) {
		PDEBUG("rcv_r1 : bad option length");
		return -1;
	}
	ctx->resp_nonce=hdr->resp_nonce;
	send_i2(ctx);
	
	/*Stopping current occurence of retransmit timer*/
	del_task(&ctx->retransmit_timer);
	
	/*Starting retransmit timer
	 * draft-proto-12, section 7.8 and 7.12 :
	 * -use of binary exponential backoff
	 * -randomize between 0.5 and 1.5 of computed time
	 */
	ctx->nb_retries=0;
	ctx->cur_timeout_val=SHIM6_I2_TIMEOUT; 
	
	random_byte=(uint8_t)random_int();
	tssetdsec(timeout, ctx->cur_timeout_val/2.0+
		  (random_byte*ctx->cur_timeout_val)/256.0);
	
	add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);

#ifdef SHIM6EVAL
	clock_gettime(CLOCK_REALTIME,&after);
	tssub(after,before,ctx->rcvr1_time);
#endif
	
	return 0;
}

/*
 * Returns the context if it exists, else NULL
 * This lookup follows the lookup specs for reception of an R1bis message
 * (section 7.18)
 *
 */
static struct shim6_ctx* shim6_lookup_r1bis(uint64_t ct_peer,
				     struct in6_addr* loc_local,
				     struct in6_addr* loc_peer) 
{
	struct shim6_ctx *ctx;
	int i;
	
	/*lookup*/
	for (i=0;i<SHIM6_HASH_SIZE;i++)
		list_for_each_entry(ctx,&ulid_hashtable[i],
				    collide_ulid) {
			if (ctx->ct_peer!=ct_peer) continue;
			if (!ipv6_addr_equal(loc_local,&ctx->lp_local) ||
			    !ipv6_addr_equal(loc_peer,&ctx->lp_peer)) continue;
			/*OK, this is the right context*/
			return ctx;
		}
	return NULL;
}

int rcv_r1bis(shim6hdr_r1bis* hdr, struct in6_addr* saddr, 
	      struct in6_addr* daddr)
{
	struct shim6_ctx *ctx;
	char* packet_end = (char*)hdr + ((hdr->common.hdrlen+1)<<3);
	struct shim6_opt *tl; /*tl part of the tlv option field
				(r1 only supports the validator option)*/
	uint8_t random_byte;
	struct timespec timeout;
	uint64_t ct;

	PDEBUG("receiving r1bis message\n");
	
	if (hdr->common.hdrlen<1) {
		PDEBUG("r1bis length < 1\n");
		return -1;
	}
	
	get_ct(&ct, hdr->ct_1, hdr->ct_2, hdr->ct_3);
	ctx=shim6_lookup_r1bis(ct,daddr,saddr);
	if (!ctx) {
		syslog(LOG_ERR, "%s : ctx not found\n",__FUNCTION__);
		return -1;
	}
		
	if (ctx->state!=SHIM6_ESTABLISHED) return 0;

	tl=(struct shim6_opt*)(hdr+1);
	
       	/*is there a validator, well given ?*/
	if ((char*)tl+sizeof(struct shim6_opt)<=packet_end && 
	    ntohs(tl->type)==SHIM6_TYPEOPT_VALIDATOR &&
	    (char*)tl+TOTAL_LENGTH(ntohs(tl->length))==
	    packet_end) {
		ctx->r1_vldt=realloc(ctx->r1_vldt,
				     TOTAL_LENGTH(ntohs(tl->length)));
		memcpy(ctx->r1_vldt,tl,TOTAL_LENGTH(ntohs(tl->length)));
	}
	/*If no validator is supplied, the r1 is still considered Ok :
	 * It's up to the responder to guarantee its own security*/
	else if ((char*)tl!=packet_end) {
		PDEBUG("%s : bad option length",__FUNCTION__);
		return -1;
	}

	ctx->resp_nonce=hdr->nonce;
	send_i2bis(ctx);

	/*Stopping current occurence of retransmit timer*/
	del_task(&ctx->retransmit_timer);
	
	/*Starting retransmit timer
	 * draft-proto-12, section 7.8 and 7.12 :
	 * -use of binary exponential backoff
	 * -randomize between 0.5 and 1.5 of computed time
	 */
	ctx->nb_retries=0;
	ctx->cur_timeout_val=SHIM6_I2BIS_TIMEOUT; 
	
	random_byte=(uint8_t)random_int();
	tssetdsec(timeout, ctx->cur_timeout_val/2.0+
		  (random_byte*ctx->cur_timeout_val)/256.0);
	
	add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);
	
	return 0;
}

/**
 * @per : set1 and set2 contain locators of kind shim6_loc_p (peer locators)
 *
 * Returns TRUE if there is at least one locator common to both sets.
 */
static int intersecting_locsets(struct locset* set1, struct locset* set2)
{
	int i,j;
	for (i=0;i<set1->size;i++)
		for (j=0;j<set2->size;j++) {
			if (ipv6_addr_equal(&set1->psetp[i].addr,
					    &set2->psetp[j].addr))
				return TRUE;
		}
	return FALSE;
}

/**
 * Implements draft shim6-proto-10, section 7.6 and 7.15
 * Checks the given context against all other existing contexts 
 * to detect context confusion and remove the old now invalid contexts
 * @pre : @ctx must have the peer context tag and the peer locator list 
 * defined
 */
static void context_confusion(struct shim6_ctx* ctx)
{
	int i;
	struct shim6_ctx* conf_ctx;
	for (i=0;i<SHIM6_HASH_SIZE;i++) {
		list_for_each_entry(conf_ctx,&ulid_hashtable[i],
				    collide_ulid) {
			if (conf_ctx==ctx) continue;
			if (conf_ctx->state!=SHIM6_ESTABLISHED &&
			    conf_ctx->state!=SHIM6_I2BIS_SENT) continue;
			if (ctx->ct_peer!=conf_ctx->ct_peer) continue;
			if (intersecting_locsets(&ctx->ls_peer,
						 &conf_ctx->ls_peer)) {
				/*Confusion detected, remove the
				  context*/
				PDEBUG("Confusion detected, deleting"
				       "the guilty context\n");
				shim6_del_ctx(conf_ctx);
			}
		}
	}
}

/**
 * @local must be TRUE if the list is local, FALSE if the list is a peer
 * locator list.
 * Returns TRUE if @addr is part of @ls, FALSE otherwise.
 */
static int in_loc_set(struct locset *ls, struct in6_addr* addr, int local)
{
	int i,list_cnt;
	struct locset *ls_it;
	if (!ls->main) {
		for (i=0;i<ls->size;i++) {
			if (ipv6_addr_equal(addr,(local)?&ls->lsetp[i].addr:
					    &ls->psetp[i].addr))
				return TRUE;	       
		}
		return FALSE;
	}
	else { /*Parse all sets*/
		ASSERT(local); /*The 'main' bit is only set for local 
				 contexts*/ 
		list_for_each_entry_all(ls_it,&ls->list,list,list_cnt) {
			for (i=0;i<ls_it->size;i++) {
				if (ipv6_addr_equal(addr,
						    &ls_it->lsetp[i].addr))
					return TRUE;
			}
		}
		return FALSE;
	}
}

/**
 * @pre : All locators in the locator list option have been verified and 
 *        are valid.
 * @post : The peer loc list of @ctx is updated. If the current peer loc 
 *        is not contained in that list, then REAP starts an exploration
 *        to find another suitable peer locator.
 */
static int get_locators(struct shim6_opt* loc_option,struct shim6_ctx* ctx)
{
	struct loc_list_opt v_loc; /*v part of the tlv, option locators list*/
	int i;
	int found=0;
	int loclist_size;
	int nb_peer_locs=0; /*Only those that passed the validity check 
			      (HBA/CGA)*/
	
	set_loc_list_opt(&v_loc,(char*)(loc_option+1));

	for (i=0;i<*v_loc.num_locs;i++) {
		/*current peer loc in peer loc list ?*/
		if (ipv6_addr_equal(&ctx->lp_peer,&v_loc.locators[i]))
			found=1;
	}
	nb_peer_locs=*v_loc.num_locs;			

	/*updating context*/
	ctx->ls_peer.gen_number=*v_loc.gen_nb;
	ctx->ls_peer.size=nb_peer_locs;
	loclist_size=ctx->ls_peer.size*sizeof(shim6_loc_p);
	
	ctx->ls_peer.psetp=realloc(ctx->ls_peer.psetp,loclist_size);
	if (!ctx->ls_peer.psetp) {
		APPLOG_NOMEM();
		ctx->ls_peer.size=0;
		exit(EXIT_FAILURE);
	}
	bzero(ctx->ls_peer.psetp,(ctx->ls_peer.size)*sizeof(shim6_loc_p));

	for (i=0;i<*v_loc.num_locs;i++) {
		ipv6_addr_copy(&(ctx->ls_peer.psetp+i)->addr,
			       v_loc.locators+i);
	}
	
	if (ctx->r1_vldt) {
		free(ctx->r1_vldt);
		ctx->r1_vldt=NULL;
	}

	/*Updating the path array list*/
	if (fill_path_array(&ctx->reap)<0) return -1;

	if (!found && ctx->state==SHIM6_ESTABLISHED) 
		reap_init_explore(&ctx->reap);

	return 0;	
}

/**
 * SPEC : Returns true if addr is contained in loc_option AND
 * HBA/CGA verification was successful. 
 * 
 * Currently the ULID option is not supported, thus addr is the local ulid,
 * and has been verified already.
 *
 * @pre : verify_cga_locators has been called before : If that function returns
 *   a negative error code, message processing must be aborted, and thus this
 *   function must not be called
 */
static int in_loc_option(struct shim6_opt* loc_option,
			 struct in6_addr* addr) 
{
	struct loc_list_opt v_loc; /*v part of the tlv, option locators list*/
	int i;

	set_loc_list_opt(&v_loc,(char*)(loc_option+1));

	for (i=0;i<*v_loc.num_locs;i++) {
		if (ipv6_addr_equal(v_loc.locators+i,addr)) return 1;
	}
	return 0;
}

/*End of negotiation, do all necessary tasks to put shim6 in operation*/
static void shim6_established(struct shim6_ctx* ctx)
{
	ctx->state=SHIM6_ESTABLISHED;

	/*Stopping current occurence of retransmit timer (I2 timer)*/
	del_task(&ctx->retransmit_timer);
	
	if (!list_empty(&ctx->init_list))
		list_del_init(&ctx->init_list);
	
	/*Reap initialization*/
	init_reap_ctx(&ctx->reap);

	/*Creating a new kernel context*/
	xfrm_add_shim6_ctx(&ctx->ulid_local.addr, &ctx->ulid_peer,
			   ctx->ct_local,ctx->ct_peer, ctx->reap.path_array,
			   ctx->reap.path_array_size,ctx->reap.tka);
#ifdef IDIPS
	/*Asking the idips server to sort the locator list*/
	idips_send_request(ctx);
#endif

#ifdef SHIM6EVAL
	/*Delete that context and start next negotiation*/
	if (!server_mode && !attack) {
		end_measure(ctx);
	}
#endif
}

int rcv_i2(shim6hdr_i2* hdr,struct in6_addr* saddr, 
	   struct in6_addr* daddr, int ifidx) 
{
	uint32_t i2_resp_nonce;
	/*Pointer to the first octet next the end of the packet*/
	char* packet_end = (char*)hdr + ((hdr->common.hdrlen+1)<<3); 
	uint64_t ct_peer;
	unsigned char test_hash[VAL_LENGTH];
	int prev;
	int validator_ok=FALSE;
	int state;
	struct shim6_ctx* ctx=NULL;
	int ans;
	int new=FALSE; /*TRUE if this i2 triggered a context creation*/
	shim6_loc_l* lulid_local;
	struct ka_opt* ka;
#ifdef LOG_RCV_I2_TIME
	struct timespec start,stop,total_time;
	static double time_array[NB_PARALLEL];
	static int count=0;
	clock_gettime(CLOCK_REALTIME,&start);
#endif

	PDEBUG("receiving i2 message\n");
	
	if (hdr->common.hdrlen<2) {
		PDEBUG("i2 length < 2\n");
		return -1;
	}

	i2_resp_nonce=ntohl(hdr->resp_nonce);
	
	/*Verifying age of resp nonce*/
	if (i2_resp_nonce != cur_resp_nonce && 
	    i2_resp_nonce != cur_resp_nonce-1) {
		PDEBUG("%s:resp nonce not in valid nonce interval\n",
		       __FUNCTION__);
		goto failure;
	}

	/*parsing options*/
	ans=parse_options((struct shim6_opt*) (hdr+1),packet_end,SHIM6_TYPE_I2,
			  NULL);
	if (ans<0) return 0;

	/*draft v12 (sec 7.13) : "If a CGA Parameter Data Structure (PDS) is 
	  included in the message, then the host MUST verify if the actual 
	  PDS contained in the message corresponds to the ULID(peer)."*/
	if (psd_opts[PO_PDS] && !shim6_is_remote_cga(psd_opts[PO_PDS],
						     saddr,0)) {
		PDEBUG("%s: source ulid is not a valid CGA\n",__FUNCTION__);
		return 0;
	}
	

	get_ct(&ct_peer, hdr->ct_1, hdr->ct_2, hdr->ct_3);

	/*Validator verification*/
	ASSERT(psd_opts[PO_VLDT]); /*checked by parse_options*/
	for (prev=0;prev<=1;prev++) { /*Tries prev=FALSE, then TRUE*/
		get_resp_hash(test_hash,i2_resp_nonce,ct_peer,
			      daddr,saddr,prev);
		if (!memcmp(test_hash,psd_opts[PO_VLDT]+1, VAL_LENGTH)) {
			validator_ok=TRUE;
			break;
		
		}
	}
	if (!validator_ok) {
		PDEBUG("%s:invalid sha1 hash\n",__FUNCTION__);
		return 0;
	}

	lulid_local=lookup_loc_l(daddr,NULL);
	if (!lulid_local) return 0;

	/*Context lookup*/
        ctx=__init_shim6_ctx(lulid_local,saddr,&new);
	if (!ctx) return 0;

	/*CGA pds allocation*/
	if (psd_opts[PO_PDS]) {
		ctx->pds=realloc(ctx->pds,
				 TOTAL_LENGTH(ntohs(psd_opts[PO_PDS]->length)));
		if (!ctx->pds) goto failure;
		memcpy(ctx->pds,psd_opts[PO_PDS],
		       TOTAL_LENGTH(ntohs(psd_opts[PO_PDS]->length)));
	}

	/*ka option?*/
	if (psd_opts[PO_KA]) {
		ka=(struct ka_opt*)(psd_opts[PO_KA]+1);
		ctx->reap.tka=ntohs(ka->tka);
	}

	/*We need to work on a copy of state, because it may change
	  during the switch*/
	state=ctx->state;
	switch (state) { 
	case SHIM6_IDLE:
		if (psd_opts[PO_LOC] && get_locators(psd_opts[PO_LOC],ctx)<0)
			goto failure;
		ctx->ct_peer=ct_peer;
		context_confusion(ctx);
		shim6_established(ctx);
		send_r2(hdr->init_nonce,ctx);
		break;
	case SHIM6_I1_SENT:
	case SHIM6_ESTABLISHED:
	case SHIM6_I2_SENT:
	case SHIM6_I2BIS_SENT:
		if (lookup_loc_p(saddr,ctx) ||
		    (psd_opts[PO_LOC] && in_loc_option(psd_opts[PO_LOC],
						       saddr))) {
			if (psd_opts[PO_LOC] && 
			    get_locators(psd_opts[PO_LOC],ctx)<0)
				goto failure;
			ctx->ct_peer=ct_peer;
			context_confusion(ctx);
			send_r2(hdr->init_nonce,ctx);
			if (state==SHIM6_I1_SENT) {
				shim6_established(ctx);
			}
		}
		else goto failure;
		break;		
	}

#ifdef LOG_RCV_I2_TIME
	clock_gettime(CLOCK_REALTIME,&stop);
	tssub(stop,start,total_time);
	time_array[count++]=tstodsec(total_time);
	if (count==NB_PARALLEL) {
		FILE* f;
		int i;
		f=fopen(LOCALSTATE_DIR "/shim6/i2.log", "a");
		if (!f) {
			syslog(LOG_ERR,"open : %m\n");
			goto failure;
		}		
		for (i=0;i<NB_PARALLEL;i++) {
			fprintf(f,"%f\n",time_array[i]);
		}
		fclose(f);		
		count=0;
	}	
#endif
	return 0;
failure:
	if (ctx && new) 
		shim6_del_ctx(ctx);
	return -1;
}


int rcv_i2bis(shim6hdr_i2bis* hdr,struct in6_addr* saddr, 
	      struct in6_addr* daddr, int ifidx)
{
	uint32_t i2_resp_nonce;
	/*Pointer to the first octet next the end of the packet*/
	char* packet_end = (char*)hdr + ((hdr->common.hdrlen+1)<<3); 
	uint64_t ct_peer;
	unsigned char test_hash[VAL_LENGTH];
	int prev;
	int validator_ok=FALSE;
	int state,new;       
	struct shim6_ctx *ctx=NULL;
	int ans;
	struct ka_opt *ka;
	struct ulid_opt *ulids;
	struct in6_addr *ulid_local,*ulid_peer;

	PDEBUG("receiving i2bis message\n");
	
	if (hdr->common.hdrlen<2) {
		PDEBUG("i2bis length < 3\n");
		return -1;
	}

	i2_resp_nonce=ntohl(hdr->resp_nonce);
	
	/*Verifying age of resp nonce*/
	if (i2_resp_nonce != cur_resp_nonce && 
	    i2_resp_nonce != cur_resp_nonce-1) {
		PDEBUG("%s:resp nonce not in valid nonce interval\n",
		       __FUNCTION__);
		goto failure;
	}

	/*parsing options*/
	ans=parse_options((struct shim6_opt*) (hdr+1),packet_end,
			  SHIM6_TYPE_I2BIS,
			  NULL);
	if (ans<0) return 0;

	/*Getting ulid pair*/
	if (psd_opts[PO_ULID]) {
		ulids=(struct ulid_opt*)(psd_opts[PO_ULID]+1);
		ulid_local=&ulids->dst_ulid;
		ulid_peer=&ulids->src_ulid;
	}
	else {
		ulid_local=daddr;
		ulid_peer=saddr;
	}

	
	/*Validator verification*/
	ASSERT(psd_opts[PO_VLDT]); /*checked by parse_options*/
	for (prev=0;prev<=1;prev++) { /*Tries prev=FALSE, then TRUE*/
		get_resp_hash(test_hash,i2_resp_nonce,ct_peer,
			      daddr,saddr,prev);
		if (!memcmp(test_hash,psd_opts[PO_VLDT]+1, VAL_LENGTH)) {
			validator_ok=TRUE;
			break;
		
		}
	}
	if (!validator_ok) {
		PDEBUG("%s:invalid sha1 hash\n",__FUNCTION__);
		return 0;
	}

	/*draft v12 (sec 7.20) : "If a CGA Parameter Data Structure (PDS) is 
	  included in the message, then the host MUST verify if the actual 
	  PDS contained in the message corresponds to the ULID(peer)."*/
	if (psd_opts[PO_PDS] && !shim6_is_remote_cga(psd_opts[PO_PDS],
						     ulid_peer,0)) {
		PDEBUG("%s: source ulid is not a valid CGA\n",__FUNCTION__);
		return 0;
	}

	/*Context lookup*/
	ctx=lookup_ulid(ulid_peer,ulid_local);

	if (!ctx) {
		shim6_loc_l *lulid_local=lookup_loc_l(ulid_local,NULL);;
		shim6_loc_l dummy_lulid_local;
		/*If the local ulid is not anymore in the local locator list,
		  use a dummy lulid_local structure*/
		if (!lulid_local) {
			PDEBUG("%s:ULID removed from structures, using dummy\n",
				__FUNCTION__);
			bzero(&dummy_lulid_local,sizeof(dummy_lulid_local));
			ipv6_addr_copy(&dummy_lulid_local.addr,ulid_local);
			dummy_lulid_local.valid_method=get_valid_method(
				ulid_local,0,&dummy_lulid_local.hs);
			lulid_local=&dummy_lulid_local;
		}
		
		ctx=__init_shim6_ctx(lulid_local,ulid_peer,&new);
		ASSERT(new);
		if (!ctx) return 0;
	}
	else new=FALSE;

	get_ct(&ct_peer, hdr->init_ct_1, hdr->init_ct_2, hdr->init_ct_3);

	/*CGA pds allocation*/
	if (psd_opts[PO_PDS]) {
		ctx->pds=realloc(ctx->pds,
				 TOTAL_LENGTH(ntohs(psd_opts[PO_PDS]->length)));
		if (!ctx->pds) goto failure;
		memcpy(ctx->pds,psd_opts[PO_PDS],
		       TOTAL_LENGTH(ntohs(psd_opts[PO_PDS]->length)));
	}

	/*ka option?*/
	if (psd_opts[PO_KA]) {
		ka=(struct ka_opt*)(psd_opts[PO_KA]+1);
		ctx->reap.tka=ntohs(ka->tka);
	}

	/*We need to work on a copy of state, because it may change
	  during the switch*/
	state=ctx->state;
	switch (state) { 
	case SHIM6_IDLE:
		if (psd_opts[PO_LOC] && get_locators(psd_opts[PO_LOC],ctx)<0)
			goto failure;
		ctx->ct_peer=ct_peer;
		context_confusion(ctx);
		shim6_established(ctx);
		send_r2(hdr->init_nonce,ctx);
		break;
	case SHIM6_I1_SENT:
	case SHIM6_ESTABLISHED:
	case SHIM6_I2_SENT:
	case SHIM6_I2BIS_SENT:
		if (lookup_loc_p(saddr,ctx) ||
		    (psd_opts[PO_LOC] && in_loc_option(psd_opts[PO_LOC],
						       saddr))) {
			if (psd_opts[PO_LOC] && 
			    get_locators(psd_opts[PO_LOC],ctx)<0)
				goto failure;
			ctx->ct_peer=ct_peer;
			context_confusion(ctx);
			send_r2(hdr->init_nonce,ctx);
			if (state==SHIM6_I1_SENT) {
				shim6_established(ctx);
			}
		}
		else goto failure;
		break;		
	}

	return 0;
failure:
	if (ctx && new) 
		shim6_del_ctx(ctx);
	return -1;
}

int rcv_r2(shim6hdr_r2* hdr,struct in6_addr* saddr, 
	   struct in6_addr* daddr) 
{
	
       	struct shim6_ctx* ctx;
	int found=0; /*to indicate that a corresponding ctx was found*/
	/*Pointer to the first octet next the end of the packet*/
	char* packet_end = (char*)hdr + ((hdr->common.hdrlen+1)<<3); 
	int ans;
	struct ka_opt* ka;
#ifdef SHIM6EVAL	
	struct timespec before,after;
	clock_gettime(CLOCK_REALTIME,&before);
#endif

	
	PDEBUG("receiving r2 message\n");
	
	if (hdr->common.hdrlen<1) {
		PDEBUG("r2 length < 1\n");
		return -1;
	}

	/*State lookup*/

	list_for_each_entry(ctx,&init_list,init_list) {
		if (ctx->init_nonce==ntohl(hdr->nonce)
		    && ipv6_addr_equal(&ctx->lp_local,daddr)
		    && ipv6_addr_equal(&ctx->lp_peer,saddr)) {
			found=1;
			break;
		}
	}
	
	if (!found) {
		PDEBUG("%s : no ctx found\n",__FUNCTION__);
		return -1;
	}
	PDEBUG("%s : a ctx was found \n",__FUNCTION__);

#ifdef SHIM6EVAL
	if (attack) {
		/*If we are attacking a shim6 host, we can 
		  now drop the R2 packet without further processing,
		  to spare ressources*/

		clock_gettime(CLOCK_REALTIME,&after);
		tssub(after,before,ctx->rcvr2_time);

		end_measure(ctx);
		return 0;
	}
#endif
	
	/*Silently ignore the R2 if the context is already established*/
	if(ctx->state==SHIM6_ESTABLISHED) return 0;

	
	/*parsing options*/
	ans=parse_options((struct shim6_opt*) (hdr+1),packet_end,SHIM6_TYPE_R2,
			  NULL);
	if (ans<0) return 0;
	

	/*draft v12 : "If a CGA Parameter Data Structure (PDS) is included in 
	  the message, then the host MUST verify if the actual PDS contained 
	  in the message corresponds to the ULID(peer)."*/
	
	if (psd_opts[PO_PDS] && !shim6_is_remote_cga(psd_opts[PO_PDS],
						     &ctx->ulid_peer,0)) {
		PDEBUG("%s: source ulid is not a valid CGA\n",__FUNCTION__);
		return 0;
	}
	

	/*Saving ct(peer)*/

	get_ct(&ctx->ct_peer, hdr->ct_1, hdr->ct_2, hdr->ct_3);
	
	
	/*CGA pds allocation*/
	if (ctx->pds) free(ctx->pds);
	if (psd_opts[PO_PDS]) {
		ctx->pds=malloc(TOTAL_LENGTH(ntohs(psd_opts[PO_PDS]->length)));
		if (!ctx->pds) return 0;
		memcpy(ctx->pds,psd_opts[PO_PDS],
		       TOTAL_LENGTH(ntohs(psd_opts[PO_PDS]->length)));
	}

	/*Saving locators*/
	if (psd_opts[PO_LOC] &&
	    get_locators(psd_opts[PO_LOC],ctx)<0) return 0;

	if (ctx->pds_sent) ctx->pds_acked=1;
	context_confusion(ctx);

	/*ka option?*/
	if (psd_opts[PO_KA]) {
		ka=(struct ka_opt*)(psd_opts[PO_KA]+1);
		ctx->reap.tka=ntohs(ka->tka);
	}


	shim6_established(ctx);

	return 0;
}

int rcv_ur(shim6hdr_ur* hdr,struct in6_addr* saddr, struct in6_addr* daddr)
{
	struct shim6_ctx *ctx;
	uint64_t ct;
	/*Pointer to the first octet next the end of the packet*/
	char* packet_end = (char*)hdr + ((hdr->common.hdrlen+1)<<3); 
	int ans;
	struct ka_opt* ka;

	PDEBUG("receiving update request message\n");

	if (hdr->common.hdrlen<1) {
		PDEBUG("ur length < 1\n");
		return -1;
	}
	get_ct(&ct,hdr->ct_1,hdr->ct_2,hdr->ct_3);
	ctx=lookup_ct(ct);

	if (!ctx) {
		syslog(LOG_ERR, "%s : ctx not found\n",__FUNCTION__);
		return -1;
	}

	/*Checking that src addr is in local set, and dst addr is in peer
	  set (draft version 10, section 10.4)*/
	if (!in_loc_set(ctx->ls_localp,daddr,TRUE) || 
	    !in_loc_set(&ctx->ls_peer,saddr,FALSE)) {
		syslog(LOG_ERR,"%s : Either the source or the dest locator " 
		       "of UR packet was not found in the locator sets\n",
			__FUNCTION__);
		return -1;
	}

	/*parsing options*/
	ans=parse_options((struct shim6_opt*) (hdr+1),packet_end,
			  SHIM6_TYPE_UPD_REQ, ctx);
	if (ans<0) return 0;
	
	/*draft v12 (sec 10.4) : "If a CGA Parameter Data Structure (PDS) is 
	  included in the message, then the host MUST verify if the actual 
	  PDS contained in the message corresponds to the ULID(peer)."*/
	if (psd_opts[PO_PDS] && !shim6_is_remote_cga(psd_opts[PO_PDS],
						     &ctx->ulid_peer,0)) {
		PDEBUG("%s: source ulid is not a valid CGA\n",__FUNCTION__);
		return 0;
	}

	/*ka option?*/
	if (psd_opts[PO_KA]) {
		ka=(struct ka_opt*)(psd_opts[PO_KA]+1);
		ctx->reap.tka=ntohs(ka->tka);
		sync_contexts(ctx,0);
	}

	if (ctx->state==SHIM6_I1_SENT) return 0;
	if (ctx->state==SHIM6_I2_SENT) 
		send_i2(ctx); /*draft v10, sec. 10.4*/
	
	
	if (psd_opts[PO_LOC] && get_locators(psd_opts[PO_LOC],ctx)<0)
		goto failure;

	/*Update the path array*/
	fill_path_array(&ctx->reap);

	if (send_ua(ctx, hdr->nonce)<0) return -1;

	return 0;
failure:
	return -1;
}


/**
 * This function deletes a clone entry. A clone entry is any node within
 * a cloned list of locators sets. The first node being the CGA-verified 
 * locators (including the non-secured ones), the other ones being the HBA
 * and HBA/CGA-compat nodes. The main node holds a refcount towards all
 * other nodes (because any context using the main node makes use of *all* 
 * locators, thus it makes use of the whole list.
 *
 * Thus if we have a list * - * - *, with only the main node referenced, the
 * refcounts are 1, 1, 1. When the context does a put on that node, this
 * functions does itself the put for the other nodes, and everyting is 
 * automatically destroyed. OTOH, if the list is * - * - * with only
 * one HBA set (e.g., second entry) referenced, after clone_loc_sets,
 * ref counts will be 1 - 1 - 1, after update_contexts, refcounts will be 
 * 1 - 2 - 1 (because just one context uses first entry), and after 
 * the put (in new_addr) : 0 - 1 - 0, thus 1.
 * When that hba context does the put, it becomes 0, thus everything has
 * finally disappeared correctly.
 */
static void del_clone_entry(struct kref *kref)
{
	struct locset *ls=container_of(kref,struct locset,kref);
	struct locset *ls_it,*ls_temp;

	ASSERT(ls->clone);

	if (ls->main) {
		/*With the ls list, we should use the _all version of the
		 * iterator, but here we do not want to consider the first node
		 * and this iterator will precisely ignore it*/
		list_for_each_entry_safe(ls_it,ls_temp,&ls->list,list) {
			ASSERT(!ls_it->main); /*Just to be sure I am not 
						missing some point*/
			kref_put(&ls_it->kref,del_clone_entry);
		}
	}

	list_del(&ls->list);
	free(ls->lsetp);
	free(ls);
}


int rcv_ua(shim6hdr_ur* hdr,struct in6_addr* saddr, struct in6_addr* daddr)
{
	struct shim6_ctx* ctx;
	uint64_t ct;
	struct locset *new;
	
	PDEBUG("receiving update ack message\n");
	
	if (hdr->common.hdrlen<1) {
		PDEBUG("ua length < 1\n");
		return -1;
	}
	get_ct(&ct,hdr->ct_1,hdr->ct_2,hdr->ct_3);
	ctx=lookup_ct(ct);
	
	if (!ctx) {
		syslog(LOG_ERR, "%s : ctx not found\n",__FUNCTION__);
		return -1;
	}

	/*Checking that src addr is in local set, and dst addr is in peer
	  set (draft version 12, section 10.4)*/
	if (!in_loc_set(ctx->ls_localp,daddr,TRUE) || 
	    !in_loc_set(&ctx->ls_peer,saddr,FALSE)) {
		syslog(LOG_ERR,"%s : Either the source or the dest locator " 
		       "of UA packet was not found in the locator sets\n",
		       __FUNCTION__);
		send_r1bis(daddr,saddr,ct);
		return -1;
	}
	if (ctx->state==SHIM6_I1_SENT) return 0;
	if (ctx->state==SHIM6_I2_SENT) 
		send_i2(ctx); /*draft v10, sec. 10.5 says we must send an 
				R2, but I think this is a mistake. I sent a
				mail to the list. Until there is an answer,
				I keep sending I2 instead of an R2.*/

	if (ntohl(hdr->nonce) != ctx->update_nonce) return 0;

	if (!ctx->ls_localp->clone) {
		syslog(LOG_ERR,"%s:Received a valid update ack, but the local"
		       " locator list is not a clone\n",__FUNCTION__);
		return -1;
	}

	/*OK, we can use the new list*/
	
	if (ctx->ls_localp->main) new=&glob_loc_sets;
	else {
		/*Then we need to find the global list, it is possible
		  by chaining pointers, not very elegant,sorry -:) */
		ASSERT(ctx->ls_localp->size!=0);
		new=(struct locset*)ctx->ls_localp->lsetp[0].hs->private;
		
	}	
	
	kref_put(&ctx->ls_localp->kref,del_clone_entry);

	ctx->ur_pending=0;

	if (ctx->pds_sent) ctx->pds_acked=1;

	ctx->ls_localp=new;
	fill_path_array(&ctx->reap);
	clear_report_lists(&ctx->reap);

	return 0;
}

/**
 * This creates a copy of the full structure of locators
 * If @prev is not NULL, *@new is set to point to the new address
 * of the locset corresponding to @prev.
 * If @prev is not NULL, @new cannot be NULL either.
 */
static struct locset* clone_loc_sets(struct locset* prev, 
				     struct locset** new)
{
	struct locset* mainset=malloc(sizeof(struct locset));
	struct locset* ls;
	struct locset* copy;
	
	if (new) *new=NULL;
	
	/*Clone the main node*/
	if (!mainset) {
		APPLOG_NOMEM();
		exit(EXIT_FAILURE);
	}
	
	memcpy(mainset,&glob_loc_sets, sizeof(*mainset));
	INIT_LIST_HEAD(&mainset->list);
	kref_init(&mainset->kref);
	mainset->clone=1;

	/*Copying the locators*/
	mainset->lsetp=malloc(glob_loc_sets.size*sizeof(shim6_loc_l));
	if (!mainset->lsetp) {
		APPLOG_NOMEM();
		exit(EXIT_FAILURE);
	}
	memcpy(mainset->lsetp,glob_loc_sets.lsetp,
	       glob_loc_sets.size*sizeof(shim6_loc_l));
	
	if (&glob_loc_sets==prev) *new=mainset;
	

	/*With the ls list, we should use the _all version of the
	 * iterator, but here we do not want to consider the first node
	 * (because it is already created)
	 * and this iterator will precisely ignore it*/
	
	list_for_each_entry(ls,&glob_loc_sets.list,list) {
		copy=malloc(sizeof(struct locset));
		if (!copy) {
			APPLOG_NOMEM();
			exit(EXIT_FAILURE);
		}
		memcpy(copy,ls,sizeof(*copy));
		list_add_tail(&copy->list,&mainset->list);
		kref_init(&copy->kref);
		copy->clone=1;
				
		/*Copying the locators*/
		copy->lsetp=malloc(ls->size*sizeof(shim6_loc_l));
		if (!copy->lsetp) {
			APPLOG_NOMEM();
			exit(EXIT_FAILURE);
		}
		memcpy(copy->lsetp,ls->lsetp,ls->size*sizeof(shim6_loc_l));
		if (ls==prev) *new=copy;
	}
	return mainset;
}

static void init_ur_timer(struct shim6_ctx *ctx)
{
	uint8_t random_byte;
	struct timespec timeout;
	/*Starting retransmit timer
	 * draft-proto-10, section 10.2 :
	 * -use of binary exponential backoff
	 * -randomize between 0.5 and 1.5 of computed time
	 */
	ctx->nb_retries=0;
	ctx->cur_timeout_val=SHIM6_UPDATE_TIMEOUT; 
	
	random_byte=(uint8_t)random_int();
	tssetdsec(timeout, ctx->cur_timeout_val/2.0+
		  (random_byte*ctx->cur_timeout_val)/256.0);
	
	add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);
	
}

/**
 * Searches for all contexts referencing the locset @prev, and replaces
 * their pointer with @new. @new must be a locset created with
 * clone_loc_sets.
 *
 * If necessary, the REAP fill_path_array() function is called to 
 * update exploration list, according to the new locator set.
 * (note that if the new list pointer is a clone, the REAP array is 
 *  updated only when the context receives the update ack).
 * 
 * @removed_address:If not NULL, then the update is due to an address removal,
 *               and the removed address is pointed to by @removed_address.
 *               If any context is found to use that address as lp_local, 
 *               A REAP exploration is immediately triggered, to 
 *               find another lp_local.
 *
 * This function also triggers the sending of an update request 
 */
static void update_contexts(struct locset* prev, struct locset* new, 
			    struct in6_addr* removed_address)
{
	struct shim6_ctx *ctx,*tmp;
	int i;
	
	ASSERT(new);
	
	for (i=0;i<SHIM6_HASH_SIZE;i++) {
		list_for_each_entry_safe(ctx,tmp,&ulid_hashtable[i],
					 collide_ulid) {
			if (ctx->ls_localp==prev) {
				/*Changing the pointer*/
				ctx->ls_localp=new;	

				/*Updating the peer*/
				switch(ctx->state) {
				case SHIM6_ESTABLISHED: 
					send_ur(ctx,TRUE);
					init_ur_timer(ctx);
					break;
				case SHIM6_I2_SENT:
					send_i2(ctx);
					break;
				case SHIM6_I2BIS_SENT:
					send_i2bis(ctx);
					break;
				}
				/*If not a clone, updating REAP
				  (if it is, waiting for the ack)*/
				if (!new->clone) fill_path_array(&ctx->reap);
				/*If we deleted the lp_local, start exploring*/
				if (removed_address && 
				    ipv6_addr_equal(removed_address,
						    &ctx->lp_local))
					reap_init_explore(&ctx->reap);
				/*If we use a clone, update the refcount*/
				if (new->clone) kref_get(&new->kref);
			}
		}
	}
}

/**
 * Synchronizes context @ctx with the kernel.
 * For the moment it is only used when there is a change in Tsend or Tka 
 * that must be reflected to the kernel.
 * if @ctx is NULL, all contexts are synchronized
 * if @sync_peer is true, the peer is also synchronised (by loc update)
 */
void sync_contexts(struct shim6_ctx* ctx, int sync_peer)
{
	int i;

	if (ctx) {
		xfrm_update_shim6_ctx(ctx,&ctx->lp_peer, &ctx->lp_local,
				      NULL,0);
		tssetsec(ctx->reap.send_timespec,get_tsend());
		if (sync_peer) send_ur(ctx,1);
		return;
	}
	for (i=0;i<SHIM6_HASH_SIZE;i++)
		list_for_each_entry(ctx,&ulid_hashtable[i],
				    collide_ulid) {
			xfrm_update_shim6_ctx(ctx,&ctx->lp_peer, &ctx->lp_local,
					      NULL,0);
			tssetsec(ctx->reap.send_timespec,get_tsend());
			if (sync_peer) send_ur(ctx,1);
		}
}

/*Returns a pointer to the main loc set, if it exists,
  or NULL if it is not found*/
inline struct locset* main_loc_set(void)
{
	return &glob_loc_sets;
}

/**
 * Saves a copy of addr in the global structure (glob_loc_sets)
 * unless that address is already registered.
 */
static int new_addr(struct in6_addr* addr, int ifidx)
{
	struct locset *ls, *clone_hba;
	struct locset *clone;
	struct hba_set *hs;
	uint8_t valid_method=0;
	shim6_loc_l *locator;
	int unbreak=FALSE;
	
	/*Check if the address has already been registered*/
	if ((locator=lookup_loc_l(addr,NULL))) {
		if (locator->ifidx==ifidx) {
			if (locator->broken) unbreak=TRUE;
			else PDEBUG("%s: Address already registered\n",
				    __FUNCTION__);
		}
		else {
			PDEBUG("%s: Address ifidx adapted from %d"
			       "to %d\n",__FUNCTION__,locator->ifidx,ifidx);
			locator->ifidx=ifidx;
			if (locator->broken) unbreak=TRUE;
		}
			
		if (!unbreak) return 0;
	}
	
	if (IN6_IS_ADDR_MULTICAST(addr))
		return 0;

	valid_method=get_valid_method(addr,ifidx,&hs);
	switch(valid_method) {
	case SHIM6_CGA:
		PDEBUG("Address %s is a CGA.\n",
		       addrtostr(addr));
		break;
	case SHIM6_HBA:
			PDEBUG("Address %s is an HBA.\n",
			       addrtostr(addr));
			break;
	default:
		PDEBUG("Address %s is not an HBA/CGA.\n",
		       addrtostr(addr));			
	}
		
	PDEBUG("Adding address %s to local locator structure\n",
	       addrtostr(addr));
	if (hs && !hs->cgacompat) {
		/*Even if the new address is an hba, we must clone
		  the entire locset, since the main set (which is the
		  entire locset, identified by the first set) has changed*/
		ls=(struct locset*)hs->private;
		clone=clone_loc_sets(ls,&clone_hba);
		ASSERT(clone_hba);
	}
	else {
		ls=main_loc_set();
		clone=clone_loc_sets(NULL,NULL);
	}
			
	/*Now that the structure is cloned, we can modify it*/
	if (!unbreak) {
		/*If the locator was not present at all, we must create
		  an entry for the new locator, but if it was present and
		  marked broken, we must just remove the broken flag and
		  update glob_gen_nb and size_not_broken*/
		ls->lsetp=realloc(ls->lsetp,(++ls->size)*sizeof(*ls->lsetp));
		if (!ls->lsetp) {
			APPLOG_NOMEM();
			return -1;
		}
		bzero(&ls->lsetp[ls->size-1],sizeof(shim6_loc_l));
		ipv6_addr_copy(&ls->lsetp[ls->size-1].addr, addr);
		ls->lsetp[ls->size-1].ifidx=ifidx;
		ls->lsetp[ls->size-1].valid_method=valid_method;
		ls->lsetp[ls->size-1].hs=hs;
	}
	else locator->broken=FALSE;

	ls->gen_number=glob_gen_nb++;
	ls->size_not_broken++;
		

 	/*If the modified locator set is an HBA set, then
	 * we must also update the gen number of the main set (index 0), 
	 * because that one makes use of all available addresses*/
	if (!ls->main) {
		struct locset* main_set=main_loc_set();
		ASSERT(main_set);
		main_set->gen_number=glob_gen_nb++;
	}

	/*Update the references in the contexts, and trigger an update request*/
	update_contexts(ls,clone,NULL);
	/*If the modified set is an HBA set, also update the corresponding
	  contexts */
	if (hs && !hs->cgacompat) update_contexts(ls,clone_hba,NULL);		

	/*When creating the clone, all ref counts are set to 1.
	 * Now, that all context has done a get on the appropriate ref count
	 * we can put the global one, so that the last context using an entry
	 * will destroy it appropriately. Also note that since the main node 
	 * actually uses all other nodes, it has a refcount for all of them,
	 * thus at init main should have refcount 1, and all other ones refcount
	 * 2 (their refcount+refcount of main). Normally, also we should now
	 * iterate over the whole list and do a put on the refcount. 
	 * But it is equivalent and more efficient to do init with refcount 1
	 * (instead of 2) for all nodes, and then only do a put on the main
	 * node here.*/
	kref_put(&clone->kref, del_clone_entry);

	return 0;
}

static int del_addr(struct in6_addr* addr, int ifidx)
{
	struct locset *ls, *ls_it;
	struct hba_set* hs;
	char valid_method=0;
	shim6_loc_l* locator;
	int i,list_cnt,found=0;
	int broken=0;

	valid_method=get_valid_method(addr,ifidx,&hs);

	/*Oppositely to new_addr, we do not need here to create a clone
	 * of the loc list, since anyway, the effect of removing a locator
	 * must be immediate, while we can start using a new loc only after
	 * acknowledgement by the peer*/
	if (hs && !hs->cgacompat) ls=(struct locset*)hs->private;
	else ls=main_loc_set();
	
	ASSERT(ls);

	/* Looking for the corresponding entry. Once found, every entry
	 * after the one we want to delete is moved one slot left.
	 * Normally (valid_method !=-1) we only check the ls locator set.
	 * But if get_valid_method failed, which happens if the interface
	 * has been removed, we check all the lists, and do not take into
	 * account the ifidx. */
	list_for_each_entry_all(ls_it,&ls->list,list,list_cnt) {
		for (locator=ls_it->lsetp,i=0; i<ls_it->size; locator++,i++) {
			if (found) {
				ipv6_addr_copy(&(locator-1)->addr,
					       &locator->addr);
			}
			else if (ipv6_addr_equal(addr,&locator->addr) &&
				 (locator->ifidx==ifidx || valid_method==-1)) {
				found=1;
				broken=locator->broken;
				if (locator->refcnt!=0) {
					PDEBUG("Address %s marked as broken\n",
					       addrtostr(addr));
					ASSERT(!broken);
					locator->broken=1;
					ls_it->size_not_broken--;
					ls_it->gen_number=glob_gen_nb++;
					return 0;
				}
				else 
					PDEBUG("Removing address %s from local "
					       "locator structure\n",
					       addrtostr(addr));
			}
		}
		if (valid_method!=-1 || found) break;
	}
	ls=ls_it;

	/*It is possible that the locator is not found if we just 
	  changed the adress from one iface to another (mip6d does that)
	  Reason: when the interface changes, new_addr is called with a
	  new address. The effect is that the old address is automatically
	  discarded. When afterwards a del_addr, in this special case new_addr
	  already did the remove implicitly (by updating the ifidx actually)
	  and del_addr cannot find it anymore.*/
	if (!found) {
		PDEBUG("Address to remove not found. "
		       "Probably an iface change...");
		return 0;
	}
	
	ls->size--;

	/*If the deleted locator was broken, the size_not_broken field has 
	  already been decremented when tagging the locator as broken*/
	if (!broken) ls->size_not_broken--;

	ls->gen_number=glob_gen_nb++;
	
 	/*If the modified locator set is an HBA set, then
	 * we must also update the gen number of the main set (index 0), 
	 * because that one makes use of all available addresses*/
	if (!ls->main) {
		struct locset* main_set=main_loc_set();
		main_set->gen_number=glob_gen_nb++;
	}


	/*Triggering the update request, here we set the same pointer as 
	  previous and new, since we did not perform a clone*/
	update_contexts(ls,ls,addr);	
	return 0;
}

/* Gets set of local adresses and fills the locator table.
 * returns -1 in case of error, else 0.
 * 
 */
int shim6_get_loc_addrs(void)
{
	struct ifaddrs* addrlist_head=NULL; /*head*/
	struct ifaddrs* addrlist_it; /*iterator*/
	int added=0; /*Number of registered addresses*/
	
	/*Get all addresses from the system*/
	if (getifaddrs(&addrlist_head)<0) {
		syslog(LOG_ERR,"getifaddrs failed : %m\n");
		goto failure;
	}
		/*Build the local locator table*/
	for (addrlist_it=addrlist_head; addrlist_it;
	     addrlist_it=addrlist_it->ifa_next) {
		struct sockaddr_in6* sa6=(struct sockaddr_in6*)
			addrlist_it->ifa_addr;
		int ifidx=if_nametoindex(addrlist_it->ifa_name);
		ASSERT(ifidx!=0);
		
		/*We do not use link local, loopback or multicast*/
		if (sa6->sin6_family != AF_INET6 ||
		    IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) ||
		    IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			continue;
		
		/*OK, store it*/
		if (new_addr(&sa6->sin6_addr, ifidx)<0) goto failure;
		added++;
	}
	
	/*Do we have at least one address ?*/
	if (added==0) {
		syslog(LOG_ERR,
		       "No useable IPv6 address is available in this system;"
			" ...have you got at least one global unicast ?\n");
		goto failure;
	}

	freeifaddrs(addrlist_head);
	return 0;
 failure:
	if (addrlist_head) freeifaddrs(addrlist_head);
	return -1;
}

inline void init_loc_set(struct locset* ls, struct hba_set* hs) {
	bzero(ls,sizeof(*ls));
	kref_init(&ls->kref);
	if (hs) {
		hs->private=ls;
	}
}

inline int init_loc_sets(void)
{
	struct hba_set* hs;
	struct locset* ls;

	/*Initializing the main locator set*/
	init_loc_set(&glob_loc_sets,NULL);
	glob_loc_sets.main=1;
	INIT_LIST_HEAD(&glob_loc_sets.list);
	/*Creating the HBA specific locator sets*/
	list_for_each_entry(hs,&hba_sets, list) {
		if (!hs->cgacompat) {
			/*Then create a specific HBA set*/
			ls=malloc(sizeof(struct locset));
			if (!ls) {
				APPLOG_NOMEM();
				return -1;
			}
			init_loc_set(ls, hs);
			list_add_tail(&ls->list,&glob_loc_sets.list);
		}
		else hs->private=main_loc_set();
	}
	return 0;
}

/**
 * @pre : cgad_params_init() must have been called before.
 */
int shim6d_init()
{
	int i;

	/*Initialize the ctx list*/
	for (i=0;i<SHIM6_HASH_SIZE;i++) {
		INIT_LIST_HEAD(&ulid_hashtable[i]);
		INIT_LIST_HEAD(&ct_hashtable[i]);
	}
	INIT_LIST_HEAD(&init_list);	

	/*Initialize the global locator table*/
	if (init_loc_sets()<0) return -1;

	/*Get the set of local addresses*/
	if (shim6_get_loc_addrs()<0) return -1;

	/*Initialize the responder nonce and validator*/
	cur_resp_nonce=random_int();
	init_timer(&resp_nonce_timer);
	add_task_rel(&RESP_NONCE_UPDATE,&resp_nonce_timer,resp_nonce_handler);
	
	prev_resp_secret=resp_secret=random_int();
	
	return 0;
}

/**
 * Allocates space for a locset together with a single address 
 * (pointed to by @return->lsetp). 
 * The single address is located in the same malloc'ed block, so that
 * that block can be freed later by a single call to free()
 */
static struct locset* alloc_single_locsetl(struct in6_addr* ulid_local)
{
	struct locset* ls = malloc(sizeof(*ls)+sizeof(shim6_loc_l));
	struct shim6_loc_l* loc;
	if (!ls) {
		APPLOG_NOMEM();
		return NULL;
	}
	bzero(ls,sizeof(*ls)+sizeof(shim6_loc_l));
	loc=(shim6_loc_l*)(ls+1);
	ipv6_addr_copy(&loc->addr,ulid_local);
	ls->size=1;
	ls->size_not_broken=1;
	ls->lsetp=loc;
	ls->gen_number=0;
	ls->single=1;
	INIT_LIST_HEAD(&ls->list);
	return ls;
}


/**
 * Allocates space for a single address and assigns it to the given locset
 */
static int alloc_single_locsetp(struct locset* ls,
				struct in6_addr* ulid_peer)
{
	shim6_loc_p* loc=malloc(sizeof(shim6_loc_p));
	if (!loc) {
		APPLOG_NOMEM();
		return -1;
	}
	bzero(loc,sizeof(*loc));
	ipv6_addr_copy(&loc->addr,ulid_peer);
	ls->size=1;
	ls->psetp=loc;
	ls->gen_number=0;
	ls->single=1;
	INIT_LIST_HEAD(&ls->list);
	return 0;
}

#ifdef SHIM6EVAL
/**
 * @security is 0, SHIM6_CGA, or SHIM6_HBA depending on the 
 * security mechanism we want to evaluate.
 * 
 * This function is very similar to init_shim6_ctx, except that 
 * this is a measurement function, that picks a ulid based on the 
 * security system we want to use.
 */
int eval_new_ctx(int security, struct in6_addr* ulid_peer) {
	struct shim6_loc_l* ulid_local;
	int new;
	struct shim6_ctx *ctx;
	uint8_t random_byte;
	struct timespec timeout;
	int i;
	struct locset *main_set=main_loc_set();
	struct locset *hba_locset;

	struct timespec after;
	
	if (!main_set) {
		fprintf(stderr,"%s:no main locset has been found\n",
			__FUNCTION__);
		return -1;
	}

	switch(security) {
	case 0:
		if (main_set->size==0) {
			fprintf(stderr,"%s:no non-secured locator was found\n",
				__FUNCTION__);
			return -1;
		}
		ulid_local=&main_set->lsetp[0];
		break;
	case SHIM6_HBA:
		hba_locset=list_next_entry(main_set,&glob_loc_sets.list, list);
		if (!hba_locset || hba_locset->size==0) {
			fprintf(stderr,"%s:no hba locator was found\n",
				__FUNCTION__);
			return -1;
		}
		ulid_local=&hba_locset->lsetp[0];
		break;
	case SHIM6_CGA:
		if (main_set->size==0) {
			fprintf(stderr,"%s:no non-secured locator was found\n",
				__FUNCTION__);
			return -1;
		}

		/*Looking for a CGA ULID*/
		if (!attack) {
			for (i=0;i<main_set->size;i++) {
				shim6_loc_l* loc = main_set->lsetp+i;
				if (loc->valid_method==SHIM6_CGA) {
					ulid_local=loc;
					goto addressfound;
				}
			}
			fprintf(stderr,"%s:no CGA has been found\n",
				__FUNCTION__);
			return -1;
		}
		else {
			/*Using the precomputed array*/
			/*we divise per two, thus using the sequence
			  0-0-1-1-2-2-..., for local ulid, while peer
			  ulid is 0-1-0-1-0-2. This generates each time
			  a different locator pair, thus a different context
			  at the peer*/
			ulid_local=&params[eval_counter/2].ulid;
		}
		break;
	default:
		fprintf(stderr,"%s:bad security parameter (%d)",__FUNCTION__,
			security);
		return -1;
	}

addressfound:
	ctx=__init_shim6_ctx(ulid_local,ulid_peer,&new);
	if (!ctx) {
		fprintf(stderr,"%s:__init_shim6_ctx failed\n",
			__FUNCTION__);
		return -1;
	}
	
	if (!new) {
			fprintf(stderr,"%s: The context already exists\n",
				__FUNCTION__);
			return -1;
	}
	send_i1(ctx);
	
	/*Starting retransmit timer
	 * draft-proto-08, section 7.8 :
	 * -use of binary exponential backoff
	 * -randomize between 0.5 and 1.5 of computed time
	 */
	ctx->nb_retries=0;
	ctx->cur_timeout_val=SHIM6_I1_TIMEOUT; 
	
	random_byte=(__u8)random_int();
	tssetdsec(timeout, ctx->cur_timeout_val/2.0+
		  (random_byte*ctx->cur_timeout_val)/256.0);
	add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);

	clock_gettime(CLOCK_REALTIME,&after);
	tssub(after,ctx->startneg,ctx->initctx_time);	
	return 0;
}
#endif


/*Initializes a new context based on the provided ulids.
 * If the context is found to already exist, a pointer to that
 * context is returned.
 * returns NULL in case of problem
 *
 * if @new is not NULL, *new is set to TRUE if a new context has been
 * created. It is set to FALSE if the context were already present.
 */
static struct shim6_ctx* __init_shim6_ctx(struct shim6_loc_l* ulid_local,
					  struct in6_addr* ulid_peer,
					  int* new)
{
	struct shim6_ctx* ctx;
	int ulid_hash=hash_ulid(ulid_peer);
	int ct_hash;
	uint64_t ct;
	struct hba_set* hs;
	int valid_method;
	struct shim6_loc_l *lulid_local;

	/*Maybe we are receiving a request for an already existing context*/
	ctx=lookup_ulid(ulid_peer,&ulid_local->addr);
	if (ctx) {
		PDEBUG("Request to create an already existing context\n");
		if (new) *new=FALSE;
		return ctx;
	}

	PDEBUG("Initializing a new context...\n");

	if (new) *new=TRUE;
	
	ctx=malloc(sizeof(struct shim6_ctx));
	if (!ctx) {
		syslog(LOG_ERR, "%s : Not enough memory\n", __FUNCTION__);
		return NULL;
	}

	/*Context initialization*/
	bzero(ctx,sizeof(struct shim6_ctx));

#ifdef SHIM6EVAL
	/*setting starting time*/
	clock_gettime(CLOCK_REALTIME,&ctx->startneg);
	ctx->eval_counter=eval_counter++;
#endif

	ctx->state=SHIM6_IDLE;

	/*ulids equal locators, and both equal those of 
	  the packet to be sent.*/
	memcpy(&ctx->ulid_local,ulid_local,sizeof(*ulid_local));
 	lulid_local=lookup_loc_l(&ulid_local->addr,NULL);
	if (lulid_local) lulid_local->refcnt++;
	ipv6_addr_copy(&ctx->ulid_peer,ulid_peer);
	
	ipv6_addr_copy(&ctx->lp_local,&ulid_local->addr);
	ipv6_addr_copy(&ctx->lp_peer,ulid_peer);

	/*On the beginning, the peer locator list only contains lp_peer*/
	if (alloc_single_locsetp(&ctx->ls_peer,ulid_peer)<0) {
		return NULL;
	}

	/*Setting the local locator list according to the valid method 
	 * of ulid_local
	 */
	valid_method=get_valid_method(&ulid_local->addr,ulid_local->ifidx,&hs);
	
	if (hs && !hs->cgacompat) {
		ctx->ls_localp=(struct locset*)hs->private;
		PDEBUG("1:ctx->ls_localp is %p\n",ctx->ls_localp);
	}
	else if (valid_method==SHIM6_CGA || (hs && hs->cgacompat)
#ifdef SHIM6EVAL
		 || measure_sec==0
#endif
		) {
		ctx->ls_localp=main_loc_set();
		PDEBUG("2:ctx->ls_localp is %p\n",ctx->ls_localp);
	}
	else {
		/*The local ulid is neither an HBA nor a CGA, only one
		  locator may be used*/
		ctx->ls_localp=alloc_single_locsetl(&ulid_local->addr);
		if (!ctx->ls_localp) {
			APPLOG_NOMEM();
			free(ctx->ls_localp->lsetp);
			return NULL;
		}
		PDEBUG("3:ctx->ls_localp is %p\n",ctx->ls_localp);
	}

	ct=gen_new_ct();

	if (!ct) {
		free(ctx->ls_peer.psetp);
		if (ctx->ls_localp->single) free(ctx->ls_localp);
		free(ctx);
		return NULL;
	}

	ctx->ct_local=ct;
	ct_hash=hash_ct(ct);
	       
	/*Timers initialization*/
	init_timer(&ctx->retransmit_timer);

	/*Set REAP tka to default value. This is the only REAP thing we need
	 *to do now already (real REAP init is done by shim6_established()
	 *because tka can be changed during shim6 init. (by i2 or r2)
	 */
	ctx->reap.tka=REAP_SEND_TIMEOUT;
	
	/*Insert into hashtables*/
	
	list_add(&ctx->collide_ulid,
		 &ulid_hashtable[ulid_hash]);
	list_add(&ctx->collide_ct,
		 &ct_hashtable[ct_hash]);
	list_add(&ctx->init_list,
		 &init_list);
	
	return ctx;
}

/*This function should be called to create a context upon request from 
 * the kernel.
 * Format for the message :
 *  --------------------------------------------------------------
 * |local ulid (128 bits) | peer ulid (128 bits) | ifidx (32bits) |
 *  --------------------------------------------------------------
 */
struct shim6_ctx* init_shim6_ctx(struct nlmsghdr* nlhdr)
{
	struct shim6_loc_l* lulid_local;
	struct in6_addr *ulid_peer, *ulid_local;
	int ifidx;
	struct shim6_ctx* ctx;
	int new;
	uint8_t random_byte;
	struct timespec timeout;


	ulid_local=NLMSG_DATA(nlhdr);
	ulid_peer=ulid_local+1;
	ifidx=*(int*)(ulid_peer+1);
	
	lulid_local=lookup_loc_l(ulid_local,NULL);
 	if (!lulid_local) {
		PDEBUG("Request to create a shim6 ctx with an "
		       "invalid local ulid.\n");
		return NULL;
	}

	ctx=__init_shim6_ctx(lulid_local,ulid_peer,&new);
	if (!ctx) return NULL;
	
	if (!new) return ctx;

	send_i1(ctx);
	
	/*Starting retransmit timer
	 * draft-proto-08, section 7.8 :
	 * -use of binary exponential backoff
	 * -randomize between 0.5 and 1.5 of computed time
	 */
	ctx->nb_retries=0;
	ctx->cur_timeout_val=SHIM6_I1_TIMEOUT; 
	
	random_byte=(__u8)random_int();
	tssetdsec(timeout, ctx->cur_timeout_val/2.0+
		  (random_byte*ctx->cur_timeout_val)/256.0);
	add_task_rel(&timeout,&ctx->retransmit_timer,shim6_retransmit);
	return ctx;
}

/**
 * Handler for message SHIM6_NL_NEW_LOC_ADDR
 * Format for the message :
 *
 *  ---------------------------------------------------------------
 * |      IPv6 addr. (128 bits)        | interface index (32 bits) |
 *  ---------------------------------------------------------------
 */
void shim6_new_loc_addr(struct nlmsghdr* nlhdr)
{
	struct in6_addr* addr=NLMSG_DATA(nlhdr);
	PDEBUG("Entering %s\n",__FUNCTION__);
	int* ifidx=(int*)(addr+1);

	PDEBUG("Adding address %s to local locator list\n",
	       addrtostr(addr));

	new_addr(addr,*ifidx);
}
/**
 * Handler for message SHIM6_NL_DEL_LOC_ADDR
 * Format for the message :
 *
 *  ---------------------------------------------------------------
 * |      IPv6 addr. (128 bits)        | interface index (32 bits) |
 *  ---------------------------------------------------------------
 */
void shim6_del_loc_addr(struct nlmsghdr* nlhdr)
{
	struct in6_addr* addr=NLMSG_DATA(nlhdr);
	int* ifidx=(int*)(addr+1);

	del_addr(addr,*ifidx);
}

/**
 * Decrements the refcount and frees the context stored in timer->private.
 * 
 */
void shim6_free_ctx(struct tq_elem* timer)
{
	struct shim6_ctx* ctx=(struct shim6_ctx*)timer->private;
	if (--ctx->refcnt==0) free(ctx);
}

void shim6_del_ctx(struct shim6_ctx* ctx)
{
	struct shim6_loc_l *lulid_local;
	PDEBUG("Entering %s\n",__FUNCTION__);

	/*Release the reap context elements*/
	if (ctx->state==SHIM6_ESTABLISHED)
		reap_release_ctx(&ctx->reap);
	
	/*Remove the context from the hash tables*/
	
	list_del(&ctx->collide_ulid);
	list_del(&ctx->collide_ct);
	if (!list_empty(&ctx->init_list)) {
		list_del(&ctx->init_list);
	}

	if (!attack && ctx->state==SHIM6_ESTABLISHED)
		xfrm_del_shim6_ctx(&ctx->ulid_local.addr, &ctx->ulid_peer,
				   ctx->ct_local, ctx->ct_peer);

	if (ctx->ls_peer.psetp) free(ctx->ls_peer.psetp);		
	if (ctx->pds) free(ctx->pds);
	if (ctx->r1_vldt) free(ctx->r1_vldt);
	if (ctx->ls_localp->single) free(ctx->ls_localp);
 	lulid_local=lookup_loc_l(&ctx->ulid_local.addr,NULL);
	if (lulid_local) {
		lulid_local->refcnt--;
		if (lulid_local->refcnt==0 && lulid_local->broken) 
			/*broken => not useable as locator
			 *refcnt is 0 => not used anymore as a ULID
			 * ==> This address can be completely removed*/
			del_addr(&lulid_local->addr,lulid_local->ifidx);
	}
	
	if (del_task_and_free(&ctx->retransmit_timer, shim6_free_ctx,ctx)==1)
		ctx->refcnt++;

	if (!ctx->refcnt) free(ctx);
}


/*Destroys all contexts*/
void shim6_del_all_ctx()
{
	struct shim6_ctx* ctx;
	struct shim6_ctx* temp;
	int i;

	/*Destroy all states*/
	for (i=0;i<SHIM6_HASH_SIZE;i++) {
		list_for_each_entry_safe(ctx,temp,&ct_hashtable[i],
					 collide_ct) {
			shim6_del_ctx(ctx);
		}
	}
}

/**
 * Retrieves the newest locset associated to @ls.
 * -If @ls is already the newest locset, @ls is returned
 * -If @ls is a clone, then the corresponding updated locset is returned.
 *  In case the returned pointer correspond to a locset that is inside the
 *  global structure of locsets.
 */
struct locset* newest_locset(struct locset *ls)
{
	if (!ls->clone) return ls;
	if (ls->main) return &glob_loc_sets;
	/*Then we need to find the global list, it is possible
	  by chaining pointers, not very elegant,sorry -:) */
	
	/*If there is no bug, all of this must be verified*/
	ASSERT(ls->size!=0);
	ASSERT(ls->lsetp[0].hs);
	ASSERT(ls->lsetp[0].hs->private);

	return (struct locset*)ls->lsetp[0].hs->private;
}

/**
 * This is the function that decides what locators to use for a particular
 * context, depending of its ulid :
 *  * loc ulid non secured : only one locator may be used
 *  * loc ulid CGA : All locators may be used
 *  * loc ulid HBA/CGA compat : All locators may be used with mixed
 *                           verif mechanisms (HBA when possible)
 *  * loc ulid pure HBA : All the HBA set may be used as the loc set.
 *
 * Also, if the non-secured mode is configured (only for experimentation !) :
 * SHIM6_EVAL is defined and measure_sec is 0, then 
 * all addresses are included, and no verification is included.
 *
 * @newest: 1 if we ask for the newest available loc set (if we send an
 *        update to the peer). 0 if we want the currently valid one (If we 
 *        want to know what locators may be used by REAP). 
 *        Note that the two cases are different only when we sent an update
 *        to the peer, but did not yet get the ack. In the mean time
 *        we cannot use the newest locators.
 * @used_ls: If not NULL, it is set to the locset corresponding to that context
 *    according to the value of newest : if newest is FALSE, the pointer
 *    to the (perhaps cloned) locset of the context is registered in @used_ls, 
 *    if newest is TRUE, the most recent version of the locset for that context
 *    is retrieved in the global structures and registered in @used_ls.
 */
int get_nb_loc_locs(struct shim6_ctx* ctx, int newest, int* all_nonsecure,
		    int* useall_locators, struct locset** used_ls)
{
	int nb_locs=0;
	int list_cnt;
	struct locset *ls_it,*ls=NULL;

	if (useall_locators) *useall_locators=0;
	if (all_nonsecure) *all_nonsecure=0;

	ASSERT(ctx);

	if (newest) ls=newest_locset(ctx->ls_localp);
	else ls=ctx->ls_localp;

	if (ctx->ls_localp->main) { /*If verif method is CGA,
				      or HBA-cgacompat
				      we can use all available
				      locators*/
		if (useall_locators) *useall_locators=1;
		list_for_each_entry_all(ls_it,&ls->list,list,list_cnt) {
			nb_locs+=ls_it->size_not_broken;
		}
	}
	else {
			nb_locs=ls->size_not_broken; 
	}
	
#ifdef SHIM6EVAL	
	if (measure_sec==0) {
		/*Only for measurement : Although this is not secure,
		  we send a set of locators without HBA nor CGA, in order
		  to compare the context establishment in the different
		  scenarios*/
		if (useall_locators) *useall_locators=1;
		nb_locs=0;
		list_for_each_entry_all(ls_it,&ls->list,list,list_cnt) {
			nb_locs+=ls_it->size_not_broken;
		}
		if (all_nonsecure) *all_nonsecure=1;
	}
#endif

	if (used_ls) *used_ls=ls;

	return nb_locs;
}

/**
 * Fills the @addr with the set of local addresses allowed for that context.
 * @pre: -@addr has a size of at least get_nb_loc_locs()
 *       -@verif_method is NULL or has a size of at least get_nb_loc_locs()
 * @useall_locators: it is supposed to be the result of get_nb_loc_locs()
 * @allnonsecure: it is supposed to be the result of get_nb_loc_locs()
 * @newest: same semantic as in get_nb_loc_locs()
 * @post: -@need_signature is set to 1 if a signature is needed for that locator
 *       set (that is, if the local ulid is a CGA, more than one loc is present
 *       in the set and HBA verif cannot be done on the whole set.
 *        -@addr_array contains the set of local locators for that context
 *        -if @verif_method is not NULL, the verif_method is set for each
 *         locator.
 */
int get_loc_locs_array(struct shim6_ctx* ctx, int newest,
		       struct in6_addr* addr_array,
		       uint8_t* verif_method,
		       int allnonsecure, int useall_locators,
		       int* need_signature)
{
	int i,j;
	int list_cnt;
	struct locset* ls, *ls_it;

	if (need_signature) *need_signature=0;

	if (newest) ls=newest_locset(ctx->ls_localp);
	else ls=ctx->ls_localp;

	if (allnonsecure) {
		j=0;
		list_for_each_entry_all(ls_it,&ls->list,list,list_cnt) {
			for (i=0;i<ls_it->size;i++,j++) {
				shim6_loc_l* loc = ls_it->lsetp+i;
				if (loc->broken) {j--;continue;}
				ipv6_addr_copy(&addr_array[j],&loc->addr);
				if (verif_method) verif_method[j]=0;		
			}
		}
	}
	else if (useall_locators) {
		/*All locators are sent. If ulid_local is a pure CGA, all 
		  locators are validated by CGA. If ulid_local is a hybrid
		  HBA/CGA, all locators are validated with CGA, except
		  those that belong to the same hba set as ulid_local. 
		  Those ones are validated with HBA.*/
		j=0;
		list_for_each_entry_all(ls_it,&ls->list,list,list_cnt) {
			for (i=0;i<ls_it->size;i++,j++) {
				shim6_loc_l* loc = ls_it->lsetp+i;
				if (loc->broken) {j--;continue;}
				ipv6_addr_copy(&addr_array[j],&loc->addr);
				if (loc->hs && loc->hs==ctx->ulid_local.hs) {
					if (verif_method) 
						verif_method[j]=SHIM6_HBA;
				}
				else {
					if (verif_method)
						verif_method[j]=SHIM6_CGA;
					if (need_signature)
						*need_signature=1;
				}
			}
		}
	}
	else if (ctx->ls_localp->single) {
		/*locset of size one, no verif needed.
		  Although no option is sent in that case, we can 
		  reach this instruction when called shim6c does a
		  'cat' on a context with one local locator. */
		ipv6_addr_copy(addr_array, &ls->lsetp->addr);
		if (verif_method) verif_method[0]=0;
	}
	else {
		/*Only the locators of that set may be used (pure HBA)*/
		for (i=0,j=0;i<ls->size;i++,j++) {
			shim6_loc_l* loc = ls->lsetp+i;
			if (loc->broken) {j--;continue;}
			ipv6_addr_copy(&addr_array[j], &loc->addr);
			if (verif_method)
				verif_method[j]=SHIM6_HBA;
		}
	}
	return 0;
}
