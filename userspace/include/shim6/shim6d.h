/*
 *	Linux shim6 implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : December 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef __SHIM6D_H
#define __SHIM6D_H

#include <list.h>
#include <shim6/reapd.h>
#include <shim6/tqueue.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <utils/kref.h>

/*Port for the information server*/
#define INFOSERV_PORT 50000 /*Private ports are in the range [49152-65535]*/

/*INFOSERV commands (sent OOB to the client)*/
enum is_command {
	INFOSERV_CLOSE
};

/*Possible states for a shim6 context*/
#define SHIM6_IDLE 1
#define SHIM6_I1_SENT 2
#define SHIM6_I2_SENT 3
#define SHIM6_ESTABLISHED 4
#define SHIM6_I2BIS_SENT 5
#define SHIM6_E_FAILED 6
#define SHIM6_NO_SUPPORT 7

/*Locators validation methods
 */
#define SHIM6_HBA 1
#define SHIM6_CGA 2

/*shim6 parameters (times are in seconds)*/
#define SHIM6_TEARDOWN_TIMEOUT         10*60
#define SHIM6_I1_TIMEOUT               4
#define SHIM6_I1_RETRIES_MAX           4
#define SHIM6_NO_R1_HOLDDOWN_TIME      60
#define SHIM6_ICMP_HOLDDOWN_TIME       10*60
#define SHIM6_I2_TIMEOUT               4
#define SHIM6_I2_RETRIES_MAX           2
#define SHIM6_I2BIS_TIMEOUT            4
#define SHIM6_I2BIS_RETRIES_MAX        2
#define SHIM6_VALIDATOR_MIN_LIFETIME   30
#define SHIM6_VALIDATOR_RESOLUTION     1
#define SHIM6_UPDATE_TIMEOUT           4
#define SHIM6_MAX_UPDATE_TIMEOUT       120



/*SHIM6 Protocol number (still to be assigned by IANA) */

#define IPPROTO_SHIM6           61

#define NEXTHDR_NONE            59 /*No next header*/
#define IPV6_RECVPKTINFO        49 /* This is a socket option from RFC 3542.
				    * This is defined in recent glibc's only. 
				    * For now, we put it here*/

/*Extern variables - To be used only by the main thread !*/
extern struct list_head ct_hashtable[];

/*Locator structure : One structure per locator*/
struct shim6_loc_p {
	struct list_head  list;
	struct in6_addr   addr;
/*Those fields are still unused*/
	uint8_t           valid_method; /*validation method*/
	uint8_t           valid_done:1,
			  probe_done:1;     
};

struct shim6_loc_l {
	struct in6_addr  addr;
	int              ifidx; /*Interface index*/
	uint8_t          valid_method;
	struct hba_set*  hs; /*Used if valid_method is SHIM6_HBA*/	
};

/*This is defined for the seek of following the same scheme as in the kernel
  part of this implementation.*/
typedef struct shim6_loc_p shim6_loc_p;
typedef struct shim6_loc_l shim6_loc_l;

/*------------------------------------------------*/

/*Data structures for locator management*/

struct locset {
	struct list_head     list;
	int                  size; /*Number of locators stored in set*/
	uint32_t             gen_number;
	union {
		shim6_loc_l* lsetp;
		shim6_loc_p* psetp;
	} set;
#define lsetp set.lsetp
#define psetp set.psetp		
	int                  main:1, /*If 1, this is the main set, containing 
				       unsecured addresses, CGA addresses and 
				       HBA-CGAcompat addresses*/
		             clone:1, /*If 1, this is a clone, used between the
					sending of an update request, and the 
					reception of the ack.*/
                             single:1; /*If 1, the locset is allocated with 
					 malloc and contains only one locator, 
					 furthermore, it has no link with any 
					 locset in the system. This kind of 
					 locset is used when the local ulid
					 is not a CGA nor an HBA.*/
	struct kref          kref;
};

extern struct locset glob_loc_sets; /*This is a rare use of list.h : In this
				      circular list, every node has a content
				      (there is no content-less head)*/


/*------------------------------------------------*/


#define SHIM6_HASH_SIZE                16
#define hash_ulid(ulid_peer) \
jhash(ulid_peer,sizeof(struct in6_addr),0)%SHIM6_HASH_SIZE
/*ct is supposed to be 64 bits long*/
#define hash_ct(ct) jhash(&ct,8,0)%SHIM6_HASH_SIZE

/*Main shim user space context, one per couple of ULIDs "shim6-activated"
 * When the state becomes established, a corresponding context (smaller)
 * is created in the kernel*/
struct shim6_ctx {
	/*Collision resolution for the ulid hashtable*/
	struct list_head    collide_ulid;
	/*Collision resolution for the ct hashtable*/
	struct list_head    collide_ct;
	/*List of initializing contexts*/
	struct list_head    init_list; 
	
	/*The ulid_local is stored as a shim6_loc_l, because those fields are
	  often used (in particular for retrieving CGA information), BUT
	  it is possible that the corresponding locator structure does not 
	  exist anymore in global structures, because the locator is broken
	  or have disappeared. But it can still be used as a ULID, which is 
	  why we duplicate info here.*/
	struct in6_addr     ulid_peer;
	struct shim6_loc_l  ulid_local;

	unsigned short      state;
	
	uint32_t               fii; /*Forked Instance Identifier; 
				   ignored for now*/

/*Locators info for the peer*/
	struct locset       ls_peer; /*Array of all peer locators*/
	struct in6_addr     lp_peer; /*Preferred loc, used as destination*/

/*Locators info for the host*/
	struct locset*      ls_localp; /*Array of local locators/pointer to 
					 global structure*/
	struct in6_addr     lp_local;

/*Context tags : 64 bits, but only 47 low order bits are used*/
	uint64_t               ct_peer;
	uint64_t               ct_local;

/*Initiator nonce*/
	uint32_t               init_nonce;
	uint32_t               update_nonce; /*This must be another field
					       than the init nonce, because
					       it can happen that an
					       update is sent while still in 
					       I1_SENT state*/

/*R1 data (for i2 retransmission)*/
        struct shim6_opt*   r1_vldt;
	uint32_t            resp_nonce; /*in network byte order*/

/*Timer information*/
	struct tq_elem      retransmit_timer;
	int                 cur_timeout_val; /*for exp. backoff*/
	int                 nb_retries; /*maximum SHIM6_**_RETRIES_MAX*/
	struct reap_ctx     reap;
/*Locator validation*/
	struct shim6_opt*   pds;  /*CGA PDS of the peer*/
/*flags*/
	char                translate:1, /*1 if translation
					   is enabled, else 0*/	
		            ur_pending:1, /*1 if an ur has been sent and
					    we are waiting the ack*/
		            pds_sent:1, /*1 if the pds has already been sent to
					  the peer. This can be delayed to the 
					  update request if only one CGA were 
					  present at negotiation*/
		            pds_acked:1; /*1 if the pds was acked by the peer.
					  * if pds_sent is 1 but not pds_acked,
					  * we must resend the pds in any 
					  * I2/loc update packet.*/
	int                 refcnt; /*Only used when deleting a context*/
#ifdef SHIM6EVAL
	struct timespec     startneg; /*Timer for measuring negotiation time*/
	struct timespec     initctx_time; /*Duration of ctx init incl. send i1*/
	struct timespec     rcvr1_time; /*duration of rcv_r1 procedure*/
	struct timespec     rcvr2_time; /*Duration of rcv_r2 procedure*/
	int                 eval_counter;
#endif
};


/*Protocol messages*/

struct shim6hdr_i1
{
	struct shim6hdr_ctl common;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t   ct_1:7,
		  R:1; /*Reserved : zero on transmit*/
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t   R:1, /*Reserved : zero on transmit*/
		  ct_1:7;
#else
#error	"Unknown endianness : The configure script did not run correctly"
#endif
	uint8_t      ct_2;
	uint32_t     ct_3;
	uint32_t     nonce;
};

/*Same structure for i1, r2, update request and update aknowledgement 
  messages*/
typedef struct shim6hdr_i1 shim6hdr_i1;
typedef struct shim6hdr_i1 shim6hdr_r2;
typedef struct shim6hdr_i1 shim6hdr_ur; 
typedef struct shim6hdr_i1 shim6hdr_ua;

struct shim6hdr_r1
{
	struct shim6hdr_ctl common;
	__u16     reserved;
	__u32     init_nonce;
	__u32     resp_nonce;
};

typedef struct shim6hdr_r1 shim6hdr_r1;

struct shim6hdr_i2
{
	struct shim6hdr_ctl common;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        uint8_t      ct_1:7,
		     R:1; /*Reserved : zero on transmit*/
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t      R:1, /*Reserved : zero on transmit*/
		     ct_1:7;
#else
#error	"Unknown endianness : The configure script did not run correctly"
#endif	
	uint8_t      ct_2;
	uint32_t     ct_3;
	uint32_t     init_nonce;
	uint32_t     resp_nonce;
	uint32_t     reserved;
};

typedef struct shim6hdr_i2 shim6hdr_i2;

static inline struct shim6_ctx* shim6_ctx(struct reap_ctx* rctx)
{
	return container_of(rctx,struct shim6_ctx,reap);
}



#ifdef SHIM6_SRC /*Function prototypes only defined in the sources*/

int shim6d_init(void);

/*This function should be called to create a context upon request from 
 * the kernel.
 * Format for the message :
 *  ---------------------------------------------
 * |local ulid (128 bits) | peer ulid (128 bits) | 
 *  ---------------------------------------------
 */
struct shim6_ctx* init_shim6_ctx(struct nlmsghdr* nlhdr);

/*Destroys a shim6 context, both in user and kernel space*/
void shim6_del_ctx(struct shim6_ctx* ctx);
/*Destroys all shim6 contexts*/
void shim6_del_all_ctx(void);

/* Looks up for a context using the context tag hash table, or the ulid
 * hash table resp.
 */
 
struct shim6_ctx* lookup_ct(__u64 ct);
struct shim6_ctx* lookup_ulid(struct in6_addr* ulid_peer,
			      struct in6_addr* ulid_local);

/**
 * Returns the address of the locator corresponding to @loc, in any
 * set.
 * If @head is NULL, the glob_loc_sets list is search. It not, 
 * The given list is searched.
 */
shim6_loc_l* lookup_loc_l(struct in6_addr* loc, struct list_head* head);

/**
 * Returns the address of the locator corresponding to @loc if 
 * it belongs to the locator set used by @ctx.
 */
shim6_loc_l* lookup_loc_l_ctx(struct in6_addr* loc, struct shim6_ctx* ctx);

/*Handlers for messages received from the kernel*/
void shim6_new_loc_addr(struct nlmsghdr* nlhdr);
void shim6_del_loc_addr(struct nlmsghdr* nlhdr);


/*Handlers for messages received from the network*/
int rcv_i1(shim6hdr_i1* hdr, struct in6_addr* saddr, struct in6_addr* daddr);
int rcv_r1(shim6hdr_r1* hdr, struct in6_addr* saddr, struct in6_addr* daddr);
int rcv_i2(shim6hdr_i2* hdr,struct in6_addr* saddr, 
	   struct in6_addr* daddr, int ifidx);
int rcv_r2(shim6hdr_r2* hdr,struct in6_addr* saddr, struct in6_addr* daddr);
int rcv_ur(shim6hdr_ur* hdr,struct in6_addr* saddr, struct in6_addr* daddr);
int rcv_ua(shim6hdr_ur* hdr,struct in6_addr* saddr, struct in6_addr* daddr);

#endif /*SHIM6_SRC*/

/*==========================================
 * SHIM6 OPTIONS
 *==========================================
 */

/*types of the options
 * As indicated in section 5.15, we multiply by two
 * every value defined in the standard, in order to take into account
 * the C flag. (if reset : type*=2, if set, type=type*2+1)
 * by default the C flag is never set.
 */
#define SHIM6_TYPEOPT_VALIDATOR 2
#define SHIM6_TYPEOPT_LOC_LIST  4
#define SHIM6_TYPEOPT_LOC_PREF  6
#define SHIM6_TYPEOPT_CGA_PDS   8
#define SHIM6_TYPEOPT_CGA_SIGN  10
#define SHIM6_TYPEOPT_ULID_PAIR 12
#define SHIM6_TYPEOPT_FII       14
#define SHIM6_TYPEOPT_MAXVALUE  14 /*Maximum value for the options*/

/*Options parameters*/
#define VAL_LENGTH 20 /*Validator length : we use sha1, which is 20 octets*/



/*General structure for option fields*/
struct shim6_opt 
{
	__u16     type;
	__u16     length;
	/*Next comes the variable length field,
	  filled in by a walking pointer.*/
};

/*===============*/
/*Specific structures for option fields
 * As option fields have variable lengths,
 * These structs ARE NOT really the packet data,
 * but a set of pointers (of correct type) to that packet
 * data.
 */

struct loc_list_opt
{
	uint32_t*             gen_nb;
	uint8_t*              num_locs;
	uint8_t*              verif_method;
	uint8_t*              padding;
	struct in6_addr*   locators;
};


/*@pre : @buf is a locator list option, beginning with the gen_nb field
 *       The option must already exist
 *@post : @buf has been parsed, and all fields of *ll are set*/
static inline void set_loc_list_opt(struct loc_list_opt* ll, void* buf)
{
	int pad_len;
	
	ll->gen_nb=(uint32_t*)buf;
       	ll->num_locs=(uint8_t*)(ll->gen_nb+1);

	/*For this option, pad_len cannot be computed from the length field,
	  because of the requirement from draft shim6-proto-09 section 5.15.2*/
	pad_len=PAD_LENGTH(5+*ll->num_locs);

	ll->verif_method=ll->num_locs+1;
	ll->padding=ll->verif_method+*ll->num_locs;
	ll->locators=(struct in6_addr*)(ll->padding+pad_len);
}

/**
 * Retrieves the newest locset associated to @ls.
 * -If @ls is already the newest locset, @ls is returned
 * -If @ls is a clone, then the corresponding updated locset is returned.
 *  In case the returned pointer correspond to a locset that is inside the
 *  global structure of locsets.
 */
struct locset* newest_locset(struct locset *ls);

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
 * @ls: If not NULL, it is set to the locset corresponding to that context
 *    according to the value of newest : if newest is FALSE, the pointer
 *    to the (perhaps cloned) locset of the context is registered in @ls, 
 *    if newest is TRUE, the most recent version of the locset for that context
 *    is retrieved in the global structures and registered in @ls.
 */
int get_nb_loc_locs(struct shim6_ctx* ctx, int newest, int* all_nonsecure,
		    int* useall_locators, struct locset** ls);

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
		       int* need_signature);




#endif /*__SHIM6D_H*/

