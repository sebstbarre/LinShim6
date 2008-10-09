/*
 *	Linux shim6 implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Heavily inspired from the xfrm.c of the MIPL project.
 *            Authors:
 *                USAGI Team
 *                Ville Nuorvala <vnuorval@tcs.hut.fi>
 *                Henrik Petander <petander@tcs.hut.fi>
 *
 *                Copyright 2003 USAGI/WIDE Project
 *                Copyright 2003-2005 Go-Core Project
 *                Copyright 2003-2006 Helsinki University of Technology
 *
 *
 *     	date : February 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <config.h>
#include "xfrm.h"
#include <stdio.h>
#include <netinet/in.h>
#include <linux/xfrm.h>
#include <linux/shim6_netlink.h>
#include <linux/shim6.h>
#include <libnetlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string.h>
#include <utils/util.h>
#include <utils/rtnl.h>
#include <utils/debug.h>
#include <shim6/shim6d.h>
#include "pipe.h"

/*As a first step, we only allow one template. If one wants to add 
 * interoperability with MIPv6/IPsec/..., more templates could be added*/
#define SHIM6_MAX_TMPLS 1 /* SHIM6 */

static pthread_t xfrm_listener;

static pthread_cond_t ack=PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

#define XFRMS_RTA(x)	((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_usersa_info))))

/*Buffer used to generate the shim6_data (avoids malloc'ing)*/
uint8_t shim6_data_buf[sizeof(struct shim6_data)+
		       MAX_SHIM6_PATHS*sizeof(struct shim6_path)];



/* This is a helper function to be used by dump_all_kern_states
 *
 * @arg must point to file descriptor where to dump the state*/
static int __dump_one_state(struct sockaddr_nl *who,
			    struct nlmsghdr *n, void *arg)
{
	struct xfrm_usersa_info *sa=NLMSG_DATA(n);
	int fd;
	struct rtattr *rta_tb[XFRMA_MAX+1];
	struct shim6_data* data;
	
	/*Getting information*/
	
	if (!arg) return -1;
	fd=*(int*)arg;
	
	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*sa)))
		return -1;
	if (n->nlmsg_type != XFRM_MSG_NEWSA)
		return 0;
	if (sa->id.proto!=IPPROTO_SHIM6) return 0;
	
	memset(rta_tb, 0, sizeof(rta_tb));	
	parse_rtattr(rta_tb, XFRMA_MAX, XFRMS_RTA(sa), 
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*sa)));
	if (!rta_tb[XFRMA_SHIM6]) return -1;
	data=RTA_DATA(rta_tb[XFRMA_SHIM6]);
	
	/*Printing information*/
	dprintf(fd,"------------------------------------------\n");	
	if (data->paths[0].flags & SHIM6_DATA_TRANSLATE)
		dprintf(fd,"Address rewriting enabled\n");
	else 
		dprintf(fd,"Address rewriting disabled\n");
	if (data->flags & SHIM6_DATA_INBOUND) {
		dprintf(fd,"Inbound context\n");
		dprintf(fd,"\tULID peer in selector: %s\n",
			addrtostr((struct in6_addr*)&sa->sel.saddr.a6));
		dprintf(fd,"\tULID local in selector (should be ::) : %s\n",
			addrtostr((struct in6_addr*)&sa->sel.daddr.a6));
		dprintf(fd,"\tULID peer in data : %s\n",
			addrtostr(&data->paths[0].remote));
		dprintf(fd,"\tULID local in data : %s\n",
			addrtostr(&data->paths[0].local));
		dprintf(fd,"\tLocal context tag : %llx\n",data->ct);
	}
	else {
		dprintf(fd,"Outbound context\n");       
		dprintf(fd,"\tULID peer in selector: %s\n",
			addrtostr((struct in6_addr*)&sa->sel.daddr.a6));
		dprintf(fd,"\tULID local in selector : %s\n",
			addrtostr((struct in6_addr*)&sa->sel.saddr.a6));
		dprintf(fd,"\tCurrent peer locator : %s\n",
			addrtostr(&data->paths[0].remote));
		dprintf(fd,"\tCurrent local locator :%s\n",
			addrtostr(&data->paths[0].local));
		dprintf(fd,"\tPeer context tag : %llx\n",data->ct);

	}
	dprintf(fd,"------------------------------------------\n");

	return 0;
}


/**
 * Dumps all kernel xfrm states to the file descriptor @fd
 * @str is not used (it is there to match cons_cmd_handler type - info_server.c)
 */
int dump_all_kern_states(int fd, char* str)
{
	if (xfrm_sa_iterate(__dump_one_state,(void*)&fd)<0)
		dprintf(fd,"An error happened during execution of "
			"xfrm_sa_iterate\n");
	return 0;
}

#define XFRMP_RTA(x)	((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_userpolicy_info))))

/* This is a helper function to be used by dump_all_kern_policies
 *
 * @arg must point to file descriptor where to dump the state*/
static int __dump_one_policy(struct sockaddr_nl *who,
			     struct nlmsghdr *n, void *arg)
{
	struct xfrm_userpolicy_info *pol=NLMSG_DATA(n);
	struct rtattr *rta_tb[XFRMA_MAX+1];
	struct xfrm_selector* sel;
	struct xfrm_user_tmpl* tmpl;
	int fd;
	
	/*Getting information*/
	
	if (!arg) return -1;
	fd=*(int*)arg;
	
	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*pol)))
		return -1;
	if (n->nlmsg_type != XFRM_MSG_NEWPOLICY)
		return 0;
	
	memset(rta_tb, 0, sizeof(rta_tb));	
	parse_rtattr(rta_tb, XFRMA_MAX, XFRMP_RTA(pol), 
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*pol)));

/*	if (!rta_tb[XFRMA_SHIM6]) return -1;
	data=RTA_DATA(rta_tb[XFRMA_SHIM6]);*/
/*Pour savoir combien il y a de templates : sans doute pol->xfrm_nr
 * Il faut aussi vérifier que tous ces templates tiennent bien dans
 * la mémoire allouée*/	
	/*Printing information*/
	dprintf(fd,"------------------------------------------\n");	
	sel=&pol->sel;
	dprintf(fd,"Selector information :\n"
		"\t sel.daddr %x:%x:%x:%x:%x:%x:%x:%x\n"
		"\t sel.saddr %x:%x:%x:%x:%x:%x:%x:%x\n"
		"\t sel.dport %x\n"
		"\t sel.dport_mask %x\n"
		"\t sel.sport %x\n"
		"\t sel.sport_mask %x\n"
		"\t sel.prefixlen_d %d\n"
		"\t sel.prefixlen_s %d\n"
		"\t sel.proto %d\n"
		"\t sel.ifindex %d\n",
		NIP6ADDR((struct in6_addr *)&sel->daddr),
		NIP6ADDR((struct in6_addr *)&sel->saddr),
		sel->dport,
		sel->dport_mask,
		sel->sport,
		sel->sport_mask,
		sel->prefixlen_d,
		sel->prefixlen_s,
		sel->proto,
		sel->ifindex);
	dprintf(fd,"priority : %d\n"
		"index:%d\n",
		pol->priority,pol->index);
	dprintf(fd,"direction : ");
	switch(pol->dir) {
	case XFRM_POLICY_OUT:
		dprintf(fd,"OUT\n"); break;
	case XFRM_POLICY_IN:
		dprintf(fd,"IN\n"); break;
	default:
		dprintf(fd,"UNKNOWN\n");
	}
	dprintf(fd,"action : ");
	switch(pol->action) {
	case XFRM_POLICY_ALLOW:
		dprintf(fd,"ALLOW\n"); break;
	case XFRM_POLICY_BLOCK:
		dprintf(fd,"BLOCK\n"); break;
	default:
		dprintf(fd,"UNKNOWN\n");
	}
	if (rta_tb[XFRMA_TMPL]) {		
		for (tmpl=RTA_DATA(rta_tb[XFRMA_TMPL]);
		     (char*)(tmpl+1)<=
			     (char*)(rta_tb[XFRMA_TMPL])+
			     rta_tb[XFRMA_TMPL]->rta_len;
		     tmpl++) {
			dprintf(fd,"Template information :\n"
				"\t xfrma_tmpl.id.daddr "
				"%x:%x:%x:%x:%x:%x:%x:%x\n"
				"\t xfrma_tmpl.id.spi %x\n"
				"\t xfrma_tmpl.id.proto %d\n"
				"\t xfrma_tmpl.saddr %x:%x:%x:%x:%x:%x:%x:%x\n"
				"\t xfrma_tmpl.reqid %d\n"
				"\t xfrma_tmpl.mode %d\n"
				"\t xfmra_tmpl.optional %d\n"
				"\t xfrma_tmpl.aalgos %x\n"
				"\t xfrma_tmpl.ealgos %d\n"
				"\t xfrma_tmpl.calgos %d\n",
				NIP6ADDR((struct in6_addr *)&tmpl->id.daddr),
				tmpl->id.spi,
				tmpl->id.proto,
				NIP6ADDR((struct in6_addr *)&tmpl->saddr),
				tmpl->reqid,
				tmpl->mode,
				tmpl->optional,
				tmpl->aalgos,
				tmpl->ealgos,
				tmpl->calgos);
		}
	}
	
	dprintf(fd,"------------------------------------------\n");

	return 0;
}

/**
 * Dumps all kernel xfrm policies to the file descriptor @fd
 * @str is not used (it is there to match cons_cmd_handler type - info_server.c)
 */
int dump_all_kern_policies(int fd, char* str)
{
	if (xfrm_pol_iterate(__dump_one_policy,(void*)&fd)<0)
		dprintf(fd,"An error happened during execution of "
			"xfrm_pol_iterate\n");
	return 0;
}

static void nlmsg_dump(int nlmsg_flags, int nlmsg_type)
{
	cdbg("nlmsg_flags %x\n"
	     "nlmsg_type %d\n",
	     nlmsg_flags,
	     nlmsg_type);
}

static void xfrm_sel_dump(const struct xfrm_selector *sel)
{
	cdbg("sel.daddr %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "sel.saddr %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "sel.dport %x\n"
	     "sel.dport_mask %x\n"
	     "sel.sport %x\n"
	     "sel.sport_mask %x\n"
	     "sel.prefixlen_d %d\n"
	     "sel.prefixlen_s %d\n"
	     "sel.proto %d\n"
	     "sel.ifindex %d\n",
	     NIP6ADDR((struct in6_addr *)&sel->daddr),
	     NIP6ADDR((struct in6_addr *)&sel->saddr),
	     sel->dport,
	     sel->dport_mask,
	     sel->sport,
	     sel->sport_mask,
	     sel->prefixlen_d,
	     sel->prefixlen_s,
	     sel->proto,
	     sel->ifindex);
}

static void xfrm_tmpl_dump(const struct xfrm_user_tmpl *tmpl)
{
	cdbg("xfrma_tmpl.id.daddr %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "xfrma_tmpl.id.spi %x\n"
	     "xfrma_tmpl.id.proto %d\n"
	     "xfrma_tmpl.saddr %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "xfrma_tmpl.reqid %d\n"
	     "xfrma_tmpl.mode %d\n"
	     "xfmra_tmpl.optional %d\n"
	     "xfrma_tmpl.aalgos %x\n"
	     "xfrma_tmpl.ealgos %d\n"
	     "xfrma_tmpl.calgos %d\n",
	     NIP6ADDR((struct in6_addr *)&tmpl->id.daddr),
	     tmpl->id.spi,
	     tmpl->id.proto,
	     NIP6ADDR((struct in6_addr *)&tmpl->saddr),
	     tmpl->reqid,
	     tmpl->mode,
	     tmpl->aalgos,
	     tmpl->ealgos,
	     tmpl->calgos);
}

static void xfrm_policy_dump(const char *msg, int nlmsg_flags, int nlmsg_type,
			     const struct xfrm_userpolicy_info *sp,
			     struct xfrm_user_tmpl *tmpls, int num_tmpl)
{
	int i;
	cdbg(msg);
	nlmsg_dump(nlmsg_flags, nlmsg_type);
	xfrm_sel_dump(&sp->sel);
	cdbg("priority %d\n"
	     "dir %d\n"
	     "action %d\n",
	    sp->priority,
	    sp->dir,
	    sp->action);
	for (i = 0; i < num_tmpl; i++)
		xfrm_tmpl_dump(&tmpls[i]);
}

static void xfrm_policy_id_dump(const char *msg, 
				const struct xfrm_userpolicy_id *sp_id)
{
	cdbg(msg);
	xfrm_sel_dump(&sp_id->sel);
	cdbg("dir %d\n", sp_id->dir);
}

static void xfrm_state_dump(const char *msg, int nlmsg_flags, int nlmsg_type,
			    const struct xfrm_usersa_info *sa)
{
	cdbg(msg);
	nlmsg_dump(nlmsg_flags, nlmsg_type);
	xfrm_sel_dump(&sa->sel);
	cdbg("id.daddr %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "id.spi %x\n"
	     "id.proto %d\n"
	     "saddr %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "reqid %d\n"
	     "mode %d\n"
	     "flags %x\n",
	     NIP6ADDR((struct in6_addr *)&sa->id.daddr),
	     sa->id.spi,
	     sa->id.proto,
	     NIP6ADDR((struct in6_addr *)&sa->saddr),
	     sa->reqid,
	     sa->mode,
	     sa->flags);
}

static void xfrm_state_id_dump(const char *msg,
			       const struct xfrm_usersa_id *sa_id,
			       const xfrm_address_t* saddr)
{
	cdbg(msg);
	cdbg("daddr %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "spi %x\n"
	     "proto %d\n"
	     "saddr %x:%x:%x:%x:%x:%x:%x:%x\n",
	     NIP6ADDR((struct in6_addr *)&sa_id->daddr),
	     sa_id->spi,
	     sa_id->proto,
	     NIP6ADDR((struct in6_addr *)saddr));
}

/* Set xfrm_selector fields for shim6 policies and shim6
 * states */
static void set_selector(const struct in6_addr *daddr, 
			 const struct in6_addr *saddr,
			 int ifindex, int proto, struct xfrm_selector *sel)
{
	bzero(sel, sizeof(*sel));

	sel->family = AF_INET6;
	sel->user = getuid();
	sel->ifindex = ifindex;
	sel->proto = proto;

	memcpy(&sel->saddr.a6, saddr, sizeof(*saddr));
	memcpy(&sel->daddr.a6, daddr, sizeof(*daddr));

	if (!ipv6_addr_equal(daddr, &in6addr_any))
		sel->prefixlen_d = 128;
	if (!ipv6_addr_equal(saddr, &in6addr_any))
		sel->prefixlen_s = 128;
}

static void set_shim6_data(__u64 ct, 
			   const struct in6_addr* in6_peer,
			   const struct in6_addr* in6_local, 
			   struct shim6_data *data, int flags,
			   struct shim6_path *paths, int npaths,
			   int path_flags)
{
	data->ct=ct;
	data->flags=flags;
	data->cur_path_idx=0; /*Not used if not doing multipath, starting
				with index 0 for the round-robin if multipath
				mode is enabled.*/
	ipv6_addr_copy(&data->paths[0].local,in6_local);
	ipv6_addr_copy(&data->paths[0].remote,in6_peer);
	data->paths[0].flags=path_flags;
	data->npaths=1;

}

static void create_shim6_tmpl(struct xfrm_user_tmpl *tmpl, __u64 ct)
{	
	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->family = AF_INET6;
	tmpl->id.proto = IPPROTO_SHIM6;
	tmpl->id.spi = (__be32)(ct & 0xFFFFFFFF);
	tmpl->mode = XFRM_MODE_SHIM6;
	tmpl->optional = 1;
	tmpl->reqid = 0;
}

static inline void xfrm_lft(struct xfrm_lifetime_cfg *lft)
{
	lft->soft_byte_limit = XFRM_INF;
	lft->soft_packet_limit = XFRM_INF;
	lft->hard_byte_limit = XFRM_INF;
	lft->hard_packet_limit = XFRM_INF;
	lft->soft_use_expires_seconds=SHIM6_TEARDOWN_TIMEOUT;       	
}

static int xfrm_policy_add(const struct xfrm_selector *sel, int update,
			   int dir, int action, int priority, 
			   struct xfrm_user_tmpl *tmpls, int num_tmpl,
			   int flags)
{
	uint8_t buf[NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info))
		    + RTA_LENGTH(sizeof(struct xfrm_user_tmpl) 
				 * SHIM6_MAX_TMPLS)];
	struct nlmsghdr *n;
	struct xfrm_userpolicy_info *pol;
	int err;
	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info));
	if (update) {
		n->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
		n->nlmsg_type = XFRM_MSG_UPDPOLICY;
	} else {
		n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
		n->nlmsg_type = XFRM_MSG_NEWPOLICY;
	}
	pol = NLMSG_DATA(n);
	memcpy(&pol->sel, sel, sizeof(struct xfrm_selector));
	xfrm_lft(&pol->lft);
	pol->priority  = priority;
	pol->dir = dir;
	pol->action = action;
	pol->share = XFRM_SHARE_ANY;
	pol->flags = flags;
	
	if(num_tmpl > 0)
		addattr_l(n, sizeof(buf), XFRMA_TMPL, 
			  tmpls, sizeof(struct xfrm_user_tmpl) * num_tmpl);
	
	if ((err = rtnl_xfrm_do(n, NULL)) < 0)
		xfrm_policy_dump("Failed to add policy:\n",
				 n->nlmsg_flags, n->nlmsg_type, 
				 pol, tmpls, num_tmpl);
	return err;
}

static int xfrm_policy_del(const struct xfrm_selector *sel, int dir)
{
	uint8_t buf[NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id))];
	struct nlmsghdr *n;
	struct xfrm_userpolicy_id *pol_id;
	int err;

	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id));
	n->nlmsg_flags = NLM_F_REQUEST;
	n->nlmsg_type = XFRM_MSG_DELPOLICY;
	
	pol_id = NLMSG_DATA(n);
	memcpy(&pol_id->sel, sel, sizeof(struct xfrm_selector));
	pol_id->dir = dir;
	
	if ((err = rtnl_xfrm_do(n, NULL)) < 0)
		xfrm_policy_id_dump("Failed to del policy:\n", pol_id);
	return err;
}

static int xfrm_state_add(const struct xfrm_selector *sel,
			  int proto, int update, uint8_t flags, 
			  const struct shim6_data *data)
{
	uint8_t buf[NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)) 
		    + RTA_LENGTH(SHIM6_DATA_LENGTH(data))];
	struct nlmsghdr *n;
	struct xfrm_usersa_info *sa;
	int err;
	
	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	if (update) {
		n->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
		n->nlmsg_type = XFRM_MSG_UPDSA;
	} else {
		n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
		n->nlmsg_type = XFRM_MSG_NEWSA;
	}
	sa = NLMSG_DATA(n);
	memcpy(&sa->sel, sel, sizeof(struct xfrm_selector));
	/* State src and dst addresses */
	memcpy(sa->id.daddr.a6, sel->daddr.a6, sizeof(sel->daddr.a6));
	sa->id.proto = proto;
	/*32 low order bits of ct are used for spi based hash table lookup
	  (only for inbound contexts*/
	if (data->flags & SHIM6_DATA_INBOUND) {
		sa->id.spi = (__be32)(data->ct & 0xFFFFFFFF);
	}
	memcpy(sa->saddr.a6, sel->saddr.a6, sizeof(sel->saddr.a6));
	xfrm_lft(&sa->lft);
	sa->family = AF_INET6;
	sa->mode = XFRM_MODE_SHIM6;
	sa->flags = flags;

	addattr_l(n, sizeof(buf), XFRMA_SHIM6,data, SHIM6_DATA_LENGTH(data));
	if ((err = rtnl_xfrm_do(n, NULL)) < 0)
		xfrm_state_dump("Failed to add state:\n",
				n->nlmsg_flags, n->nlmsg_type, sa);
	return err;
}

static int xfrm_state_del(int proto, const struct xfrm_selector *sel, 
			  const struct shim6_data* data)
{
	uint8_t buf[NLMSG_LENGTH(sizeof(struct xfrm_usersa_id))
		    + RTA_LENGTH(sizeof(struct in6_addr))
		    + RTA_LENGTH(SHIM6_DATA_LENGTH(data))];
	struct nlmsghdr *n;
	struct xfrm_usersa_id *sa_id;
	int err;
	
	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
	n->nlmsg_flags = NLM_F_REQUEST;
	n->nlmsg_type = XFRM_MSG_DELSA;

	sa_id = NLMSG_DATA(n);
	/* State src and dst addresses */
	memcpy(sa_id->daddr.a6, sel->daddr.a6, sizeof(sel->daddr.a6));
	sa_id->family = AF_INET6;
	sa_id->proto = proto;
	
	if (addattr_l(n, sizeof(buf), XFRMA_SRCADDR,sel->saddr.a6, 
		      sizeof(sel->saddr.a6))<0)
		syslog(LOG_ERR,"%s: error while adding XFRMA_SRCADDR attr\n",
		       __FUNCTION__);
	if (addattr_l(n, sizeof(buf), XFRMA_SHIM6,data, 
		      SHIM6_DATA_LENGTH(data))<0)
		syslog(LOG_ERR,"%s: error while adding XFRMA_SHIM6 attr\n",
		       __FUNCTION__);
	if ((err = rtnl_xfrm_do(n, NULL)) < 0)
		xfrm_state_id_dump("Failed to del state:\n", sa_id,&sel->saddr);
	return err;
}


int xfrm_add_shim6_ctx(const struct in6_addr* ulid_local, 
		       const struct in6_addr* ulid_peer,
		       __u64 ct_local, __u64 ct_peer, struct shim6_path *paths,
		       int npaths)
{
	struct xfrm_selector sel;
	struct xfrm_user_tmpl tmpl;
	struct shim6_data *data=(struct shim6_data*)shim6_data_buf;

	/*Create state and policy for inbound and outbound directions
	  Outbound state MUST be created first (because the kernel interprets 
	  the source address for the first created context as the local 
	  ULID/loc.)*/

	/*outbound*/
	create_shim6_tmpl(&tmpl,0);	
	set_selector(ulid_peer, ulid_local, 0, 0, &sel);
	set_shim6_data(ct_peer,ulid_peer,ulid_local,data,0,paths,npaths, 0);
	xfrm_state_add(&sel, IPPROTO_SHIM6, FALSE, 0, data);
	xfrm_policy_add(&sel, 0, XFRM_POLICY_OUT, XFRM_POLICY_ALLOW, 
			SHIM6_PRIO_DEFAULT, &tmpl, 1,0);
	
	/*inbound*/
	create_shim6_tmpl(&tmpl,ct_local);
	set_selector(&in6addr_any, ulid_peer, 0, 0, &sel);	
	set_shim6_data(ct_local,ulid_peer,ulid_local,data, 
		       SHIM6_DATA_INBOUND, NULL,0, 0);
	xfrm_state_add(&sel, IPPROTO_SHIM6, FALSE, 0, data);
	xfrm_policy_add(&sel,0,XFRM_POLICY_IN,XFRM_POLICY_ALLOW,
			SHIM6_PRIO_DEFAULT,&tmpl,1,0);
	
	return 0;
}


int xfrm_del_shim6_ctx(const struct in6_addr* ulid_local, 
		       const struct in6_addr* ulid_peer,
		       __u64 ct_local, __u64 ct_peer)
{
	struct xfrm_selector sel;
	struct shim6_data *data=(struct shim6_data*) shim6_data_buf;

	/*outbound*/
	set_selector(ulid_peer, ulid_local, 0, 0, &sel);
	set_shim6_data(ct_peer,ulid_peer,ulid_local,data,0, NULL, 0, 0);
	xfrm_state_del(IPPROTO_SHIM6, &sel, data);
	xfrm_policy_del(&sel, XFRM_POLICY_OUT);
	
	/*inbound*/
	set_selector(&in6addr_any, ulid_peer, 0, 0, &sel);	
	set_shim6_data(ct_local,ulid_peer,ulid_local,data, SHIM6_DATA_INBOUND,
		       NULL,0,0);
	xfrm_state_del(IPPROTO_SHIM6, &sel, data);
	xfrm_policy_del(&sel, XFRM_POLICY_IN);
	
	return 0;
}

/*Updates a shim6 ctx to reflect a locator change
 * - the kernel states are updated
 * - the locators inside the shim6_ctx are replaced with the new ones
 */
int xfrm_update_shim6_ctx(struct shim6_ctx* ctx,
			  const struct in6_addr* new_loc_p,
			  const struct in6_addr* new_loc_l, 
			  struct shim6_path *paths, int npaths)
{
	struct xfrm_selector sel;
	struct shim6_data *data=(struct shim6_data*)shim6_data_buf;
	struct xfrm_user_tmpl tmpl;
	int translate; /*SHIM6_DATA_TRANSLATE if
			 translation must be enabled*/
	

	PDEBUG("%s:new_loc_p:%s",__FUNCTION__,addrtostr(new_loc_p));
	PDEBUG("%s:new_loc_l:%s",__FUNCTION__,addrtostr(new_loc_l));

	/*Activate translation ?*/
	if (ipv6_addr_equal(new_loc_p,&ctx->ulid_peer) && 
	    ipv6_addr_equal(new_loc_l,&ctx->ulid_local.addr))
		translate=0;
	else {
		translate=SHIM6_DATA_TRANSLATE;
		PDEBUG("translation enabled");
	}

	/*outbound */
	create_shim6_tmpl(&tmpl,0);
	set_selector(&ctx->ulid_peer,&ctx->ulid_local.addr,0,0,&sel);
	set_shim6_data(ctx->ct_peer,new_loc_p,new_loc_l,data, 
		       SHIM6_DATA_UPD, paths, npaths, translate);
	xfrm_state_add(&sel,IPPROTO_SHIM6,TRUE,0,data);
	xfrm_policy_add(&sel, TRUE, XFRM_POLICY_OUT, XFRM_POLICY_ALLOW, 
			SHIM6_PRIO_DEFAULT, &tmpl, 1,0);
	
	/*inbound */
	create_shim6_tmpl(&tmpl,ctx->ct_local);
	set_selector(&in6addr_any,&ctx->ulid_peer,0,0,&sel);
	set_shim6_data(ctx->ct_local,&ctx->ulid_peer,&ctx->ulid_local.addr,
		       data, SHIM6_DATA_INBOUND|SHIM6_DATA_UPD,
		       NULL, 0, translate);
	xfrm_state_add(&sel,IPPROTO_SHIM6,TRUE,0,data);


	
	/*Update the preferred locators in the daemon context*/
	ipv6_addr_copy(&ctx->lp_local,new_loc_l);
	ipv6_addr_copy(&ctx->lp_peer,new_loc_p);

	ctx->translate=(translate==SHIM6_DATA_TRANSLATE);

	return 0;	
}

#define XFRMEXP_RTA(x)	((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_user_expire))))

static int parse_expire(struct nlmsghdr *msg)
{
	struct xfrm_user_expire *exp;
	struct rtattr *rta_tb[XFRMA_MAX+1];
	struct shim6_data* data;
	struct shim6_ctx* ctx;

	if (msg->nlmsg_len < NLMSG_LENGTH(sizeof(*exp))) {
		PDEBUG("Too short nlmsg");
		return -1;
	}

	exp = NLMSG_DATA(msg);

	if (exp->state.id.proto != IPPROTO_SHIM6)
		return 0;

	memset(rta_tb, 0, sizeof(rta_tb));
	parse_rtattr(rta_tb, XFRMA_MAX, XFRMEXP_RTA(exp), 
		     msg->nlmsg_len - NLMSG_LENGTH(sizeof(*exp)));
	
	if (!rta_tb[XFRMA_SHIM6])
		return -1;
	
	data = (struct shim6_data *) RTA_DATA(rta_tb[XFRMA_SHIM6]);

	if (data->flags & SHIM6_DATA_INBOUND) 
		ctx=lookup_ct(data->ct);
	else 
		ctx=lookup_ulid((struct in6_addr*)&exp->state.sel.daddr,
				(struct in6_addr*)&exp->state.sel.saddr);
	if (!ctx) {
		PDEBUG("%s : userspace context not found\n",__FUNCTION__);
		if (data->flags&SHIM6_DATA_INBOUND)
			PDEBUG("\tinbound, ct is %llx\n",data->ct);
		else PDEBUG("\toutbound, saddr %s daddr %s\n",
			    addrtostr((struct in6_addr*)&exp->state.sel.saddr),
			    addrtostr((struct in6_addr*)&exp->state.sel.daddr));
		return -1;
	}
	shim6_del_ctx(ctx);
	return 0;
}


struct handler_data {
	int (*parse)(struct nlmsghdr*);
	struct nlmsghdr *n;
};

static int xfrm_rcv(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct handler_data hd;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	switch (n->nlmsg_type) {
	case XFRM_MSG_EXPIRE:
		hd.parse=parse_expire;
		hd.n=n;

		pthread_mutex_lock(&mutex);
		pipe_push_event(PIPE_EVENT_XFRM,&hd);
		pthread_cond_wait(&ack,&mutex);
		pthread_mutex_unlock(&mutex);		
		break;
	}
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	return 0;
}

struct rtnl_handle xfrm_rth;

static void *xfrm_listen(void *dummy)
{
	pthread_dbg("thread started");
	rtnl_ext_listen(&xfrm_rth, xfrm_rcv, NULL);
	pthread_exit(NULL);
}

/**
 * Checks if the policy is a shim6 policy. (We consider that a policy
 * is a shim6 policy if its priority is set to SHIM6_PRIO_DEFAULT or
 * NOSHIM6_PRIO_DEFAULT)
 *
 * @post : If the policy has priority SHIM6_PRIO_DEFAULT or 
 *         NOSHIM6_PRIO_DEFAULT, it is removed from
 *         the kernel. Returns 0 in case of success, -1 in case of failure.
 * 
 */
static int __clean_one_policy(struct sockaddr_nl *who,
			      struct nlmsghdr *n, void* arg)
{
	struct xfrm_userpolicy_info *pol=NLMSG_DATA(n);

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*pol)))
		return -1;
	if (n->nlmsg_type != XFRM_MSG_NEWPOLICY)
		return 0;
	if (pol->priority==SHIM6_PRIO_DEFAULT || 
	    pol->priority==NOSHIM6_PRIO_DEFAULT)
		xfrm_policy_del(&pol->sel,pol->dir);
	return 0;
}

/**
 * Checks if the state is a shim6 state. (We consider that a state
 * is a shim6 state if its id.proto is set to IPPROTO_SHIM6)
 *
 * @post : If the state has id.proto IPPROTO_SHIM6, it is removed from
 *         the kernel. Returns 0 in case of success, -1 in case of failure.
 * 
 */
static int __clean_one_state(struct sockaddr_nl *who,
			     struct nlmsghdr *n, void* arg)
{
	struct xfrm_usersa_info *sa=NLMSG_DATA(n);
	struct rtattr *rta_tb[XFRMA_MAX+1];
	struct shim6_data* data;
	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*sa)))
		return -1;
	if (n->nlmsg_type != XFRM_MSG_NEWSA)
		return 0;
	if (sa->id.proto!=IPPROTO_SHIM6) return 0;
	
	memset(rta_tb, 0, sizeof(rta_tb));	
	parse_rtattr(rta_tb, XFRMA_MAX, XFRMS_RTA(sa), 
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*sa)));
	if (!rta_tb[XFRMA_SHIM6]) return -1;
	data=RTA_DATA(rta_tb[XFRMA_SHIM6]);
	
	xfrm_state_del(IPPROTO_SHIM6,&sa->sel,data);
	
	return 0;
}

/**
 * Removes any remaining shim6 xfrm state/policy from a previous execution 
 * of shim6d. 
 */
static int clean_old_shim6_states(void)
{
	if (xfrm_pol_iterate(__clean_one_policy,NULL)<0) {
		applog(LOG_ERR,"%s:xfrm_pol_iterate failed",__FUNCTION__);
		return -1;
	}
	if (xfrm_sa_iterate(__clean_one_state,NULL)<0) {
		applog(LOG_ERR,"%s:xfrm_sa_iterate failed",__FUNCTION__);
		return -1;
	}
	return 0;
}

int xfrm_init(void)
{
	int val;
	struct xfrm_selector sel;
	int err=0;

	if (rtnl_xfrm_open(&xfrm_rth, 0) < 0)
		goto error;

	val = XFRMNLGRP_EXPIRE;
	if (setsockopt(xfrm_rth.fd, SOL_NETLINK,
		       NETLINK_ADD_MEMBERSHIP, &val, sizeof(val)) < 0)
		goto error;
	/* create netlink listener thread */
	if (pthread_create(&xfrm_listener, NULL, xfrm_listen, NULL))
		goto error;
	
	/*Removing old states that remain from a previous shim6d execution.*/
	if (clean_old_shim6_states()<0) goto error;

	/*Create policies that prevent ICMP and Shim6 packets
	  to go through the Shim6 layer.*/
	set_selector(&in6addr_any,&in6addr_any,0,IPPROTO_ICMPV6,&sel);
	err=xfrm_policy_add(&sel,0,XFRM_POLICY_OUT,XFRM_POLICY_ALLOW,
				   NOSHIM6_PRIO_DEFAULT,NULL,0,0);
	if (err<0 && err!=-EEXIST) goto error;
	sel.proto=IPPROTO_SHIM6;
	err=xfrm_policy_add(&sel,0,XFRM_POLICY_OUT,XFRM_POLICY_ALLOW,
			    NOSHIM6_PRIO_DEFAULT,NULL,0,0);
	if (err<0 && err!=-EEXIST) goto error;
	
	return 0;

error:
	PDEBUG("%s: error code %d",__FUNCTION__,err);
	return err;
}

void xfrm_handler(void* data)
{
	struct handler_data* hd=(struct handler_data*)data;
	hd->parse(hd->n);
/*The xfrm_rcv function can now return*/
	pthread_mutex_lock(&mutex);
	pthread_cond_signal(&ack);
	pthread_mutex_unlock(&mutex);
}
