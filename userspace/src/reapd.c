/*
 *	Linux REAP implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : June 2008
 *
 *      Based on draft-ietf-shim6-failure-detection-13
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */


#include <shim6/reapd.h>
#include <shim6/shim6d.h>
#include <shim6/tqueue.h>
#include "idips.h"
#include "xfrm.h"
#include "shim6_rawsocket.h"
#include "shim6_local.h"
#include "random.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

#include <linux/shim6.h>
#include <linux/netlink.h>
#include <linux/shim6_netlink.h>
#include <list.h>
#include <utils/debug.h>
#include <utils/jhash.h>
#include <utils/checksum.h>
#include <utils/util.h>


/*===============*/

/*Time intervals for sending probes during exploration process*/

#define PROBE_INIT_NB                 4 /*size of the initial burst of probes
					  (sent every PROBE_INIT_TIME)
					  Caution : We MUST have 
					  PROBE_INIT_NB<=MAX_SENT_PROBES_REPORT
					  (reapd.h), or the effective value
					  of PROBE_INIT_NB will be infinite,
					  regardless of the definition here.*/

static const struct timespec MAX_PROBE_TIMEOUT = { /*60 seconds*/
	.tv_sec=60,
	.tv_nsec=0};
static const struct timespec PROBE_INIT_TIME = { /*500ms*/
	.tv_sec=0,
	.tv_nsec=500000000};

/*===============*/

/*Default timeout for keeping available the probe reports after the end of
  an exploration process. After this delay, the probe reports lists are 
  cleared*/
static const struct timespec END_EXPLORE_TIMEOUT = { /*10 seconds*/
	.tv_sec=10,
	.tv_nsec=0};

/*================*/

/*Various declarations*/
static void send_probe(struct reap_ctx* rctx, int isolated);
static void start_send_timer(struct reap_ctx* rctx, int restart);
static void send_handler(struct tq_elem* send_timer);

/*variables that can be set from the main thread, customized through 
  info server with set command*/
static uint16_t reap_send_timeout = REAP_SEND_TIMEOUT;

/*================*/

void set_tsend(uint16_t new)
{
	
	if (new==reap_send_timeout) return;
	reap_send_timeout=new;	
	
	sync_contexts(NULL,1);
}

uint16_t get_tsend(void)
{
	return reap_send_timeout;
}

/*States MUST never be transitioned manually.
 * Rather, this function must be called
 * to do this, to ensure that any operation associated with the state change
 * is correctly performed
 * Note that initial state CANNOT be set with this function, since it is not
 * a transition.
 */
static inline void reap_set_state(struct reap_ctx *rctx, int state)
{
	switch(state) {
	case REAP_OPERATIONAL:
		break;
	case REAP_INBOUND_OK:
#ifdef LOG_EXPL_TIME
		if (rctx->state==REAP_OPERATIONAL) {
			/*Save exploration start time*/
			clock_gettime(CLOCK_REALTIME,&rctx->expl_time);
			/*For the transition op->inb.ok, one probe has already
			  been received*/
			rctx->expl_nb_rcvd_probes=1;
			rctx->expl_nb_sent_probes=0;
		}
#endif
		break;
	case REAP_EXPLORING:
		
#ifdef LOG_EXPL_TIME
		if (rctx->state==REAP_OPERATIONAL) {
			/*Save exploration start time*/
			clock_gettime(CLOCK_REALTIME,&rctx->expl_time);
			rctx->expl_nb_rcvd_probes=0;
			rctx->expl_nb_sent_probes=0;
		}
#endif
		break;
	default: ASSERT(0); /*Force the program to crash, in order to debug this
			      case, which should never happen*/
	}
	rctx->state=state;
}

void reap_release_ctx(struct reap_ctx* rctx)
{
	struct probe_address_node* probe_node;
	struct probe_address_node* temp;
	struct shim6_ctx* ctx=shim6_ctx(rctx);

	/*Stopping timers*/
	
	if (del_task_and_free(&rctx->probe_timer, shim6_free_ctx,ctx)==1)
		ctx->refcnt++;
	if (del_task_and_free(&rctx->send_timer, shim6_free_ctx,ctx)==1)
		ctx->refcnt++;
	if (del_task_and_free(&rctx->end_explore_timer, shim6_free_ctx,ctx)==1)
		ctx->refcnt++;
	
	/*Clear the lists of probe reports.*/
	
	list_for_each_entry_safe(probe_node, temp, &rctx->sent_probes, list) {
		list_del(&probe_node->list);
		free(probe_node); 
	}
	
	list_for_each_entry_safe(probe_node, temp, &rctx->recvd_probes, list) {
		list_del(&probe_node->list);
		free(probe_node);
	}
}

void clear_report_lists(struct reap_ctx* rctx)
{
	struct probe_address_node* probe_node; 
	struct probe_address_node* temp; 

#ifdef SHIM6_DEBUG
	struct shim6_ctx* ctx=shim6_ctx(rctx);
	PDEBUG("Clearing reports list for ctx %" PRIx64 "\n",ctx->ct_local);
#endif

	list_for_each_entry_safe(probe_node, temp, &rctx->sent_probes, list) {
		list_del(&probe_node->list);
		free(probe_node);
	}
	rctx->nb_probes_sent=0;
	list_for_each_entry_safe(probe_node, temp, &rctx->recvd_probes, list) {
		list_del(&probe_node->list);
		free(probe_node);
	}
	rctx->nb_probes_recvd=0;
}

void end_explore_handler(struct tq_elem* timer)
{	
	struct reap_ctx* rctx=container_of(timer,struct reap_ctx,
					   end_explore_timer);

	clear_report_lists(rctx);
}

static void reset_probed_flags(struct reap_ctx* rctx)
{
	int i;
	for (i=0;i<rctx->path_array_size;i++) {
		rctx->path_array[i].flags&=~PROBED;
	}
}

/* @sta is the sta field of the probe causing the end of exploration
 * (either REAP_OPERATIONAL or REAP_INBOUND_OK)
 *
 * If the LOG_EXPL_TIME option is set, the exploration time is logged
 * in /etc/shim6/expl.log
 *
 */
static void reap_end_explore(struct reap_ctx* rctx, 
			     struct probe_address* addresses, int sta)
{
	struct timespec end_explore_timeout=END_EXPLORE_TIMEOUT;
	int fd=-1;
	struct shim6_ctx* ctx=shim6_ctx(rctx);
	
	
	PDEBUG("End of exploration process\n");

        /*Stopping the probe and send timers*/
	del_task(&rctx->send_timer);
	del_task(&rctx->probe_timer);

	/*Clearing the PROBED flags*/
	reset_probed_flags(rctx);

	/*If the peer is in operational state, we can immediately clear
	 * the list of probe reports, it isn't useful anymore. 
	 * But if the peer is not in operational state (inbound_ok)
	 * we still keep the reports during some time*/
	if (sta==REAP_OPERATIONAL)
		clear_report_lists(rctx);
	else {
		add_task_rel(&end_explore_timeout,
			     &rctx->end_explore_timer,
			     end_explore_handler);
	}
	
#ifdef LOG_EXPL_TIME
	do {
		struct timespec now;
		struct timespec expl_time;

		/*Saving the exploration time in /etc/shim6/expl.log*/
		fd=open("/etc/shim6/expl.log", O_WRONLY | O_CREAT | O_APPEND,
			00640);
		if (fd<0) {
			switch(errno) {
			case ENOENT:
				/*The /etc/shim6 is probably not present, 
				  create it*/
				mkdir("/etc/shim6",S_IRWXU | S_IROTH | S_IRGRP);
				/*Try again*/
				fd=open("/etc/shim6/expl.log", 
					O_WRONLY | O_CREAT | O_APPEND,00640);
				if (fd>0) break;
			default:
				syslog(LOG_ERR,"open : %m\n");
				syslog(LOG_ERR,
				       "impossible to log expl. time\n");
				goto failure_log_expl;
			}
		}
		clock_gettime(CLOCK_REALTIME, &now);
		tssub(now,rctx->expl_time,expl_time);
		dprintf(fd, "previous : local : %s ",addrtostr(&ctx->lp_local));
		dprintf(fd, "peer : %s\n",addrtostr(&ctx->lp_peer));
		if (addresses) {
			dprintf(fd, "new : local : %s ",
				addrtostr(&addresses->src));
			dprintf(fd, "peer : %s\n",addrtostr(&addresses->dest));
		}
		else {
			dprintf(fd, 
				"Previous path available again "
				"(previous==new)\n");
		}
		dprintf(fd, "time : %ld seconds %ld nanoseconds\n",
			expl_time.tv_sec,
			expl_time.tv_nsec);
		dprintf(fd, "recvd probes : %d\n", rctx->expl_nb_rcvd_probes);
		/*If state in the peer is inbound_ok, we will reply with a probe
		  operational*/
		dprintf(fd, "sent probes : %d\n\n", 
			(sta==REAP_INBOUND_OK)?rctx->expl_nb_sent_probes+1:
			rctx->expl_nb_sent_probes);
	} while (0);
failure_log_expl:
#endif
	
	/*Update the preferred locators in the daemon/kernel context*/
	if (addresses)
		xfrm_update_shim6_ctx(ctx,&addresses->dest,&addresses->src,
				      NULL,0);
	if (fd!=-1) close(fd);
}

/*If @restart is 
 * 1 : restarts the send timer
 * 0 : starts the send timer if it was not already running
 */
static void start_send_timer(struct reap_ctx* rctx, int restart)
{
	if (restart) {
		del_task(&rctx->send_timer);
	}
	if (!timer_pending(&rctx->send_timer))
		add_task_rel(&rctx->send_timespec,&rctx->send_timer,
			     send_handler);
}


void probe_handler(struct tq_elem* timer)
{
	struct reap_ctx* rctx=container_of(timer,struct reap_ctx,
					   probe_timer);
	/*Send a new probe*/
	send_probe(rctx,FALSE);
	
	if (rctx->state==REAP_INBOUND_OK) start_send_timer(rctx,0);
}

#ifndef IDIPS
/*Moves randomly each element inside path_array. The elements remain exactly
 * the same, they have just their index inside the array changed randomly
 * returns -1 in case of error, 0 in case of success*/
void randomize_array(struct shim6_path* path_array, int size)
{
	int i,rand_index;
	struct shim6_path temp;

	ASSERT(path_array!=NULL);

	PDEBUG("Entering randomize_array\n");
	for (i=0;i<size-1;i++) {
		rand_index=i+random_int()%(size-i);
		/*swap index i and rand_index*/
		if (rand_index!=i) {
			memcpy(&temp,&path_array[i],sizeof(struct shim6_path));
			memcpy(&path_array[i],&path_array[rand_index],
			       sizeof(struct shim6_path));
			memcpy(&path_array[rand_index],&temp,
			       sizeof(struct shim6_path));
		}
	}
	PDEBUG("Leaving randomize_array\n");
}
#endif

/* Initialize relevant fields in rctx to start a new burst of probes.
 * This must be called when leaving the operational state
 */
static void inline init_probe_sending(struct reap_ctx* rctx) 
{
	PDEBUG("Entering init_probe_sending");
	rctx->probe_ival=PROBE_INIT_TIME;
#ifdef IDIPS
	idips_send_request(shim6_ctx(rctx));
#else
	randomize_array(rctx->path_array,rctx->path_array_size);
#endif
}

static void send_handler(struct tq_elem* send_timer)
{
	struct reap_ctx* rctx=container_of(send_timer,struct reap_ctx,
					   send_timer);

	ASSERT(rctx->state==REAP_INBOUND_OK);
	
	reap_set_state(rctx,REAP_EXPLORING);
	/*Restart the exponential backoff for probe sending*/
	init_probe_sending(rctx);
	
	/*restart the timer : This is necessary to ensure we immediately
	 * start sending at a high rate. The current timer would maybe wait
	 * one minute before to switch to the high rate. (because we do not 
	 * know what is its current expiry time)
       	 **/
	
	del_task(&rctx->send_timer);
	del_task(&rctx->probe_timer);
	send_probe(rctx,FALSE); /*Start the new stream*/
}

/*Send a keepalive message for context ct, embedded in nlhdr.
 * format for the netlink message :
 *  ----------------
 * |  ct_local      |
 *  ----------------
 */

void reap_send_ka(struct nlmsghdr* nlhdr)
{
	struct reaphdr_ka* ka;
	union shim6_msgpp ka_msg={.ka=&ka};
	struct in6_addr dest_addr, src_addr;
	struct shim6_ctx* ctx;
	uint64_t* ct = NLMSG_DATA(nlhdr);


	ctx=lookup_ct(*ct);

	if (!ctx) {
		syslog(LOG_ERR, "reap_send_ka : kernel knows a "
		       "context tag that the daemon does not know : "
		       "%" PRIx64 "\n",*ct);
		return;
	}

	PDEBUG("sending keepalive\n");
	
	/*Setting src and dest addresses*/
	
	ipv6_addr_copy(&dest_addr,&ctx->lp_peer);
	ipv6_addr_copy(&src_addr, &ctx->lp_local);

	if (shim6_alloc_send(sizeof(struct reaphdr_ka),0,
			     REAP_TYPE_KEEPALIVE, ka_msg,NULL))
		return;
	
	set_ct(ctx->ct_peer,ka->ct_1,ka->ct_2,ka->ct_3);

	ka->pad=0;
	ka->R=0;

	/*Computing checksum*/
	
	ka->common.csum=ipsum_calculate((unsigned char*)ka,
					(ka->common.hdrlen+1)*8,NULL);
		
	/*sending the paquet*/

	if (shim6_send(ka,sizeof(*ka),&src_addr,&dest_addr)<0)
		syslog(LOG_ERR,"shim6_send : %m\n");

	free(ka);

	return;
}

/*Sets the current path to explore to the next unprobed one.
 * If all paths until the end of the array have been probed already, then
 * we restart an exploration cycle by resetting the PROBED flag for all pairs
 * and setting the current pair to the first entry of the array.*/
static void next_path(struct reap_ctx* rctx)
{
	while(rctx->path_array[rctx->cur_path_index].flags & PROBED) {
		rctx->cur_path_index=
			(rctx->cur_path_index+1)%rctx->path_array_size;
		if (rctx->cur_path_index==0) {
			reset_probed_flags(rctx);
			return;
		}
	}
}

/*Sends a new probe 
 * selects the address pair to use for this by using 
 * the index provided in the context. This index is incremented each time 
 * a probe is sent, so that the destination locators list is parsed 
 * and should so be ordered
 *
 * @isolated is TRUE if the probe should be sent alone, FALSE if it is part of
 * exploration stream. That is, isolated is FALSE when called
 *    - at the beginning of an exploration (first probe sent)
 *    - from the probe timer handler.
 * In all other cases the probes are sent upon an event occuring, such as the
 * arrival of a probe from the peer. Such cases are handled by one probe being
 * immediately sent to the peer, without influence on the exploration stream.
 *
 */
static void send_probe(struct reap_ctx* rctx, int isolated) 
{
	reaphdr_probe* probe=NULL;
	int err;
	struct in6_addr dest_addr;
	struct in6_addr src_addr;
	struct probe_address_node* probe_node=NULL; 
	struct probe_address_node* probe_node_it=NULL; /*For iteration*/
	struct probe_address* probe_report;
	int probe_len; /*Total length of the message, without IPv6 hdr*/
	int nb_trials=1;
	int timer_jitter; /*rand value between -20 and +20 (per cents)*/
	struct timespec rprobe_ival; /*Randomized probe ival*/
	struct shim6_ctx* ctx=shim6_ctx(rctx);
	
 retry:

	PDEBUG("Sending a probe\n");
	
	/*Choosing src and dest addresses*/
	
	ASSERT(rctx!=NULL);

	if(rctx->state==REAP_OPERATIONAL) {
		ipv6_addr_copy(&dest_addr,&ctx->lp_peer);
		ipv6_addr_copy(&src_addr, &ctx->lp_local);
	}
	else {
		ASSERT(rctx->path_array!=NULL);
		/*Is the current path already probed ?*/
		if (rctx->path_array[rctx->cur_path_index].flags & PROBED)
			next_path(rctx);
		ipv6_addr_copy(&dest_addr,
			       &rctx->path_array[rctx->cur_path_index].remote);
		ipv6_addr_copy(&src_addr,
			       &rctx->path_array[rctx->cur_path_index].local);
		rctx->path_array[rctx->cur_path_index].flags|=PROBED;
		
		/*Next probe will be sent with next path in the list*/
		next_path(rctx);
	}

	/*Creating a sent probe node in the reap context*/

	probe_node=malloc(sizeof(struct probe_address_node));

	if (!probe_node) {
		syslog(LOG_ERR, "send probe : malloc failed\n");
		return;
	}


	/*Filling the probe_node*/
	ipv6_addr_copy(&probe_node->content.src,&src_addr);
	ipv6_addr_copy(&probe_node->content.dest,&dest_addr);
	probe_node->content.nonce=random_int();
	probe_node->content.option=0;

	/*Adding the node to the list*/
	list_add_tail(&probe_node->list, &rctx->sent_probes);

	
	/*Ultra verbose mode for tracing an exploration*/
	
	PDEBUG("sent probe :\n");
	PDEBUG("     src = %s\n",addrtostr(&probe_node->content.src));
	PDEBUG("     dest = %s\n",addrtostr(&probe_node->content.dest));
	PDEBUG("     nonce = %x\n",ntohl(probe_node->content.nonce));
	PDEBUG("     reap state : %d\n",rctx->state);
	PDEBUG("     size of recvd probe list : %d, and sent : %d\n",
	       rctx->nb_probes_recvd, rctx->nb_probes_sent);
	
	/*---------------------------------------------*/
	

	if (rctx->nb_probes_sent==MAX_SENT_PROBES_REPORT) {
		/*So we have reached the max probe reports number, we must
		  free one.*/
		struct list_head* old_report;
		struct probe_address_node* old_node;

		ASSERT(!list_empty(&rctx->sent_probes));
		old_report=rctx->sent_probes.next;
		list_del(old_report);
		old_node=list_entry(old_report,struct probe_address_node,list);
		free(old_node);		
	}
	else rctx->nb_probes_sent++;
	
	/*Computing the size of the probe message to send.*/
	probe_len=sizeof(reaphdr_probe)+
		(rctx->nb_probes_sent+rctx->nb_probes_recvd)*
		sizeof(struct probe_address);
	
	PDEBUG("probe_len : %d\n",probe_len);

	probe=malloc(probe_len);
	
	if (!probe) {
		syslog(LOG_ERR,"send probe : malloc failed\n");
		goto fail;
	}
	
	/*Start with elements associated to the list*/
	probe->precvd=rctx->nb_probes_recvd;
	probe->psent=rctx->nb_probes_sent;
	probe_report=(struct probe_address*)(probe+1);
	list_for_each_entry_prev(probe_node_it, &rctx->sent_probes, list) {
		memcpy(probe_report,probe_node_it,
		       sizeof(struct probe_address));
		probe_report++;
	}
	
	list_for_each_entry_prev(probe_node_it, &rctx->recvd_probes, list) {
		memcpy(probe_report,probe_node_it,
		       sizeof(struct probe_address));
		probe_report++;
	}
	
	probe->common.nexthdr=NEXTHDR_NONE;	
	probe->common.hdrlen=(probe_len-8)>>3;
	probe->common.P=SHIM6_MSG_CONTROL;
	probe->common.type=REAP_TYPE_PROBE;
	probe->common.type_spec=0;
	probe->common.hip_compat=0;
	probe->common.csum=0; /*We need to initialize this field for correct
				csum computation later*/
	
	probe->R=0;
	set_ct(ctx->ct_peer, probe->ct_1, probe->ct_2, probe->ct_3)
	probe->sta=rctx->state;
	probe->reserved_1=0;
	probe->reserved_2=0;
	

	/*Computing checksum*/
	
	probe->common.csum=ipsum_calculate((unsigned char*)probe,
					   (probe->common.hdrlen+1)*8,NULL);
	
	
	/*Sending the paquet*/

	err=shim6_send(probe,probe_len,&src_addr,&dest_addr);

	if (err) {
		/* if errno is 'network unreachable', 
		 * just try to send another probe. Nevertheless,
		 * If all possible probes give a network unreachable error
		 * then we start exploring
		 * in slow mode (MAX_PROBE_TIMEOUT).
		 */
		if (errno==ENETUNREACH) {
			if (nb_trials==rctx->path_array_size) {
				rctx->probe_ival=MAX_PROBE_TIMEOUT;
				free(probe); probe=NULL;	      
				goto  next_retransmit;
			}
			nb_trials++;
			free(probe); probe=NULL;
			list_del(&probe_node->list);
			free(probe_node); probe_node=NULL;
			rctx->nb_probes_sent--;

			PDEBUG("Network unreachable, retrying...\n");
			goto retry;
		}
		syslog(LOG_ERR,"connect : %m\n");
		goto fail;
	}
	


	free(probe);
	probe=NULL;

#ifdef LOG_EXPL_TIME
	rctx->expl_nb_sent_probes++;
#endif
	

	if (isolated) return;
	
 next_retransmit:
	/*Preparing the next (re)transmission*/
	ASSERT(tscmp(rctx->probe_ival,PROBE_INIT_TIME,>=));
	
	if (rctx->nb_probes_sent>=PROBE_INIT_NB && 
	    tscmp(rctx->probe_ival,MAX_PROBE_TIMEOUT,<)) { 
		/*Multiply probe_ival by two.*/
		tsadd(rctx->probe_ival,rctx->probe_ival,
		      rctx->probe_ival);
		if (tscmp(rctx->probe_ival,MAX_PROBE_TIMEOUT,>))
			rctx->probe_ival=MAX_PROBE_TIMEOUT;
	}
	
	/*Randomizing probe_ival by +/-20%*/
	timer_jitter=tstomsec(rctx->probe_ival)*
		(1+(-20+random_int()%41)/100.0);
	tssetmsec(rprobe_ival,timer_jitter);
	add_task_rel(&rprobe_ival, &rctx->probe_timer, 
		     &probe_handler);
	
	return;
	
 fail:
	if (probe_node) {
		list_del(&probe_node->list);
		free(probe_node);
		rctx->nb_probes_sent--;
	}
	if (probe) free(probe);
}

void reap_init_explore(struct reap_ctx* rctx)
{
	PDEBUG("Entering %s\n",__FUNCTION__);

	if (rctx->state!=REAP_OPERATIONAL) {
		/*This can happen if a fast detection occured (current loc
		  disappeared) before, then the kernel also detects the 
		  failure by send timeout*/
		PDEBUG("%s : already exploring",__FUNCTION__);
		return;
	}
	
	/*Setting state to exploring*/
	reap_set_state(rctx,REAP_EXPLORING);

	init_probe_sending(rctx);

	/*Sending the first probe*/
	send_probe(rctx,FALSE);
}

void reap_init_explore_kern(struct nlmsghdr* nlhdr)
{
	uint64_t* ct=NLMSG_DATA(nlhdr);
	struct shim6_ctx* ctx;

	ctx=lookup_ct(*ct);
	
	if (!ctx) {
		syslog(LOG_ERR, "%s : ctx not found\n",__FUNCTION__);
		return;
	}
	reap_init_explore(&ctx->reap);
}

/**
 * @rctx->path_array must be either malloc'ed or NULL
 * @rctx->path_array==NULL : The path array is created based on peer and local
 * locators.
 * @rctx->path_array!=NULL : The path array is replaced with a new one, based 
 * on the currently known peer and local locators
 */
int fill_path_array(struct reap_ctx* rctx)
{
	struct shim6_path* path;
	int i,j;
	struct shim6_ctx* ctx=shim6_ctx(rctx);
	int nb_loc_locs;
	int all_nonsecure,useall_locators;
	struct in6_addr* locaddr_array=NULL;
	
	PDEBUG("Entering fill_path_array\n");

	nb_loc_locs=get_nb_loc_locs(ctx,FALSE,&all_nonsecure,&useall_locators,
				    NULL);
	
	if (nb_loc_locs<0) return -1;

	if (ctx->ls_peer.size*nb_loc_locs > MAX_SHIM6_PATHS) {
		syslog(LOG_ERR,"%s:More paths than supported by LinShim6,"
		       "(max %d), please redefine MAX_SHIM6_PATHS "
		       "($kernel_src/include/linux/shim6.h) and rebuild"
		       " LinShim6. Alternatively you can contact the"
		       " author to tell him why a higher value should be set"
		       " to a higher value.", __FUNCTION__, MAX_SHIM6_PATHS);
		exit(EXIT_FAILURE);
	}

	rctx->path_array=realloc(rctx->path_array,
				 ctx->ls_peer.size*nb_loc_locs*
				 sizeof(struct shim6_path));
	locaddr_array=malloc(nb_loc_locs*sizeof(*locaddr_array));
	
	if (!rctx->path_array || !locaddr_array) {
		APPLOG_NOMEM();
		exit(EXIT_FAILURE);
	}
	
	/*Building local loc array*/
	if (get_loc_locs_array(ctx,FALSE,locaddr_array,NULL,all_nonsecure,
			       useall_locators,NULL)<0) goto failure;
	
	rctx->path_array_size=ctx->ls_peer.size*nb_loc_locs;
	path=rctx->path_array;
	for (i=0;i<nb_loc_locs;i++)
		for (j=0;j<ctx->ls_peer.size;j++) {
			ipv6_addr_copy(&path->local,
				       &locaddr_array[i]);
			PDEBUG("src:%s\n",addrtostr(&path->local));
			ipv6_addr_copy(&path->remote,
				       &ctx->ls_peer.psetp[j].addr);
			PDEBUG("dest:%s\n",addrtostr(&path->remote));
			path->flags=0;
			
			if (!ipv6_addr_equal(&ctx->ulid_local.addr, 
					     &path->local) ||
			    !ipv6_addr_equal(&ctx->ulid_peer,
					     &path->remote))
				path->flags |= SHIM6_DATA_TRANSLATE;
			
			
			path++;
		}

	rctx->cur_path_index=0;

	free(locaddr_array);
	return 0;
failure:
	if (locaddr_array) free(locaddr_array);
	return -1;
}

void init_reap_ctx(struct reap_ctx* rctx)
{
	int ans;
	
	/*The only case where we do not use reap_set_state, because
	  this is the initialization, not a transition*/
	rctx->state=REAP_OPERATIONAL;
	rctx->cur_path_index=0;

	/*Lists initialization*/
	INIT_LIST_HEAD(&rctx->recvd_probes);
	rctx->nb_probes_recvd=0;
	INIT_LIST_HEAD(&rctx->sent_probes);
	rctx->nb_probes_sent=0;

	/*Init the timeouts to default values
	  note that rctx->tka is initialized in shim6d.c,
	  because it might be changed by I2 or R2 messages*/
	tssetsec(rctx->send_timespec,reap_send_timeout);

	rctx->path_array=NULL;

	ans=fill_path_array(rctx);
	if (ans<0) return;

	/*Init the timers*/
	init_timer(&rctx->probe_timer);
	init_timer(&rctx->send_timer);
	init_timer(&rctx->end_explore_timer);

	return;
}

void reap_rcv_probe(struct reaphdr_probe* hdr) 
{
	struct shim6_ctx* ctx;
	struct reap_ctx* rctx;
	uint64_t ct;
	struct probe_address_node* probe_node; 
	struct probe_address* sent_probe_report;
	struct probe_address* rcvd_probe_report;
	int probe_len; /*Total length of the message, without IPv6 hdr*/
	/*Pointer to the first octet following the end of the packet
	  This is used to ensure we do not try to access memory outside
	  the packet*/
	char* packet_end; 
	int orig_state;
	int i; /*loop counter*/

	probe_len=(hdr->common.hdrlen+1)<<3;
	if (probe_len<MIN_PROBE_LEN || probe_len > MAX_PROBE_LEN) {
		syslog(LOG_ERR, "reap_rcv_probe : invalid probe length\n");
		return;
	}

	packet_end=(char*)hdr+probe_len;

	/*Verifying checksum*/
	if (!ipsum_verify((unsigned char*)hdr,
			  (hdr->common.hdrlen+1)*8,NULL)) {
		syslog(LOG_ERR, "reap_rcv_probe : incorrect checksum\n");
		return;
	}

	/*Context tag reconstitution*/
	get_ct(&ct,hdr->ct_1,hdr->ct_2,hdr->ct_3);

	ctx=lookup_ct(ct);

	if (!ctx) {
		syslog(LOG_ERR, "reap_rcv_probe : reap ctx not found\n");
		return;
	}

	if (ctx->state!=SHIM6_ESTABLISHED) return;
	
	rctx=&ctx->reap;
	
#ifdef LOG_EXPL_TIME
	rctx->expl_nb_rcvd_probes++;
#endif

	/*If we are about to start a new exploration, first clear the report
	  lists*/
	if (rctx->state==REAP_OPERATIONAL && hdr->sta==REAP_EXPLORING)
		clear_report_lists(rctx);

	/*Creating a recvd probe node in the reap context*/
	/*The data for the currently sent probe is within the first sent probe
	  report*/
	sent_probe_report=(struct probe_address*)((char*)(hdr+1));
	
	if ((char*)sent_probe_report+sizeof(struct probe_address) > 
	    packet_end) {
		syslog(LOG_ERR, "reap_rcv_probe : probe does not contain "
		       "a sent probe report\n");
		goto out;
	}

	probe_node=malloc(sizeof(struct probe_address_node));
	if (!probe_node) {
		syslog(LOG_ERR, "reap_rcv_probe : malloc failed\n");
		goto out;
	}
	
	ipv6_addr_copy(&probe_node->content.src,&sent_probe_report->src);
	ipv6_addr_copy(&probe_node->content.dest,&sent_probe_report->dest);
	probe_node->content.nonce=sent_probe_report->nonce;
	probe_node->content.option=sent_probe_report->option;
	
	list_add_tail(&probe_node->list, &rctx->recvd_probes);
	
	if (rctx->nb_probes_recvd==MAX_RECVD_PROBES_REPORT) {
		/*So we have reached the max probe reports number, we must
		  free one.*/
		struct list_head* old_report;
		struct probe_address_node* old_node;

		ASSERT(!list_empty(&rctx->recvd_probes));
		old_report=rctx->recvd_probes.next;		
		list_del(old_report);
		old_node=list_entry(old_report,struct probe_address_node,list);
		free(old_node);
	}
	else rctx->nb_probes_recvd++;


	/*Ultra verbose mode for tracing an exploration*/
	
	PDEBUG("received probe :\n");
	PDEBUG("     src = %s\n",addrtostr(&probe_node->content.src));
	PDEBUG("     dest = %s\n",addrtostr(&probe_node->content.dest));
	PDEBUG("     nonce = %x\n",ntohl(probe_node->content.nonce));
	PDEBUG("     R=%d, S=%d, sta=%d\n",hdr->precvd,hdr->psent,hdr->sta);
	PDEBUG("     reap state : %d\n",rctx->state);
	PDEBUG("     size of recvd probe list : %d, and sent : %d\n",
	       rctx->nb_probes_recvd, rctx->nb_probes_sent);
	
	/*---------------------------------------------*/

	
	/*Parsing the received probe reports : Removing every sent probe
	  reported as seen by the peer*/
	rcvd_probe_report=(struct probe_address*)
		((char*)(hdr+1)+hdr->psent * sizeof(struct probe_address));

	for (i=0; i<hdr->precvd; rcvd_probe_report++,i++) {
		if ((char*)rcvd_probe_report+
		    sizeof(struct probe_address) > packet_end) {
			PDEBUG("reap_rcv_probe : value too big for precvd\n");
			goto out;
		}
		list_for_each_entry(probe_node,&rctx->sent_probes,list) {
			if (probe_node->content.nonce==
			    rcvd_probe_report->nonce) {
				list_del(&probe_node->list);
				free(probe_node);
				rctx->nb_probes_sent--;
				break;
			}
				
		}
	}

	rcvd_probe_report=(struct probe_address*)
		((char*)(hdr+1)+hdr->psent * sizeof(struct probe_address));
	
	orig_state=rctx->state;
	
	switch(hdr->sta) {
	case REAP_OPERATIONAL:
		if (hdr->precvd==0) {
			PDEBUG("reap_rcv_probe : No received probe "
			       "report\n");
			rcvd_probe_report=NULL;
		}
		if (rctx->state!=REAP_OPERATIONAL)
			reap_end_explore(rctx, rcvd_probe_report,hdr->sta);
		reap_set_state(rctx,REAP_OPERATIONAL);
		break;
	case REAP_EXPLORING:
		reap_set_state(rctx,REAP_INBOUND_OK);
		if (orig_state==REAP_OPERATIONAL) {
			init_probe_sending(rctx);
			send_probe(rctx,FALSE);
			start_send_timer(rctx,TRUE);
			goto out;
		}
		send_probe(rctx,TRUE);
		start_send_timer(rctx,TRUE);		
		break;
	case REAP_INBOUND_OK:
		/*End of exploration*/ 
		if (hdr->precvd==0) {
			PDEBUG("reap_rcv_probe : No received probe "
			       "report\n");
			rcvd_probe_report=NULL;
		}

		if (rctx->state!=REAP_OPERATIONAL)
			reap_end_explore(rctx, rcvd_probe_report,hdr->sta);
		reap_set_state(rctx,REAP_OPERATIONAL);
		send_probe(rctx,TRUE);
		break;
	}
 out:
	return;
}

void reap_rcv_ka(struct reaphdr_ka* hdr) 
{
	struct shim6_ctx* ctx;
	struct reap_ctx* rctx;
	uint64_t ct;
	int pld_len;

	pld_len=(hdr->common.hdrlen+1)<<3;
	if (pld_len<16) {
		syslog(LOG_ERR, "reap_rcv_ka : invalid length\n");
		return;
	}
	/*Verifying checksum*/
	if (!ipsum_verify((unsigned char*)hdr,
			  (hdr->common.hdrlen+1)*8,NULL)) {
		syslog(LOG_ERR, "reap_rcv_ka : incorrect checksum\n");
		return;
	}

	/*Context tag reconstitution*/
	get_ct(&ct,hdr->ct_1,hdr->ct_2,hdr->ct_3);
	
	ctx=lookup_ct(ct);

	if (!ctx) {
		syslog(LOG_ERR, "reap_rcv_ka : ctx not found\n");
		return;
	}

	if (ctx->state!=SHIM6_ESTABLISHED) return;

	rctx=&ctx->reap;
	
	switch(rctx->state) {
	case REAP_EXPLORING:
		reap_set_state(rctx,REAP_INBOUND_OK);
		send_probe(rctx,TRUE);
		start_send_timer(rctx,0);
		break;
	case REAP_INBOUND_OK:
	case REAP_OPERATIONAL:
		del_task(&rctx->send_timer);
		break;
	}

	return;
}



void reap_notify_in(struct nlmsghdr* nlhdr)
{
	uint64_t* ct = NLMSG_DATA(nlhdr);
	struct shim6_ctx* ctx;
	struct reap_ctx* rctx;

	ctx=lookup_ct(*ct);

	if (!ctx) {
		syslog(LOG_ERR, "reap_notify_in : kernel knows a "
		       "context tag that the daemon does not know : "
		       "%" PRIx64 "\n",*ct);
		return;
	}

	rctx=&ctx->reap;

	switch(rctx->state) {
	case REAP_OPERATIONAL:
		break;
	case REAP_INBOUND_OK:
		del_task(&rctx->send_timer);
		break;
	case REAP_EXPLORING:
		PDEBUG("Received data packet while exploring\n");
		reap_set_state(rctx,REAP_INBOUND_OK);
		start_send_timer(rctx,0);
		send_probe(rctx,TRUE);
		break;
	}
}

void reap_notify_out(struct nlmsghdr* nlhdr)
{
	uint64_t* ct = NLMSG_DATA(nlhdr);
	struct shim6_ctx* ctx;
	struct reap_ctx* rctx;
	
	ctx=lookup_ct(*ct);

	if (!ctx) {
		syslog(LOG_ERR, "reap_notify_out : kernel knows a "
		       "context tag that the daemon does not know : "
		       "%" PRIx64 "\n",*ct);
		return;
	}

	rctx=&ctx->reap;
	
	if (rctx->state==REAP_INBOUND_OK) {
		start_send_timer(rctx,FALSE);
	}
}

/* Initialization function for reapd.
 * return -1 in case of failure, 0 in case of success.
 */
int reapd_init()
{
	return 0;
}
