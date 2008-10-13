/*
 *	Linux REAP implementation - user space daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : June 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _REAPD_H
#define _REAPD_H

#include <config.h>

#include <linux/shim6.h>

#include <netinet/ip6.h>
#include <asm/types.h>
#include <string.h>
#include <paths.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <linux/netlink.h>
#include <list.h>
#include <shim6/tqueue.h>
#include <utils/util.h>

struct reap_ctx {
	int                 state;

	struct shim6_path*  path_array;
	int                 path_array_size; /*Number of entries in the array*/

	int                 cur_path_index; /*current index in path_array*/

	

	struct timespec     probe_ival; /*Time interval between probes*/

	struct timespec     send_timespec;
	struct tq_elem      probe_timer; /*Timer queue element (for the 
					   probe timer)*/

	struct tq_elem      send_timer; 
	struct tq_elem      end_explore_timer; /*Used to keep the probe
						reports available during some
						time after the end of an
						exploration*/
	
	short               nb_probes_sent; /*total number of probes sent
					      for current exploration, with a
					      max of 15 (also if we actually
					      send more than 15 probes), 
					      because this value is copied
					      in the probe psent field, 
					      which is 4 bits long*/
	short               nb_probes_recvd;

/*Timeout values (in seconds)*/
	int                 tka; /*Keepalive timeout*/
       
	/*recvd probes list*/
	struct list_head    recvd_probes;

	/*sent probes list*/
	struct list_head    sent_probes;
	
#ifdef LOG_EXPL_TIME
	struct timespec     expl_time; /*to record exploration start 
					 time*/
	int                 expl_nb_sent_probes;
	int                 expl_nb_rcvd_probes;
#endif

};

 /*This allows a probe_address element to be stored in a doubly linked list.
  * it is still possible to get only the content by casting to a 
  * struct probe_address
  * For this reason, NO FIELD CAN BE ADDED BEFORE content.
  */
 struct probe_address_node
 {
	 struct probe_address content;
	 struct list_head list;
 };


#ifdef SHIM6_SRC

/* Initialization function for reapd.
 * return -1 in case of failure, 0 in case of success.
 */
int reapd_init(void);

void init_reap_ctx(struct reap_ctx* rctx);

/*Called upon fast failure detection*/
void reap_init_explore(struct reap_ctx* rctx);

/*Handlers for messages received from the kernel*/
void reap_new_ctx(struct nlmsghdr* nlhdr);
void reap_release_ctx(struct reap_ctx* rctx);
void reap_init_explore_kern(struct nlmsghdr* nlhdr);
void reap_notify_in(struct nlmsghdr* nlhdr);
void reap_notify_out(struct nlmsghdr* nlhdr);
void reap_send_ka(struct nlmsghdr* nlhdr);

/*Handlers for messages received from the nerwork*/
void reap_rcv_probe(struct reaphdr_probe* hdr);
void reap_rcv_ka(struct reaphdr_ka* hdr);

/**
 * @rctx->path_array must be either malloc'ed or NULL
 * @rctx->path_array==NULL : The path array is created based on peer and local
 * locators.
 * @rctx->path_array!=NULL : The path array is replaced with a new one, based 
 * on the currently known peer and local locators
 */
int fill_path_array(struct reap_ctx* rctx);

/*get or set the value of the send timer (in seconds)*/
void set_tsend(uint16_t new);
uint16_t get_tsend(void);

#endif /*SHIM6_SRC*/

#endif /*_REAPD_H*/
