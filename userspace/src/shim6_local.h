/*
 *	Linux shim6d daemon  - Local header
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : May 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef __SHIM6_LOCAL_H__
#define __SHIM6_LOCAL_H__ 1

#include <utils/debug.h>
#include <shim6/shim6d.h>

struct signature {
	uint8_t* sign;
	int      slen;
};

#ifdef SHIM6EVAL
/**
 * @security is 0, SHIM6_CGA, or SHIM6_HBA depending on the 
 * security mechanism we want to evaluate.
 * 
 * This function is very similar to init_shim6_ctx, except that 
 * this is an measurement function, that picks a ulid based on the 
 * security system we want to use.
 */
int eval_new_ctx(int security, struct in6_addr* ulid_peer);

/**
 * - Gives the measure time to standard output,
 * - Starts a new measure if less then 20 measurements have been done already.
 */
void end_measure(struct shim6_ctx* ctx);

/*Precomputed array of parameters for attacking a shim6 server*/

struct parameters {
	shim6_loc_l          ulid;
	struct in6_addr      loc_2;
	struct loc_list_opt  loclist;
	struct cga_params    *pds; /*The prefix is not necessarily good,
				     need to change it when sending the 
				     packet - done in attack_set_params() 
				     - opt.c*/
	struct signature     sgn;
};


extern int measure_sec;
extern int server_mode;
extern int nooptcache;
extern int eval_counter;
extern struct parameters params[];
extern int sequential; 
#endif

extern int attack;

/**
 * Decrements the refcount and frees the context stored in timer->private.
 * 
 */
void shim6_free_ctx(struct tq_elem* timer);

/*Returns the total number of local locators*/
int nb_glob_locs(void);


/*Variable set by the main thread, indicating a broken pipe*/
extern int bpipe;

#endif /* __SHIM6_LOCAL_H__ */
