/*
 *	Linux Shim6 (LinShim6) implementation, options implementation
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : Feb 2008
 *
 *      Based on draft-ietf-shim6-proto-09
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */


#ifndef __OPT_H_
#define __OPT_H_ 1

#include "shim6_local.h"

/**********************************************************************
 *Code for option writing
 **********************************************************************/

/**
 * Always call this function before starting adding options (with add_xxx)
 * @pre : In case the options must be added to an UR message, then the
 * ur_pending bit in @context MUST be set BEFORE calling that function,
 * so that the CGA cache is correctly invalidated (otherwise the old locator
 * set will be sent to the peer).
 */
void opt_init(struct shim6_ctx* context);


/*Add options to local state
 *success: returns the option total length (T+L+V)
 *failure: returns -1 and the local state is reinitialized
 */
/*This function may return 0 if no validator had been sent with the R1 message
 * in that case write_options will not add the validator to the message*/
int add_vali2_option(void);
int add_loc_option(void);
int add_cga_pds_option(void);
/*CGA signature option : can only be called AFTER loc and cga_pds options*/
int add_cga_sign_option(void);
/*Keepalive Timeout option*/
int add_ka_option(void);
/*ULID pair option*/
int add_ulid_option(void);

/*Write all options in the packet to be sent
 *success: returns a pointer to the first byte following the last option
 *failure: returns NULL
 */
char* write_options(char* buf);

/**********************************************************************
 *Code for option reception (parsing)
 **********************************************************************/

enum {
	PO_VLDT,
	PO_LOC,
	PO_PDS,
	PO_SIGN,
	PO_KA,
	PO_ULID,
	PO_MAX,
};
extern struct shim6_opt* psd_opts[PO_MAX];

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
		  struct shim6_ctx* ctx);

#ifdef SHIM6EVAL
/*Set params for an attack*/
void attack_set_params(struct parameters *params);
#endif

#endif /* __OPT_H_ */
