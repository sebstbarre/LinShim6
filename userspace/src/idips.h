/*
 *	Linux shim6 implementation - Interaction with the IDIPS client daemon
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : January 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef __IDIPS_H
#define __IDIPS_H

#ifdef IDIPS
int idips_init(void);

int idips_send_request(shim6_loc_l* src, int nsrc,
		       shim6_loc_p* dst, int ndst, __u64 ct);

void idips_pipe_handler(void* data);
#endif

#endif /*__IDIPS_H*/
