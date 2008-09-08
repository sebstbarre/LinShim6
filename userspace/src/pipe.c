/*
 *	Linux shim6d daemon - Pipe management for sending requests
 *      to the main thread.
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : October 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */


#include <unistd.h>
#include <syslog.h>
#include <shim6/tqueue.h>
#include "pipe.h"
#include "info_server.h"
#include "xfrm.h"
#include "idips.h"

static int pipe_fds[2];

int pipe_init()
{
	if (pipe(pipe_fds)<0) {
		syslog(LOG_ERR,"%s, pipe : %m\n",__FUNCTION__);
		return -1;
	}
	return pipe_fds[0];
}

int pipe_push_event(int type, void* data)
{
	struct pipe_event pe={type,data};
	if (write(pipe_fds[1],&pe,sizeof(pe))
	    !=sizeof(pe)) {
		syslog(LOG_ERR,"%s, %s : %m",__FILE__,__FUNCTION__);
		return -1;
	}
	return 1;
}

/*Runs the handler for the latest received event*/
void pipe_run_handler(void)
{
	struct pipe_event pe;
	int ret;
	ret=read(pipe_fds[0],&pe,sizeof(pe));
	if (ret!=sizeof(pe)) {
		syslog(LOG_ERR,"%s, read returned %d\n"
		       "\t error message : %m",__FUNCTION__,ret);
	}
	
	switch(pe.type) {
	case PIPE_EVENT_TIMER:
		timer_run_handler(pe.data);
		break;
	case PIPE_EVENT_INFO_SRV:
		info_srv_handler(pe.data);
		break;
	case PIPE_EVENT_XFRM:
		xfrm_handler(pe.data);
		break;
#ifdef IDIPS
	case PIPE_EVENT_IDIPS:
		idips_pipe_handler(pe.data);
		break;
#endif
	default:
		syslog(LOG_ERR,"%s, event of unknown type\n",__FUNCTION__);
	}
}
