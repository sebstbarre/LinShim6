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

#ifndef __PIPE_H__
#define __PIPE_H__ 1

enum {
	PIPE_EVENT_TIMER = 1,
	PIPE_EVENT_INFO_SRV,
	PIPE_EVENT_XFRM,
	PIPE_EVENT_IDIPS,
};

struct pipe_event {
	int type;
	void* data; /*data is type dependent*/
};

int pipe_init(void);

/*Runs the handler for the latest received event*/
void pipe_run_handler(void);

/*Push a new event for execution by the main thread*/
int pipe_push_event(int type, void* data);

#endif
