/*
 *	Linux SHIM6 implementation
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : Feb 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 */

#ifndef __DEBUG_H__
#define __DEBUG_H__ 1

#include <config.h>
#include <syslog.h>
#include <stdlib.h>

#ifdef DEBUGGING
#define ASSERT(x)							\
	do { if (!(x)) {syslog(LOG_ERR,"Assertion `%s' failed at %s:%d\n", \
			       #x, __FILE__, __LINE__); exit(EXIT_FAILURE);} } \
	while(0)
#define pthread_dbg(x) dbgprint(__FUNCTION__, "[%x] %s\n", pthread_self(), x)
#else
#define pthread_dbg(x)
#define ASSERT(x) do { } while(0)
#endif

#ifdef SHIM6_DEBUG
# define PDEBUG(fmt,args...) syslog(LOG_INFO,__FILE__ ":" fmt,##args)
#else
# define PDEBUG(fmt,args...)
#endif

#ifdef MIP6_NDEBUG /*Debug messages related to MIP6 code*/
#define NDEBUG 1
#define dbg(...)
#define cdbg(...)
#else
#define dbg(...) dbgprint(__FUNCTION__, __VA_ARGS__)
#define cdbg(...) dbgprint(NULL, __VA_ARGS__)

void dbgprint(const char *fname, const char *fmt, ...);


#endif /*MIP6_NDEBUG*/

#include <applog.h> /*log Library from radvd/DoCoMo*/

#endif /* __DEBUG_H__ */
