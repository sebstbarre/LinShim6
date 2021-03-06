/*
 * $Id: debug.c 1.23 06/05/07 21:52:42+03:00 anttit@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 * 
 * Author: Antti Tuominen <anttit@tcs.hut.fi>
 *
 * Copyright 2003-2005 Go-Core Project
 * Copyright 2003-2006 Helsinki University of Technology
 *
 * MIPL Mobile IPv6 for Linux is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2 of
 * the License.
 *
 * MIPL Mobile IPv6 for Linux is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MIPL Mobile IPv6 for Linux; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/uio.h>

#include <utils/debug.h>

FILE *sdbg;

void dbgprint(const char *fname, const char *fmt, ...)
{
        char s[1024];
        va_list args;
 
        va_start(args, fmt);
        vsprintf(s, fmt, args);
	if (fname)
		syslog(LOG_ERR, "%s: ", fname);
	syslog(LOG_ERR, "%s", s);
        va_end(args);
}

void debug_print_buffer(const void *data, int len, const char *fname, 
			const char *fmt, ...)
{ 
	int i; 
	char s[1024];
        va_list args;
 
        va_start(args, fmt);
        vsprintf(s, fmt, args);
        syslog(LOG_ERR, "%s: %s", fname, s);
        va_end(args);
	for (i = 0; i < len; i++) { 
		if (i % 16 == 0) syslog(LOG_ERR, "\n%04x: ", i); 
		syslog(LOG_ERR, "%02x ", ((unsigned char *)data)[i]); 
	} 
	syslog(LOG_ERR,"\n\n"); 
	
}
