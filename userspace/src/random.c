/*
 *	Linux Shim6 implementation - daemon part
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : July 2008
 *
 *      Random number generation  
 * 
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <utils/debug.h>
#include "random.h"

int random_int(void)
{
	static int nbcalls=0;
	if (nbcalls==1000) nbcalls=0;
	if (nbcalls++==0) {		
		int randfd,seed,ans;
		PDEBUG("Asking for a random seed to /dev/random\n");

		randfd=open("/dev/random",O_RDONLY);
		
		if (randfd<0) {
			syslog(LOG_ERR, "Could not open /dev/random : %m\n");
			exit(EXIT_FAILURE);
		}
		ans=read(randfd,&seed,sizeof(int));
		if (ans!=sizeof(int)) {
			syslog(LOG_ERR,
			       "Error while reading /dev/random : %m\n");
			exit(EXIT_FAILURE);
		}
		close(randfd);
		srandom(seed);
		PDEBUG("...Seed obtained");
	}	
	return random();
}
