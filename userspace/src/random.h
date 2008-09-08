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

#ifndef __RANDOM_H__
#define __RANDOM_H__ 1

/**
 * Returns a random integer
 * It uses the standard Linux random() function, seeded with 
 * /dev/random on the first call, and every 1000 calls.
 */
int random_int(void);

#endif /*__RANDOM_H__*/
