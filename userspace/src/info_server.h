/*
 *	Linux REAP implementation - information server
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : December 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _INFO_SERVER_H
#define _INFO_SERVER_H

#define BUFFER_SIZE 200 /*Buffer size for transfer from /proc info files to
			 * the network.*/

int init_info_server(void);
void exit_info_server(void);

void info_srv_handler(void* data);

#endif /*_INFO_SERVER_H*/
