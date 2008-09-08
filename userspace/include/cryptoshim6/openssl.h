/*
 *	Linux shim6 implementation (LinShim6) - daemon part
 *
 *      OpenSSL interface (inspired from the DoCoMo SEND implementation)
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : November 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _OPENSSL_H
#define _OPENSSL_H

extern void openssl_fini(void);
extern int openssl_init(void);
extern void openssl_err(const char *, const char *);

#endif /*_OPENSSL_H*/
