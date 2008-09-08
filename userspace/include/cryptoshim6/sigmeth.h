/*
 *	Linux shim6 implementation (LinShim6) - daemon part
 *
 *      CGA support (inspired from the DoCoMo SEND implementation)
 *      Management of signature methods (currently only one is defined).
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

#ifndef _SIGMETH_H
#define _SIGMETH_H

#include "cga_params.h"

extern void dump_sig_methods(void);
extern struct sig_method *find_sig_method_byname(const char *);
extern struct sig_method *find_sig_method_bytype(uint8_t);
extern void register_sig_method(struct sig_method *);
extern void sigmeth_fini(void);
extern int sigmeth_init(void);
extern int sigmeth_params_init(struct sig_method *,
    struct cga_params *);
extern void walk_sig_methods(int (*)(struct sig_method *, void *),
    void *);

#endif /*_SIGMETH_H*/
