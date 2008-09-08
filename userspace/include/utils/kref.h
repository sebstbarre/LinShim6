/*
 * kref.c - library routines for handling generic reference counted objects
 *
 * This is an adaptation (by S. Barré, sbarre@info.ucl.ac.be) for user space 
 * of the Linux implementation available
 * in include/linux/kref.h (impl. in lib/kref.c)
 *
 * This is intended for use in a parallel environment provided by the 
 * pthread library.
 *
 * 
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004 IBM Corp.
 *
 * based on kobject.h which was:
 * Copyright (C) 2002-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (C) 2002-2003 Open Source Development Labs
 *
 * This file is released under the GPLv2.
 *
 */

#ifndef _KREF_H_
#define _KREF_H_

#include <config.h>
#include <syslog.h>

struct kref {
	int refcount;
};

void kref_init(struct kref *kref);
void kref_get(struct kref *kref);
int kref_put(struct kref *kref, void (*release) (struct kref *kref));

#endif /* _KREF_H_ */
