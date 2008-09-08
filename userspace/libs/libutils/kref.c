/*
 * kref.c - library routines for handling generic reference counted objects
 *
 * This is an adaptation (by S. Barré, sebastien.barre@uclouvain.be) 
 * for user space 
 * of the Linux implementation available
 * in include/linux/kref.h (impl. in lib/kref.c)
 *
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004 IBM Corp.
 *
 * based on lib/kobject.c which was:
 * Copyright (C) 2002-2003 Patrick Mochel <mochel@osdl.org>
 *
 * This file is released under the GPLv2.
 *
 */

#include <config.h>
#include <utils/kref.h>
#include <utils/debug.h>

/**
 * kref_init - initialize object.
 * @kref: object in question.
 */
void kref_init(struct kref *kref)
{
	kref->refcount=1;
}

/**
 * kref_get - increment refcount for object.
 * @kref: object.
 */
void kref_get(struct kref *kref)
{
	ASSERT(kref->refcount);
	PDEBUG("kref_get while refcount is %d\n", kref->refcount);
	kref->refcount++;
}

/**
 * kref_put - decrement refcount for object.
 * @kref: object.
 * @release: pointer to the function that will clean up the object when the
 *	     last reference to the object is released.
 *	     This pointer is required, and it is not acceptable to pass kfree
 *	     in as this function.
 *
 * Decrement the refcount, and if 0, call release().
 * Return 1 if the object was removed, otherwise return 0.  Beware, if this
 * function returns 0, you still can not count on the kref from remaining in
 * memory.  Only use the return value if you want to see if the kref is now
 * gone, not present.
 */
int kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
	int ans=0;
	ASSERT(release);
	PDEBUG("kref_put while refcount is %d\n",kref->refcount);
	
	kref->refcount--;
	if (kref->refcount==0) {
		release(kref);
		ans=1;
	}
	
	return ans;
}
