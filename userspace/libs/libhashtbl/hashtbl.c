/*
 * Copyright © 2006, DoCoMo Communications Laboratories USA, Inc.,
 *   the DoCoMo SEND Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of DoCoMo Communications Laboratories USA, Inc., its
 *    parents, affiliates, subsidiaries, theDoCoMo SEND Project nor the names
 *    of the Project's contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL DOCOMO COMMUNICATIONS LABORATORIES USA,
 *  INC., ITS PARENTS, AFFILIATES, SUBSIDIARIES, THE PROJECT OR THE PROJECT'S
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "config.h"
#include "list.h"

typedef uint32_t (*hash_func)(void *, int);
typedef int (*match_func)(void *, void *);
typedef void (*free_func)(void *);
typedef void (*walk_func)(void *, void *);

typedef struct htbl_item {
	void *val;
	struct list_head list;
} htbl_item_t;

struct htbl {
	int size;
	hash_func hash_cb;
	match_func match_cb;
	struct list_head *tbl;
};

struct htbl *
htbl_create(int size, hash_func hashcb, match_func matchcb)
{
	struct htbl *t;
	int i;

	if (!hashcb || !matchcb) {
		return (NULL);
	}

	if ((t = malloc(sizeof (*t))) == NULL) {
		return (NULL);
	}
	if ((t->tbl = calloc(size, sizeof (*t->tbl))) == NULL) {
		free(t);
		return (NULL);
	}
	for (i = 0; i < size; i++) {
		INIT_LIST_HEAD(t->tbl + i);
	}
	t->size = size;
	t->hash_cb = hashcb;
	t->match_cb = matchcb;

	return (t);
}

void
htbl_add(struct htbl *tbl, void *val, htbl_item_t *itp)
{
	uint32_t i = tbl->hash_cb(val, tbl->size);

	if (itp == NULL) {
		return;
	}
	memset(itp, 0, sizeof (*itp));

	itp->val = val;
	list_add(&itp->list, tbl->tbl + i);

	return;
}

void *
htbl_find(struct htbl *tbl, void *key)
{
	htbl_item_t *hp;
	struct list_head *lh;
	uint32_t i = tbl->hash_cb(key, tbl->size);

	list_for_each(lh, tbl->tbl + i) {
		hp = list_entry(lh, htbl_item_t, list);
		if (tbl->match_cb(key, hp->val) == 0) {
			return (hp->val);
		}
	}

	return (NULL);
}

void *
htbl_rem(struct htbl *tbl, void *key)
{
	htbl_item_t *hp;
	struct list_head *lh, *ln;
	uint32_t i = tbl->hash_cb(key, tbl->size);

	list_for_each_safe(lh, ln, tbl->tbl + i) {
		hp = list_entry(lh, htbl_item_t, list);
		if (tbl->match_cb(key, hp->val) == 0) {
			list_del(&hp->list);
			INIT_LIST_HEAD(&hp->list);
			return (hp->val);
		}
	}

	return (NULL);
}

void *
htbl_rem_hit(struct htbl *tbl, htbl_item_t *hit)
{
	if (hit->list.prev == NULL || hit->list.next == NULL) {
		return (NULL);
	}
	list_del(&hit->list);
	INIT_LIST_HEAD(&hit->list);
	return (hit->val);
}

void
htbl_walk(struct htbl *tbl, walk_func walker, void *cookie)
{
	int i;
	struct list_head *lh, *ln;
	htbl_item_t *hp;

	for (i = 0; i < tbl->size; i++) {
		list_for_each_safe(lh, ln, tbl->tbl + i) {
			hp = list_entry(lh, htbl_item_t, list);
			walker(hp->val, cookie);
		}
	}
}

void
htbl_destroy(struct htbl *tbl, free_func freeval)
{
	int i;
	struct list_head *lh, *ln;
	htbl_item_t *hp;

	if (freeval) {
		for (i = 0; i < tbl->size; i++) {
			list_for_each_safe(lh, ln, tbl->tbl + i) {
				hp = list_entry(lh, htbl_item_t, list);
				freeval(hp->val);
			}
		}
	}

	free(tbl->tbl);
	free(tbl);
}
