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
#include <sys/types.h>

#include "config.h"

#define	PQ_INITIAL_SIZE	16

typedef int (*match_func)(void *, void *);
typedef void (*walk_func)(void *, void *);
typedef void (*free_func)(void *);

typedef struct pq_item {
	void	*item;
	int	k;
} pq_item_t;

struct pq {
	pq_item_t	**items;
	int		size;
	int		allocd;
	match_func	match_cb;
};

static __inline__ void
exch(pq_item_t **it, int k, int i)
{
	pq_item_t *tp = it[k];
	it[k]->k = i;
	it[i]->k = k;
	it[k] = it[i];
	it[i] = tp;
}

static __inline__ void
fixup(struct pq *pq, int k)
{
	pq_item_t **it = pq->items;

	while (k > 1 && pq->match_cb(it[k / 2]->item, it[k]->item) < 0) {
		exch(it, k, k / 2);
		k /= 2;
	}
}

static __inline__ void
fixdown(struct pq *pq, int k, int size)
{
	int i;
	pq_item_t **it = pq->items;

	while ((2 * k) <= size) {
		i = 2 * k;
		if (i < size && pq->match_cb(it[i]->item, it[i + 1]->item)
		    < 0) {
			i++;
		}
		if (pq->match_cb(it[k]->item, it[i]->item) >= 0) {
			break;
		}
		exch(it, k, i);
		k = i;
	}
}

struct pq *
pq_create(match_func matchcb)
{
	struct pq *pq;

	if (!matchcb) {
		return (NULL);
	}

	if ((pq = malloc(sizeof (*pq))) == NULL) {
		return (NULL);
	}
	memset(pq, 0, sizeof (*pq));

	if ((pq->items = calloc(PQ_INITIAL_SIZE, sizeof (*pq->items)))
	    == NULL) {
		free(pq);
		return (NULL);
	}
	pq->allocd = PQ_INITIAL_SIZE;
	pq->match_cb = matchcb;

	return (pq);
}

int
pq_insert(struct pq *pq, void *it, pq_item_t *pqi)
{
	pq_item_t **newmem;

	if ((pq->size + 1) == pq->allocd) {
		/* need to grow backing array */
		if ((newmem = realloc(pq->items,
		    sizeof (*pq->items) * pq->allocd * 2)) == NULL) {
			return (-1);
		}
		pq->items = newmem;
		pq->allocd *= 2;
	}
	pqi->item = it;
	pq->items[++pq->size] = pqi;
	pqi->k = pq->size;
	fixup(pq, pq->size);

	return (0);
}

void *
pq_delmax(struct pq *pq)
{
	if (pq->size == 0) {
		return (NULL);
	}
	exch(pq->items, 1, pq->size);
	fixdown(pq, 1, pq->size - 1);
	return (pq->items[pq->size--]->item);
}

void *
pq_del(struct pq *pq, pq_item_t *pqi)
{
	int k = pqi->k;

	if (pqi->k < 0 || pqi->k > pq->size) {
		return (NULL);
	}

	exch(pq->items, pqi->k, pq->size);
	pq->size--;
	fixup(pq, k);
	fixdown(pq, k, pq->size);

	return (pqi->item);
}

void
pq_reprio(struct pq *pq, pq_item_t *pqi)
{
	int k = pqi->k;

	if (pqi->k < 0 || pqi->k > pq->size) {
		return;
	}

	fixup(pq, k);
	fixdown(pq, k, pq->size);
}

void *pq_getmax(struct pq *pq)
{
	if (pq->size == 0) {
		return (NULL);
	}
	return (pq->items[1]->item);
}

void pq_walk(struct pq *pq, walk_func walk_cb, void *arg)
{
	int i;

	for (i = 1; i <= pq->size; i++) {
		walk_cb(pq->items[i]->item, arg);
	}
}

int
pq_size(struct pq *pq)
{
	return (pq->size);
}

void
pq_destroy(struct pq *pq, free_func free_cb)
{
	int i;

	if (!pq) {
		return;
	}

	if (free_cb) {
		for (i = 1; i <= pq->size; i++) {
			free_cb(pq->items[i]->item);
		}
	}

	memset(pq->items, 0, pq->allocd);
	free(pq->items);
	memset(pq, 0, sizeof (*pq));
	free(pq);
}
