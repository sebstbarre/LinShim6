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

#ifndef	__PQ_H
#define	__PQ_H

#ifndef	_LIB_MATCH_FUNC
#define	_LIB_MATCH_FUNC
typedef int (*match_func)(void *, void *);
#endif

#ifndef	_LIB_WALK_FUNC
#define	_LIB_WALK_FUNC
typedef void (*walk_func)(void *, void *);
#endif

#ifndef	_LIB_FREE_FUNC
#define	_LIB_FREE_FUNC
typedef void (*free_func)(void *);
#endif

typedef void pq_t;

typedef struct pq_item {
	void	*item;
	int	k;
} pq_item_t;

extern pq_t *pq_create(match_func);
extern void *pq_del(pq_t *, pq_item_t *);
extern void *pq_delmax(pq_t *);
extern void pq_destroy(pq_t *, free_func);
extern void *pq_getmax(pq_t *);
extern int pq_insert(pq_t *, void *, pq_item_t *);
extern void pq_reprio(pq_t *, pq_item_t *);
extern int pq_size(pq_t *);
extern void pq_walk(pq_t *, walk_func, void *);

#endif	/* __PQ_H */
