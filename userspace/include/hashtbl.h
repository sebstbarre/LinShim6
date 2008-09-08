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

#ifndef	_SND_HASHTBL_H
#define	_SND_HASHTBL_H

#include <stdint.h>
#include "list.h"

typedef uint32_t (*hash_func)(void *, int);

#ifndef	_LIB_MATCH_FUNC
#define	_LIB_MATCH_FUNC
typedef int (*match_func)(void *, void *);
#endif

#ifndef	_LIB_FREE_FUNC
#define	_LIB_FREE_FUNC
typedef void (*free_func)(void *);
#endif

#ifndef	_LIB_WALK_FUNC
#define	_LIB_WALK_FUNC
typedef void (*walk_func)(void *val, void *cookie);
#endif

typedef void htbl_t;

typedef struct htbl_item {
	void *val;
	struct list_head list;
} htbl_item_t;

extern htbl_t *htbl_create(int, hash_func, match_func);
extern void htbl_destroy(htbl_t *, free_func);
extern void htbl_add(htbl_t *, void *, htbl_item_t *);
extern void *htbl_find(htbl_t *, void *);
extern void *htbl_rem(htbl_t *, void *);
extern void *htbl_rem_hit(htbl_t *, htbl_item_t *);
extern void htbl_walk(htbl_t *, walk_func, void *);

/* hash convenience functions */
extern uint32_t hash_string(const char *p, int sz);
extern uint32_t hash_l2addr(const uint8_t *l2a, int l2len, int sz);
extern uint32_t hash_in6_addr(void *v, int sz);
extern uint32_t hash_in_addr(void *v, int sz);

#endif /* _SND_HASHTBL_H */
