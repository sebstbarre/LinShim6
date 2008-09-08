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

#ifndef	_LIB_SBUFF_H
#define	_LIB_SBUFF_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct sbuff {
	uint8_t		*head;
	uint8_t		*data;
	int		rem;
	int		len;
	int		truesize;
	int		refcnt;
};

static __inline__ void
sbuff_init(struct sbuff *b, size_t sz, void *data)
{
	b->head = b->data = data;
	b->truesize = b->rem = sz;
	b->len = 0;
	b->refcnt = 1;
}

static __inline__ struct sbuff *
sbuff_alloc(size_t sz)
{
	struct sbuff *b = malloc(sizeof (*b) + sz);

	if (b != NULL) {
		sbuff_init(b, sz, b + 1);
	}

	return (b);
}

static __inline__ void
sbuff_free(struct sbuff *b)
{
	if (--b->refcnt == 0) {
		free(b);
	}
}

static __inline__ void
sbuff_hold(struct sbuff *b)
{
	b->refcnt++;
}

/*
 * Add data to a buffer. Returns -1 if the buffer would be overrun, 0
 * on success.
 */
static __inline__ int
sbuff_put(struct sbuff *b, const void *d, size_t dlen)
{
	if (dlen > b->rem) {
		return (-1);
	}
	memcpy(b->data, d, dlen);
	b->rem -= dlen;
	b->len += dlen;
	b->data += dlen;

	return (0);
}

/*
 * List sbuff_put(), but doesn't copy any data; just does bounds check and
 * advances the data pointer and size counters.
 */
static __inline__ int
sbuff_advance(struct sbuff *b, size_t dlen)
{
	if (dlen > b->rem) {
		return (-1);
	}
	b->rem -= dlen;
	b->len += dlen;
	b->data += dlen;

	return (0);
}

/*
 * Opposite of sbuff_advance().
 */
static __inline__ int
sbuff_retreat(struct sbuff *b, size_t dlen)
{
	if (dlen > b->len) {
		return (-1);
	}
	b->rem += dlen;
	b->len -= dlen;
	b->data -= dlen;

	return (0);
}

static __inline__ void *
sbuff_pull(struct sbuff *b, size_t dlen)
{
	void *d = NULL;

	if (dlen <= b->len) {
		d = b->data;
		b->data += dlen;
		b->rem -= dlen;
		b->len -= dlen;
	}

	return (d);
}

static __inline__ void *
sbuff_data(struct sbuff *b)
{
	return (b->data);
}

static __inline__ void
sbuff_reset(struct sbuff *b)
{
	b->data = b->head;
	b->rem = b->truesize;
	b->len = 0;
}

static __inline__ void
sbuff_reset_to(struct sbuff *b, int to_len)
{
	int d = to_len - b->len;

	if (d <= 0) {
		return;
	}
	b->data -= d;
	b->rem += d;
	b->len += d;
}

#endif	/* _LIB_SBUFF_H */
