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

#ifndef	__THRPOOL_H
#define	__THRPOOL_H

#include <stdint.h>
#include <pthread.h>

#include <prioq.h>

typedef struct thrpool_id {
	void			*pqi;
	pthread_t		pthread_id;
} thrpool_id_t;

#ifndef	NOTHREADS

extern void thrpool_init(void);
extern int thrpool_req(void (*)(void *), void *, thrpool_id_t *, int);
extern int thrpool_req_excl(void (*)(void *), void *, thrpool_id_t *);
extern void thrpool_set_max(uint32_t);
extern void thrpool_set_min(uint32_t);
extern void thrpool_set_q_size(uint32_t);

extern void thr_specific_set(thrpool_id_t *, void *);
extern void thr_specific_set_self(void *);
extern void *thr_specific_get(thrpool_id_t *);
extern void *thr_specific_get_self(void);

/* Interrupts a blocked select() call */
extern void thr_interrupt(thrpool_id_t *);

#else	/* NOTHREADS */

static __inline__ int
thrpool_req(void (*func)(void *), void *arg, thrpool_id_t *tid, int prio)
{
	func(arg);
	return (0);
}

#define	thrpool_req_excl(handler_func, handler_arg, t) \
				thrpool_req(handler_func, handler_arg, t, 0)
#define	thrpool_init()
#define	thrpool_set_max(dummy)
#define	thrpool_set_min(dummy)
#define thr_specific_set(t, x);
#define thr_specific_set_self(x);
#define thr_specific_get(t);
#define thr_specific_get_self();
#define	thr_interrupt(t)

#endif	/* NOTHREADS */

#endif	/* __THRPOOL_H */
