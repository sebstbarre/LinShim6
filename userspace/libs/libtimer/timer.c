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
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <sys/select.h>

#include "config.h"
#include <libinit.h>
#include "prioq.h"
#include "thrpool.h"
#include "timer.h"
#include "applog.h"

#ifdef	APPLOG_DEBUG
static struct dlog_desc dbg_timer = {
	.desc = "timer",
	.ctx = "libtimer"
};
#endif

#define	TIMER_GRAN		10 * 1000 /* 10ms granularity allowance */
#define	TIMER_INTR_SIG		60

#ifndef	timercmp
# define timercmp(a, b, CMP)                                                  \
  (((a)->tv_sec == (b)->tv_sec) ?                                             \
   ((a)->tv_usec CMP (b)->tv_usec) :                                          \
   ((a)->tv_sec CMP (b)->tv_sec))
#endif

#ifndef	timeradd
# define timeradd(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                          \
    if ((result)->tv_usec >= 1000000)                                         \
      {                                                                       \
        ++(result)->tv_sec;                                                   \
        (result)->tv_usec -= 1000000;                                         \
      }                                                                       \
  } while (0)
#endif

#ifndef	timersub
# define timersub(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)
#endif

static pq_t *timer_pq;
static pthread_mutex_t pqlock = PTHREAD_MUTEX_INITIALIZER;

#ifndef	NOTHREADS
static int started;
static pthread_cond_t startcv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t startlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t firing_cv = PTHREAD_COND_INITIALIZER;
static volatile void *timer_cb_firing;

static pthread_t timer_tid;

static void
wakeup(void)
{
	pthread_kill(timer_tid, 60);
}

static void
interruptable_sleep(struct timeval *abswake)
{
	fd_set fds[1];
	int r;
	struct timeval now[1], tv[1], *wake;

	if (abswake) {
		gettimeofday(now, NULL);
		wake = tv;
		timersub(abswake, now, wake);

		if (wake->tv_sec < 0 || wake->tv_usec < 0) {
			DBG(&dbg_timer, "negative wait; idling");
			wake = NULL;
		} else {
			DBG(&dbg_timer, "%ld.%.6ld: sleeping for %ld.%.6ld",
			    now->tv_sec, now->tv_usec,
			    wake->tv_sec, wake->tv_usec);
		}
	} else {
		wake = NULL;
	}

	FD_ZERO(fds);
	r = select(0, fds, NULL, NULL, wake);
	if (r < 0) {
		if (errno == EINTR) {
			DBG(&dbg_timer, "wakeup");
		} else {
			DBG(&dbg_timer, "select: %s", strerror(errno));
		}
	} else {
		DBG(&dbg_timer, "timeout");
	}
}

static void
noop_sighand(int s)
{
}
#endif	/* NOTHREADS */

static int
cmp_timers(void *a, void *b)
{
	timer_item_t *t1 = a;
	timer_item_t *t2 = b;

	/*
	 * Reverse the order of comparison to order the pq from
	 * least to greatest.
	 */
	if (t1->tv.tv_sec != t2->tv.tv_sec) {
		return (t2->tv.tv_sec - t1->tv.tv_sec);
	}
	return (t2->tv.tv_usec - t1->tv.tv_usec);
}

/*
 * 'when' is in relative time
 */
int
timer_set(struct timeval *when, timer_func cb, void *arg, timer_item_t *tp)
{
	struct timeval now[1];
	int reset = 0;
	int r = 0;

	if (cb == NULL) {
		return (1);
	}

	pthread_mutex_lock(&pqlock);
	if (timerisset(&tp->tv)) {
		reset = 1;
	} else {
		memset(tp, 0, sizeof (*tp));
	}

	tp->func = cb;
	tp->arg = arg;

	gettimeofday(now, NULL);
	timeradd(now, when, &tp->tv);

	DBG(&dbg_timer, "%p: %ld.%.6ld: wake %ld.%.6ld reset %d", tp,
	    now->tv_sec, now->tv_usec, tp->tv.tv_sec, tp->tv.tv_usec, reset);

	if (!reset) {
		if ((r = pq_insert(timer_pq, tp, &tp->pqi)) != 0) {
			timerclear(&tp->tv);
			goto done;
		}
		
	} else {
		pq_reprio(timer_pq, &tp->pqi);
	}
#ifndef	NOTHREADS
	/* wake up timer thread */
	wakeup();
#endif

done:
	pthread_mutex_unlock(&pqlock);
	return (r);
}

void
timer_clear(timer_item_t *tp)
{
	struct timeval tvbuf[1];

	DBG(&dbg_timer, "%p", tp);

	if (tp == NULL || !timerisset(&tp->tv)) {
		return;
	}

	pthread_mutex_lock(&pqlock);
	pq_del(timer_pq, &tp->pqi);
	timerclear(&tp->tv);
	pthread_mutex_unlock(&pqlock);

	timer_check(tvbuf);
}

/*
 * Like timer_clear, but guarantees that the timer being deleted
 * will not fire after this call has returned. However, the timer
 * may fire before this function has grabbed the pqlock, so calling
 * functions must ensure that they do not hold any locks that the
 * timer will try to acquire, or a deadlock may ensue.
 */
void
timer_clear_sync(timer_item_t *tp)
{
	struct timeval tvbuf[1];

	DBG(&dbg_timer, "%p", tp);

	pthread_mutex_lock(&pqlock);
#ifndef	NOTHREADS
	while (timer_cb_firing == tp) {
		pthread_cond_wait(&firing_cv, &pqlock);
	}
#endif
	pq_del(timer_pq, &tp->pqi);
	timerclear(&tp->tv);
	pthread_mutex_unlock(&pqlock);

	timer_check(tvbuf);
}

struct timeval *
timer_check(struct timeval *tvbuf)
{
	struct timeval now[1], *tvr = NULL;
	timer_item_t *tp;
	timer_func cb;
	void *arg;

	pthread_mutex_lock(&pqlock);

	while ((tp = pq_getmax(timer_pq)) != NULL) {
		gettimeofday(now, NULL);
		DBG(&dbg_timer, "now %ld.%.6ld pqmax %ld.%.6ld",
		    now->tv_sec, now->tv_usec, tp->tv.tv_sec,tp->tv.tv_usec);

		if (timercmp(&tp->tv, now, >)) {
			tvbuf->tv_sec = tp->tv.tv_sec;
			tvbuf->tv_usec = tp->tv.tv_usec;
			tvr = tvbuf;

			/* Fire timer if within granularity threshold */
			if (tp->tv.tv_sec != now->tv_sec ||
			    (tp->tv.tv_usec - now->tv_usec) > TIMER_GRAN) {
				goto done;
			}
		}

		/* fire timer */
		tvr = NULL;
		if ((tp = pq_delmax(timer_pq)) == NULL) {
			applog(LOG_CRIT, "%s: threading BUG!", __FUNCTION__);
			goto done;
		}
		cb = tp->func;
		arg = tp->arg;
		timerclear(&tp->tv);

		DBG(&dbg_timer, "%ld.%.6ld: firing %p", now->tv_sec,
		    now->tv_usec, tp);

#ifndef	NOTHREADS
		timer_cb_firing = tp;
#endif
		pthread_mutex_unlock(&pqlock);

		thrpool_req(cb, arg, NULL, 0);

		pthread_mutex_lock(&pqlock);
#ifndef	NOTHREADS
		timer_cb_firing = NULL;
		pthread_cond_signal(&firing_cv);
#endif
	}

done:
	pthread_mutex_unlock(&pqlock);
	return (tvr);
}

#ifndef	NOTHREADS
static void *
timer_thr(void *a)
{
	struct timeval tv[1], *tvp, *wake;

	DBG(&dbg_timer, "starting");
	/* wake up timer thread */
	pthread_mutex_lock(&startlock);
	started = 1;
	pthread_cond_signal(&startcv);
	pthread_mutex_unlock(&startlock);

	for (;;) {
		if ((tvp = timer_check(tv)) == NULL) {
			DBG(&dbg_timer, "timer_check==NULL, idling");
			wake = NULL;
		} else {
			wake = tvp;
			DBG(&dbg_timer, "wake %ld.%ld", wake->tv_sec,
			    wake->tv_usec);
		}
		interruptable_sleep(wake);
	}
}
#endif

void
timer_walk(walk_func cb, void *a)
{
	pthread_mutex_lock(&pqlock);
	pq_walk(timer_pq, cb, a);
	pthread_mutex_unlock(&pqlock);
}

int
timer_init(void)
{
#ifdef	APPLOG_DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_timer,
		NULL
	};
#endif

	if (lib_is_initialized()) {
		return (0);
	}

#ifdef	APPLOG_DEBUG
	applog_register(dbgs);
#endif

	if ((timer_pq = pq_create(cmp_timers)) == NULL) {
		return (-1);;
	}
#ifndef	NOTHREADS
	if (pthread_create(&timer_tid, NULL, timer_thr, NULL) != 0) {
		fprintf(stderr, "pthread_create() failed\n");
		return (-1);
	}
	signal(60, noop_sighand);

	/* Wait until timer_thr has started - reuse wake* */
	pthread_mutex_lock(&startlock);
	DBG(&dbg_timer, "Waiting for timer thread to start");
	while (!started) {
		pthread_cond_wait(&startcv, &startlock);
	}
	pthread_mutex_unlock(&startlock);
	DBG(&dbg_timer, "done");
#endif
	return (0);
}

static __attribute__ (( destructor)) void
timer_fini(void)
{
	pthread_mutex_lock(&pqlock);
	pq_destroy(timer_pq, NULL);
	pthread_mutex_unlock(&pqlock);
	pthread_mutex_destroy(&pqlock);
}
