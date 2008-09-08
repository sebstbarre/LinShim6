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
#include <pthread.h>
#include <stdint.h>
#include <signal.h>

#include <config.h>
#include <hashtbl.h>
#include <list.h>
#include <prioq.h>
#include <applog.h>
#include <libinit.h>

#define	THRPOOL_MIN_COUNT	0
#define	THRPOOL_MAX_COUNT	50
#define	THRPOOL_MAX_Q_SIZE	256

#define	THRPOOL_INTR_SIGNAL	60 /* signal used to interrupt threads */

#ifdef	APPLOG_DEBUG
static struct dlog_desc dbg_thrp = {
	.desc = "thrpool",
	.ctx = "libthrpool"
};
static struct dlog_desc dbg_thrpx = {
	.desc = "thrpool",
	.ctx = "libthrpool"
};
#endif

typedef struct thrpool_id {
	pq_item_t		*pqi;
	pthread_t		pthread_id;
} thrpool_id_t;

struct thrpool {
	struct list_head	list;
	thrpool_id_t		tid;
	pthread_cond_t		cv;
	void			(*reqfunc)(void *);
	void			*reqarg;
};

struct thrpool_q_item {
	int			prio;
	thrpool_id_t		*tid;
	void			(*reqfunc)(void *);
	void			*reqarg;
	pq_item_t		pqi;	// for normal queue
	struct list_head	list;	// for exclusive queue
};

static LIST_HEAD(idle_thr_list);
static LIST_HEAD(active_thr_list);
static pthread_mutex_t thrpool_lock = PTHREAD_MUTEX_INITIALIZER;

static pq_t *thrpool_q;
static uint32_t thrpool_max_q_size = THRPOOL_MAX_Q_SIZE;

static uint32_t thrpool_min_count = THRPOOL_MIN_COUNT;
static uint32_t thrpool_max_count = THRPOOL_MAX_COUNT;
static uint32_t thrpool_curr_count;

static LIST_HEAD(thrpool_excl_q);
static int thrpool_excl, thrpool_excl_q_size;

static struct thrpool *newthr(void);

/* Thread-specific support */
static htbl_t *thrspec_tbl;
static pthread_mutex_t speclock = PTHREAD_MUTEX_INITIALIZER;
struct thrspec {
	pthread_t tid;
	void *d;
	htbl_item_t hti;
};

static uint32_t
hash_thrspec(void *a, int sz)
{
	struct thrspec *p = a;

	return ((uint32_t)p->tid % sz);
}

static int
match_thrspec(void *a, void *b)
{
	struct thrspec *p1 = a;
	struct thrspec *p2 = b;

	return ((uint32_t)p1->tid - (uint32_t)p2->tid);
}

static int
cmp_thrpool_q_item(void *a, void *b)
{
	struct thrpool_q_item *i1 = a;
	struct thrpool_q_item *i2 = b;

	return (i1->prio - i2->prio);
}

static void
noop_sighand(int s)
{
}

static inline struct thrpool_q_item *
make_thrpool_q_item(void (*func)(void *), void *arg, thrpool_id_t *tid,
    int prio)
{
	struct thrpool_q_item *tqp;

	if ((tqp = malloc(sizeof (*tqp))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (NULL);
	}

	memset(tqp, 0, sizeof (*tqp));
	tqp->prio = prio;
	tqp->reqfunc = func;
	tqp->reqarg = arg;
	if (tid) {
		tid->pqi = &tqp->pqi;
		tqp->tid = tid;
	}

	return (tqp);
}

static inline int
thrpool_enqueue(void (*func)(void *), void *arg, thrpool_id_t *tid, int prio)
{
	struct thrpool_q_item *tqp;

	if (!thrpool_q ||
	    pq_size(thrpool_q) >= thrpool_max_q_size) {
		DBG(&dbg_thrp, "no q, or q is full");
		return (-1);
	}
	if ((tqp = make_thrpool_q_item(func, arg, tid, prio)) == NULL) {
		return (-1);
	}

	pq_insert(thrpool_q, tqp, &tqp->pqi);

	return (0);
}

/* Assumes tp is currently on the idle list */
static inline void
assign_task(struct thrpool *tp, void (*func)(void *), void *arg,
    thrpool_id_t *tid)
{
	list_del(&tp->list);
	list_add(&tp->list, &active_thr_list);
	tp->reqfunc = func;
	tp->reqarg = arg;
	if (tid != NULL) {
		*tid = tp->tid;
	}
	pthread_cond_signal(&tp->cv);
	DBG(&dbg_thrpx, "assigned to %d", tp->tid.pthread_id);
}

static inline struct thrpool *
get_idle_thr(void)
{
	struct thrpool *tp;

	if (list_empty(&idle_thr_list)) {
		return (NULL);
	}
	list_for_each_entry(tp, &idle_thr_list, list) {
		break;
	}

	return (tp);
}

static void
wait_for_task(struct thrpool *tp)
{
	while (tp->reqfunc == NULL) {
		pthread_cond_wait(&tp->cv, &thrpool_lock);
	}
	DBG(&dbg_thrpx, "%d: got task", pthread_self());
}

static inline void
prepare_qd_task(struct thrpool *tp, struct thrpool_q_item *tqp)
{
	tp->reqfunc = tqp->reqfunc;
	tp->reqarg = tqp->reqarg;

	if (tqp->tid) {
		tqp->tid->pthread_id = pthread_self();
		tqp->tid->pqi = NULL;
	}

	free(tqp);
	list_add(&tp->list, &active_thr_list);
}

static void
assign_qd_tasks(void)
{
	struct thrpool_q_item *tqp;
	struct thrpool *tp;

	/*
	 * If just one pending req, let this thr do it. If none, go back
	 * to normal wait state.
	 */
	if (pq_size(thrpool_q) < 2) {
		DBG(&dbg_thrpx, "< 2 pending requests");
		return;
	}

	for (;;) {
		if ((tp = get_idle_thr()) == NULL) {
			if (thrpool_curr_count >= thrpool_max_count) {
				DBG(&dbg_thrp, "no more idle threads "
				    "available, and at max thr cnt");
				return;
			}
			if ((tp = newthr()) == NULL) {
				return;
			}
		}
		if ((tqp = pq_delmax(thrpool_q)) == NULL) {
			DBG(&dbg_thrpx, "no more pending requests");
			return;
		}
		list_del(&tp->list);
		prepare_qd_task(tp, tqp);
		pthread_cond_signal(&tp->cv);
		DBG(&dbg_thrpx, "assigned task to %d", tp->tid.pthread_id);
	}
}

static inline void
assign_excl_task(struct thrpool *tp)
{
	struct thrpool_q_item *tqp = NULL;

	list_for_each_entry(tqp, &thrpool_excl_q, list) {
		break;
	}
	list_del(&tqp->list);
	thrpool_excl_q_size--;

	DBG(&dbg_thrpx, "thr %d", pthread_self());
	prepare_qd_task(tp, tqp);
}

/*
 * Returns 0 if no task was retrieved, otherwise 1.
 */
static int
get_excl_task(struct thrpool *tp)
{
	/* If the excl q is empty, we are transitioning from excl to
	 * normal state. Assign pending requests to waiting
	 * threads.
	 */
	if (list_empty(&thrpool_excl_q)) {
		DBG(&dbg_thrpx, "excl -> non excl");
		thrpool_excl = 0;
		assign_qd_tasks();
		return (0);
	}

	/*
	 * If we are in excl mode and are not the last active thr to
	 * finish up, wait to be awoken for normal tasks.
	 */
	if (!list_empty(&active_thr_list)) {
		DBG(&dbg_thrpx, "not last active thr; waiting (%d)",
		    pthread_self());
		list_add(&tp->list, &idle_thr_list);
		wait_for_task(tp);
		return (1);
	}

	/* We are the last thr to finish, so run the task now. */
	assign_excl_task(tp);
	return (1);
}

static void
get_task(struct thrpool *tp)
{
	struct thrpool_q_item *tqp;

	pthread_cleanup_push((void (*)(void *))pthread_mutex_unlock,
			     (void *)&thrpool_lock);
	pthread_mutex_lock(&thrpool_lock);

	if (tp->reqfunc != NULL) {
		DBG(&dbg_thrpx, "%d: got assigned task", pthread_self());
		goto done;
	}

	/* remove from active list */
	list_del(&tp->list);

	if (thrpool_excl && get_excl_task(tp)) {
		goto done;
	}

	if (thrpool_curr_count > thrpool_max_count) {
		/* bail out */
		pthread_cond_destroy(&tp->cv);
		free(tp);
		thrpool_curr_count--;

		pthread_exit(NULL); /* cleanup handler unlocks... */
	}

	/* Check for any queued requests */
	if ((tqp = pq_delmax(thrpool_q)) != NULL) {
		prepare_qd_task(tp, tqp);
		DBG(&dbg_thrpx, "%d: got qd task", pthread_self());
	} else {
		list_add(&tp->list, &idle_thr_list);
		DBG(&dbg_thrpx, "%d: awaiting task", pthread_self());
		wait_for_task(tp);
	}
	
done:
	; /*Necessary by design of pthread_cleanup_pop
	    (If not there, we can have error 'label at end of 
	    compound statement')*/
	pthread_cleanup_pop(1);
}

static void *
thrpool_thr(void *a)
{
	struct thrpool *tp = a;

	for (;;) {
		get_task(tp);

		pthread_testcancel();
		tp->reqfunc(tp->reqarg);
		tp->reqfunc = tp->reqarg = NULL;
		pthread_testcancel();
	}

	return (NULL);
}

/*
 * Caller must hold thrpool_lock
 */
static struct thrpool *
newthr(void)
{
	struct thrpool *tp;
	struct thrspec *tsp;

	if (thrpool_curr_count > thrpool_max_count) {
		return (NULL);
	}

	if ((tp = malloc(sizeof (*tp))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (NULL);
	}
	if ((tsp = malloc(sizeof (*tsp))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		free(tp);
		return (NULL);
	}

	memset(tp, 0, sizeof (*tp));
	pthread_cond_init(&tp->cv, NULL);
	pthread_create(&tp->tid.pthread_id, NULL, thrpool_thr, tp);

	/* Add thread-specific data holder */
	pthread_mutex_lock(&speclock);
	if (thrspec_tbl != NULL) {
		memset(tsp, 0, sizeof (*tsp));
		tsp->tid = tp->tid.pthread_id;
		htbl_add(thrspec_tbl, tsp, &tsp->hti);
	} else {
		free(tsp);
	}
	pthread_mutex_unlock(&speclock);

	list_add(&tp->list, &idle_thr_list);
	thrpool_curr_count++;

	DBG(&dbg_thrp, "%d (/%d)", tp->tid.pthread_id, thrpool_curr_count);

	return (tp);
}

/*
 * Caller must hold thrpool_lock
 */
static void
delthr(struct thrpool *tp)
{
	struct list_head *lh;
	struct thrpool *tmptp = NULL;
	thrpool_id_t *tid = &tp->tid;
	struct thrspec tk[1], *tsp;

	pthread_cancel(tid->pthread_id);
	pthread_mutex_unlock(&thrpool_lock);
	pthread_join(tid->pthread_id, NULL);

	/* Remove thread-specific data holder */
	pthread_mutex_lock(&speclock);
	tk->tid = tid->pthread_id;
	if (thrspec_tbl && (tsp = htbl_rem(thrspec_tbl, tk)) != NULL) {
		free(tsp);
	}
	pthread_mutex_unlock(&speclock);

	/* tp may have been freed; search again now */
	pthread_mutex_lock(&thrpool_lock);
	list_for_each(lh, &idle_thr_list) {
		tmptp = list_entry(lh, struct thrpool, list);
		if (tmptp->tid.pthread_id == tid->pthread_id) {
			break;
		} else {
			tmptp = NULL;
		}
	}
	if (tmptp == NULL) {
		list_for_each(lh, &active_thr_list) {
			tmptp = list_entry(lh, struct thrpool, list);
			if (tmptp->tid.pthread_id == tid->pthread_id) {
				break;
			} else {
				tmptp = NULL;
			}
		}
	}
	if (tmptp == NULL) {
		/* it's gone */
		return;
	}
	tp = tmptp;

	list_del(&tp->list);
	pthread_cond_destroy(&tp->cv);
	thrpool_curr_count--;

	DBG(&dbg_thrp, "%d (/%d)", tp->tid.pthread_id, thrpool_curr_count);

	free(tp);

}

int
thrpool_req(void (*func)(void *), void *arg, thrpool_id_t *tid, int prio)
{
	struct thrpool *tp;
	int r = 0;

	pthread_mutex_lock(&thrpool_lock);

	DBG(&dbg_thrpx, "curr count: %d / %d excl: %d", thrpool_curr_count,
	    thrpool_max_count, thrpool_excl);

	if (thrpool_excl) {
		DBG(&dbg_thrpx, "excl; enqueuing request");
		r = thrpool_enqueue(func, arg, tid, prio);
		goto done;
	}

	tp = get_idle_thr();
	if (tp == NULL && thrpool_curr_count >= thrpool_max_count) {
		/* try enqueueing it */
		DBG(&dbg_thrpx, "enqueuing request");
		r = thrpool_enqueue(func, arg, tid, prio);
		goto done;
	}

	if (tp == NULL && (tp = newthr()) == NULL) {
		r = -1;
		goto done;
	}
	assign_task(tp, func, arg, tid);

done:
	pthread_mutex_unlock(&thrpool_lock);

	return (r);
}

/*
 * Add a task that will run exclusively, i.e. no other thrpool reqs
 * will be running at the same time. This is useful if you want to
 * avoid locking for data that is updated infrequently. You must
 * ensure that any non-thrpool threads in your app will not try
 * to read or write this data, however.
 *
 * All excl tasks run at highest priority, so no priority argument
 * is needed.
 */
int
thrpool_req_excl(void (*func)(void *), void *arg, thrpool_id_t *tid)
{
	struct thrpool_q_item *tqp;
	struct thrpool *tp;
	int r = -1;

	pthread_mutex_lock(&thrpool_lock);

	if (thrpool_excl_q_size >= thrpool_max_q_size) {
		DBG(&dbg_thrp, "q is full");
		goto done;
	}
	thrpool_excl = 1;

	if (list_empty(&active_thr_list)) {
		/* we can run the task right away */
		DBG(&dbg_thrpx, "no active threads, running task");
		if ((tp = get_idle_thr()) == NULL && (tp = newthr()) == NULL) {
			goto done;
		}
		assign_task(tp, func, arg, tid);
		r = 0;
		goto done;
	}

	/* else q the task until all active threads are done */
	DBG(&dbg_thrpx, "enqueuing request");
	if ((tqp = make_thrpool_q_item(func, arg, tid, 0)) == NULL) {
		thrpool_excl = 0;
		goto done;
	}

	list_add_tail(&tqp->list, &thrpool_excl_q);
	thrpool_excl_q_size++;
	r = 0;

done:
	pthread_mutex_unlock(&thrpool_lock);
	return (r);
}

void
thrpool_set_min(uint32_t min)
{
	int i;

	pthread_mutex_lock(&thrpool_lock);
	if (min > thrpool_max_count) {
		thrpool_max_count = min;
	}
	for (i = thrpool_curr_count; i <= min; i++) {
		newthr();
	}
	thrpool_min_count = min;
	pthread_mutex_unlock(&thrpool_lock);
}

void
thrpool_set_max(uint32_t max)
{
	struct list_head *lh, *ln;
	struct thrpool *tp;

	pthread_mutex_lock(&thrpool_lock);
	if (max < thrpool_min_count) {
		thrpool_min_count = max;
	}
	thrpool_max_count = max;

	if (thrpool_curr_count <= thrpool_max_count) {
		goto done;
	}

	/* Clean up idle list */
	list_for_each_safe(lh, ln, &idle_thr_list) {
		tp = list_entry(lh, struct thrpool, list);
		delthr(tp);
		if (thrpool_curr_count <= thrpool_max_count) {
			break;
		}
	}

done:
	pthread_mutex_unlock(&thrpool_lock);
}

void
thrpool_set_q_size(uint32_t sz)
{
	thrpool_max_q_size = sz;
}

void
thr_specific_set(thrpool_id_t *tid, void *d)
{
	struct thrspec k[1], *p;

	pthread_mutex_lock(&speclock);
	k->tid = tid->pthread_id;

	if (thrspec_tbl && (p = htbl_find(thrspec_tbl, k)) != NULL) {
		p->d = d;
	}
	pthread_mutex_unlock(&speclock);
}

void
thr_specific_set_self(void *d)
{
	thrpool_id_t tid[1];
	tid->pthread_id = pthread_self();
	thr_specific_set(tid, d);
}

void *
thr_specific_get(thrpool_id_t *tid)
{
	struct thrspec k[1], *p;
	void *d = NULL;

	pthread_mutex_lock(&speclock);
	k->tid = tid->pthread_id;

	if (thrspec_tbl && (p = htbl_find(thrspec_tbl, k)) != NULL) {
		d = p->d;
	}
	pthread_mutex_unlock(&speclock);

	return (d);
}

void *
thr_specific_get_self(void)
{
	thrpool_id_t tid[1];
	tid->pthread_id = pthread_self();
	return (thr_specific_get(tid));
}

void
thr_interrupt(thrpool_id_t *tid)
{
	pthread_mutex_lock(&thrpool_lock);
	if (tid->pqi != NULL) {
		/* enqueued, but not yet on a thread - just remove it */
		pq_del(thrpool_q, tid->pqi);
		pthread_mutex_unlock(&thrpool_lock);
		return;
	}
	pthread_mutex_unlock(&thrpool_lock);
	pthread_kill(tid->pthread_id, THRPOOL_INTR_SIGNAL);
}

void
thrpool_init(void)
{
	int i;
#ifdef	APPLOG_DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_thrp,
#ifdef	THRPOOL_LOTS_AND_LOTS_OF_DEBUG
		&dbg_thrpx,
#endif
		NULL
	};
#endif

	if (lib_is_initialized()) {
		return;
	}

#ifdef	APPLOG_DEBUG
	applog_register(dbgs);
#endif

	thrspec_tbl = htbl_create(17, hash_thrspec, match_thrspec);

	pthread_mutex_lock(&thrpool_lock);
	for (i = 0; i < thrpool_min_count; i++) {
		newthr();
	}
	pthread_mutex_unlock(&thrpool_lock);

	/* Catch interrupt signal */
	signal(THRPOOL_INTR_SIGNAL, noop_sighand);

	thrpool_q = pq_create(cmp_thrpool_q_item);
}

static __attribute__ (( destructor)) void
thrpool_fini(void)
{
	struct list_head *lh, *ln;

	pthread_mutex_lock(&thrpool_lock);
	list_for_each_safe(lh, ln, &idle_thr_list) {
		delthr(list_entry(lh, struct thrpool, list));
	}
	thrpool_min_count = thrpool_max_count = 0;
	list_for_each_safe(lh, ln, &active_thr_list) {
		delthr(list_entry(lh, struct thrpool, list));
	}

	pq_destroy(thrpool_q, free);
	if (thrspec_tbl) htbl_destroy(thrspec_tbl, free);

	pthread_mutex_unlock(&thrpool_lock);
	pthread_mutex_destroy(&thrpool_lock);
}
