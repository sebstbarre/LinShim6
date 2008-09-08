/*
 * $Id: tqueue.c 1.49 06/02/28 18:57:32+02:00 anttit@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 * 
 * Authors:
 *  Antti Tuominen <anttit@tcs.hut.fi>
 *  Ville Nuorvala <vnuorval@tcs.hut.fi>
 *
 * Copyright 2001-2005 GO-Core Project
 * Copyright 2003-2006 Helsinki University of Technology
 *
 * Modified by Sébastien Barré, May 2008
 *
 * MIPL Mobile IPv6 for Linux is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2 of
 * the License.
 *
 * MIPL Mobile IPv6 for Linux is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MIPL Mobile IPv6 for Linux; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <utils/debug.h>
#include <utils/util.h>
#include <shim6/tqueue.h>
#include "pipe.h"

LIST_HEAD(tq_list);

static volatile int killed = 0;
static pthread_mutex_t mutex;
static pthread_cond_t cond;
static pthread_t tq_runner;

static inline int is_first_task(struct tq_elem *tqe)
{
	return (tq_list.next == &tqe->list);
}

static void *runner(void *arg);

/**
 * taskqueue_init - initialize task queue
 * Initializes task queue and creates a task runner thread.
 * Returns the pipe fd that the caller is supposed to listen in order to be
 * notified of timer events, or -1 in case of error.
 **/
int taskqueue_init(void)
{
	pthread_mutexattr_t mattrs;
	pthread_mutexattr_init(&mattrs);
	pthread_mutexattr_settype(&mattrs, PTHREAD_MUTEX_FAST_NP);
	if (pthread_mutex_init(&mutex, &mattrs) ||
	    pthread_cond_init(&cond, NULL) ||
	    pthread_create(&tq_runner, NULL, runner, NULL))
		return -1;

	return 1;
}

/**
 * taskqueue_destroy - destroy task queue
 *
 * Destroys task queue and deletes all entries.  Task runner will
 * complete pending task, if taskqueue_destroy() is called mid task.
 **/
void taskqueue_destroy(void)
{
	struct list_head *l, *n;
	pthread_mutex_lock(&mutex);
	list_for_each_safe(l, n, &tq_list) {
		struct tq_elem *tqe;
		list_del(l);
		tqe = list_entry(l, struct tq_elem, list);
		tsclear(tqe->expires);
	}
	killed = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
	pthread_join(tq_runner, NULL);
}

/**
 * sorted_insert - insert queue item sorted by expiration time
 * @tqi: task queue entry to insert
 *
 * Inserts @tqi to task queue sorted by expiration time.
 **/
static inline void sorted_insert(struct tq_elem *tqi)
{
	struct list_head *l;

	list_for_each(l, &tq_list) {
		struct tq_elem *cur = list_entry(l, struct tq_elem, list);
		if (tsbefore(cur->expires, tqi->expires)) {
			list_add_tail(&tqi->list, &cur->list);
			return;
		}
	}
	list_add_tail(&tqi->list, &tq_list);
}

/*Inits a timer element */
void init_timer(struct tq_elem *tqi)
{
	tqi->list.prev=NULL;
	tqi->list.next=NULL;
	tqi->stopped=0;
	tqi->pushed=0;
}

/*Returns false if the timer is pending, else return true*/
int timer_pending(struct tq_elem *tqi)
{
	return tqi->list.next==NULL;
}

/**
 * del_task - delete task from list
 * @elem: task queue element to remove
 *
 * Deletes task queue element @elem.  Element is removed from the list
 * (not freed), and expire time is set to zero.  Returns 0 on success,
 * otherwise negative error code (If elem was not a pending timer).
 **/
int del_task(struct tq_elem *elem)
{
	int ans=0;
	ASSERT(elem != NULL);
	
	pthread_mutex_lock(&mutex);
	ans=list_del(&elem->list);
	tsclear(elem->expires);
	elem->stopped=1;
	pthread_mutex_unlock(&mutex);
	
	return ans;
}

/**
 * Looks at the state of @elem, and acts accordingly:
 * - If the timer was pending, It is removed and 0 is returned.
 * - If it was pushed on the pipe, its handler is replaced by the
 *   destroy_handler. 1 is returned.
 * - If it is neither pending nor pushed on the pipe, 0 is returned.
 *
 * Note that if 1 is returned, the caller should take appropriate action
 * to destroy itself the timer structure.
 *
 * @private is a private data field that will be set to elem->private,
 * so that it can be used by the destroy handler.
 *
 */
int del_task_and_free(struct tq_elem *elem, void (*destroy_handler)
		      (struct tq_elem *), void* private)
{
	ASSERT(elem != NULL);
	
	pthread_mutex_lock(&mutex);
	
	if (elem->pushed) {
		pthread_mutex_unlock(&mutex);	
		elem->task=destroy_handler;	       
		elem->private=private;
		return 1;
	}
	else  {
		list_del(&elem->list);
		pthread_mutex_unlock(&mutex);
		return 0;
	}
}

/**
 * add_task_abs - add new task with task to task queue
 * @expires: absolute expiry time
 * @tqi: task entry
 * @task: task to execute on expiry
 *
 * Adds @task to task queue.  Task will expire in @ms milliseconds.
 * Task @data is stored with the entry.  @tqi points to a buffer which
 * holds the actual task queue entry.
 **/
int add_task_abs(const struct timespec *expires,
		 struct tq_elem *tqi, void (*task)(struct tq_elem *))
{
	pthread_mutex_lock(&mutex);
	if (tsisset(tqi->expires)) {
		list_del(&tqi->list);
	}
	tqi->expires = *expires;
	tqi->task = task;
	tqi->thread = pthread_self();
	tqi->stopped=0;
	sorted_insert(tqi);
	if (is_first_task(tqi))
		pthread_cond_signal(&cond);

	pthread_mutex_unlock(&mutex);

	return 0;
}

/**
 * runner - run expiring tasks
 * @arg: NULL
 *
 **/
static void *runner(void *arg)
{
	pthread_dbg("thread started");
	pthread_mutex_lock(&mutex);
	for (;;) {
		struct timespec now;

		if (killed)
			break;

		if (list_empty(&tq_list))
			pthread_cond_wait(&cond, &mutex);

		clock_gettime(CLOCK_REALTIME, &now);

		while (!list_empty(&tq_list)) {
			struct tq_elem *first;
			first = list_entry(tq_list.next, struct tq_elem, list);
			if (tsbefore(first->expires, now)) {
				pthread_cond_timedwait(&cond, &mutex,
						       &first->expires);
				break;
			}
			list_del(&first->list);
			tsclear(first->expires);
			first->pushed=1;
			pthread_mutex_unlock(&mutex);
			pipe_push_event(PIPE_EVENT_TIMER,first);
			pthread_mutex_lock(&mutex);
		}		
	}
	pthread_mutex_unlock(&mutex);
	pthread_exit(NULL);
}

/*Runs the handler for the timer last expired timer*/
void timer_run_handler(void* data)
{
	struct tq_elem* first=(struct tq_elem*) data;
	
	/*if stopped is true, then del_task has been called between timer
	 * expiry and execution of this function*/
	if (first->stopped) return;
	
	first->pushed=0; /*Not in the pipe anymore*/
	
	first->task(first);
}
