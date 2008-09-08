/* $Id: tqueue.h 1.21 06/05/05 12:14:34+03:00 anttit@tcs.hut.fi $ */

#ifndef __TQUEUE_H__
#define __TQUEUE_H__ 1

#include <time.h>
#include <pthread.h>

#include <list.h>
#include <utils/util.h>

struct tq_elem {
	struct list_head list;
	struct timespec expires;       	/* expire time for task */
	pthread_t thread;		/* who queued this task */
	void (*task)(struct tq_elem *);	/* pointer to task      */
	int stopped:1,                  /* default 0, set to one by del_task*/
	    pushed:1;                   /* Currently in the pipe */
	void* private;                  /* private data to be used by the 
					   destroy handler */
};

#define tq_data(ptr, type, member) \
        container_of(ptr, type, member)


#ifdef SHIM6_SRC
/*
 * Initialize task queue.  Must be done before using anything else.
 * Returns the pipe fd that the caller is supposed to listen in order to be
 * notified of timer events, or -1 in case of error.
 */
int taskqueue_init(void);

/*
 * Remove all pending tasks and destroy queue.
 */
void taskqueue_destroy(void);

/* Add task task(tqi) to be triggered at expires */
int add_task_abs(const struct timespec *expires,
		 struct tq_elem *tqi, void (*task)(struct tq_elem *));

/* Add task to be triggered after expires_in */
static inline int add_task_rel(const struct timespec *expires_in,
			       struct tq_elem *tqi,
			       void (*task)(struct tq_elem *))
{
       struct timespec expire;

       clock_gettime(CLOCK_REALTIME, &expire);
       tsadd(expire, *expires_in, expire);

       return add_task_abs(&expire, tqi, task);
}

/* Delete task from list */
int del_task(struct tq_elem *tqi);

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
		      (struct tq_elem *), void* private);


/*Init a new timer*/
void init_timer(struct tq_elem *tqi);

int timer_pending(struct tq_elem *tqi);

/*Runs the handler for the timer last expired timer*/
void timer_run_handler(void* data);

#endif /*SHIM6_SRC*/
	
#endif /* __TQUEUE_H__ */
