/*
** timeout.c - Generic timeout code
**
** Copyright (c) 1997 Peter Eriksson <pen@lysator.liu.se>
**
** This program is free software; you can redistribute it and/or
** modify it as you wish - as long as you don't claim that you wrote
** it.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <syslog.h>

#include "pidentd.h"

#ifdef HAVE_THREADS


static struct timeout_cb
{
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    pthread_t tid;
    
    int running;

    struct timeout *top;
} tcb;



static void *
timeout_thread(void *misc)
{
    struct timeout_cb *tcb = (struct timeout_cb *) misc;
    struct timeout *tp;
    time_t now;

    
    if (debug)
	fprintf(stderr, "timeout_thread() started\n");
		
    pthread_mutex_lock(&tcb->mtx);
    while (tcb->running)
    {
	time(&now);

	tp = tcb->top;
	while (tp && now >= tp->when)
	{
	    tcb->top = tp->next;
	    pthread_mutex_unlock(&tcb->mtx);
	    
	    if (tp->fun)
		tp->fun(tp->arg);
	    
	    pthread_mutex_lock(&tcb->mtx);
	    tp = tcb->top;
	}
	
	if (tp == NULL)
	    pthread_cond_wait(&tcb->cv, &tcb->mtx);
	else
	{
	    struct timespec when;

	    when.tv_sec = tp->when;
	    when.tv_nsec = 0;
	    
	    pthread_cond_timedwait(&tcb->cv, &tcb->mtx, &when);
	}
    }

    if (debug)
	fprintf(stderr, "timeout_thread() terminating\n");
		
    return NULL;
}


int
timeout_init(void)
{
    pthread_mutex_init(&tcb.mtx, NULL);
    pthread_cond_init(&tcb.cv, NULL);

    tcb.top = NULL;
    tcb.running = 1;
    
    if (pthread_create(&tcb.tid, NULL, timeout_thread, &tcb))
    {
	syslog(LOG_ERR, "pthread_create(timeout_thread) failed: %m");
	tcb.running = 0;
	return -1;
    }

    return 0;
}


struct timeout *
timeout_create(int timeout,
	       void (*fun)(void *arg),
	       void *arg)
{
    struct timeout *tp;
    struct timeout **prev, *cur;
    

    tp = s_malloc(sizeof(*tp));

    if (debug)
	fprintf(stderr, "timeout_create(%d, ...) -> %08lx\n",
		timeout, (long) tp);
    
    tp->next = NULL;
    tp->when = time(NULL)+timeout;

    tp->fun = fun;
    tp->arg = arg;


    /*
    ** Insert the timeout into the correct slot in the time-sorted
    ** linked list
    */
    pthread_mutex_lock(&tcb.mtx);
    prev = &tcb.top;
    cur = tcb.top;
    while (cur != NULL && cur->when < tp->when)
    {
	prev = &cur->next;
	cur = cur->next;
    }
    *prev = tp;
    tp->next = cur;
    pthread_mutex_unlock(&tcb.mtx);
    pthread_cond_signal(&tcb.cv);

    return tp;
}


int
timeout_reset(struct timeout *tp,
	      int timeout)
{
    struct timeout **prev, *cur;
    
    if (debug)
	fprintf(stderr, "timeout_reset(%08lx, %d)\n", (long) tp, timeout);
    
    pthread_mutex_lock(&tcb.mtx);

    tp->when = time(NULL)+timeout;

    /* Locate it in the timeout list */
    prev = &tcb.top;
    cur = tcb.top;
    while (cur != NULL && cur != tp)
    {
	prev = &cur->next;
	cur = cur->next;
    }

    /* Remove it from the list */
    if (cur == tp)
	*prev = cur->next;
    
    /* Reinsert it at the new position */
    prev = &tcb.top;
    cur = tcb.top;
    while (cur != NULL && cur->when < tp->when)
    {
	prev = &cur->next;
	cur = cur->next;
    }
    *prev = tp;
    tp->next = cur;
    
    pthread_mutex_unlock(&tcb.mtx);
    pthread_cond_signal(&tcb.cv);
    
    return 0;
}


int
timeout_cancel(struct timeout *tp)
{
    struct timeout **prev, *cur;

    
    if (debug)
	fprintf(stderr, "timeout_cancel(%08lx)\n", (long) tp);
    
    pthread_mutex_lock(&tcb.mtx);

    prev = &tcb.top;
    cur = tcb.top;
    while (cur != NULL && cur != tp)
    {
	prev = &cur->next;
	cur = cur->next;
    }

    if (cur == tp)
    {
	*prev = cur->next;
	pthread_mutex_unlock(&tcb.mtx);
	pthread_cond_signal(&tcb.cv);
    }
    else
	pthread_mutex_unlock(&tcb.mtx);

    s_free(tp);
    return 0;
}


#else /* No threads */

#include <signal.h>

/* UGLY version */

static void (*saved_fun)(void *arg);
static void *saved_arg;

static RETSIGTYPE
sigalarm_handler(int sig)
{
    /* XXX: Shouldn't really do things like this in the signal
       handler, but... who cares :-) */
    
    (*saved_fun)(saved_arg);
}


int
timeout_init(void)
{
    signal(SIGALRM, SIG_IGN);
}


struct timeout *
timeout_create(int timeout,
	      void (*fun)(void *arg),
	      void *arg)
{
    saved_fun = fun;
    saved_arg = arg;

    if (debug)
	fprintf(stderr, "timeout_init(SIGALARM version) called\n");
    
    signal(SIGALRM, sigalarm_handler);
    alarm(timeout);
}


int
timeout_reset(struct timeout *tp,
	      int timeout)
{
    signal(SIGALRM, sigalarm_handler);
    alarm(timeout);
}


int
timeout_cancel(struct timeout *tp)
{
    alarm(0);
    signal(SIGALRM, SIG_IGN);
}

#endif

