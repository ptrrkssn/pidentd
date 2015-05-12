/*
** ui_thr.h - Pthreads over UI Threads sort-of-compatibility header
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

#ifndef PIDENTD_UI_THR_H
#define PIDENTD_UI_THR_H

#include <thread.h>
#include <errno.h>


#define pthread_mutex_t			mutex_t
#define pthread_mutex_init(mp,ap)	mutex_init(mp,0,NULL)
#define pthread_mutex_lock(mp)		mutex_lock(mp)
#define pthread_mutex_unlock(mp)	mutex_unlock(mp)
#define pthread_mutex_destroy(mp)	mutex_destroy(mp)

#define pthread_cond_t			cond_t
#define pthread_cond_init(mp,ap)	cond_init(mp,0,NULL)
#define pthread_cond_wait(cp,mp)	cond_wait(cp,mp)
#define pthread_cond_timedwait(cp,mp,t)	cond_timedwait(cp,mp,t)
#define pthread_cond_signal(cp)		cond_signal(cp)
#define pthread_cond_broadcast(cp)	cond_broadcast(cp)
#define pthread_cond_destroy(cp)	cond_destroy(cp)

#define pthread_attr_t			int
#define pthread_attr_init(ap)		(*(ap) = 0)

#define pthread_t			thread_t

#define PTHREAD_CREATE_DETACHED		THR_DETACHED
#define PTHREAD_CREATE_JOINABLE		0

#define pthread_attr_setdetachstate(ap,state)	((*(ap)) = state)
     
#define pthread_create(tidp,attrp,func,arg)	\
    	thr_create(NULL, 0, (func), (arg), ((attrp) ? *((int *) attrp) : 0), (tidp))

#define pthread_join(tid, statusp)	thr_join(tid, NULL, statusp)


typedef struct
{
    mutex_t lock;
    int f;
} my_pthread_once_t;
#define pthread_once_t my_pthread_once_t

#define PTHREAD_ONCE_INIT		{ DEFAULTMUTEX, 0 }

#define pthread_once(ov,fun)	\
{ \
    mutex_lock(&(ov)->lock); \
    if ((ov)->f == 0) \
    { \
	(ov)->f = 1; \
	fun(); \
    } \
    mutex_unlock(&(ov)->lock); \
}

#endif
