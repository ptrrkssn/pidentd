/*
** cma_thr.h - Pthreads over DCE/CMA Threads sort-of-compatibility header
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

#ifndef PIDENTD_CMA_THR_H
#define PIDENTD_CMA_THR_H

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#else
#include "hp_pthread.h"
#endif

#include <errno.h>

#define pthread_mutex_init(mp,ap)	\
	pthread_mutex_init((mp), ((ap) ? *((pthread_mutexattr_t *) (ap)) : pthread_mutexattr_default))

#if 0
#define pthread_mutex_lock(mp)		pthread_mutex_lock(mp)
#define pthread_mutex_unlock(mp)	pthread_mutex_unlock(mp)
#define pthread_mutex_destroy(mp)	pthread_mutex_destroy(mp)
#endif
     
#define pthread_cond_init(cp,ap)	\
	pthread_cond_init((cp), ((ap) ? *((pthread_condattr_t *) (ap)) : pthread_condattr_default))


#define pthread_cond_wait(cp,mp)	\
     (pthread_cond_wait(cp,mp) ? errno : 0)

#define pthread_cond_timedwait(cp,mp,to)	\
     (pthread_cond_timedwait(cp,mp,to) ? errno : 0)
     
#if 0
#define pthread_cond_signal(cp)		pthread_cond_signal(cp)
#define pthread_cond_destroy(cp)	pthread_cond_destroy(cp)
#endif

#define pthread_attr_t			int
#define pthread_attr_init(ap)		(*(ap) = 0)

#define PTHREAD_CREATE_DETACHED		1
#define PTHREAD_CREATE_JOINABLE		0

#define PTHREAD_ONCE_INIT 		{ 0 }
     
#define pthread_attr_setdetachstate(ap,state)	((*(ap)) = state)
     
#define pthread_create(tidp,attrp,func,arg)	\
    	(pthread_create((tidp), pthread_attr_default, (func), (arg)), \
	 (((attrp) && *((int *) attrp)) ? pthread_detach((tidp)) : 0))


#endif
