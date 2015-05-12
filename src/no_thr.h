/*
** no_thr.h - "Pthreads" for systems without working threads.
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

#ifndef PIDENTD_NO_THR_H
#define PIDENTD_NO_THR_H

#include <sys/types.h>
#include <errno.h>

#ifdef _POSIX_SOURCE
#define THREAD_TYPE_DEFINED
#endif

#ifndef THREAD_TYPE_DEFINED
#define pthread_mutex_t			int
#endif

#define pthread_mutex_init(mp,ap)	(*(mp) = 0)
#define pthread_mutex_lock(mp)		(*(mp) = 1)
#define pthread_mutex_unlock(mp)	(*(mp) = 0)
#define pthread_mutex_destroy(mp)	(0)

#ifndef THREAD_TYPE_DEFINED
#define pthread_cond_t			int
#endif

#define pthread_cond_init(cp,ap)	(*(cp) = 0)
#define pthread_cond_wait(cp,mp)	(0)
#define pthread_cond_signal(cp)		(*(cp) = 1)
#define pthread_cond_broadcast(cp)	(*(cp) = 1)
#define pthread_cond_destroy(cp)	(0)

#ifndef THREAD_TYPE_DEFINED
#define pthread_attr_t			int
#endif

#define pthread_attr_init(ap)		(*(ap) = 0)

#ifndef THREAD_TYPE_DEFINED
#define pthread_t			int
#endif

#define PTHREAD_CREATE_DETACHED		1

#ifndef THREAD_TYPE_DEFINED
#define pthread_once_t			int
#endif

#define PTHREAD_ONCE_INIT		0
#define pthread_once(ov,fun)		(*(ov) && ((*(ov) = 1), (fun()), 1))

#define pthread_attr_setdetachstate(ap,state)	((*ap) = state)
     
#define pthread_create(tidp,attrp,func,arg)	((*(func))(arg), 0)
    	
#endif
