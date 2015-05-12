/*
** hp_pthread.h - CMA Pthreads definitions for systems missing the
**		   <pthread.h> header file, but having the CMA library.
**		   (Ie: HP-UX 10.20)
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

#ifndef PIDENTD_HP_PTHREAD_H
#define PIDENTD_HP_PTHREAD_H

#include <sys/time.h>

extern int *__errno();
#define errno (*__errno())


typedef struct
{
    void *field1;
    short int field2;
    short int field3;
} cma_t_handle;

typedef cma_t_handle pthread_attr_t;
typedef cma_t_handle pthread_mutexattr_t;
typedef cma_t_handle pthread_condattr_t;

typedef cma_t_handle pthread_t;
typedef cma_t_handle pthread_mutex_t;
typedef cma_t_handle pthread_cond_t;

typedef struct
{
    int f1;
    int f2;
    int f3;
} pthread_once_t;


/*
** Global default attribute variables
*/
extern pthread_attr_t 		pthread_attr_default;
extern pthread_mutexattr_t	pthread_mutexattr_default;
extern pthread_condattr_t	pthread_condattr_default;


extern int
pthread_mutex_init(pthread_mutex_t *,
		   pthread_mutexattr_t);

extern int
pthread_mutex_lock(pthread_mutex_t *);

extern int
pthread_mutex_unlock(pthread_mutex_t *);

extern int
pthread_mutex_destroy(pthread_mutex_t *);



extern int
pthread_cond_init(pthread_cond_t *,
		  pthread_condattr_t);

extern int
pthread_cond_wait(pthread_cond_t *,
		  pthread_mutex_t *);

extern int
pthread_cond_timedwait(pthread_cond_t *,
		       pthread_mutex_t *,
		       struct timespec *);

extern int
pthread_cond_signal(pthread_cond_t *);

extern int
pthread_cond_broadcast(pthread_cond_t *);

extern int
pthread_cond_destroy(pthread_cond_t *);


extern int
pthread_create(pthread_t *,
	       pthread_attr_t,
	       void *(*)(void *),
	       void *);

extern int
pthread_once(pthread_once_t *,
	     void (*)(void));

#endif
