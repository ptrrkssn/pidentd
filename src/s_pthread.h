/*
** s_pthread.h - Pthread emulation header file
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

#ifndef S_PTHREAD_H
#define S_PTHREAD_H

#include "config.h"


#ifdef HAVE_LIBPTHREAD
#  include <pthread.h>

#elif HAVE_LIBPTHREADS
/* IBM AIX almost-pthreads */
#  include <pthread.h>
#  ifndef PTHREAD_CREATE_JOINABLE
#    define PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED
#  endif

#elif HAVE_LIBTHREAD
#  include "ui_thr.h"

#elif HAVE_LIBCMA
#  include "cma_thr.h"

#else
#  include "no_thr.h"
#endif

#endif
