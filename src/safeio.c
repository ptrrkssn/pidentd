/*
** safeio.c - Signal/Async safe wrapper functions
**
** Copyright (c) 1997-1999 Peter Eriksson <pen@lysator.liu.se>
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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <math.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

#include "pidentd.h"


void
s_abort(void)
{
    int *p = (int *) NULL;

    *p = 4711;
    abort();
}



int
s_open(const char *path,
       int oflag,
       ...)
{
    int s;
    mode_t mode = 0;

    if (oflag & O_CREAT)
    {
	va_list ap;

	va_start(ap, oflag);
	/* FIXME: need to use widened form of mode_t here.  */
	mode = va_arg(ap, int);
	va_end(ap);
    }

    while ((s = open(path, oflag, mode)) < 0 && errno == EINTR)
	;
    
    if (s < 0 && (errno == EMFILE
		  || errno == ENFILE
		  || errno == ENOMEM 
#ifdef ENOSR
		  || errno == ENOSR
#endif
		  ))
    {
	/* Too many open files */
	
	syslog(LOG_WARNING, "s_open(\"%s\", 0%o): %m", path, oflag);
    }
    
    return s;
}



ssize_t
s_write(int fd,
	const char *buf,
	size_t len)
{
    ssize_t code;
    
    while ((code = write(fd, buf, len)) < 0 && errno == EINTR)
	;
    
    return code;
}



ssize_t
s_read(int fd,
       char *buf,
       size_t len)
{
    ssize_t code;
    
    while ((code = read(fd, buf, len)) < 0 && errno == EINTR)
	;
    
    return code;
}



int
s_close(int fd)
{
    int code;
    
    while ((code = close(fd)) < 0 && errno == EINTR)
	;
    
    return code;
}



/*
** A "safe" malloc, that always succeeds (or logs an
** error to syslog and the abort()'s.
**
** The buffer returned is zeroed out.
*/
void *
s_malloc(size_t size)
{
    void *p;

    p = (void *) malloc(size);
    if (p == NULL)
    {
	if (debug)
	    fprintf(stderr, "s_malloc(%lu) failed - aborting\n",
		    (unsigned long) size);
	
	syslog(LOG_ERR, "malloc(%lu): %m", (unsigned long) size);
	s_abort();
    }

    memset(p, 0, size);
    return p;
}


void
s_free(void *p)
{
    if (p != NULL)
	free(p);
}


char *
s_strdup(const char *s)
{
    char *ns;
    size_t len;
    
    
    if (s == NULL)
	return NULL;

    len = strlen(s)+1;
    ns = (char *) malloc(len);
    if (ns == NULL)
    {
	syslog(LOG_ERR, "strdup(): malloc(%lu): %m", (unsigned long) len);
	s_abort();
    }

    memcpy(ns, s, len);
    return ns;
}


int
s_accept(int fd,
	 struct sockaddr *sin,
	 socklen_t *len)
{
    int new_fd;


    while ((new_fd = accept(fd, sin, len)) < 0 && errno == EINTR)
	;

    return new_fd;
}


int
s_getsockname(int fd,
	      struct sockaddr *sin,
	      socklen_t *len)
{
    int code;


    while ((code = getsockname(fd, sin, len)) < 0 && errno == EINTR)
	;

    return code;
}


int
s_getpeername(int fd,
	      struct sockaddr *sin,
	      socklen_t *len)
{
    int code;


    while ((code = getpeername(fd, sin, len)) < 0 && errno == EINTR)
	;

    return code;
}



static pthread_mutex_t random_lock;
static pthread_once_t random_once = PTHREAD_ONCE_INIT;

static void
random_lock_init(void)
{
    unsigned int seed;
    
    pthread_mutex_init(&random_lock, NULL);
    
    seed = time(NULL);
#ifdef HAVE_SRANDOM
    srandom(seed);
#else
    srand(seed);
#endif
}


long
s_random(void)
{
    long res;
    
    pthread_once(&random_once, random_lock_init);
    
    pthread_mutex_lock(&random_lock);
#ifdef HAVE_RANDOM
    res = random();
#else
    res = rand();
#endif
    pthread_mutex_unlock(&random_lock);

    return res;
}



int
s_snprintf(char *buf,
	   size_t bufsize,
	   const char *format,
	   ...)
{
    va_list ap;
    int retcode;


    va_start(ap, format);

    if (bufsize < 1)
    {
	if (debug)
	    fprintf(stderr, "s_snprintf(..., %d, ...): illegal bufsize\n",
		    bufsize);
	syslog(LOG_ERR, "s_snprintf(..., %d, ...): illegal bufsize",
	       bufsize);
	s_abort();
    }
    
    buf[bufsize-1] = '\0';
#ifdef HAVE_VSNPRINTF
    retcode = vsnprintf(buf, bufsize, format, ap);
#else
#ifdef SPRINTF_RETVAL_POINTER
    /* XXX: The reason we check for sprintf()'s return type and not
       vsprintf() (which we should) is that SunOS 4 doesn't declare
       vsprintf() in any header files, but it does have the same return
       value as sprintf(). So expect a compiler warning here. *Sigh* */
    {
	char *cp = vsprintf(buf, format, ap);
	if (cp == NULL)
	    retcode = -1;
	else
	    retcode = strlen(cp);
    }
#else
    retcode = vsprintf(buf, format, ap);
#endif
#endif
    if (debug > 3)
	fprintf(stderr, "s_snprintf(%08lx, %d, \"%s\", ...) = %d\n",
		(unsigned long) buf, bufsize, format, retcode);
    
    if (retcode > 0 && (buf[bufsize-1] != '\0' ||
			retcode > bufsize-1))
    {
	if (debug)
	    fprintf(stderr, "s_snprintf(..., %d, ...) = %d: buffer overrun\n",
		    bufsize, retcode);
	syslog(LOG_ERR, "s_snprintf(..., %d, ...) = %d: buffer overrun\n",
	       bufsize, retcode);
	
	s_abort();
    }

    va_end(ap);

    return retcode;
}
