/*
** kernel.c - The kernel access threads
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
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pidentd.h"


int kernel_threads = 4;
int kernel_buffers = 16;
int kernel_attempts = 5;


static buffer_t kbuf_request;
static buffer_t kbuf_free;


#ifndef HAVE_THREADS
static void *ka_data = NULL;
#endif


struct kernel *
kernel_alloc(void)
{
    struct kernel *kp;
    
    kp = (struct kernel *) buffer_get(&kbuf_free);
    
    avail_init(&kp->av);
    
    kp->status = -1;
    kp->euid = NO_UID;
    kp->ruid = NO_UID;

    kp->pid = NO_PID;
    kp->cmd = NULL;
    kp->argv = NULL;
    
    return kp;
}


void
kernel_free(struct kernel *kp)
{
    s_free(kp->cmd);
    s_free(kp->argv);
    
    buffer_put(&kbuf_free, kp);
}


static void *
kernel_thread(void *vp)
{
    struct kernel *kp;
    int attempt;
    char buf1[32];

    
    if (debug)
	fprintf(stderr, "kernel_thread() started\n");

    while ((kp = (struct kernel *) buffer_get(&kbuf_request)) != NULL)
    {
	if (debug)
	{
	    fprintf(stderr, "remote = %s:%d\n",
		    s_inet_ntox(&kp->remote, buf1, sizeof(buf1)),
		    ntohs(SGPORT(kp->remote)));
	    
	    fprintf(stderr, "local = %s:%d\n",
		    s_inet_ntox(&kp->local, buf1, sizeof(buf1)),
		    ntohs(SGPORT(kp->local)));
	}

	attempt = 0;
	while (attempt++ < kernel_attempts)
	{
	    kp->status = ka_lookup(vp, kp);
	    if (debug)
		fprintf(stderr, "ka_lookup(), attempt = %d, status = %d\n",
			attempt, kp->status);
	    if (kp->status > 0)
		break;

	    if (attempt > 2 && (attempt & 1) == 1)
		sleep(1); /* Wait for kernel structures to stabilize */
	}

	avail_signal(&kp->av);
#ifndef HAVE_THREADS
	break;
#endif
    }
    
    if (debug)
	fprintf(stderr, "kernel_thread() terminating\n");

    return NULL;
}


int
kernel_init(void)
{
    int i;
    pthread_t tid;
    struct kernel *kp;
    

    /*
    ** Create the request queue
    */
    if (buffer_init(&kbuf_request, kernel_buffers) < 0)
    {
	syslog(LOG_ERR, "buffer_create(%d) failed: %m", kernel_buffers);
	return -1;
    }


    /*
    ** Create the free pool of buffers
    */
    if (buffer_init(&kbuf_free, kernel_buffers * 2) < 0)
    {
	syslog(LOG_ERR, "buffer_create(%d) failed: %m", kernel_buffers * 2);
	return -1;
    }

    for (i = 0; i < kernel_buffers * 2; i++)
    {
	kp = s_malloc(sizeof(*kp));
	buffer_put(&kbuf_free, kp);
    }


#ifdef HAVE_THREADS
    /*
    ** Create the kernel accessing thread workpool
    */
    for (i = 0; i < kernel_threads; i++)
    {
	void *key = NULL;

	if (ka_open(&key) < 0)
	    return -1;
	
	pthread_create(&tid, NULL, &kernel_thread, key);
    }
    
    return 0;
#else
    /*
    ** Open the kernel devices
    */
    return ka_open(&ka_data);
#endif
}


void
kernel_query(struct kernel *kp)
{
    buffer_put(&kbuf_request, kp);

#ifdef HAVE_THREADS
    avail_wait(&kp->av);
#else
    kernel_thread(ka_data);
#endif
}


