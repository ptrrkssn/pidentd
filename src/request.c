/*
** request.c - Handle an IDENT protocol request
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
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "pidentd.h"

int extensions_enabled = 0;
int multiquery_enabled = 0;
int request_timeout = 120;  /* 2 minutes */

int requests_max = 0;
int requests_cur;
pthread_mutex_t requests_mtx;
pthread_cond_t requests_cv;


static int
handle_request(int fd,
	       char *buf,
	       struct sockaddr_gen *remote_addr)
{
    struct kernel *kp;
    int local_port, remote_port;
    socklen_t len;
    char *cmd, *bp;
    
    
    if (debug)
	fprintf(stderr, "handle_request: fd#%d: '%s'\n", fd, buf);

    if (sscanf(buf, " %d , %d", &local_port, &remote_port) == 2)
    {
	if (local_port < 1 || local_port > 65535 ||
	    remote_port < 1 || remote_port > 65535)
	{
	    send_error(fd,
		       local_port, remote_port,
		       "INVALID-PORT",
		       remote_addr);
	    return 0;
	}
	
	kp = kernel_alloc();
	kp->remote = *remote_addr;
	SGPORT(kp->remote) = htons(remote_port);
	
	len = sizeof(kp->local);
	if (s_getsockname(fd, (struct sockaddr *) &kp->local, &len) < 0)
	{
	    syslog(LOG_ERR, "s_getsockname(%d): %m", fd);
	    kernel_free(kp);
	    return -1;
	}
	
	SGPORT(kp->local) = htons(local_port);
	
	kernel_query(kp);

	if (debug)
	{
	    fprintf(stderr, "kernel_query, status = %d\n", kp->status);
	    if (kp->status == 1)
	    {
		if (kp->ruid != NO_UID)
		    fprintf(stderr, "\truid = %ld\n", (long) kp->ruid);
		if (kp->euid != NO_UID)
		    fprintf(stderr, "\teuid = %ld\n", (long) kp->euid);
		if (kp->pid != NO_PID)
		    fprintf(stderr, "\tpid  = %ld\n", (long) kp->pid);
		if (kp->cmd)
		    fprintf(stderr, "\tcmd  = %s\n", kp->cmd);
		if (kp->argv)
		    fprintf(stderr, "\targv = %s\n", kp->argv);
	    }
	}
	
	switch (kp->status)
	{
	  case 1:
	    send_result(fd, kp);
	    break;
	    
	  case 0:
	    send_error(fd,
		       local_port, remote_port,
		       "NO-USER",
		       remote_addr);
	    break;
	    
	  default:
	    send_error(fd,
		       local_port, remote_port,
		       "UNKNOWN-ERROR",
		       remote_addr);
	}

	kernel_free(kp);
	return 0;
    }

    if (extensions_enabled)
    {
	cmd = s_strtok_r(buf, " ", &bp);
	if (cmd == NULL)
	    goto Fail;
	
	if (strcasecmp("version", cmd) == 0)
	{
	    send_version(fd, remote_addr);
	    return 0;
	}
	
	if (strcasecmp("quit", cmd) == 0)
	    return -1;
    }
    
  Fail:
    send_error(fd, 0, 0, "UNKNOWN-ERROR", remote_addr);
    return -1;
}


static void
timeout_handler(void *arg)
{
    struct request *rp = (struct request *) arg;

    if (debug)
	fprintf(stderr, "timeout_handler(%08lx)\n", (unsigned long) arg);

    if (rp != NULL)
	shutdown(rp->fd, 2);
}



void *
request_thread(void *vp)
{
    struct request *rp = (struct request *) vp;
    struct timeout *tp = NULL;
    char buf[1024];
    size_t len;
    ssize_t got, pos;



    if (debug)
	fprintf(stderr, "request_thread: fd#%d: start\n", rp->fd);

    len = 0;
    pos = 0;
    if (request_timeout > 0)
	tp = timeout_create(request_timeout, timeout_handler, rp);

    do
    {
	if (len >= sizeof(buf)-1)
	{
	    syslog(LOG_NOTICE,
		   "request_thread: fd #%d: input buffer full: closing down",
		   rp->fd);
	    goto Exit;
	}
	
	got = s_read(rp->fd, buf+len, sizeof(buf)-len-1);
	if (got < 0)
	{
	    syslog(LOG_ERR, "request_thread: read(%d, ..., %d) failed: %m",
		   rp->fd, sizeof(buf)-len-1);
	    goto Exit;
	}

	if (got == 0)
	{
	    if (debug)
		fprintf(stderr, "s_read(%d, ...): returned 0\n", rp->fd);
	    goto Exit;
	}
	
	len += got;

	/* Locate end of request line */
	while (pos < len && !(buf[pos] == '\n' || buf[pos] == '\r'))
	    ++pos;

	if (pos < len || got == 0)
	{
	    if (got > 0 || pos > 0)
	    {
		buf[pos] = '\0';
		if (handle_request(rp->fd, buf, &rp->addr) != 0)
		    goto Exit;

		if (!multiquery_enabled)
		    goto Exit;

		if (tp)
		    timeout_reset(tp, request_timeout);

		++pos; /* Skip NUL */
	    }

	    /* Skip any additional SPC/CR/LF characters */
	    while (pos < len && isspace((unsigned char) buf[pos]))
		++pos;
	    if (pos < len)
		memcpy(buf, buf+pos, len-pos);
	    len = pos = (len-pos);
	}
    } while (got > 0);
	
  Exit:
    if (tp)
	timeout_cancel(tp);
    
    if (debug)
	fprintf(stderr, "request_thread: fd#%d: terminating\n", rp->fd);
    
    s_close(rp->fd);
    s_free(rp);

    if (requests_max > 0)
    {
	pthread_mutex_lock(&requests_mtx);
	if (requests_cur == requests_max)
	    pthread_cond_signal(&requests_cv);
	
	requests_cur--;
	pthread_mutex_unlock(&requests_mtx);
    }
    return NULL;
}




int
request_run(int fd, int nofork)
{
    struct request *rip;
    pthread_t tid;

    
    rip = s_malloc(sizeof(*rip));
    rip->fd = fd;

    rip->addr_len = sizeof(rip->addr);
    if (s_getpeername(fd, (struct sockaddr *) &rip->addr, &rip->addr_len) < 0)
    {
	syslog(LOG_ERR, "s_getpeername(%d): %m", fd);
	s_free(rip);
	close(fd);
	return EXIT_FAILURE;
    }

    if (nofork)
    {
	request_thread(rip);
	return EXIT_SUCCESS;
    }
    else
    {
	if (requests_max > 0)
	{
	    pthread_mutex_lock(&requests_mtx);
	    while (requests_cur >= requests_max)
		pthread_cond_wait(&requests_cv, &requests_mtx);
	    
	    requests_cur++;
	    pthread_mutex_unlock(&requests_mtx);
	}
	
	if (pthread_create(&tid,
			   &cattr_detached,
			   &request_thread, (void *) rip) < 0)
	{
	    syslog(LOG_ERR, "pthread_create(request_thread) failed: %m");
	    return EXIT_FAILURE;
	}
    }

    return EXIT_SUCCESS;
}


int
request_init(void)
{
    pthread_mutex_init(&requests_mtx, NULL);
    pthread_cond_init(&requests_cv, NULL);
    requests_cur = 0;
    
    return 0;
}
