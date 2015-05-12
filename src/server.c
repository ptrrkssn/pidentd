/*
** server.c - IDENT TCP/IP socket server code
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

#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

#include "pidentd.h"



int listen_sock = -1;
int listen_port = IPPORT_IDENT;
int listen_addr = INADDR_ANY;
int listen_backlog = 256;


static int
unlimit_nofile(void)
{
#ifndef RLIMIT_NOFILE
    return 64;
#else
    struct rlimit rlb;

    if (getrlimit(RLIMIT_NOFILE, &rlb) < 0)
    {
	syslog(LOG_ERR, "getrlimit() failed: %m");
	return -1;
    }

    rlb.rlim_cur = rlb.rlim_max;
    
    if (setrlimit(RLIMIT_NOFILE, &rlb) < 0)
    {
	syslog(LOG_ERR, "getrlimit() failed: %m");
	return -1;
    }

    return rlb.rlim_cur;
#endif
}


int
server_init(void)
{
    static int one = 1;
    int nofile;
    struct sockaddr_in sin;
    
    
    /*
    ** Increase the number of available file descriptors
    ** to the maximum possible.
    */
    nofile = unlimit_nofile();
    if (nofile < 0)
	return -1;


    if (listen_sock < 0)
    {
	listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sock < 0)
	{
	    syslog(LOG_ERR, "socket(AF_INET, SOCK_STREAM) failed: %m");
	    return -1;
	}

	(void) setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
		   (void *) &one, sizeof(one));
	
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(listen_addr);
	sin.sin_port = htons(listen_port);

	if (bind(listen_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
	{
	    syslog(LOG_ERR, "bind(port=%d) failed: %m",
		   listen_port);
	    return -1;
	}
    }

    /* We do this outside of the 'if' statement to support
       some broken 'inetd' daemons... */
    if (listen(listen_sock, listen_backlog) < 0)
    {
	syslog(LOG_ERR, "listen(backlog=%d) failed: %m", listen_backlog);
	return -1;
    }

    return 0;
}


int
server_run(void)
{
    int fd;
    
    while (1)
    {
	fd = s_accept(listen_sock, NULL, NULL);
	if (fd < 0)
	{
	    syslog(LOG_ERR, "accept() failed: %m");
	    
	    switch (errno)
	    {
	      case EBADF:
	      case EMFILE:
	      case ENODEV:
	      case ENOMEM:
	      case ENOTSOCK:
	      case EOPNOTSUPP:
	      case EWOULDBLOCK:
		return -1;
	    }
	}

	request_run(fd, 0);
    }
}
