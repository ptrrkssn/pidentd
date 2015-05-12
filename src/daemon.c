/*
** daemon.c - Become a Unix daemon, and support functions.
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
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "pidentd.h"


/*
** Fork and disassociate ourself from any controlling tty.
*/
void
become_daemon(void)
{
    pid_t pid;
    int i, fd;


    pid = fork();
    if (pid < 0)
    {
	syslog(LOG_ERR, "fork() failed: %m");
	exit(EXIT_FAILURE);
    }
    else if (pid > 0)
	exit(EXIT_SUCCESS);

    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
#ifdef SIGTTSP
    signal(SIGTTSP, SIG_IGN);
#endif

#ifdef HAVE_SETSID
    setsid();
#endif

    chdir("/");
    umask(0);
    
    for (i = 0; i < 3; i++)
    {
	close(i);

	fd = s_open("/dev/null", O_RDWR);
	if (fd != i)
	{
	    dup2(fd, i);
	    close(fd);
	}
    }
}


/*
** Create a (or truncate an existing) file containing
** our process id number.
*/
void
pidfile_create(const char *path)
{
    int fd;
    char buf[64];

    
    fd = s_open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0)
    {
	syslog(LOG_ERR, "s_open(\"%s\", O_WRONLY): %m", path);
	return;
    }

    s_snprintf(buf, sizeof(buf), "%ld\n", (long) getpid());
    if (s_write(fd, buf, strlen(buf)) < 0)
	syslog(LOG_ERR, "s_write(fd, ..., %d): %m", fd, strlen(buf));
    
    s_close(fd);
}

