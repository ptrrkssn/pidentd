/*
** ibench.c - a small benchmarking/stress-testing program for IDENT servers.
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
**
**
** Please note that this program *should* be run on the same machine
** as the IDENT server you wish to test. It assumes it can connect to
** it via the loopback interface.
**
** If you specify a server address using the -rADDR option, then
** the lookups will be for the *servers* username (normally "nobody"),
** and not the username "ibench" runs as.
*/

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <signal.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <time.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>

#ifndef SYS_SOCKET_H_INCLUDED
#define SYS_SOCKET_H_INCLUDED
#include <sys/socket.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include "pidentd.h"


static struct sockaddr_in host_sin;
static char *username;
static int rev_flag = 0;
static volatile int abort_test = 0;
static int ntests = 0;
static int ignore_reply = 0;


static RETSIGTYPE
sigint_handler(int sig)
{
    abort_test = 1;
}


/*
** Perform an IDENT lookup.
** Returns: -1 in case of a network or system error
**           0 if all was OK
**           1 if the reply was malformed
**           2 if the reply was with the wrong username
*/
static int
run_test(void)
{
    int fd, buflen;
    socklen_t len;
    struct sockaddr_in our, sin;
    char buf[1024], buf2[1024];
    

    ++ntests;
    
    sin = host_sin;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
	if (errno != EINTR)
	    perror("socket");
	return -1;
    }
    
    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
	if (errno != EINTR)
	    perror("connect");
	goto Fail;
    }

    len = sizeof(our);
    if (getsockname(fd, (struct sockaddr *) &our, &len) < 0)
    {
	if (errno != EINTR)
	    perror("getsockname");
	goto Fail;
    }

#ifdef HAVE_SNPRINTF
    if (rev_flag)
	snprintf(buf, sizeof(buf),
		 "%d , %d\r\n", ntohs(sin.sin_port), ntohs(our.sin_port));
    else
	snprintf(buf, sizeof(buf),
		 "%d , %d\r\n", ntohs(our.sin_port), ntohs(sin.sin_port));
#else
    if (rev_flag)
	sprintf(buf, "%d , %d\r\n", ntohs(sin.sin_port), ntohs(our.sin_port));
    else
	sprintf(buf, "%d , %d\r\n", ntohs(our.sin_port), ntohs(sin.sin_port));
#endif
    
    if (write(fd, buf, strlen(buf)) < 0)
    {
	if (errno != EINTR)
	    perror("write");
	goto Fail;
    }

    if (shutdown(fd, 1) < 0)
    {
	if (errno != EINTR)
	    perror("shutdown");
	goto Fail;
    }
    
    buflen = read(fd, buf, sizeof(buf));
    if (buflen < 0)
    {
	if (errno != EINTR)
	    perror("read");
	goto Fail;
    }
    
    close(fd);
    
    buf[buflen] = '\0';

    buflen = sscanf(buf, " %*d , %*d : USERID : %*s :%[^\r\n]", buf2);

    if (buflen != 1)
    {
	fprintf(stderr, "Malformed reply (%d): %s\n", buflen, buf);
	return 1;
    }

    if (!ignore_reply && strcmp(buf2, username) != 0)
    {
	fprintf(stderr, "Incorrect username: %s != %s\n", buf2, username);
	return 2;
    }

    return 0;
    
  Fail:
    close(fd);
    return -1;
}

void usage(FILE *fp)
{
    fputs("Usage: ibench [-h] [-i] [-rADDR] [<seconds> [<port> [<username>]]]\n",
	  fp);
    fputs("\t-h\tDisplay this information.\n", fp);
    fputs("\t-i\tIgnore the IDENT response.\n", fp);
    fputs("\t-rADDR\tPerform a reverse lookup against a remote server.\n", fp);
}


int
main(int argc,
     char *argv[])
{
    int i, test_len, len, ecode;
    time_t start, stop;
    struct passwd *pp;
    

    memset(&host_sin, 0, sizeof(host_sin));
    host_sin.sin_family = AF_INET;
    host_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    for (i = 1; i < argc && argv[i][0] == '-'; i++)
	switch (argv[i][1])
	{
	  case 'h':
	    usage(stdout);
	    exit(EXIT_SUCCESS);

	  case 'r':
	    rev_flag = 1;
	    host_sin.sin_addr.s_addr = inet_addr(argv[1]+2);
	    username = "nobody";
	    break;

	  case 'i':
	    ignore_reply = 1;
	    break;
	    
	  default:
	    usage(stderr);
	    exit(EXIT_FAILURE);
	}
    
    if (i < argc)
	test_len = atoi(argv[i++]);
    else
	test_len = 60;

    if (i < argc)
	host_sin.sin_port = htons(atoi(argv[i++]));
    else
	host_sin.sin_port = htons(IPPORT_IDENT);

    if (i < argc)
	username = argv[i++];
    else
    {
	pp = getpwuid(getuid());
	username = pp->pw_name;
    }

    if (i < argc)
    {
	fprintf(stderr, "ibench: extranous arguments\n");
	usage(stderr);
	exit(EXIT_FAILURE);
    }
	
    time(&start);
    ntests = 0;
    ecode = 0;
    
    signal(SIGINT, sigint_handler);

    printf("Test started, will run for %d seconds (or press Ctrl-C to terminate).\n", test_len);
    
    do
    {
	if (abort_test || (ecode = run_test()))
	{
	    time(&stop);
	    break;
	}
	
	time(&stop);
    }
    while (stop - start < test_len);

    len = stop-start;
    if (len == 0)
	len = 1;

    if (ecode == 0 || (ecode == -1 && abort_test))
    {
	printf("Test OK: %d requests in %d seconds (%d requests/s)\n",
	       ntests, len, ntests/len);
	exit(EXIT_SUCCESS);
    }
    else
    {
	printf("Test FAILED after %d requests in %d seconds (%d requests/s)\n",
	       ntests, len, ntests/len);
	exit(EXIT_FAILURE);
    }
}
