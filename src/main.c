/*
** main.c - Main entrypoint for Pidentd 3.0
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
#include <string.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>

#include "pidentd.h"

#if defined(HAVE_LIBTHREAD) && defined(HAVE_THR_SETCONCURRENCY)
#  include <thread.h>
#endif

extern char *optarg;
extern int optind;

char *argv0 = "identd";

int debug = 0;
uid_t server_uid = NO_UID;
gid_t server_gid = ROOT_GID;
char *pidfile_path = PATH_PIDFILE;

#ifdef HAVE_LIBDES
int encrypt_flag = 0;
char *encrypt_keyfile = PATH_KEYFILE;
#endif

pthread_attr_t cattr_detached;


static void
usage(FILE *fp)
{
    fprintf(fp, "Usage: %s [options]\n", argv0);
    fputs("\n", fp);
    fputs("Options:\n", fp);
    fputs("  -d           Enable debug mode\n", fp);
    fputs("  -h           Print this information\n", fp);
    fputs("  -V           Print version and OS information\n", fp);
    fputs("\n", fp);
    fputs("  -w           Start in Inetd 'wait' mode\n", fp);
    fputs("  -i           Start in Inetd 'nowait' mode\n", fp);
    fputs("  -I           Start in Init mode\n", fp);
    fputs("  -b           Start in Standalone mode\n", fp);
    fputs("\n", fp);
    fputs("  -e           Enable protocol extensions\n", fp);
    fputs("  -m           Enable multiquery mode\n", fp);
#ifdef HAVE_LIBDES
    fputs("  -E           Enable DES encrypted replies\n", fp);
#endif
    fputs("  -n           Send uid numbers instead of usernames\n", fp);
    fputs("  -o           Return OTHER instead of UNIX\n", fp);
    fputs("  -N           Check for .noident files\n", fp);
    fputs("\n", fp);
    fputs("  -l           Log a message to syslog at startup\n", fp);
    fputs("  -t<time>     Request timeout limit in seconds\n", fp);
    fputs("  -p<port>     Port to listen for connections on\n", fp);
    fputs("  -g<group>    Group name/number to run as\n", fp);
    fputs("  -u<user>     User name/number to run as\n", fp);
    fputs("  -C<file>     Config file to include\n", fp);
    fputs("  -P<file>     Where to write the process id number\n", fp);
    fputs("  -K<threads>  Number of kernel lookup threads\n", fp);
}


static void
program_header(FILE *fp)
{
    fprintf(fp, "[Pidentd, version %s (compiled for %s) - %s %s]\n",
	    server_version, osinfo_build,
	    __DATE__, __TIME__);
}

void
drop_root_privs(void)
{
    if (geteuid() != ROOT_UID)
	return;
    
    if (server_uid == NO_UID)
    {
	if (str2uid("nobody", &server_uid, &server_gid) < 0)
	    server_uid = ROOT_UID;
    }
    
    if (setgroups(1, &server_gid) < 0)
	goto Error;
    
    if (server_gid != ROOT_GID)
	if (setgid(server_gid) < 0)
	    goto Error;
    
    if (server_uid != ROOT_UID)
	if (setuid(server_uid) < 0)
	    goto Error;

    return;
  Error:
    syslog(LOG_ERR, "Error while changing user/group privileges");
    exit(EXIT_FAILURE);
}    

int
main(int argc, char *argv[])
{
    int c;
#ifdef LOG_DAEMON
    int code = LOG_DAEMON;
#else
    int code = 0;
#endif
    int socket_type = -1;
    int init_mode = 0;
    int log_header = 0;
    

    if (argv[0] != NULL)
    {
	char *cp;
	
	cp = strrchr(argv[0], '/');
	if (cp != NULL)
	    argv0 = s_strdup(cp+1);
	else
	    argv0 = s_strdup(argv[0]);
    }
    
#ifdef SIGTTOU    
    signal(SIGTTOU, SIG_IGN);
#endif
    signal(SIGPIPE, SIG_IGN);
    
    s_openlog(argv0, LOG_PID|LOG_ODELAY, code);

    
    /*
    ** Try to autodetect how we was started.
    */
    socket_type = socktype(STDIN_FILENO);
    
    if (debug)
	fprintf(stderr, "socktype = %d\n", socket_type);

    if (socket_type == SOCKTYPE_LISTEN || socket_type == SOCKTYPE_CONNECTED)
	listen_sock = STDIN_FILENO;
    
    conf_parse(PATH_CFGFILE, 1);

    
    while ((c = getopt(argc, argv, "lNVEdhbwiIemnop:u:g:t:C:P:K:L:")) != -1)
	switch (c)
	{
#ifdef HAVE_LIBDES
	  case 'E':
	    encrypt_flag = 1;
	    break;
#endif
	    
	  case 'n':
	    uidonly_flag = 1;
	    break;
	    
	  case 'd':
	    debug++;
	    break;
	    
	  case 'h':
	    usage(stdout);
	    return EXIT_SUCCESS;
	    
	  case 'e':
	    extensions_enabled = 1;
	    break;
	    
	  case 'm':
	    multiquery_enabled = 1;
	    break;
	    
	  case 'w':
	    listen_sock = STDIN_FILENO;
	    socket_type = SOCKTYPE_LISTEN;
	    break;
	    
	  case 'i':
	    listen_sock = STDIN_FILENO;
	    socket_type = SOCKTYPE_CONNECTED;
	    break;
	    
	  case 'I':
	    listen_sock = -1;
	    socket_type = SOCKTYPE_NOTSOCKET;
	    init_mode = 1;
	    break;
	    
	  case 'b':
	    listen_sock = -1;
	    socket_type = SOCKTYPE_NOTSOCKET;
	    break;

	  case 'l':
	    log_header = 1;
	    break;
	    
	  case 'p':
	    if (str2port(optarg, &listen_port) < 0)
	    {
		syslog(LOG_ERR, "invalid argument to '-p': %s", optarg);
		if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		    fprintf(stderr, "%s: invalid argument to '-p': %s",
			    argv0, optarg);
		return EXIT_FAILURE;
	    }
	    break;

	  case 't':
	    if (str2int(optarg, &request_timeout) < 0)
	    {
		syslog(LOG_ERR, "invalid argument to '-t': %s", optarg);
		if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		    fprintf(stderr, "%s: invalid argument to '-t': %s",
			    argv0, optarg);
		return EXIT_FAILURE;
	    }
	    break;
	    
	  case 'g':
	    if (str2gid(optarg, &server_gid) < 0)
	    {
		syslog(LOG_ERR, "invalid argument to '-g': %s", optarg);
		if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		    fprintf(stderr, "%s: invalid argument to '-g': %s",
			    argv0, optarg);
		return EXIT_FAILURE;
	    }
	    break;
	    
	  case 'u':
	    if (str2uid(optarg, &server_uid, &server_gid) < 0)
	    {
		syslog(LOG_ERR, "invalid argument to '-u': %s", optarg);
		if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		    fprintf(stderr, "%s: invalid argument to '-u': %s",
			    argv0, optarg);
		return EXIT_FAILURE;
	    }
	    break;

	  case 'L':
	    code = syslog_str2fac(optarg);
	    if (code < 0)
	    {
		syslog(LOG_ERR, "invalid argument to '-L': %s", optarg);
		if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		    fprintf(stderr, "%s: invalid argument to '-L': %s",
			    argv0, optarg);
		return EXIT_FAILURE;
	    }
	    closelog();
	    s_openlog(argv0, LOG_PID|LOG_ODELAY, code);
	    break;
	    
	  case 'C':
	    if (conf_parse(optarg, 0) < 0)
	    {
		if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		    fprintf(stderr, "%s: error parsing config file: %s\n",
			    argv[0], optarg);
		return EXIT_FAILURE;
	    }
	    break;
	    
	  case 'P':
	    pidfile_path = s_strdup(optarg);
	    break;

	  case 'K':
	    if (str2int(optarg, &kernel_threads) < 0)
	    {
		syslog(LOG_ERR, "invalid argument to '-K': %s", optarg);
		if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		    fprintf(stderr, "%s: invalid argument to '-K': %s",
			    argv0, optarg);
		return EXIT_FAILURE;
	    }
	    break;

	  case 'o':
	    opsys = "OTHER";
	    break;

	  case 'N':
	    noident_flag = 1;
	    break;

	  case 'V':
	    program_header(stdout);
	    exit(EXIT_SUCCESS);
	    
	  default:
	    if (socket_type == -1 || socket_type == SOCKTYPE_NOTSOCKET)
		usage(stderr);
	    else
		syslog(LOG_ERR, "invalid command line option: %s",
		       argv[optind]);
	    
	    return EXIT_FAILURE;
	}

    if (debug)
	program_header(stderr);

    if (socket_type == -1)
    {
	syslog(LOG_ERR, "unable to autodetect socket type");
	fprintf(stderr, "%s: unable to autodetect socket type\n",
		argv0);
	return EXIT_FAILURE;
    }
    
    if (ka_init())
    {
	syslog(LOG_ERR, "OS version mismatch - compiled for %s", osinfo_build);
	if (socket_type == SOCKTYPE_NOTSOCKET)
	    fprintf(stderr,
		    "%s: OS version mismatch - compiled for: %s\n",
		    argv[0], osinfo_build);
	return EXIT_FAILURE;
    }

    
    if (!debug && 
	getppid() != INIT_PID && !init_mode &&
	socket_type != SOCKTYPE_CONNECTED &&
	listen_sock < 0)
    {
	become_daemon();
    }

#ifdef HAVE_THR_SETCONCURRENCY
#if 1
    thr_setconcurrency(kernel_threads+8);
#else
    thr_setconcurrency(sysconf(_SC_NPROCESSORS_ONLN));
#endif
#endif

    if (log_header)
	syslog(LOG_INFO, "started");
    else
	syslog(LOG_DEBUG, "started");


    pthread_attr_init(&cattr_detached);
    pthread_attr_setdetachstate(&cattr_detached, PTHREAD_CREATE_DETACHED);
    
    
    if (socket_type != SOCKTYPE_CONNECTED)
    {
	if (!debug && pidfile_path != NULL)
	    pidfile_create(pidfile_path);
	
	if (server_init() < 0)
	{
	    if (debug)
		fprintf(stderr, "%s: failed binding to the TCP/IP socket\n",
			argv[0]);
	    goto Exit;
	}
    }

#ifdef HAVE_LIBDES
    if (encrypt_flag)
    {
	if (pdes_init(encrypt_keyfile) < 0)
	{
	    syslog(LOG_ERR, "encryption could not be initalized: %m");
	    if (debug)
	    {
		fprintf(stderr, "%s: encryption could not be initialized: ",
			argv[0]);
		perror("");
	    }
	    goto Exit;
	}
    }
#endif

/* Sigh - stupid Linux handles threads like... Anyway, we'll have to
   add this kludge to work around the fact that threads in Linux can
   have different uid's... Luckily Linux doesn't need root to get at
   the needed information anyway. */
#ifdef __linux__
    drop_root_privs();
#endif
    
    if (kernel_init() < 0)
    {
	if (debug)
	    fprintf(stderr, "%s: failed opening kernel devices\n",
		    argv[0]);
	goto Exit;
    }

#ifndef __linux__
    drop_root_privs();
#endif
    
    timeout_init();
    request_init();
    
    if (socket_type != SOCKTYPE_CONNECTED)
    {
	if (debug)
	    fprintf(stderr, "entering server main loop\n");
    
	server_run();
    }
    else
	return request_run(listen_sock, 1);

  Exit:
    syslog(LOG_DEBUG, "terminating");
    return EXIT_FAILURE;
}
