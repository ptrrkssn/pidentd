/*
** send.c - Format and send IDENT protocol replies.
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <syslog.h>
#include <pwd.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pidentd.h"

int uidonly_flag = 0;
int noident_flag = 0;
int result_syslog_level = -1;

char *charset = NULL;
char *opsys = "UNIX";


static int
check_noident(char *dir)
{
    char buf[2048];
    size_t len;

    
    if (dir == NULL || strlen(dir) > 1024)
	return -1;

    len = strlen(dir);
    memcpy(buf, dir, len);
    if (len > 0 && buf[len-1] != '/')
	buf[len++] = '/';
    strcpy(buf+len, ".noident");

    if (access(buf, F_OK) == 0)
	return 1;
    else
	return 0;
}


void
send_error(int fd,
	   int l_port,
	   int r_port,
	   const char *what,
	   struct sockaddr_gen *remote_addr)
{
    char buf[1024];
    char buf2[32];

    
    s_snprintf(buf, sizeof(buf),
	     "%d , %d : ERROR : %s\r\n", l_port, r_port, what);
    s_write(fd, buf, strlen(buf));

    if (result_syslog_level > -1)
	syslog(result_syslog_level,
	       "reply to %s: %d , %d : ERROR: %s",
	       s_inet_ntox(remote_addr, buf2, sizeof(buf2)),
	       l_port, r_port, what);
}


void
send_result(int fd,
	    struct kernel *kp)
{
    char buf[2048], pbuf[2048], buf2[32];
    struct passwd pwb, *pp = NULL;
    uid_t uid;


    if (debug)
	fprintf(stderr, "send_result(%d) - ruid = %ld, euid = %ld\n",
		fd, (long) kp->ruid, (long) kp->euid);
    
    if (kp->ruid == NO_UID)
	uid = kp->euid;
    else
	uid = kp->ruid;

    if (!uidonly_flag || noident_flag)
	(void) s_getpwuid_r(uid, &pwb, pbuf, sizeof(pbuf), &pp);

    if (noident_flag && pp != NULL && check_noident(pp->pw_dir) == 1)
    {
	syslog(LOG_INFO, "User %s elected to use .noident", pp->pw_name);
	
	send_error(fd,
		   ntohs(SGPORT(kp->local)),
		   ntohs(SGPORT(kp->remote)),
		   "HIDDEN-USER",
		   &kp->remote);
	return;
    }

#ifdef HAVE_LIBDES
    if (encrypt_flag)
    {
	char buffer[33];

	pdes_encrypt(kp, buffer);
	s_snprintf(buf, sizeof(buf),
		 "%d , %d : USERID : OTHER%s%s :[%s]\r\n",
		 ntohs(SGPORT(kp->local)),
		 ntohs(SGPORT(kp->remote)),
		 charset != NULL ? " , " : "",
		 charset != NULL ? charset : "",
		 buffer);
    }
    else
#endif
	
    if (!uidonly_flag && pp != NULL && strlen(pp->pw_name) < sizeof(buf)-128)
    {
	s_snprintf(buf, sizeof(buf),
		 "%d , %d : USERID : %s%s%s :%s\r\n",
		 ntohs(SGPORT(kp->local)),
		 ntohs(SGPORT(kp->remote)),
		 opsys,
		 charset != NULL ? " , " : "",
		 charset != NULL ? charset : "",
		 pp->pw_name);
    }
    else
    {
	s_snprintf(buf, sizeof(buf),
		 "%d , %d : USERID : OTHER :%ld\r\n",
		 ntohs(SGPORT(kp->local)),
		 ntohs(SGPORT(kp->remote)),
		 (long) uid);
    }
    
    s_write(fd, buf, strlen(buf));
    
    if (result_syslog_level > -1)
	syslog(result_syslog_level,
	       "reply to %s: %.*s",
	       s_inet_ntox(&kp->remote, buf2, sizeof(buf2)),
	       strlen(buf)-2, buf);
}



void
send_version(int fd,
	     struct sockaddr_gen *remote_addr)
{
    char buf[1024], buf2[32];
    
    s_snprintf(buf, sizeof(buf),
	     "0 , 0 : X-VERSION : pidentd %s for %s (%s %s)\r\n",
	     server_version,
	     osinfo_build, __DATE__, __TIME__);
    
    s_write(fd, buf, strlen(buf));
    
    if (result_syslog_level > -1)
	syslog(result_syslog_level,
	       "reply to %s: %.*s",
	       s_inet_ntox(remote_addr, buf2, sizeof(buf2)),
	       strlen(buf)-2, buf);
}
