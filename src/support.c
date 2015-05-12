/*
** support.c - Miscellaneous support functions.
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
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pidentd.h"

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif


/*
** Get the OS name and version number
*/
char *
osinfo_get(char *buf)
{
#ifdef HAVE_UNAME
    struct utsname ub;

    if (uname(&ub) < 0)
	return NULL;
#ifndef _AIX
    sprintf(buf, "%s %s", ub.sysname, ub.release);
#else
    sprintf(buf, "%s %s.%s", ub.sysname, ub.version, ub.release);
#endif
#else
    strcpy(buf, "<unknown>");
#endif

    return buf;
}



/*
** Classify what type of socket the file descript "fd" is
*/
int
socktype(int fd)
{
    struct sockaddr_in remote_sin, local_sin;
    socklen_t len;
    int code;


    /* Try to get the local socket adress and port number */
    len = sizeof(local_sin);
    code = getsockname(fd, (struct sockaddr *) &local_sin, &len);
    if (code < 0)
    {
	if (errno == ENOTSOCK || errno == EINVAL)
	    /* Not a TCP/IP socket */
	    return SOCKTYPE_NOTSOCKET; 
	else
	    return -1;
    }

     
    /* Try to get the remote socket adress and port number */
    len = sizeof(remote_sin);
    code = getpeername(fd, (struct sockaddr *) &remote_sin, &len);
    if (code < 0)
    {
	if (errno == ENOTCONN)
	    /* Locally bound TCP socket, awaiting connections */
	    return SOCKTYPE_LISTEN; 
	else
	    return -1;
    }
    
    /* Established TCP connection */
    return SOCKTYPE_CONNECTED; 
}



/*
** A slightly safer strtok_r() function
*/
char *
s_strtok_r(char *s, const char *d, char **bp)
{
    char *cp;

    
    if (d == NULL || bp == NULL)
	return NULL;
    
    if (s == NULL)
	s = *bp;

    if (s == NULL)
	return NULL;
    
    s += strspn(s, d);
    if (*s == '\0')
	return NULL;

    cp = s;
    s = strpbrk(cp, d);
    if (s == NULL)
	*bp = strchr(cp, 0);
    else
    {
	*s++ = '\0';
	*bp = s;
    }
    
    return cp;
}




#if !defined(HAVE_GETPWNAM_R) || !defined(HAVE_GETPWUID_R)
static pthread_mutex_t pwd_lock;
static pthread_once_t pwd_once = PTHREAD_ONCE_INIT;

static void
pwd_lock_init(void)
{
    pthread_mutex_init(&pwd_lock, NULL);
}

static char *
strcopy(const char *str, char **buf, size_t *avail)
{
    char *start;
    size_t len;

    
    if (str == NULL)
	return NULL;

    len = strlen(str)+1;
    if (len > *avail)
	return NULL;

    start = *buf;
    
    memcpy(*buf, str, len);
    *avail -= len;
    *buf += len;
    
    return start;
}
#endif


int
s_getpwnam_r(const char *name,
	   struct passwd *pwd,
	   char *buffer, size_t bufsize,
	   struct passwd **result)
{
#ifdef HAVE_GETPWNAM_R
    int code;

    
    memset(pwd, 0, sizeof(*pwd));
    memset(buffer, 0, bufsize);

#ifdef HAVE_UI_GETPW /* Unix International / Solaris / UnixWare */
    
    while ((*result = getpwnam_r(name, pwd, buffer, bufsize)) == NULL &&
	   errno == EINTR)
	;

    if (*result == NULL)
	code = errno;
    else
	code = 0;
    
#elif HAVE_DCE_GETPW /* DCE/CMA */
    
    while ((code = getpwnam_r(name, pwd, buffer, bufsize)) != 0 &&
	   errno == EINTR)
	;
    if (code == 0)
	*result = pwd;
    else
	code = errno;
    
#else /* Posix version */
    
    while ((code = getpwnam_r(name, pwd, buffer, bufsize, result)) == EINTR)
	;

#endif
    
    return code;
    
#else /* No reentrant getpw*_r calls available */
    
    struct passwd *pp;

    pthread_once(&pwd_once, pwd_lock_init);
    
    pthread_mutex_lock(&pwd_lock);
    
    pp = getpwnam(name);
    if (pp == NULL)
    {
	pthread_mutex_unlock(&pwd_lock);
	*result = NULL;
	return -1;
    }

    memset(pwd, 0, sizeof(*pwd));
    
    pwd->pw_name = strcopy(pp->pw_name, &buffer, &bufsize);
    pwd->pw_passwd = strcopy(pp->pw_passwd, &buffer, &bufsize);
    pwd->pw_uid = pp->pw_uid;
    pwd->pw_gid = pp->pw_gid;
    pwd->pw_gecos = strcopy(pp->pw_gecos, &buffer, &bufsize);
    pwd->pw_dir = strcopy(pp->pw_dir, &buffer, &bufsize);
    pwd->pw_shell = strcopy(pp->pw_shell, &buffer, &bufsize);

    *result = pwd;
    
    pthread_mutex_unlock(&pwd_lock);
    return 0;
#endif
}



int
s_getpwuid_r(uid_t uid,
	     struct passwd *pwd,
	     char *buffer, size_t bufsize,
	     struct passwd **result)
{
#ifdef HAVE_GETPWUID_R
    int code;

    
    memset(pwd, 0, sizeof(*pwd));
    memset(buffer, 0, bufsize);

#ifdef HAVE_UI_GETPW /* Unix International / Solaris / UnixWare */
    
    while ((*result = getpwuid_r(uid, pwd, buffer, bufsize)) == NULL &&
	   errno == EINTR)
	;

    if (*result == NULL)
	code = errno;
    else
	code = 0;
    
#elif HAVE_DCE_GETPW /* DCE/CMA */
    
    while ((code = getpwuid_r(uid, pwd, buffer, bufsize)) != 0 &&
	   errno == EINTR)
	;
    if (code == 0)
	*result = pwd;
    else
	code = errno;
    
#else /* Posix version */
    
    while ((code = getpwuid_r(uid, pwd, buffer, bufsize, result)) == EINTR)
	;
    
#endif
    
    return code;
    
#else
    struct passwd *pp;

    pthread_once(&pwd_once, pwd_lock_init);
    pthread_mutex_lock(&pwd_lock);

    pp = getpwuid(uid);
    if (pp == NULL)
    {
	pthread_mutex_unlock(&pwd_lock);

	*result = NULL;
	return -1;
    }

    memset(pwd, 0, sizeof(*pwd));
    
    pwd->pw_name = strcopy(pp->pw_name, &buffer, &bufsize);
    pwd->pw_passwd = strcopy(pp->pw_passwd, &buffer, &bufsize);
    pwd->pw_uid = pp->pw_uid;
    pwd->pw_gid = pp->pw_gid;
    pwd->pw_gecos = strcopy(pp->pw_gecos, &buffer, &bufsize);
    pwd->pw_dir = strcopy(pp->pw_dir, &buffer, &bufsize);
    pwd->pw_shell = strcopy(pp->pw_shell, &buffer, &bufsize);

    *result = pwd;
    
    pthread_mutex_unlock(&pwd_lock);
    
    return 0;
#endif
}



int
s_strcasecmp(const char *s1, const char *s2)
{
    int i;

    while ((i = (*s1 - *s2)) == 0 && *s1)
    {
	++s1;
	++s2;
    }

    return i;
}

    

void
s_openlog(const char *ident, int logopt, int facility)
{
    openlog(ident, logopt
#ifdef LOG_DAEMON
	    , facility
#endif
	    );
}


#ifdef LOG_KERN
static struct logfacname
{
    const char *name;
    int code;
} facility[] =
{
    { "kern", 	LOG_KERN },
    { "user", 	LOG_USER },
    { "mail", 	LOG_MAIL },
    { "daemon", LOG_DAEMON },
    { "auth",	LOG_AUTH },
    { "syslog",	LOG_SYSLOG },
    { "lpr", 	LOG_LPR },
#ifdef LOG_NEWS
    { "news",   LOG_NEWS },
#endif
#ifdef LOG_UUCP
    { "uucp", 	LOG_UUCP },
#endif
#ifdef LOG_CRON
    { "cron", 	LOG_CRON },
#endif
    { "local0",	LOG_LOCAL0 },
    { "local1",	LOG_LOCAL1 },
    { "local2",	LOG_LOCAL2 },
    { "local3",	LOG_LOCAL3 },
    { "local4",	LOG_LOCAL4 },
    { "local5",	LOG_LOCAL5 },
    { "local6",	LOG_LOCAL6 },
    { "local7",	LOG_LOCAL7 },
    { NULL, -1 }
};


int
syslog_str2fac(const char *name)
{
    int i;

    if (name == NULL)
	return -1;
    
    for (i = 0; facility[i].name != NULL &&
	     s_strcasecmp(facility[i].name, name) != 0; i++)
	;

    return facility[i].code;
}

#else /* !LOG_KERN */

int
syslog_str2fac(const char *name)
{
    return 0;
}
#endif


#ifdef LOG_EMERG
static struct loglevname
{
    const char *name;
    int level;
} level[] =
{
    { "emerg", 	 LOG_EMERG },
    { "alert",   LOG_ALERT },
    { "crit",    LOG_CRIT },
    { "err",     LOG_ERR },
    { "warning", LOG_WARNING },
    { "notice",  LOG_NOTICE },
    { "info",    LOG_INFO },
    { "debug",   LOG_DEBUG },

    { NULL, -1 }
};


int
syslog_str2lev(const char *name)
{
    int i;

    if (name == NULL)
	return -1;
    
    for (i = 0; level[i].name != NULL &&
	     s_strcasecmp(level[i].name, name) != 0; i++)
	;

    return level[i].level;
}

#else /* !LOG_KERN */

int
syslog_str2fac(const char *name)
{
    return 0;
}
#endif



/*
** An MT-safe version of inet_ntoa() for IPv4/inet_ntop() for IPv6 (is safe)
*/
const char *
s_inet_ntox(struct sockaddr_gen *ia,
	    char *buf,
	    size_t bufsize)
{

#ifdef HAVE_IPV6
    return inet_ntop(SGFAM(*ia), SGADDRP(*ia), buf, bufsize);
#else
    unsigned char *bp;

    bp = (unsigned char *) SGADDRP(*ia);
    
    if (s_snprintf(buf, bufsize, "%u.%u.%u.%u", bp[0], bp[1], bp[2], bp[3]) < 0)
	return NULL;

    return buf;
#endif
}
