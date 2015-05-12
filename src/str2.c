/*
** str2.c - String to Foo conversion routines.
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
#include <ctype.h>
#include <string.h>

#include <pwd.h>

#include <grp.h>
#include <netdb.h>

#include "pidentd.h"


int
is_int(const char *p)
{
    while (isspace((unsigned char) *p))
	++p;
	   
    if (*p == '-')
	++p;

    while (isdigit((unsigned char) *p))
	++p;

    while (isspace((unsigned char) *p))
	++p;

    return (*p == '\0');
}


int
str2int(const char *buf, int *out)
{
    if (!is_int(buf))
	return -1;
    
    if (sscanf(buf, " %d ", out) != 1)
	return -1;

    return 0;
}

int
str2str(char *buf, char **out)
{
    int sep;
    char *start, *cp;

    
    while (isspace((unsigned char) *buf))
	++buf;

    switch (*buf)
    {
      case '\0':
	*out = NULL;
	return 0;

      case '\'':
      case '"':
	sep = *buf;
	start = ++buf;
	while (*buf != '\0' && *buf != sep)
	    ++buf;
	if (*buf == '\0')
	    return -1;
	*buf = '\0';
	*out = s_strdup(start);
	return 0;

      default:
	cp = buf;
	while (*cp != '\0')
	    ++cp;
	--cp;
	while (cp > buf && isspace((unsigned char) *cp))
	    --cp;
	*++cp = '\0';

	*out = s_strdup(buf);
	return 0;
    }
}


int
str2bool(const char *buf,
	 int *out)
{
    while (isspace((unsigned char) *buf))
	++buf;

    if (strcasecmp(buf, "true") == 0 ||
	strcasecmp(buf, "on") == 0 ||
	strcasecmp(buf, "enable") == 0 ||
	strcasecmp(buf, "enabled") == 0 ||
	strcasecmp(buf, "yes") == 0)
    {
	return (*out = 1);
    }
    
    if (strcasecmp(buf, "false") == 0 ||
	strcasecmp(buf, "off") == 0 ||
	strcasecmp(buf, "disable") == 0 ||
	strcasecmp(buf, "disabled") == 0 ||
	strcasecmp(buf, "no") == 0)
    {
	return (*out = 0);
    }

    return -1;
}




int
str2port(const char *str, int *out)
{
    struct servent *sp;


    if (is_int(str))
    {
	*out = atoi(str);
	return 0;
    }
    
    sp = getservbyname(str, "tcp");
    if (sp == NULL)
	return -1;


    *out = ntohs(sp->s_port);
    return 0;
}



int
str2gid(const char *str, gid_t *out)
{
    struct group *gp;

    if (is_int(str))
    {
	*out = atoi(str);
	return 0;
    }
    
    gp = getgrnam(str);
    if (gp == NULL)
	return -1;

    *out = gp->gr_gid;
    return 0;
}



int
str2uid(const char *str, uid_t *uid, gid_t *gid)
{
    struct passwd pb, *pp;
    char buf[1024];

    
    if (is_int(str))
    {
        /* FIXME: Handle overflow?  */
	*uid = atol(str);

	pp = NULL;
	(void) s_getpwuid_r(*uid, &pb, buf, sizeof(buf), &pp);
	if (pp != NULL)
	    *gid = pp->pw_gid;
	
	return 0;
    }

    pp = NULL;
    (void) s_getpwnam_r(str, &pb, buf, sizeof(buf), &pp);
    if (pp == NULL)
	return -1;

    *uid = pp->pw_uid;
    *gid = pp->pw_gid;

    return 0;
}


