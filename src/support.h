/*
** support.h - Miscellaneous support functions.
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

#ifndef PIDENTD_SUPPORT_H
#define PIDENTD_SUPPORT_H

extern char osinfo_build[];
extern char *osinfo_get(char *buf);


#define SOCKTYPE_NOTSOCKET 0
#define SOCKTYPE_LISTEN    1
#define SOCKTYPE_CONNECTED 2

extern int socktype(int fd);

extern char *s_strtok_r(char *b, const char *s, char **bp);

extern int s_strcasecmp(const char *s1, const char *s2);

struct passwd;
extern int s_getpwnam_r(const char *name,
			struct passwd *pwd,
			char *buffer, size_t bufsize,
			struct passwd **result);

extern int s_getpwuid_r(uid_t uid,
			struct passwd *pwd,
			char *buffer, size_t bufsize,
			struct passwd **result);

extern void s_openlog(const char *ident, int logopt, int facility);

extern int syslog_str2fac(const char *name);
extern int syslog_str2lev(const char *name);

extern const char *s_inet_ntox(struct sockaddr_gen *ia, char *buf,
	size_t bufsize);

#endif
