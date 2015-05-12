/*
** send.h - Format and send IDENT protocol replies.
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

#ifndef PIDENTD_SEND_H
#define PIDENTD_SEND_H

extern int uidonly_flag;
extern int noident_flag;
extern char *charset;
extern char *opsys;
extern int result_syslog_level;

extern void send_error(int fd,
		       int fport,
		       int lport,
		       const char *what,
		       struct sockaddr_gen *remote);

extern void send_result(int fd,
			struct kernel *kp);

extern void send_version(int fd,
			 struct sockaddr_gen *remote);

#endif
