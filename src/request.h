/*
** request.h - Handle an IDENT protocol request
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

#ifndef PIDENTD_REQUEST_H
#define PIDENTD_REQUEST_H

#include <sys/types.h>
#include <netinet/in.h>

struct request
{
    int fd;
    struct sockaddr_gen addr;
    socklen_t addr_len;
};

extern int extensions_enabled;
extern int multiquery_enabled;
extern int request_timeout;
extern int requests_max;

extern void *request_thread(void *);
extern int request_init(void);
extern int request_run(int fd, int nofork);

#endif
