/*
** server.h - IDENT TCP/IP socket server code
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

#ifndef PIDENTD_SERVER_H
#define PIDENTD_SERVER_H

extern int listen_sock;
extern int listen_port;
extern int listen_addr;
extern int listen_backlog;


extern int server_init(void);
extern int server_run(void);

#endif
