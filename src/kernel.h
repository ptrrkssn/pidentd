/*
** kernel.h - The kernel access threads
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

#ifndef PIDENTD_KERNEL_H
#define PIDENTD_KERNEL_H

#include <sys/types.h>
#ifndef SYS_SOCKET_H_INCLUDED
#define SYS_SOCKET_H_INCLUDED
#include <sys/socket.h>
#endif
#include <netinet/in.h>

struct kernel
{
    /* Request parameters */
    struct sockaddr_gen local;
    struct sockaddr_gen remote;

    /* Result parameters */
    avail_t av;
    
    int status;
    uid_t euid;
    uid_t ruid;

    pid_t pid;
    char *cmd;
    char *argv;
};

extern int kernel_threads;
extern int kernel_buffers;
extern int kernel_attempts;

extern struct kernel *kernel_alloc(void);
extern void kernel_free(struct kernel *kp);

extern int kernel_init(void);
extern void kernel_query(struct kernel *kp);


/*
** Operating system specific kernel access functions
*/
extern int ka_init(void);
extern int ka_open(void **misc);
extern int ka_lookup(void *misc, struct kernel *kp);

#endif
