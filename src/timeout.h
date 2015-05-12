/*
** timeout.h - Generic timeout code
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

#ifndef PIDENTD_TIMEOUT_H
#define PIDENTD_TIMEOUT_H

#include <time.h>


struct timeout
{
    struct timeout *next;

    time_t when;

    void (*fun)(void *arg);
    void *arg;
};



extern int timeout_init(void);
extern struct timeout *timeout_create(int t, void (*fun)(void *arg), void *arg);
extern int timeout_reset(struct timeout *tp, int t);
extern int timeout_cancel(struct timeout *tp);

#endif
