/*
** avail.h - Data availability control functions.
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

#ifndef PIDENTD_AVAIL_H
#define PIDENTD_AVAIL_H

typedef struct
{
    int avail;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
} avail_t;

extern int avail_init(avail_t *ap);
extern int avail_wait(avail_t *ap);
extern int avail_signal(avail_t *ap);

#endif
