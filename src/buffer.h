/*
** buffer.h - FIFO buffer management routines.
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

#ifndef PIDENTD_BUFFER_H
#define PIDENTD_BUFFER_H

typedef struct
{
    void **buf;
    int bsize;
    int occupied;
    int nextin;
    int nextout;
    pthread_mutex_t mtx;
    pthread_cond_t more;
    pthread_cond_t less;
} buffer_t;


extern int buffer_init(buffer_t *bp, int bsize);
extern void buffer_destroy(buffer_t *bp);

extern void buffer_put(buffer_t *bp, void *item);
extern void *buffer_get(buffer_t *bp);

#endif
    
