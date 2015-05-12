/*
** buffer.c - FIFO buffer management routines.
**
** Copyright (c) 1997-1998 Peter Eriksson <pen@lysator.liu.se>
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

#include <stdlib.h>

#include "pidentd.h"



int
buffer_init(buffer_t *bp, int bsize)
{
    bp->buf = s_malloc(sizeof(void *) * bsize);

    bp->bsize = bsize;
    bp->occupied = 0;
    bp->nextin = 0;
    bp->nextout = 0;

    pthread_mutex_init(&bp->mtx, NULL);
    pthread_cond_init(&bp->more, NULL);
    pthread_cond_init(&bp->less, NULL);

    return 0;
}



void
buffer_put(buffer_t *bp, void *item)
{
    pthread_mutex_lock(&bp->mtx);

    while (bp->occupied >= bp->bsize)
	pthread_cond_wait(&bp->less, &bp->mtx);

    bp->buf[bp->nextin++] = item;

    bp->nextin %= bp->bsize;
    bp->occupied++;

    pthread_mutex_unlock(&bp->mtx);
    pthread_cond_signal(&bp->more);
}



void *
buffer_get(buffer_t *bp)
{
    void *item;

    pthread_mutex_lock(&bp->mtx);
    while (bp->occupied <= 0)
	pthread_cond_wait(&bp->more, &bp->mtx);

    item = bp->buf[bp->nextout++];
    bp->nextout %= bp->bsize;
    bp->occupied--;

    pthread_mutex_unlock(&bp->mtx);
    pthread_cond_signal(&bp->less);

    return item;
}



void
buffer_destroy(buffer_t *bp)
{
    pthread_mutex_destroy(&bp->mtx);
    pthread_cond_destroy(&bp->more);
    pthread_cond_destroy(&bp->less);
    s_free(bp->buf);
}
    
