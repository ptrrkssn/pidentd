/*
** pdes.h - Pidentd DES encryption stuff
**
** Copyright (c) 1997-1999 Peter Eriksson <pen@lysator.liu.se>
**
** This program is free software; you can redistribute it and/or
** modify it as you wish - as long as you don't claim that you wrote
** it.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#ifndef PIDENTD_PDES_H
#define PIDENTD_PDES_H

struct info
{
    uint32_t checksum;
    uint16_t random;
    /* FIXME: uid_t isn't necessarily short.  */
    uint16_t uid;
    uint32_t date;
    uint32_t ip_local;
    uint32_t ip_remote;
    uint16_t port_local;
    uint16_t port_remote;
};

typedef union data
{
    struct info   fields;
    uint32_t        longs[6];
    unsigned char chars[24];
} data;

struct kernel;

extern int pdes_init(char *keyfile);
extern int pdes_encrypt(struct kernel *kp, char buffer[33]);
extern int pdes_decrypt(void);
     
#endif

