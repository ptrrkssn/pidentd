/*
** pdes.c - Pidentd DES encryption stuff
**
** Copyright (c) 1997-1999 Peter Eriksson <pen@lysator.liu.se>
**
** Original source written by Planar 1994.02.21.
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

#ifdef HAVE_LIBDES

#include <stdio.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>

#include <sys/types.h>
#include <netinet/in.h>

#include <sys/stat.h>
#include <sys/time.h>

#ifdef HAVE_DES_H
#include <des.h>
#elif HAVE_OPENSSL_DES_H
#include <openssl/des.h>
#endif

#include "pdes.h"

#include "pidentd.h"

const static char to_asc[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



static des_key_schedule sched;



int
pdes_init(char *keyfile)
{
    char keybuf[1024+1];
    int fd, res;
    des_cblock key_bin;


    if (keyfile == NULL)
    {
	errno = EINVAL;
	return -1;
    }
    
    fd = s_open(keyfile, O_RDONLY);
    if (fd < 0)
	return -1;
    
    res = s_read(fd, keybuf, sizeof(keybuf)-1);
    if (res != sizeof(keybuf)-1)
    {
	/* Key file did not contain atleast one valid key */

	if (debug)
	    fprintf(stderr, "pdes: First key was not complete (%d bytes)\n",
		    res);
	
	s_close(fd);
	errno = EINVAL;
	return -1;
    }

    /* Locate the last key in the key file */
    while ((res = s_read(fd, keybuf, sizeof(keybuf)-1)) == sizeof(keybuf)-1)
	;
    s_close(fd);

    if (res > 0 && res != sizeof(keybuf)-1)
    {
	/* Last key was not complete */
	
	if (debug)
	    fprintf(stderr, "pdes: Last key was not complete (%d bytes)\n",
		    res);
	
	errno = EINVAL;
	return -1;
    }

    keybuf[sizeof(keybuf)-1] = '\0';
    des_string_to_key(keybuf, &key_bin);
    des_set_key(&key_bin, sched);

    return 0;
}



int
pdes_encrypt(struct kernel *kp,
	     char result[33])
{
    union data r;
    int i, j;
    time_t bt;
    

    r.fields.random = s_random();
    /* FIXME: uid_t isn't necessarily short.  */
    if (kp->ruid == NO_UID)
	r.fields.uid = htons(kp->euid);
    else
	r.fields.uid = htons(kp->ruid);

    time(&bt);
    r.fields.date = htonl(bt);
       
    r.fields.ip_local    = kp->local.sin_addr.s_addr;
    r.fields.ip_remote   = kp->remote.sin_addr.s_addr;
    r.fields.port_local  = kp->local.sin_port;
    r.fields.port_remote = kp->remote.sin_port;

    r.fields.checksum = 0;
    for (i = 1; i < 6; i++)
	r.longs[0] ^= r.longs[i];

    des_ecb_encrypt((des_cblock *)&(r.longs[0]), (des_cblock *)&(r.longs[0]),
		    sched, DES_ENCRYPT);
    
    r.longs[2] ^= r.longs[0];
    r.longs[3] ^= r.longs[1];
    
    des_ecb_encrypt((des_cblock *)&(r.longs[2]), (des_cblock *)&(r.longs[2]),
		    sched, DES_ENCRYPT);
    
    r.longs[4] ^= r.longs[2];
    r.longs[5] ^= r.longs[3];
    
    des_ecb_encrypt((des_cblock *)&(r.longs[4]), (des_cblock *)&(r.longs[4]),
		    sched, DES_ENCRYPT);

    for (i = 0, j = 0; i < 24; i+=3, j+=4)
    {
	result[j  ] = to_asc[63 & (r.chars[i  ] >> 2)];
	result[j+1] = to_asc[63 & ((r.chars[i  ] << 4) + (r.chars[i+1] >> 4))];
	result[j+2] = to_asc[63 & ((r.chars[i+1] << 2) + (r.chars[i+2] >> 6))];
	result[j+3] = to_asc[63 & (r.chars[i+2])];
    }
    result[32] = '\0';

    return 0;
}


#endif
