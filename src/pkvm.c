/*
** pkvm.c - Partial Kernel "Virtual" Memory access function emulation.
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

#include "config.h"

#if defined(NEED_LIBKVM) && !defined(HAVE_KVM_OPEN)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <nlist.h>

#include "pidentd.h"
#include "pkvm.h"

#ifdef NLIST_NAME_UNION
#define N_NAME n_un.n_name
#else
#define N_NAME n_name
#endif


#ifndef _PATH_UNIX
#define _PATH_UNIX "/vmunix"
#endif
#ifndef _PATH_KMEM
#define _PATH_KMEM "/dev/kmem"
#endif
#ifndef _PATH_SWAP
#define _PATH_SWAP "/dev/swap"
#endif


kvm_t *
kvm_open(const char *namelist,
	 const char *corefile,
	 const char *swapfile,
	 int flag,
	 const char *errstr)
{
    kvm_t *kd;

    
    if (namelist == NULL)
	namelist = _PATH_UNIX;
    if (corefile == NULL)
	corefile = _PATH_KMEM;
    if (swapfile == NULL)
	swapfile = _PATH_SWAP;
    
    kd = s_malloc(sizeof(kvm_t));
    kd->namelist = s_strdup(namelist);
    
    if ((kd->fd = s_open(corefile, flag)) < 0)
    {
	if (errstr)
	    perror(errstr);
	s_free(kd->namelist);
	s_free(kd);
	return NULL;
    }
    
    return kd;
}


int
kvm_close(kvm_t *kd)
{
    int code;
    
    code = close(kd->fd);
    s_free(kd->namelist);
    s_free(kd);
    
    return code;
}


/*
** Extract offsets to the symbols in the 'nl' list. Returns 0 if all found,
** or else the number of variables that was not found.
*/
int
kvm_nlist(kvm_t *kd, struct nlist *nl)
{
    int code;
    int i;
    
    code = nlist(kd->namelist, nl);
    if (code != 0)
	return code;
    
    /*
    ** Verify that we got all the needed variables. Needed because some
    ** implementations of nlist() returns 0 although it didn't find all
    ** variables.
    */
    if (code == 0)
    {
	for (i = 0; nl[i].n_name != NULL && nl[i].n_name[0] != '\0'; i++)
	    if (nl[i].n_value == 0)
		code++;
    }
    
    return code;
}


/*
** Get a piece of the kernel memory
*/
ssize_t
kvm_read(kvm_t *kd,
	 off_t addr,
	 void *buf,
	 size_t len)
{
    errno = 0;
    
    if (lseek(kd->fd, addr, SEEK_SET) != addr || errno != 0)
    {
	if (debug)
	    fprintf(stderr,
		    "kvm_read(%d,%08lx,..,%lu): lseek failed (errno=%d)\n",
		    kd->fd, addr, (unsigned long) len, errno);
	return -1;
    }
    
    if (s_read(kd->fd, (char *) buf, len) != len || errno != 0)
    {
	if (debug)
	    fprintf(stderr,
		    "kvm_read(%d,%08lx,..,%lu): read failed (errno=%d)\n",
		    kd->fd, addr, (unsigned long) len, errno);
	return -1;
    }
	
    return len;
}


#else
/* Just a dummy function */
int kvm_dummy(void)
{
    return -1;
}
#endif
