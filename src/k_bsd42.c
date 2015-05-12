/*
** k_bsd42.c - 4.2BSD (and compatible OS) kernel access functions.
**
** Copyright (c) 1997      Peter Eriksson <pen@lysator.liu.se>
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

/* Needed for HP-UX */
#define _INCLUDE_STRUCT_FILE


#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <nlist.h>
#include <pwd.h>
#undef _POSIX_SOURCE
#include <signal.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#define SYS_SOCKET_H_INCLUDED
#include <sys/socketvar.h>

#define KERNEL

#include <sys/file.h>
#include <fcntl.h>
#include <sys/dir.h>
#include <sys/wait.h>
  
#undef KERNEL

#include <sys/user.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

#include <arpa/inet.h>

#include "pidentd.h"

#ifdef HAVE_KVM_H
#include <kvm.h>
#else
#include "pkvm.h"
#endif


struct kainfo
{
    kvm_t *kd;
    struct nlist nl[4];
};


#define N_FILE 0  
#define N_NFILE 1
#define N_TCB 2




int
ka_init(void)
{
    return 0;
}


int
ka_open(void **misc)
{
    int rcode;
    struct kainfo *kp;


    kp = s_malloc(sizeof(*kp));
    
    /*
    ** Open the kernel memory device
    */
    if ((kp->kd = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL)) == NULL)
    {
	if (debug)
		perror("kvm_open");

	syslog(LOG_ERR, "kvm_open: %m");
	s_free(kp);
	return -1;
    }

    kp->nl[0].n_name = "_file";
    kp->nl[1].n_name = "_nfile";
#ifdef HPUX7
    kp->nl[2].n_name = "_tcb_cb";
#else
    kp->nl[2].n_name = "_tcb";
#endif
    kp->nl[3].n_name = NULL;
    
    /*
    ** Extract offsets to the needed variables in the kernel
    */
    if ((rcode = kvm_nlist(kp->kd, kp->nl)) != 0)
    {
	kp->nl[0].n_name = "file";
	kp->nl[1].n_name = "nfile";
#ifdef HPUX7
	kp->nl[2].n_name = "tcb_cb";
#else
	kp->nl[2].n_name = "tcb";
#endif
	
	if ((rcode = kvm_nlist(kp->kd, kp->nl)) != 0)
	{
	    if (debug)
		fprintf(stderr, "kvm_nlist: returned %d\n", rcode);

	    syslog(LOG_ERR, "kvm_nlist, rcode = %d: %m", rcode);
	    kvm_close(kp->kd);
	    s_free(kp);
	    return -1;
	}
    }

    *misc = (void *) kp;
    return 0;
}


/*
** Get a piece of kernel memory with error handling.
** Returns 1 if call succeeded, else 0 (zero).
*/
static int
getbuf(kvm_t *kd,
       off_t addr,
       void *buf,
       size_t len,
       char *what)
{
    if (kvm_read(kd, addr, buf, len) < 0)
    {
	syslog(LOG_INFO, "getbuf: kvm_read(%08x, %lu) - %s : %m",
		   addr, (unsigned long) len, what);
	
	return 0;
    }
    
    return 1;
}



/*
** Traverse the inpcb list until a match is found.
** Returns NULL if no match.
*/
static struct socket *
getlist(kvm_t *kd,
	struct inpcb *pcbp,
	struct in_addr *faddr,
	int fport,
	struct in_addr *laddr,
	int lport)
{
    struct inpcb *head;
    int limiter = 65536;
    
    if (pcbp == NULL)
	return NULL;
    
    head = pcbp->inp_prev;
    do 
    {
	if ( pcbp->inp_faddr.s_addr == faddr->s_addr &&
	     pcbp->inp_laddr.s_addr == laddr->s_addr &&
	     pcbp->inp_fport        == fport &&
	     pcbp->inp_lport        == lport)
	    return (struct socket *) (pcbp->inp_socket);
	
	if (--limiter <= 0)	
	    break;
	
    } while (pcbp->inp_next != head &&
	     getbuf(kd,
		    (off_t) pcbp->inp_next,
		    pcbp,
		    sizeof(struct inpcb),
		    "tcblist"));
    
    return NULL;
}



/*
** Return the user number for the connection owner
*/
int
ka_lookup(void *vp, struct kernel *kp)
{
    struct in_addr *faddr;
    int fport;
    struct in_addr *laddr;
    int lport;
    
    struct kainfo *kip;
    struct inpcb tcb;
    struct file *xfile = NULL;
    off_t addr;
    int nfile;
    
    struct socket *sockp;
    int i;
    struct ucred ucb;
    
    kip = (struct kainfo *) vp;
    
    faddr = &kp->remote.sin_addr;
    laddr = &kp->local.sin_addr;
    fport = kp->remote.sin_port;
    lport = kp->local.sin_port;
    
    /* -------------------- FILE DESCRIPTOR TABLE -------------------- */
    if (!getbuf(kip->kd,
		(off_t) kip->nl[N_NFILE].n_value,
		&nfile,
		sizeof(nfile),
		"nfile"))
	goto Fail;
    
    if (!getbuf(kip->kd,
		(off_t) kip->nl[N_FILE].n_value, &addr,
		sizeof(addr), "&file"))
	goto Fail;
    
    xfile = (struct file *) s_malloc(nfile*sizeof(struct file));

    if (!getbuf(kip->kd, addr, xfile, sizeof(struct file) * nfile, "file[]"))
	goto Fail;
    
    /* -------------------- TCP PCB LIST -------------------- */
    if (!getbuf(kip->kd, (off_t) kip->nl[N_TCB].n_value, &tcb,
		sizeof(tcb), "tcb"))
	goto Fail;
    
    tcb.inp_prev = (struct inpcb *) kip->nl[N_TCB].n_value;
    sockp = getlist(kip->kd, &tcb, faddr, fport, laddr, lport);
    if (sockp == NULL)
    {
	s_free(xfile);
	return 0;
    }
    
    /*
    ** Locate the file descriptor that has the socket in question
    ** open so that we can get the 'ucred' information
    */
    for (i = 0; i < nfile; i++)
    {
	if (xfile[i].f_count == 0)
	    continue;
	
	if (xfile[i].f_type == DTYPE_SOCKET &&
	    (struct socket *) xfile[i].f_data == sockp)
	{
	    if (!getbuf(kip->kd,
			(off_t) xfile[i].f_cred, &ucb, sizeof(ucb), "ucb"))
		goto Fail;
	    
	    kp->ruid = ucb.cr_ruid;
	    kp->euid = ucb.cr_uid;
	    
	    s_free(xfile);
	    return 1;
	}
    }

  Fail:
    s_free(xfile);
    return -1;
}

