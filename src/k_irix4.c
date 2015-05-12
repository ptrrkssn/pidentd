/*
** k_irix4.c - IRIX 4 kernel access functions
**
**
** Copyright (c) 1997-1998   Peter Eriksson <pen@lysator.liu.se>
**    			     Christopher Kranz, Princeton University
**
** This program is free software; you can redistribute it and/or
** modify it as you wish - as long as you don't claim that you wrote
** it.
**
**
** The method for which one descends through the kernel
** process structures was borrowed from lsof 2.10 written by Victor A. Abell,
** Purdue Research Foundation.
*/

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <nlist.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>

#include "pkvm.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <sys/socketvar.h>

#include <sys/proc.h>
#include <sys/syssgi.h>

#define _KERNEL

#include <sys/file.h>

#include <sys/inode.h>

#include <fcntl.h>

#include <sys/user.h>
#include <sys/wait.h>
  
#undef _KERNEL

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <netinet/in_pcb.h>

#include <netinet/tcp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

#include <arpa/inet.h>

#include <sys/sbd.h>


#include "pidentd.h"



struct kainfo
{
    kvm_t *kd;
    struct nlist nl[5];
};

#define N_FILE 0  
#define N_V    1
#define N_TCB  2
#define N_PROC 3
 


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
    kp->kd = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
    if (kp->kd < 0)
    {
	syslog(LOG_ERR, "kvm_open: %m");
	s_free(kp);
	return -1;
    }
	
  

    kp->nl[0].n_name = "file";
    kp->nl[1].n_name = "v";
    kp->nl[2].n_name = "tcb";
    kp->nl[3].n_name = "proc";
    kp->nl[4].n_name = NULL;

    /*
    ** Extract offsets to the needed variables in the kernel
    */
    rcode = kvm_nlist(kp->kd, kp->nl);
    if (rcode != 0)
    {
	syslog(LOG_ERR, "kvm_nlist(), rcode=%d: %m", rcode);
	kvm_close(kp->kd);
	s_free(kp);
	return -1;
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
    addr = K0_TO_PHYS(addr);
    
    if (kvm_read(kd, addr, buf, len) < 0)
    {
	if (debug)
	    fprintf(stderr, "k_irix4: getbuf failed reading %s\n", what);
	
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
    
    if (pcbp == NULL)
	return NULL;
    
    head = pcbp->inp_prev;
    do 
    {
	if (pcbp->inp_faddr.s_addr == faddr->s_addr &&
	    pcbp->inp_laddr.s_addr == laddr->s_addr &&
	    pcbp->inp_fport        == fport &&
	    pcbp->inp_lport        == lport)
	    return pcbp->inp_socket;
	
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
    
    off_t addr;
    struct socket *sockp;
    int i;
    struct inode inode;
    off_t paddr;
    struct proc *pp;
    struct proc ps;
    off_t pa;
    int px;
    int nofiles;
    struct user *up;
    char *uu = NULL;
    size_t uul;
    struct file **fp;
    struct file f;
    
    struct kainfo *kip;
    struct file *xfile = NULL;
    int nfile;
    struct var v;
    struct inpcb tcb;
    

    kip = (struct kainfo *) vp;
    
    faddr = &kp->remote.sin_addr;
    laddr = &kp->local.sin_addr;
    fport = kp->remote.sin_port;
    lport = kp->local.sin_port;

    /* -------------------- FILE DESCRIPTOR TABLE -------------------- */
    if (!getbuf(kip->kd, (off_t) kip->nl[N_V].n_value,
		&v, sizeof(v), "v"))
	goto Fail;
    
    nfile = v.v_file;
    addr = kip->nl[N_FILE].n_value;
    
    xfile = (struct file *) s_malloc(nfile * sizeof(struct file));
    
    if (!getbuf(kip->kd,addr, xfile, sizeof(struct file) * nfile, "file[]"))
	goto Fail;
    
    /* -------------------- TCP PCB LIST -------------------- */
    if (!getbuf(kip->kd, (off_t) kip->nl[N_TCB].n_value,
		&tcb, sizeof(tcb), "tcb"))
	goto Fail;
    
    tcb.inp_prev = (struct inpcb *) kip->nl[N_TCB].n_value;
    sockp = getlist(kip->kd, &tcb, faddr, fport, laddr, lport);
    
    if (sockp == NULL)
    {
	s_free(xfile);
	s_free(uu);
	return 0;
    }
    
    /* -------------------- SCAN PROCESS TABLE ------------------- */
    if ((paddr = kip->nl[N_PROC].n_value) == NULL)
    {
	syslog(LOG_DEBUG, "k_getuid:  paddr == NULL");
	goto Fail;
    }
    
    paddr &= 0x7fffffff;
    
    uul = (size_t) (sizeof(struct user)
		    + (v.v_nofiles * sizeof(struct file *)));

    uu = s_malloc(uul);
    
    fp = (struct file **)(uu + sizeof(struct user));
    up = (struct user *)uu;
    
    for (pp = &ps, px = 0 ; px < v.v_proc ; px++)
    {
	pa = paddr + (off_t)(px * sizeof(struct proc));
	
	if (!getbuf(kip->kd, pa, (char *)&ps, sizeof(ps), "proc"))
	    continue;
	
	if (pp->p_stat == 0 || pp->p_stat == SZOMB)
	    continue;
	
	/* ------------------- GET U_AREA FOR PROCESS ----------------- */
	if ((i = syssgi(SGI_RDUBLK, pp->p_pid, uu, uul)) < sizeof(struct user))
	    continue;
	
	/* ------------------- SCAN FILE TABLE ------------------------ */
	if (i <= sizeof(struct user)
	    || ((long)up->u_ofile - UADDR) != sizeof(struct user))
	    nofiles = 0;
	else
	    nofiles = (i - sizeof(struct user)) / sizeof(struct file *);
	
	for (i = 0 ; i < nofiles ;i++)
	{
	    if (fp[i] == NULL)
		break;
	    
	    if (!getbuf(kip->kd, (off_t) fp[i], &f, sizeof(f), "file"))
		goto Fail;
	    
	    if (f.f_count == 0)
		continue;
	    
	    if (!getbuf(kip->kd, (off_t) f.f_inode,
			&inode, sizeof(inode), "inode"))
		goto Fail;
	    
	    if ((inode.i_ftype & IFMT) == IFCHR && soc_fsptr(&inode) == sockp)
	    {
		kp->ruid = up->u_ruid;
		kp->euid = up->u_uid;
		s_free(xfile);
		s_free(uu);
		return 1;
	    }
	} /* scan file table */
    }  /* scan process table */

  Fail:
    s_free(xfile);
    s_free(uu);
    return -1;
}

