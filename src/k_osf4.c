/*
** k_osf4.c - Digital Unix / OSF/1 4.0 kernel access functions
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

/*
 * 16 Apr 96 - Changes by Paul Szabo <psz@maths.usyd.edu.au>
 *
 * May 23, 1994 - Modified by Allan E. Johannesen (aej@wpi.edu) from code
 * kindly provided by Digital during the Beta test of Digital Alpha AXP OSF/1
 * 3.0 when WPI discovered that the file structures had changed.  Prior to 3.0,
 * OSF/1 ident support had only needed 64-bit modifications to the `other.c'
 * kernel routine (those mods done at WPI during the initial OSF/1 Beta tests).
 *
 * NOTE:
 *   This tool is NOT part of DEC OSF/1 and is NOT a supported product.
 *
 * BASED ON code provided by
 *   Aju John, UEG, Digital Equipment Corp. (ZK3) Nashua, NH.
 *
 * The following is an **unsupported** tool. Digital Equipment Corporation
 * makes no representations about the suitability of the software described
 * herein for any purpose. It is provided "as is" without express or implied
 * warranty.
 *
 * BASED ON:
 *  PADS program by Stephen Carpenter, UK UNIX Support, Digital Equipment Corp.
 * */

/*
 * Multiple, almost simultaneous identd requests were causing a
 * 'kernel panic' crash on our 2-CPU 2100 server running OSF 3.2C
 * (though no such problems were seen on Alphastations). We were
 * initially told to try patch 158. When that did not cure the
 * problem, Digital service came up with the following on 9 May 96:
 *
 * > The following came from an outage in the states about the same thing.
 * > 
 * > The active program was "identd" which is a freeware
 * > program that identifies the user who is opening a port on the system.
 * > 
 * > Careful analysis shows that the identd program is causing the crash by
 * > seeking to an invalid address in /dev/kmem. The program, identd reads
 * > through /dev/kmem looking for open files that are sockets, which then send
 * > pertainent information back to the other end. In this case, the socket has
 * > gone away before the read has been performed thereby causing a panic.
 * > 
 * > identd reading /dev/kmem, causing a fault on the  kernel stack guard pages
 * > which in turn cause the kernel to panic. To fix  this problem, set the
 * > following in /etc/sysconfigtab:
 * > 
 * > vm:
 * >         kernel-stack-guard-pages = 0
 * > 
 * > could you try this and see if that fixes your problem.
 *
 * This has fixed our problem, though I am worried what other
 * effects this may have.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <nlist.h>
#include <sys/types.h>
#define SHOW_UTT
#include <sys/user.h>
#define KERNEL_FILE
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>

#include "pkvm.h"

#include "pidentd.h"


/* The following is in <sys/proc.h>, but only if _KERNEL is defined */
struct pid_entry {
    pid_t   pe_pid;                /* process id */
    int     pe_generation;         /* checks for struct re-use */
    struct proc *pe_proc;          /* pointer to this pid's proc */
    union {
	struct pid_entry *peu_nxt;     /* next entry in free list */
	struct {
	    int     peus_pgrp;     /* pid is pgrp leader? */
	    int     peus_sess;     /* pid is session leader? */
	} peu_s;
    } pe_un;
};

/* The following is in <sys/proc.h>, but only if _KERNEL is defined */
#define	PID_INVALID(pid) ((pid_t)(pid) < 0 || (pid_t)(pid) > (pid_t)PID_MAX)

/* The following is in <sys/ucred.h>, but only if _KERNEL is defined */
#define	INVALID_UID(uid) ((uid_t)(uid) < 0 || (uid_t)(uid) > (uid_t)UID_MAX)


#ifdef NOFILE_IN_U		/* more than 64 open files per process ? */
#  define OFILE_EXTEND
#else
#  define NOFILE_IN_U NOFILE
#endif

#define BUFLEN 1024 /* buffer length */

#define N_PIDTAB 0
#define N_NPID 1


struct kainfo
{
    kvm_t *kd;
    struct nlist nl[3];
};

int
ka_init(void)
{
    char osinfo_current[256];

    if (osinfo_get(osinfo_current) == NULL)
	return -1;

    return strcmp(osinfo_build, osinfo_current);
}


/*
** Open kernel devices, lookup kernel symbols etc...
*/
int
ka_open(void **misc)
{
    struct kainfo *kp;


    kp = s_malloc(sizeof(*kp));
    
    /*
    ** Open the kernel memory device
    */
    if ((kp->kd = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL)) == NULL)
    {
	syslog(LOG_ERR, "kvm_open: %m");
	s_free(kp);
	return -1;
    }
    
    kp->nl[0].n_name = "_pidtab";
    kp->nl[1].n_name = "_npid";
    kp->nl[2].n_name = NULL;
    
    /*
    ** Extract offsets to the needed variables in the kernel
    */
    if (kvm_nlist(kp->kd, kp->nl) != 0)
    {
	syslog(LOG_ERR, "kvm_nlist: %m");
	kvm_close(kp->kd);
	s_free(kp);
	return -1;
    }

    *misc = (void *) kp;
    return 0;
}


/*
** Return the user number for the connection owner
*/
int
ka_lookup(void *vp, struct kernel *kp)
{
    struct kainfo *kip;
    kvm_t *kd;
    struct nlist *name_list;
    
    struct in_addr *faddr;
    int fport;
    struct in_addr *laddr;
    int lport;

    off_t pidtab_base;	/* Start address of the process table */
    int npid;		/* Number of processes in the process table */
    
    struct proc_plus_utask {
	struct proc The_Proc;
	struct utask Proc_Utask;
    } pu;
    
    struct pid_entry *the_pid_entry = NULL;
    struct file **ofile_table_extension = NULL, open_file;
    int index, index1;
    
#define the_proc pu.The_Proc
#define proc_utask pu.Proc_Utask
#define p_i the_pid_entry[index]
#define f_s proc_utask.uu_file_state


/* Just to save us some typing: we ALWAYS test return from kvm_read */
#define goodr(k,addr,buf,len) (kvm_read(k,addr,buf,len) == len)
#define badr(k,addr,buf,len)  (kvm_read(k,addr,buf,len) != len)

    kip = (struct kainfo *) vp;
    kd = kip->kd;
    name_list = kip->nl;
    
    faddr = &kp->remote.sin_addr;
    laddr = &kp->local.sin_addr;
    fport = kp->remote.sin_port;
    lport = kp->local.sin_port;
    
#ifdef OFILE_EXTEND
    /* Reserve space for the extended open file table of a process */
    ofile_table_extension = s_malloc((getdtablesize ())
				     * sizeof(struct file *));
#endif

    if (debug)
    {
	fprintf (stderr, "Looking up faddr %08x  fport %d\n",
		 faddr->s_addr, fport);
	fprintf (stderr, "           laddr %08x  lport %d\n",
		 laddr->s_addr, lport);
    }
    
    /* Find the start of the process table */
    if (badr(kd, (off_t) name_list[N_PIDTAB].n_value,
	     &pidtab_base, sizeof(pidtab_base)))
    {
	syslog(LOG_INFO, "Cannot read pidtab_base");
	goto Fail;
    }
    
    /* Find the size of the process table */
    if (badr(kd, (off_t) name_list[N_NPID].n_value, &npid, sizeof(npid)))
    {
	syslog(LOG_INFO, "Cannot read npid");
	goto Fail;
    }
    
    if (debug)
	fprintf (stderr, "Number of processes: %d\n", npid);
    
    /* Read in the process structure */
    the_pid_entry = s_malloc(sizeof(struct pid_entry) * npid);
    
    if (badr(kd, pidtab_base, the_pid_entry, sizeof(struct pid_entry) * npid))
    {
	syslog(LOG_INFO, "Cannot read process structure");
	goto Fail;
    }
    
    for (index = 0; index < npid; index++)
    {
	if (p_i.pe_proc == 0)
	    continue;

	if (PID_INVALID(p_i.pe_pid))
	    continue;
	    
	/* Read in the proc and utask structs of the process */
	if (badr(kd, (off_t) p_i.pe_proc, &pu, sizeof(pu)))
	    continue;

	if (p_i.pe_pid != the_proc.p_pid)
	    continue;

	if (INVALID_UID(the_proc.p_ruid))
	    continue;
	
	if (debug > 1)
	    fprintf (stderr, "Looking at proc slot %d: PID %d, UID %d\n", index,
		    the_proc.p_pid, the_proc.p_ruid);
	
	/* Sanity checks */
	if (f_s.uf_lastfile < 0)
	    continue;

	if (f_s.uf_lastfile + 1 > getdtablesize())
	    continue;
	
#ifdef OFILE_EXTEND
	if (f_s.uf_lastfile >= NOFILE_IN_U)
	{
	    if (f_s.uf_of_count > getdtablesize())
		continue;
	    
	    if (badr(kd, (off_t) f_s.uf_ofile_of, ofile_table_extension,
		     f_s.uf_of_count * sizeof(struct file *)))
		continue;
	}
#endif

	if (debug > 1)
	    fprintf (stderr, "proc slot %d uses %d files\n", index, f_s.uf_lastfile);

	
	for (index1 = 0; index1 <= f_s.uf_lastfile; index1++)
	{
	    if (index1 < NOFILE_IN_U)
	    {
		if (f_s.uf_ofile[index1] == NULL)
		    continue;
		if (f_s.uf_ofile[index1] == (struct file *) -1)
		    continue;
		
		if (badr(kd, (off_t) f_s.uf_ofile[index1],
			 &open_file, sizeof(open_file)))
		    continue;
	    }
#ifdef OFILE_EXTEND
	    else
	    {
		if (ofile_table_extension[index1-NOFILE_IN_U] == NULL)
		    continue;

		if (badr(kd,
			 (off_t) ofile_table_extension[index1-NOFILE_IN_U],
			 &open_file, sizeof(open_file)))
		    continue;
	    }
#endif
	    
	    if (debug > 2)
		fprintf (stderr, "Looking at proc slot %d, file %d\n", index, index1);
	    
	    if (open_file.f_type == DTYPE_SOCKET)
	    {
		struct socket try_socket;
		struct inpcb try_pcb;
		
		if (badr(kd, (off_t) open_file.f_data,
			 &try_socket, sizeof(try_socket)))
		    continue;
		
		if (try_socket.so_pcb != NULL)
		{
		    if (badr(kd, (off_t) try_socket.so_pcb,
			     &try_pcb, sizeof(try_pcb)))
			continue;

		    if (debug > 2)
			fprintf (stderr, "\tSocket: %x:%d - %x:%d\n",
				 try_pcb.inp_faddr.s_addr,
				 try_pcb.inp_fport,
				 try_pcb.inp_laddr.s_addr,
				 try_pcb.inp_lport);
		    
		    if (try_pcb.inp_faddr.s_addr == faddr->s_addr &&
			try_pcb.inp_laddr.s_addr == laddr->s_addr &&
			try_pcb.inp_fport        == fport &&
			try_pcb.inp_lport        == lport)
		    {
			kp->ruid = the_proc.p_ruid;
			kp->euid = the_proc.p_svuid;
			kp->pid  = the_proc.p_pid;
			
			s_free(ofile_table_extension);
			s_free(the_pid_entry);
			return 1;
		    }
		}
	    }
	}
    }
    
    s_free(ofile_table_extension);
    s_free(the_pid_entry);
    return 0;
    
  Fail:
    s_free(ofile_table_extension);
    s_free(the_pid_entry);
    return -1;
}
