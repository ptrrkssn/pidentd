/*
** k_osf5.c - Compaq Tru64 UNIX 5.x kernel access functions
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
 * 31 Jan 2001 - Modified 4.0 version to support 5.x.  by Bob Kras 
 *		added support for ufile_entry and simplified large
 *		fd support (since all v5 have large fd's) 
 *		Cleaned up ifdef's, used ipv6 pcb.
 *		<robert.kras@compaq.com>
 *
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
#include <netinet/in6.h>
#include <netinet/in_pcb.h>

#include "pkvm.h"

#include "pidentd.h"


/* The following is in <sys/proc.h>, but only if _KERNEL is defined */
#define	PID_INVALID(pid) ((pid_t)(pid) < 0)

/* The following is in <sys/ucred.h>, but only if _KERNEL is defined */
#define	INVALID_UID(uid) ((uid_t)(uid) < 0 || (uid_t)(uid) > (uid_t)UID_MAX)


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
    struct file open_file;
    int index, index1;

    struct ufile_entry * uofp[NEW_OPEN_MAX_SYSTEM/U_FE_OF_ALLOC_SIZE];
    
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
    
    if (debug)
    {
	fprintf (stderr, "Looking up faddr %s  fport %d\n",
		 inet_ntoa(faddr->s_addr),ntohs(fport));
	fprintf (stderr, "           laddr %08x  lport %d\n",
		 inet_ntoa(laddr->s_addr),ntohs(lport));
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
	syslog(LOG_INFO, "Cannot read pid table structure");
	goto Fail;
    }
    
    /* Iterate through pids */
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
	
	if (debug > 2)
	    fprintf (stderr, "Looking at proc slot %d: PID %d, UID %d\n", index,
		    the_proc.p_pid, the_proc.p_ruid);

	/* Sanity checks */
	if (f_s.uf_lastfile < 0)
	    continue;

	if (f_s.uf_lastfile + 1 > NEW_OPEN_MAX_SYSTEM)
	    continue;

	/* If we are using an extender, lets go get it. */
	if (f_s.uf_lastfile >= NOFILE_IN_U)
	{
	    if (f_s.uf_of_count > NEW_OPEN_MAX_SYSTEM)
		continue;
	    
	    if (f_s.uf_of_entry==NULL)
		continue;

	    if(badr(kd, (off_t) f_s.uf_of_entry, uofp, sizeof(uofp)))
		continue;
	}

	/* Iterate through each file in the process. */
	for (index1 = 0; index1 <= f_s.uf_lastfile; index1++)
	{
		struct ufile_entry	open_ufile;
		struct ufile_entry *ufep;

	    if (index1 < NOFILE_IN_U)
	    {
		/* ufile_entry is in the u */
		if ( f_s.uf_entry[(index1)/U_FE_ALLOC_SIZE] )
			ufep = f_s.uf_entry[(index1)/U_FE_ALLOC_SIZE] + 
					(index1%U_FE_ALLOC_SIZE);
		else ufep = NULL;
	    }
	    else {
		/* ufile_entry is in the extender */
		ufep=uofp[(index1-NOFILE_IN_U)/U_FE_OF_ALLOC_SIZE];
		if (ufep) ufep +=((index1-NOFILE_IN_U) % U_FE_OF_ALLOC_SIZE);
		else {
			continue;
		}
	    }

	if (ufep==NULL) 
		continue;
		
	/* now read the ufile_entry */
	if (badr (kd, (off_t) ufep,
			 &open_ufile, sizeof(open_ufile)))
		    continue;

	if (open_ufile.ufe_ofile == NULL)
			continue;

	if (open_ufile.ufe_ofile == (struct file *) -1)
			continue;

	/* next, read the struct file */
        if (badr(kd, (off_t) open_ufile.ufe_ofile,
			 &open_file, sizeof(open_file)))
	        continue;
	    
	/* If we have a socket, lets go check if this is the one. */
        if (open_file.f_type == DTYPE_SOCKET)
	{
		struct socket try_socket;
		struct inpcb try_pcb;
		
		if (badr(kd, (off_t) open_file.f_data,
			 &try_socket, sizeof(try_socket)))
		    continue;
		
		if (try_socket.so_pcb != NULL)
		{
		    /* Read the PCB */
		    if (badr(kd, (off_t) try_socket.so_pcb,
			     &try_pcb, sizeof(try_pcb)))
			continue;
		    if (debug > 2) 
			fprintf (stderr, "\tSocket: %s:%d - %s:%d\n",
				 inet_ntoa(try_pcb.inp_faddr.s6_laddr[3]),
				 ntohs(try_pcb.inp_fport),
				inet_ntoa( try_pcb.inp_laddr.s6_laddr[3]),
				 ntohs(try_pcb.inp_lport));
			    
	    /* Finally, check if is this the one? */
	    if (try_pcb.inp_faddr.s6_laddr[3] == faddr->s_addr &&
			try_pcb.inp_laddr.s6_laddr[3] == laddr->s_addr &&
				try_pcb.inp_fport        == fport &&
				try_pcb.inp_lport        == lport)
			    {
				kp->ruid = the_proc.p_ruid;
				kp->euid = the_proc.p_svuid;
				kp->pid  = the_proc.p_pid;
				
				s_free(the_pid_entry);
				return 1;
			    }
			}
		    }
		}
         }
	    
	    s_free(the_pid_entry);
	    return 0;
	    
	  Fail:
	    s_free(the_pid_entry);
	    return -1;
}
