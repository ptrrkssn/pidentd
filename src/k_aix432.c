/*
** k_aix432.c - IBM AIX 4.3.2 kernel access functions.
**	
** Modified for AIX 4.3.2 system by Wendy Lin, PUCC, Jul. 1999,
**	based on k_aix42.c.  The 4.3.2. specific getprocs() calls
**	are modelled after PBS and lsof.
**
** Copyright (c) 1997   Peter Eriksson <pen@lysator.liu.se>
**		 1994	Harlan Stenn <harlan@pfcs.com>
**		 1992	Charles M. Hannum
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

#include <sys/types.h>

#if defined(__GNUC__)

typedef	long long	aligned_off64_t __attribute__ ((aligned (8)));
typedef	long long	aligned_offset_t  __attribute__ ((aligned (8)));
#define	off64_t		aligned_off64_t
#define	offset_t	aligned_offset_t

#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <syslog.h>

#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <net/route.h>
#include <netinet/in.h>
 
#include <netinet/ip.h>
 
#include <netinet/in_pcb.h>
#include <arpa/inet.h>

#define _KERNEL 1
#include <sys/file.h>
#undef  _KERNEL
#include <procinfo.h>
 
#include "pidentd.h"

struct kainfo
{
    int kd;
};


int
ka_init(void)
{
    return 0;
}


int
ka_open(void **misc)
{
    struct kainfo *kp;


    kp = s_malloc(sizeof(*kp));
    
    if ((kp->kd = open("/dev/kmem", O_RDONLY)) == -1)
    {
	syslog(LOG_ERR, "open(\"/dev/kmem\"): %m");
	s_free(kp);
	return -1;
    }

    *misc = (void *) kp;
    return 0;
}


static int
kread (int kmem,
       off_t addr,
       char *buf,
       int len)
{
    int br;
    
    if (lseek (kmem, addr, SEEK_SET) == (off_t) -1)
	return (-1);
    
    br = read(kmem, buf, len);
    
    return ((br == len) ? 0 : 1);
}



int
ka_lookup(void *vp, struct kernel *kp)
{
    int inc_procs = 256,
	num_procs = 0, num, fd;
    pid_t  pid;
    struct procsinfo *procsinfo = NULL, *pp;
    struct fdsinfo *fdsinfo = NULL;
    struct file *filep, file;
    struct socket *socketp, socket;
    struct protosw *protoswp, protosw;
    struct domain *domainp, domain;
    struct inpcb *inpcbp, inpcb;
    
    struct in_addr *faddr;
    int fport;
    struct in_addr *laddr;
    int lport;
    
    struct kainfo *kip;
    
    kip = (struct kainfo *) vp;
    
    faddr = &kp->remote.sin_addr;
    laddr = &kp->local.sin_addr;
    fport = kp->remote.sin_port;
    lport = kp->local.sin_port;


    procsinfo = (struct procsinfo *)
		s_malloc ((size_t) (inc_procs * sizeof (struct procsinfo)));
    pp = procsinfo;
    num_procs = 0;
    pid = 0;
    while ((num = getprocs (pp, sizeof(struct procsinfo),
			  (struct fdsinfo *) NULL, 0,
			  &pid, inc_procs)) > 0) {
	num_procs += num;
	if (num < inc_procs)
		break;
	procsinfo = (struct procsinfo *)
			realloc(procsinfo,
			   (num_procs+inc_procs)*sizeof(struct procsinfo));
	pp = &procsinfo[num_procs];
    }
    
    /*
    ** Allocate space for file descriptors outside the loop because
    ** the size has to be the size of struct fdsinfo, which is
    ** OPEN_MAX * sizeof(struct fdsinfox).  Can't use individual
    ** pi_maxofile's.
    */
    fdsinfo = (struct fdsinfo *)
		s_malloc ((size_t) sizeof(struct fdsinfo));

    /*
    ** Check all proc table entries, but return as soon as one match
    ** is found.
    */
    pp = procsinfo;
    for (; num_procs != 0; num_procs--, pp++)
    {
	if (pp->pi_state == 0 || pp->pi_state == SZOMB)
	    continue;

	if ((num = pp->pi_maxofile) == 0)
	    continue;

	pid = pp->pi_pid;
	if (getprocs((struct procsinfo *) NULL, 0,
		     fdsinfo, sizeof (struct fdsinfo),
		     &pid, 1) != 1)
	    continue;

	for (fd = 0; fd < num; fd++)
	{
	    if ((filep = fdsinfo->pi_ufd[fd].fp) == NULL)
		continue;
	    
	    if (kread (kip->kd, (off_t) filep, (char *) &file, sizeof (file)))
	    {
		syslog (LOG_ERR, "can not read file struct from %#x",
			       (unsigned) filep);
		goto Fail;
	    }

	    if (file.f_type != DTYPE_SOCKET)
		continue;
	    
	    if ((socketp = (struct socket *) file.f_data) == NULL)
		continue;
	    
	    if (kread (kip->kd,(off_t) socketp, (char *) &socket,
		       sizeof (socket)))
	    {
		syslog (LOG_ERR, "can not read socket struct from %#x",
			(unsigned) socketp);
		goto Fail;
	    }

	    if ((protoswp = socket.so_proto) == NULL)
		continue;

	    if (kread (kip->kd, (off_t) protoswp, (char *) &protosw,
		       sizeof (protosw)))
	    {
		syslog (LOG_ERR, "can not read protosw struct from %#x",
		       (unsigned) protoswp);
		goto Fail;
	    }

	    if (protosw.pr_protocol != IPPROTO_TCP)
		continue;
	    
	    if ((domainp = protosw.pr_domain) == NULL)
		continue;

	    if (kread (kip->kd, (off_t) domainp, (char *) &domain,
		       sizeof (domain)))
	    {
		syslog (LOG_ERR, "can not read domain struct from %#x",
			(unsigned) domainp);
		goto Fail;
	    }

	    if (domain.dom_family != AF_INET
#ifdef AF_INET6
		&& domain.dom_family != AF_INET6
#endif
		)
		continue;
	    
	    if ((inpcbp = (struct inpcb *) socket.so_pcb) == NULL)
		continue;

	    if (kread (kip->kd, (off_t) inpcbp, (char *) &inpcb,
		       sizeof (inpcb)))
	    {
		syslog (LOG_ERR, "can not read inpcb struct from %#x",
			(unsigned) inpcbp);
		goto Fail;
	    }

	    if (socketp != inpcb.inp_socket)
		continue;
	    
	    if (inpcb.inp_faddr.s_addr != faddr->s_addr ||
		inpcb.inp_fport != fport ||
		inpcb.inp_laddr.s_addr != laddr->s_addr ||
		inpcb.inp_lport != lport)
		continue;
	    
	    kp->ruid = pp->pi_uid;
	    kp->euid = pp->pi_suid;
	    kp->pid  = pp->pi_pid;

	    s_free(fdsinfo);
	    s_free(procsinfo);

	    return 1;
	}
    }
    
    s_free(fdsinfo);
    s_free(procsinfo);
    return 0;

  Fail:
    s_free(fdsinfo);
    s_free(procsinfo);
    return -1;
}

