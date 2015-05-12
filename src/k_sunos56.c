/*
** k_sunos56.c - SunOS 5.6 kernel access functions
**
** Copyright (c) 1995-1997 Casper Dik <Casper.Dik@Holland.Sun.COM>
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

#if 0
#define DEBUGHASH
#endif

#define _KMEMUSER
#define _KERNEL

/* some definition conflicts. but we must define _KERNEL */

#define exit 		kernel_exit
#define strsignal	kernel_strsignal
#define mutex_init	kernel_mutex_init
#define mutex_destroy	kernel_mutex_destroy
#define sema_init	kernel_sema_init
#define sema_destroy	kernel_sema_destroy

#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <stdio.h>
#include <kvm.h>
#include <nlist.h>
#include <math.h>
#include <stddef.h>
#include <sys/fcntl.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <inet/common.h>
#include <inet/ip.h>


#define FANOUT_OFFSET(n)  (kip->nl[N_FANOUT].n_value + (n) * sizeof(icf_t) + offsetof(icf_t, icf_ipc))

#undef exit
#undef strsignal
#undef mutex_init
#undef mutex_destroy
#undef sema_init
#undef sema_destroy

#undef SEMA_HELD
#undef RW_LOCK_HELD
#undef RW_READ_HELD
#undef RW_WRITE_HELD
#undef MUTEX_HELD

#include <unistd.h>
#include <string.h>
#include <stddef.h>


#include "pidentd.h"

#define N_FANOUT 0

struct kainfo
{
    kvm_t *kd;
    struct nlist nl[2];
};


/*
** Make sure we are running on a supported OS version
*/
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
    
    
    kp->nl[0].n_name = "ipc_tcp_conn_fanout";
    kp->nl[1].n_name = NULL;
    
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
** Get a piece of kernel memory with error handling.
** Returns 1 if call succeeded, else 0 (zero).
*/
static int
getbuf(kvm_t *kd, off_t addr, char *buf, size_t len, char *what)
{
    int i;
    ssize_t status;
    
    
    i = 0;
    while (i < 5 && (status = kvm_read(kd, addr, buf, len)) < 0)
	++i;
    
    if (status < 0)
	return 0;
    
    return 1;
}


/*
** Return the user number for the connection owner
*/
int
ka_lookup(void *vp, struct kernel *kp)
{
    struct kainfo *kip;
    queue_t sqr;
    ipc_t ic, *icp;
    unsigned short uslp, usfp;
    unsigned int offset;
    file_t tf;
    unsigned long zero = 0;
    uint16_t *ports;
    uint32_t *locaddr, *raddr;
#ifdef DEBUGHASH
    int i;
#endif
    struct proc *procp;
    struct in_addr *faddr;
    int fport;
    struct in_addr *laddr;
    int lport;
    
    
    kip = (struct kainfo *) vp;
    
    faddr = &kp->remote.sin_addr;
    laddr = &kp->local.sin_addr;
    fport = kp->remote.sin_port;
    lport = kp->local.sin_port;
    
    usfp = fport;
    uslp = lport;
    
    offset = usfp ^ uslp;
    offset ^= (unsigned) faddr->S_un.S_un_b.s_b4 ^ (offset >> 8);
    offset &= 0xff;
    
    if (!getbuf(kip->kd, (off_t) FANOUT_OFFSET(offset),
		(char *) &icp,
		sizeof(ipc_t *),
		"ipc_tcp_fanout[offset]"))
	return -1;
    
#ifndef DEBUGHASH
    if (icp == NULL)
    {
	syslog(LOG_DEBUG, "ka_lookup: hash miss");
	return -1;
    }
#endif
    
    locaddr = (uint32_t *) &ic.ipc_laddr;
    raddr = (uint32_t *) &ic.ipc_faddr;
    ports = (uint16_t *) &ic.ipc_ports;
    
#ifdef DEBUGHASH
    for (i = 0; i < 256; i++)
    {
	if (!getbuf(kip->kd, (off_t) FANOUT_OFFSET(i),
		    (char *) &icp,
		    sizeof(ipc_t *),
		    "ipc_tcp_fanout[offset]"))
	    return -1;
	if (icp == NULL)
	    continue;
#endif
	
	while (icp != NULL)
	{
	    if (!getbuf(kip->kd, (off_t) icp,
			(char *) &ic,
			sizeof(ic),
			"hash entry"))
		return -1;
	    
	    if (usfp == ports[0] && /* remote port */
		uslp == ports[1] && /* local port */
#if 0
		memcmp(&laddr->s_addr, locaddr, 4) == 0 && /* local */
#else
		(memcmp(&laddr->s_addr, locaddr, 4) == 0 ||
		 /* In SunOS 5.3, the local part can be all zeros */
		 memcmp(&zero, locaddr, 4) == 0) /* local */ &&
#endif
		memcmp(&faddr->s_addr, raddr, 4) == 0)
		break;
	    icp = ic.ipc_hash_next;
	}
#ifdef DEBUGHASH
	if (icp != NULL)
	    break;
    } /* for i */
    if (icp != NULL)
	printf("found, offset = %x, i = %x, i ^ offset = %x\n", offset, i,
	offset ^ i);
#endif
    
    if (icp == NULL)
    {
	syslog(LOG_INFO, "ka_lookup: port not found");
	return 0;
    }
    
    if (!getbuf(kip->kd, (off_t) ic.ipc_rq+offsetof(queue_t, q_stream),
		(char *) &sqr.q_stream,
		sizeof(sqr.q_stream),
		"queue.q_stream"))
	return -1;
    
    /* at this point sqr.q_stream holds the pointer to the stream we're
       interested in. Now we're going to find the file pointer
       that refers to the vnode that refers to this stream stream */
    
    
    if (kvm_setproc(kip->kd) != 0)
	return -1;
    
    while ((procp = kvm_nextproc(kip->kd)) != NULL)
    {
	struct uf_entry files[NFPCHUNK];
	int nfiles = procp->p_user.u_nofiles;
	off_t addr = (off_t) procp->p_user.u_flist;
	
	while (nfiles > 0)
	{
	    int nread = nfiles > NFPCHUNK ? NFPCHUNK : nfiles;
	    int size = nread * sizeof(struct uf_entry);
	    int i;
	    struct file *last = NULL;
	    vnode_t vp;
	    
	    if (!getbuf(kip->kd, addr, (char *) &files[0], size, "ufentries"))
	    {
		return -1;
	    }
	    
	    for (i = 0; i < nread; i++)
	    {
		if (files[i].uf_ofile == 0 || files[i].uf_ofile == last)
		    continue;
		if (!getbuf(kip->kd, (off_t) (last = files[i].uf_ofile),
			    (char *) &tf, sizeof(tf), "file pointer"))
		{
		    return -1;
		}
		
		if (tf.f_vnode == NULL)
		    continue;
		
		if (!getbuf(kip->kd, (off_t) tf.f_vnode +
			    offsetof(vnode_t, v_stream),
			    (char *) &vp.v_stream,
			    sizeof(vp.v_stream), "vnode.v_stream"))
		    return -1;
		
		if (vp.v_stream == sqr.q_stream)
		{
		    cred_t cr;
		    struct pid p;
		    
		    if (!getbuf(kip->kd,
				(off_t) tf.f_cred,
				(char *) &cr,
				sizeof(cr),
				"cred"))
			return -1;
		    
		    kp->ruid = cr.cr_ruid;
		    kp->euid = cr.cr_uid;
		    
		    if (getbuf(kip->kd,
			       (off_t) procp->p_pidp,
			       (char *) &p,
			       sizeof(struct pid),
			       "pidp"))
		    {
			kp->pid = p.pid_id;
			/* get cmd */
			kp->cmd = s_strdup(procp->p_user.u_comm);
			/* get cmd args */
			kp->argv = s_strdup(procp->p_user.u_psargs);
		    }
		    
		    return 1;
		}
	    }
	    nfiles -= nread;
	    addr += size;
	}
    }
    
    return 0;
}
