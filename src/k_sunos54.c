/*
** k_sunos54.c - SunOS 5.4 kernel access functions.
**
** Copyright (c) 1995-1997 Casper Dik <Casper.Dik@Holland.Sun.COM>
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

#include "config.h"

#include <syslog.h>

#define DEBUGHASH

#include "pidentd.h"

#define _KMEMUSER
#define _KERNEL

/* some definition conflicts. but we must define _KERNEL */

#define exit 		kernel_exit
#define strsignal	kernel_strsignal

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <stdio.h>
#include <kvm.h>
#include <nlist.h>
#include <math.h>
#include <sys/fcntl.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <inet/common.h>
#include <inet/ip.h>


#define BROKEN_HASH

/*
 * In Solaris 2.4 there have been a number of changes:
 * - the ipc_s structure had its field names changed
 * - the file global no longer exists in the kernel.
 * (this sort of makes sense for MP machines: having to go through
 * one global lock for all file opens/closes doesn't scale
 * very well)
 */

#undef exit
#undef strsignal

#include <unistd.h>
#include <string.h>
#include <stddef.h>


#define N_FANOUT 0
#define N_PRACTIVE 1

struct kainfo
{
    kvm_t *kd;
    struct proc *nextp, currentp;
    struct nlist nl[3];
};


/*
** Make sure we are running on a supported OS version
*/
int
ka_init(void)
{
    char osinfo_current[256];

    /* The kvm routines are not MT-Safe! */
    kernel_threads = 1;
    
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
    
    
    kp->nl[0].n_name = "ipc_tcp_fanout";
    kp->nl[1].n_name = "practive";
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
** Get a piece of kernel memory with error handling.
** Returns 1 if call succeeded, else 0 (zero).
*/
static int
getbuf(kvm_t *kd,
       off_t addr,
       char *buf,
       size_t len,
       char *what)
{
    int i;
    ssize_t status;
    
    
    i = 0;
    while (i < 5 && (status = kvm_read(kd, addr, buf, len)) < 0)
	++i;
    
    if (status < 0)
    {
	syslog(LOG_DEBUG, "kvm_read(\"%s\", %lx, %lu): %m", what, addr, len);
	return 0;
    }
    
    return 1;
}




/* Work around for Solaris 2.x bug in kvm_setproc,
 * kvm_setproc doesn't reread practive */

static int
xkvm_setproc (struct kainfo *kp)
{
    if (!getbuf(kp->kd,
		(off_t) kp->nl[N_PRACTIVE].n_value,
		(char *) &kp->nextp,
		sizeof(kp->nextp),
		"practive"))
	return -1;
    
    return 0;
}

static struct proc *
xkvm_nextproc(struct kainfo *kp)
{
    if (!getbuf(kp->kd,
		(off_t) kp->nextp,
		(char*) &kp->currentp,
		sizeof(kp->currentp),
		"kvm_nextproc"))
	return 0;
    
    kp->nextp = kp->currentp.p_next;
    return &kp->currentp;
}

/*
** Return the user number for the connection owner
*/
int
ka_lookup(void *vp, struct kernel *kp)
{
    struct kainfo *kip;
    
    struct in_addr *faddr;
    int fport;
    struct in_addr *laddr;
    int lport;
    
    queue_t sqr;
    ipc_t ic, *icp;
    unsigned short uslp, usfp;
    unsigned int offset;
    file_t tf;
    unsigned long zero = 0;
    u16 *ports;
    u32 *locaddr, *raddr;
#ifdef DEBUGHASH
    int i;
#endif
    struct proc *procp;
#ifdef BROKEN_HASH
    ipc_t *alticp = 0;
    unsigned int altoffset;
#endif
    
    kip = (struct kainfo *) vp;
    
    faddr = &kp->remote.sin_addr;
    laddr = &kp->local.sin_addr;
    fport = kp->remote.sin_port;
    lport = kp->local.sin_port;

    usfp = fport;
    uslp = lport;

    if (debug)
	fprintf(stderr, "Scanning for %d:%d\n", fport, lport);
    
#ifdef BROKEN_HASH
    /* code used (ports > 8) instead of (ports >> 8)
       low byte of local port number not used, low byte of 
       local addres is used
	ip_bind  in the kernel (+ approx 0x4c0)
                srl     %i3, 0x18, %o0
                xor     %i2, %o0, %o0
                srl     %i3, 0x10, %o1
                xor     %o0, %o1, %o0
                xor     %o0, %l0, %o0
                xor     %o0, %i3, %o0
                and     %o0, 0xff, %o0
                sethi   %hi(0xfc1d9c00), %o2
                or      %o2, 0x1c0, %o2          ! ipc_tcp_fanout

     */
#if (defined(BIG_ENDIAN) || defined(_BIG_ENDIAN))
    altoffset = usfp >> 8;
#else
    altoffset = uslp >> 8;
#endif
    altoffset ^= usfp ^ uslp;
    altoffset ^= faddr->S_un.S_un_b.s_b4;
    if (uslp > 8 || usfp != 0)
	altoffset ^= 1;
    altoffset &= 0xff;
    if (!getbuf(kip->kd,
		(off_t) kip->nl[N_FANOUT].n_value + sizeof(ipc_t *) * altoffset,
		(char *) &alticp,
		sizeof(ipc_t *),
		"ipc_tcp_fanout[altoffset]"))
	alticp = NULL;
#endif
    
    offset = usfp ^ uslp;
    offset ^= (unsigned) faddr->S_un.S_un_b.s_b4 ^ (offset >> 8);
    offset &= 0xff;

    if (!getbuf(kip->kd, (off_t) kip->nl[N_FANOUT].n_value + sizeof(ipc_t *) * offset,
		(char *) &icp,
		sizeof(ipc_t *),
		"ipc_tcp_fanout[offset]"))
	return -1;
    
#ifdef BROKEN_HASH
    if (icp == NULL && alticp != NULL) {
	icp = alticp;
	alticp = NULL;
    }
#endif
#ifndef DEBUGHASH
    if (icp == 0) {
	syslog(LOG_DEBUG, "ka_lookup: hash miss");
	return -1;
    }
#endif

    locaddr = &ic.ipc_tcp_laddr;
    raddr = &ic.ipc_tcp_faddr;
    ports = (u16 *) &ic.ipc_tcp_ports;

#ifdef DEBUGHASH
  for (i = 0; i < 256; i++) {
    if (!getbuf(kip->kd,
		(off_t) kip->nl[N_FANOUT].n_value + sizeof(ipc_t *) * i,
		(char *) &icp,
		sizeof(ipc_t *),
		"ipc_tcp_fanout[offset]"))
	return -1;
    if (icp == NULL)
	continue;
#endif

    while (icp != NULL) {
	if (!getbuf(kip->kd,
		    (off_t) icp,
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
#ifdef BROKEN_HASH
	if (icp == NULL && alticp != NULL) {
	    icp = alticp;
	    alticp = NULL;
	}
#endif
    }
#ifdef DEBUGHASH
    if (icp != NULL)
	break;
  } /* for i */
    if (icp != NULL && debug)
	fprintf(stderr,
		"found, offset = %x, i = %x, i ^ offset = %x\n", offset, i,
		offset ^ i);
#endif

    if (icp == NULL) {
	syslog(LOG_INFO, "ka_lookup: port not found");
	return -1;
    }
    
    if (!getbuf(kip->kd,
		(off_t) ic.ipc_rq+offsetof(queue_t, q_stream),
		(char *) &sqr.q_stream,
		sizeof(sqr.q_stream),
		"queue.q_stream"))
	return -1;

    /* at this point sqr.q_stream holds the pointer to the stream we're
       interested in. Now we're going to find the file pointer
       that refers to the vnode that refers to this stream stream */

    /* Solaris 2.4 no longer links all file pointers together with
     * f_next, the only way seems to be scrounging them from
     * the proc/user structure, ugh.
     */

    if (xkvm_setproc(kip) != 0)
    {
	syslog(LOG_ERR, "kvm_setproc(): %m");
	return -1;
    }

    while ((procp = xkvm_nextproc(kip)) != NULL)
    {
	struct uf_entry files[NFPCHUNK];
	int nfiles = procp->p_user.u_nofiles;
	off_t addr = (off_t) procp->p_user.u_flist;

	while (nfiles > 0) {
	    int nread = nfiles > NFPCHUNK ? NFPCHUNK : nfiles;
	    int size = nread * sizeof(struct uf_entry);
	    int i;
	    struct file *last = 0;
	    vnode_t vp;

	    if (!getbuf(kip->kd, addr, (char*) &files[0], size, "ufentries"))
		return -1;
	    
	    for (i = 0; i < nread; i++) {
		if (files[i].uf_ofile == 0 || files[i].uf_ofile == last)
		    continue;
		if (!getbuf(kip->kd,(unsigned long) (last = files[i].uf_ofile),
			(char *) &tf, sizeof(tf), "file pointer")) {
			    return -1;
		}

		if (tf.f_vnode == NULL)
		    continue;

		if (!getbuf(kip->kd,
			    (off_t) tf.f_vnode + offsetof(vnode_t,v_stream),
			    (char *) &vp.v_stream,
			    sizeof(vp.v_stream),
			    "vnode.v_stream"))
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
    
    return -1;
}
