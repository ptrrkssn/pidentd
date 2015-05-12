/*
** k_sunos58.c - SunOS 5.8 kernel access functions
**
** Copyright (c) 1995-1999 Casper Dik <Casper.Dik@Holland.Sun.COM>
** Copyright (c) 1997      Peter Eriksson <pen@lysator.liu.se>
**
** This program is free software; you can redistribute it and/or
** modify it as you wish - as long as you don't claim that you wrote
** it.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** For now, only support IPv4 for Solaris 8
*/

#include "config.h"

#include <unistd.h>
#include <string.h>
#include <stddef.h>

#include <stdio.h>
#include <nlist.h>
#include <math.h>

#if 0
#define DEBUGHASH
#endif

#define _KMEMUSER
#define _KERNEL

#include <kvm.h>

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

#include <sys/fcntl.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <net/if_types.h>
#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <netinet/ip6.h>
#include <net/if.h>

#if   !defined(IN6_V4_MAPPED_TO_INADDR)

#define IPv6_2_IPv4(v6, v4)                                     \
        ((v4)->s_addr = *((uint32_t *)                          \
                (((uint8_t *)((struct in6_addr *)v6)->s6_addr)+12)))

#else         /*  defined(IN6_V4_MAPPED_TO_INADDR) */

#define IPv6_2_IPv4(v6, v4) IN6_V4MAPPED_TO_INADDR((struct in6_addr *)v6, v4)

#endif        /* defined(IN6_V4MAPPED_TO_INADDR) */

typedef struct hashentry {
    tcpb_t  *he_tcp;
    kmutex_t he_lock;
} he_t;

#define FANOUT_OFFSET(n)  (kip->hash_table + (n) * sizeof(he_t) + offsetof(he_t, he_tcp))

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

#include "pidentd.h"

#define N_FANOUT 0
#define N_HASH_SIZE 1

struct kainfo
{
    kvm_t *kd;
    int hash_size;
    unsigned long hash_table;
    struct nlist nl[3];
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
    
    
    kp->nl[0].n_name = "tcp_conn_fanout";
    kp->nl[1].n_name = "tcp_conn_hash_size";
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

    /*
     * Read the two kernel values we need but won't change
     */
    if (!getbuf(kp->kd, kp->nl[N_HASH_SIZE].n_value, (char *) &kp->hash_size,
	    sizeof(kp->hash_size), kp->nl[N_HASH_SIZE].n_name) ||
	!getbuf(kp->kd, kp->nl[N_FANOUT].n_value, (char *) &kp->hash_table,
	sizeof(kp->hash_table), kp->nl[N_FANOUT].n_name)) {
	    kvm_close(kp->kd);
	    s_free(kp);
	    syslog(LOG_ERR, "getbuf: can't get needed symbols");
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
    char *faddr;
    int fport;
    char *laddr;
    int lport;
    struct stdata *std;
    tcpb_t *tcpb;
    queue_t *q;
    tcpb_t tb;
    char *iphash;
    
    kip = (struct kainfo *) vp;
    
    faddr = (char *) SGADDRP(kp->remote);
    laddr = (char *) SGADDRP(kp->local);
    fport = SGPORT(kp->remote);
    lport = SGPORT(kp->local);

    /* XXX: the V4_PART macros don't work and port to well to this */
    iphash = SGFAM(kp->remote) == AF_INET ? faddr : faddr + 12;
    
    usfp = fport;
    uslp = lport;
    
    /*
     * All tcp connections are in one single hash table; IPV4 connections
     * over AF_INET6 sockets do not show up in the normal tcp hash tables
     *
     * First we need to find the hash entry in the tcp table;
     * then we need to follow the chain and get the TCP entry.
     *
     * In Solaris 8, the tcp structure is split in two: the core part
     * needed in TIME_WAIT state and the full structure.
     */

#define GETBYTE(x,n)		((unsigned)(((unsigned char*)&x)[n]))
    offset = GETBYTE(*iphash,3) ^ GETBYTE(usfp,0) ^ GETBYTE(usfp,1) ^
	GETBYTE(uslp,0) ^ GETBYTE(uslp,1) ^
	((GETBYTE(usfp,0) ^ GETBYTE(uslp,0) ^ GETBYTE(*iphash,2)) << 10) ^
	(GETBYTE(*iphash,1) << 6);

    offset %= kip->hash_size;

    if (!getbuf(kip->kd, FANOUT_OFFSET(offset), (char*) &tcpb, sizeof(tcpb),
	"tcp_conn_fanout[hash]"))
	    return -1;

    if (tcpb == NULL) {
	 syslog(LOG_DEBUG, "k_getuid: tcp hash miss");
	 return -1;
    }

    while (tcpb != NULL) {

	if (!getbuf(kip->kd, (unsigned long) tcpb, (char *) &tb, sizeof(tb),
	    "struct tcp"))
		return -1;

	if (uslp == tb.tcpb_lport && usfp == tb.tcpb_fport) {
	    if (SGFAM(kp->remote) == AF_INET) {
		struct in_addr fv4, lv4;
		IPv6_2_IPv4(&tb.tcpb_ip_src_v6, &lv4);
		IPv6_2_IPv4(&tb.tcpb_remote_v6, &fv4);
		if (memcmp(&lv4, laddr, 4) == 0 && memcmp(&fv4, faddr, 4) == 0)
			break;
	    } else if (memcmp(&tb.tcpb_ip_src_v6, laddr, SGSIZE(kp->local))
			 == 0 &&
			memcmp(&tb.tcpb_remote_v6, faddr, SGSIZE(kp->remote))
			 == 0) {
			    break;
	    }
	}

	tcpb = tb.tcpb_conn_hash;
    }

    if (tcpb == NULL)
	return -1;

    if (!getbuf(kip->kd, (unsigned long) tb.tcpb_tcp + offsetof(tcp_t, tcp_rq),
	(char *) &q, sizeof(q), "queue *"))
	    return -1;

    if (!getbuf(kip->kd, (unsigned long) q + offsetof(queue_t, q_stream),
	(char *) &std, sizeof(std), "tcp_rq->q_stream"))
	    return -1;

    /* at this point std holds the pointer to the stream we're
       interested in. Now we're going to find the file pointer
       that refers to the vnode that refers to this stream stream */
    
    if (kvm_setproc(kip->kd) != 0)
	return -1;
    

    /*
     * In Solaris 8, the file lists changed dramatically.
     * There's no longer an NFPCHUNK; the uf_entries are
     * part of a seperate structure inside user.
     */
#define NFPREAD		64

#ifndef NFPCHUNK
#define uf_ofile	uf_file
#define u_flist		u_finfo.fi_list
#define u_nofiles	u_finfo.fi_nfiles
#endif

    while ((procp = kvm_nextproc(kip->kd)) != NULL)
    {
	struct uf_entry files[NFPREAD];
	int nfiles = procp->p_user.u_nofiles;
	off_t addr = (off_t) procp->p_user.u_flist;
	
	while (nfiles > 0)
	{
	    int nread = nfiles > NFPREAD ? NFPREAD : nfiles;
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
		
		if (vp.v_stream == std)
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
