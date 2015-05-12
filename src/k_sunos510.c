/*
** k_sunos510.c - SunOS 5.10 kernel access functions
**
** Copyright (c) 1995-2003 Casper Dik <Casper.Dik@Holland.Sun.COM>
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
*/

#include "config.h"

#include <unistd.h>
#include <string.h>
#include <stddef.h>

#include <stdio.h>
#include <nlist.h>
#include <math.h>

#define _KMEMUSER
#define _KERNEL

#include <sys/cred_impl.h>
#include <kvm.h>

/* some definition conflicts. but we must define _KERNEL */

#define ffs		kernel_ffs
#define ka_init		kernel_ka_init
#define getbuf 		kernel_ka_init
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
#include <inet/ipclassifier.h>
#include <netinet/ip6.h>
#include <net/if.h>

uint_t   ipcl_conn_fanout_size;

#if   !defined(IN6_V4_MAPPED_TO_INADDR)

#define IPv6_2_IPv4(v6, v4)                                     \
        ((v4)->s_addr = *((uint32_t *)                          \
                (((uint8_t *)((struct in6_addr *)v6)->s6_addr)+12)))

#else         /*  defined(IN6_V4_MAPPED_TO_INADDR) */

#define IPv6_2_IPv4(v6, v4) IN6_V4MAPPED_TO_INADDR((struct in6_addr *)v6, v4)

#endif        /* defined(IN6_V4MAPPED_TO_INADDR) */

#define FANOUT_OFFSET(n)  (kip->hash_table + (n) * sizeof(connf_t) + \
			offsetof(connf_t, connf_head))

#undef exit
#undef strsignal
#undef mutex_init
#undef mutex_destroy
#undef sema_init
#undef sema_destroy
#undef ffs
#undef ka_init
#undef getbuf

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
    uint_t hash_size;
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
    
    
    kp->nl[0].n_name = "ipcl_conn_fanout";
    kp->nl[1].n_name = "ipcl_conn_fanout_size";
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
    unsigned short uslp, usfp;
    unsigned int offset;
    file_t tf;
    unsigned long zero = 0;
    uint32_t *locaddr, *raddr;
    struct proc *procp;
    char *faddr;
    int fport;
    char *laddr;
    int lport;
    struct stdata *std;
    conn_t *connfp;
    queue_t *q;
    char *iphash;
    cred_t cr;
    conn_t con;
    uint_t ports;
    uint16_t *pptr = (uint16_t *)&ports;
    
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
     */

    pptr[0] = fport;
    pptr[1] = lport;
    /* XXX: need to change in build 46 */
    offset = (unsigned)ntohl(*(uint_t *)iphash) ^
	(ports >> 24) ^ (ports >> 16) ^ (ports >> 8) ^ ports;

    offset %= kip->hash_size;

    if (!getbuf(kip->kd, FANOUT_OFFSET(offset), (char*) &connfp, sizeof(connfp),
	"ipcl_conn_fanout[hash]"))
	    return -1;

    if (connfp == NULL) {
	 syslog(LOG_DEBUG, "k_getuid: tcp hash miss");
	 return -1;
    }

    while (connfp != NULL) {

	if (!getbuf(kip->kd, (unsigned long) connfp, (char *) &con, sizeof(con),
	    "struct conn_s"))
		return -1;

	if (uslp == con.conn_lport && usfp == con.conn_fport) {
	    if (SGFAM(kp->remote) == AF_INET) {
		struct in_addr fv4, lv4;
		IPv6_2_IPv4(&con.conn_srcv6, &lv4);
		IPv6_2_IPv4(&con.conn_remv6, &fv4);
		if (memcmp(&lv4, laddr, 4) == 0 && memcmp(&fv4, faddr, 4) == 0)
			break;
	    } else if (memcmp(&con.conn_srcv6, laddr, SGSIZE(kp->local))
			 == 0 &&
			memcmp(&con.conn_remv6, faddr, SGSIZE(kp->remote))
			 == 0) {
			    break;
	    }
	}

	connfp = con.conn_next;
    }

    if (connfp == NULL)
	return -1;

    if (!getbuf(kip->kd, (off_t) con.conn_cred, (char *) &cr,
				sizeof(cr), "cred"))
	return -1;
    
    kp->ruid = cr.cr_ruid;
    kp->euid = cr.cr_uid;

    return (1);
}
