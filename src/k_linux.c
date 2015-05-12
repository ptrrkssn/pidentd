/*
** k_linux.c - Linux 0.99.13q or later kernel access functions
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

#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pidentd.h"

/*
** Make sure we are running on a supported OS version
*/
int
ka_init(void)
{
    return 0; /* We always succeed */
}


int
ka_open(void **misc)
{
    FILE *fp;

    
    while ((fp = fopen("/proc/net/tcp", "r")) == NULL && errno == EINTR)
	;
    
    if (fp == NULL)
    {
	syslog(LOG_ERR, "fopen(\"/proc/net/tcp\", \"r\"): %m");
	return -1;
    }

    *misc = (void *) fp;
    return 0;
}


int 
ka_lookup(void *vp, struct kernel *kp)
{
    FILE *fp;
    long dummy;
    char buf[512];
    long r_laddr, r_raddr, myladdr, myraddr;
    int r_lport, r_rport, mylport, myrport;
    int euid;
    int nra;
    
/*
 * PSz 11 Dec 02
 * 
 * We have observed Debian identd (on a fairly busy dual-CPU machine)
 * sometimes reporting 'root' for connections belonging to "real" users.
 * File /proc/net/tcp is written mostly in routine get__sock in
 * /usr/src/kernel-source-2.2.19/net/ipv4/proc.c :
 * 
 * 	sprintf(tmpbuf, "%4d: %08lX:%04X %08lX:%04X"
 * 		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu",
 * 		i, src, srcp, dest, destp, sp->state, 
 * 		(tw_bucket ?
 * 		 0 :
 * 		 (format == 0) ?
 * 		 tp->write_seq-tp->snd_una : atomic_read(&sp->wmem_alloc)),
 * 		(tw_bucket ?
 * 		 0 :
 * 		 (format == 0) ?
 * 		 tp->rcv_nxt-tp->copied_seq: atomic_read(&sp->rmem_alloc)),
 * 		timer_active, timer_expires-jiffies,
 * 		(tw_bucket ? 0 : tp->retransmits),
 * 		(!tw_bucket && sp->socket) ? sp->socket->inode->i_uid : 0,
 * 		(!tw_bucket && timer_active) ? sp->timeout : 0,
 * 		(!tw_bucket && sp->socket) ? sp->socket->inode->i_ino : 0);
 * 
 * Should we skip lines with just ino, or both uid and ino, zero?
 */
    unsigned long int ino;

    
    r_rport = ntohs(kp->remote.sin_port);
    r_lport = ntohs(kp->local.sin_port);
    r_raddr = kp->remote.sin_addr.s_addr;
    r_laddr = kp->local.sin_addr.s_addr;

    fp = (FILE *) vp;

    kp->ruid = NO_UID;
    rewind(fp);

    /* eat header */
    if (fgets(buf, sizeof(buf)-1,fp) == NULL)
	return -1;

    while (fgets(buf, sizeof(buf)-1, fp) != NULL)
    {
	nra = sscanf(buf, "%d: %lX:%x %lX:%x %x %lX:%lX %x:%lX %lx %d %ld %lu",
		     &dummy, &myladdr, &mylport, &myraddr, &myrport,
		     &dummy, &dummy, &dummy, &dummy, &dummy, &dummy,
		     &euid, &dummy, &ino);
	if (nra >= 12)
	{
	    if (myladdr == r_laddr && mylport == r_lport &&
		myraddr == r_raddr && myrport == r_rport)
	    {
		if (nra >= 14 && euid == 0 && ino == 0) {
		  /*
		   * Both uid and ino are zero: not even a socket?
		   * Skip (continue), probably fail; or fail (break)
		   * straight away? Hopefully we retry later.
		   */
		  continue;
		}
		kp->euid = euid;
		return 1;
	    }
	}
    }

    return -1;
}

