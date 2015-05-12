/*
** k_irix.c - SGI IRIX -
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
/*
** =========================================================================
** Luc Chouinard, lucc@sgi.com
** =========================================================================
*/

#include "config.h"

#ifdef _POSIX_C_SOURCE /* Ugly hack below - pen */

#define __EXTENSIONS__ 1
#define _SGI_SOURCE 1

#include <standards.h>

#undef _XOPEN4UX
#define _XOPEN4UX 1
#undef _SGIAPI
#define _SGIAPI 1

#endif /* End ugly hack */


#include <time.h>
#include <netdb.h>
#include <paths.h>
#include <fcntl.h>
#include <bstring.h>
#include <mntent.h>
#include <sys/select.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/utssys.h>
#include <sys/var.h>
#include <netinet/in.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/sysmp.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/procfs.h>

#include "pidentd.h"


typedef struct {
    f_user_t *pl, *pr;
} kpriv_t;

/* initialize and check os version current-vs-compiled
   This version of the program runs on any machine that will 
   allow it to run */
int
ka_init(void)
{
    return 0;
}

/*
 * allocate enough memory for the maximum number of procs.
 */
ka_open(void **misc)
{
    kpriv_t *kp;
    off_t vaddr;
    int kfd;

    kp = s_malloc(sizeof(kpriv_t));
    vaddr = (off_t) sysmp(MP_KERNADDR, MPKA_VAR);
    if ((kfd = open(_PATH_KMEM, O_RDONLY)) >= 0)
    {
	if (lseek(kfd, vaddr, SEEK_SET) == vaddr)
	{
	    struct var v;
	    
	    if (read(kfd, &v, sizeof(v)) == sizeof(v))
	    {
		kp->pl = s_malloc(v.v_proc * sizeof(f_user_t));
		kp->pr = s_malloc(v.v_proc * sizeof(f_user_t));
		*misc = (void *) kp;
		return 0;
	    }
	}
	close(kfd);
    }
}

/*
 * Get a list of process using a addr/port couple
 */
static int
getusers(struct sockaddr_in *sin, f_user_t *u)
{
    struct fid fid;
    f_anonid_t fa;
    int n;

    fid.fid_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
    memcpy(fid.fid_data, sin, sizeof(*sin));
    fid.fid_data[sizeof(*sin)] = 7;
    fa.fa_fid = &fid;
    (void) strncpy(fa.fa_fsid, FSID_SOCKET, sizeof fa.fa_fsid);
    if ((n = utssys(&fa, F_ANONYMOUS, UTS_FUSERS, u)) <= 0)
	return 0;
    return n;
}

/*
 * set status and return
 * if possible get cmd and args also through procfs
 */
static int
stval(f_user_t *u, struct kernel *kp)
{
    char pname[256];
    int pfd;

#ifdef IRIX4
    s_snprintf(pname, sizeof(pname), "/debug/%05d", (int)u->fu_pid);
#else
    s_snprintf(pname, sizeof(pname), "/proc/pinfo/%d", (int)u->fu_pid);
#endif

    kp->cmd = NULL;
    kp->argv = NULL;
    kp->ruid = kp->euid=u->fu_uid;
    if ((pfd = s_open(pname, O_RDONLY)) >= 0)
    {
	prpsinfo_t info;
	prcred_t cr;
    
	if (ioctl(pfd, PIOCPSINFO, &info) >= 0)
	{
	    kp->cmd = s_malloc(strlen(info.pr_fname) + 1);
	    strcpy(kp->cmd, info.pr_fname);
	    kp->argv = s_malloc(strlen(info.pr_psargs) + 1);
	    strcpy(kp->argv, info.pr_psargs);
	}
	if (ioctl(pfd, PIOCCRED, &cr) >= 0)
	{
	    kp->euid=cr.pr_euid;
	    kp->ruid=cr.pr_ruid;
	}
	close(pfd);
    }
    kp->status = 1;
    kp->pid = u->fu_pid;
    return 1;
}

/*
** Return the user number for the connection owner
*/
int 
ka_lookup(void *vp, struct kernel *kp)
{
    int nr, nl;
    kpriv_t *pr = (kpriv_t *)vp;

    kp->status = -1;
    nl = getusers(&kp->local, pr->pl);
    nr = getusers(&kp->remote, pr->pr);
    if (nr != 0 && nl != 0)
	return stval(&pr->pl[0], kp);
    else
    {
	if (nl != 0)
	{
	    int i, j;

	    for (i = 0; i < nr; i++)
		for (j = 0; j < nl; j++)
		    if (pr->pr[i].fu_pid == pr->pl[j].fu_pid)
			return stval(&pr->pr[i], kp);

	    return stval(&pr->pl[0], kp);
	}
	else
	    return stval(&pr->pr[0], kp);
    }
    return 0;
}

