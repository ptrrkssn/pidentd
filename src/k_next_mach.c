/*
** k_next_mach.c - NeXTstep 3 kernel access functions.
**
** This program is in the public domain and may be used freely by anyone
** who wants to. 
**
** Please send bug fixes/bug reports to: Peter Eriksson <pen@lysator.liu.se>
*/

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <nlist.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>

#include "pkvm.h"

#include <sys/socket.h>
#include <sys/socketvar.h>

#include <sys/ioctl.h>

/* FIXME: check for features?  */
#ifndef NeXT31
#  define KERNEL
#  define KERNEL_FEATURES 
#else
#  define KERNEL_FILE
#endif

#include <sys/file.h>

#ifndef NeXT31
#  undef KERNEL
#  undef KERNEL_FEATURES 
#else
#  undef KERNEL_FILE
#endif

#include <sys/user.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>

#include "pidentd.h"


struct kainfo
{
    kvm_t *kd;
    struct nlist nl[4];
};


#define N_FILE 0  
#define N_NFILE 1
#define N_TCB 2




int
ka_init(void)
{
#if 0
    char osinfo_current[256];

    if (osinfo_get(osinfo_current) == NULL)
	return -1;

    return strcmp(osinfo_build, osinfo_current);
#endif
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
    if ((kp->kd = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL)) == NULL)
    {
	if (debug)
		perror("kvm_open");

	syslog(LOG_ERR, "kvm_open: %m");
	s_free(kp);
	return -1;
    }

    kp->nl[0].n_un.n_name = "_file_list";
    kp->nl[1].n_un.n_name = "_max_file";
    kp->nl[2].n_un.n_name = "_tcb";
    kp->nl[3].n_un.n_name = NULL;
    
    /*
    ** Extract offsets to the needed variables in the kernel
    */
    if ((rcode = kvm_nlist(kp->kd, kp->nl)) != 0)
    {
	if (debug)
	    fprintf(stderr, "kvm_nlist: returned %d\n", rcode);

	syslog(LOG_ERR, "kvm_nlist, rcode = %d: %m", rcode);
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
    if (kvm_read(kd, addr, buf, len) < 0)
    {
	syslog(LOG_INFO, "getbuf: kvm_read(%08x, %lu) - %s : %m",
		   addr, (unsigned long) len, what);
	
	return 0;
    }
    
    return 1;
}



/*
** Traverse the inpcb list until a match is found 
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
    int limiter = 65536;
  
    if (pcbp == NULL)
	return NULL;		/* Someone gave us a duff one here */
  
    head = pcbp->inp_prev;
    do
    {
      	if (pcbp->inp_faddr.s_addr == faddr->s_addr &&
	    pcbp->inp_laddr.s_addr == laddr->s_addr &&
	    pcbp->inp_fport        == fport &&
	    pcbp->inp_lport        == lport)
	    return pcbp->inp_socket;

	if (--limiter <= 0)
	    break;	  

    } while (pcbp->inp_next != head &&
	     getbuf(kd, (off_t) pcbp->inp_next, 
                   pcbp, sizeof(struct inpcb), "tcblist"));

    return NULL;			/* Not found */
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

    struct kainfo *kip;
    struct ucred ucb;
    struct socket *sockp;
    int nfile;
    struct inpcb tcb;
    struct file file_entry;
    void *addr;

    kip = (struct kainfo *) vp;

    faddr = &kp->remote.sin_addr;
    laddr = &kp->local.sin_addr;
    fport = kp->remote.sin_port;
    lport = kp->local.sin_port;
    
    /* -------------------- TCP PCB LIST -------------------- */
    if (!getbuf(kip->kd,
		(off_t) kip->nl[N_TCB].n_value,
		&tcb, sizeof(tcb), "tcb"))
	return -1;
      
    tcb.inp_prev = (struct inpcb *) kip->nl[N_TCB].n_value;
    sockp = getlist(kip->kd, &tcb, faddr, fport, laddr, lport);

    if (sockp == NULL)
	return 0;

    /* -------------------- FILE DESCRIPTOR TABLE -------------------- */
    /* So now we hit the fun Mach kernel structures */
    if (!getbuf(kip->kd,
		(off_t) kip->nl[N_FILE].n_value,
		&addr, sizeof(addr), "&file_table"))
	return -1;
      
    /* We only use nfile as a failsafe in case something goes wrong! */
    if (!getbuf(kip->kd,
		(off_t) kip->nl[N_NFILE].n_value,
		&nfile, sizeof(nfile), "nfile"))
	return -1;
      
    file_entry.links.next = addr;
    /* ------------------- SCAN FILE TABLE ------------------------ */
    do
    {
	if (!getbuf(kip->kd,
		    (off_t) file_entry.links.next,
		    &file_entry, sizeof(file_entry), "struct file"))
	    return -1;
	 
	if (file_entry.f_count == 0)
	    continue;

	if (file_entry.f_type == DTYPE_SOCKET &&
	    (struct socket *) file_entry.f_data == sockp)
	{
	    if (!getbuf(kip->kd,
			(off_t) file_entry.f_cred, 
	                &ucb, sizeof(ucb), "ucb"))
		return -1;
	       
	    kp->ruid = ucb.cr_ruid;
	    kp->euid = ucb.cr_uid;

	    return 1;
	}
    } while ((file_entry.links.next != addr) && (--nfile));

    return -1;
}
