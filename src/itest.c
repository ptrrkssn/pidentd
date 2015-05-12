/*
 * Simple but effective hack to test the kernel.o file.
 * It takes on stdin the output from "netstat -f inet -n | grep ESTAB"
 * in either Solaris 2.x (non-standard formats can easily be converted
 * to this)
 *	laddr.lport faddr.fport .....
 * or BSD 4.x (the defacto standard netstat output):
 *	tcp <num> <num>  laddr.lport faddr.fport
 * format.
 *
 * The output must be numeric, as non-numeric output is truncated when
 * hostnames get too long and ambiguous.  And we don't want netstat to
 * first convert numbers to names and then this program to convert
 * names back to numbers.
 *
 * Casper Dik (casper@fwi.uva.nl)
 */

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#ifdef sequent
#include <strings.h>
#define strrchr rindex
#else
#include <string.h>
#include <stdlib.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "pidentd.h"


int debug = 0;


#ifdef sequent
char *strtok(str, dels)
    char *str;
    char *dels;
{
  static char *bufp;
  

  if (str)
    bufp = str;

  if (!bufp || !*bufp)
    return (char *) 0;;

  while (*bufp && index(dels, *bufp) != (char *) 0)
    ++bufp;

  str = bufp;
  
  while (*bufp && index(dels, *bufp) == (char *) 0)
    ++bufp;
  
  if (*bufp)
    *bufp++ = '\0';

  return str;
}
#endif

int
parse_addr(struct sockaddr_gen *addr, char *loc)
{
    char *tmp = strrchr(loc,'.');
    int af;

    if (tmp == NULL)
	return -1;

    *tmp++ ='\0';

#ifdef HAVE_IPV6
    SGFAM(*addr) = strchr(loc, ':') != 0 ? AF_INET6 : AF_INET;
    if (inet_pton(SGFAM(*addr), loc, SGADDRP(*addr)) != 1)
	return -1;
#else
    addr->sin_family = AF_INET;
    ((struct in_addr *) SGADDRP(*addr))->s_addr = inet_addr(loc);
#endif
    SGPORT(*addr) = htons(atoi(tmp));
    return 0;
}

int
main(int argc, char **argv)
{
    int c;
    char buf[500];
    int try;
    void *kp;


    while ((c = getopt(argc, argv, "d")) != -1) {
        switch (c)
	{
	  case 'd':
	    debug++;
	    break;
	  default:
	    fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
	    return 1;
	}
    }

    if (ka_init()) {
	fprintf(stderr,
		"%s: OS version mismatch - compiled for: %s\n",
		argv[0], osinfo_build);
	return 1;
    }
    if (ka_open(&kp) < 0) {
        fprintf(stderr, "%s: Cannot open kernel memory\n", argv[0]);
	return 1;
    }

    while (fgets(buf,sizeof(buf),stdin)) {
	char *loc, *rem, *tmp;
	unsigned short lport, fport;
	struct in_addr faddr, laddr;
        struct kernel k;
	struct passwd *pwd;
	char buf2[sizeof(buf)];

	strcpy(buf2,buf);

	loc = strtok(buf, " \t");
	if (strcmp(loc,"tcp") == 0) {
	    int i;
	    for (i = 0; i < 3; i++)
		loc = strtok(NULL, " \t");
	}
	rem = strtok(NULL, " \t");
	if (loc == NULL || rem == NULL) {
	    fprintf(stderr,"Malformed line: %s\n", buf2);
	    continue;
	}
	/* parse remote, local address */
	if (parse_addr(&k.local, loc) != 0) {
	    fprintf(stderr,"Malformed line: %s\n", buf2);
	    continue;
	}
	if (parse_addr(&k.remote, rem) != 0) {
	    fprintf(stderr,"Malformed line: %s\n", buf2);
	    continue;
	}

	k.status = -1;
	k.euid = -1;
	k.ruid = -1;
	k.pid = -1;
	k.cmd = NULL;
	k.argv = NULL;

	lport = ntohs(SGPORT(k.local));
	fport = ntohs(SGPORT(k.remote));

	for (try = 0; try < 5; try++)
	  {
	    k.status = ka_lookup(kp, &k);
	    if (k.status>0)
	      break;
	  }

	if (k.status<=0)
	  {
	    fprintf(stderr,"%-9.9s\t%-13s\t%-4d\t%-13s\t%-4d\n", 
		    "*unknown*", loc, lport, rem, fport);
	    continue;
	  }

	pwd = getpwuid(k.ruid);
	if (pwd)
	    printf("%-8.8s[%d]", pwd->pw_name, k.euid);
	else
	    printf("%-8.8d[%d]", k.ruid, k.euid);
	if (k.cmd)
	{
	  printf (" \t%-13s\t%-4d\t%-13s\t%-4d\tPID=%d\tCMD=%s\tCMD+ARG=%s\n",
		  loc, lport, rem, fport, k.pid, k.cmd, k.argv);
	  s_free(k.cmd); s_free(k.argv);
	}
	else
	  printf (" \t%-13s\t%-4d\t%-13s\t%-4d pid[%d]\n",
		  loc, lport, rem, fport, k.pid);

    }

    return 0;
}
