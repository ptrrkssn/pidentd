/*
** k_dummy.c - A dummy (demonstration) kernel access module
**
** Copyright (c) 1997 Peter Eriksson <pen@lysator.liu.se>
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

#include "pidentd.h"

/*
** ka_init should verify that the binary is running on a
** supported OS version (in most cases it should verify
** that it is running on exactly the same version as it was
** compiled on).
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
** ka_open should open any kernel file descriptors or other
** resources needed to access it, put it into some dynamically
** allocated structure and store it into the 'misc' pointer.
**
** It should return 0 if all was OK, else -1
*/
int
ka_open(void **misc)
{
    *misc = NULL;
    return 0;
}



/*
** ka_lookup gets called when a request thread wants to
** do a kernel lookup.
**
** The pointer returned from ka_init() is passed as the "vp" parameter.
** The local and remote address and port is available in the "kp"
** parameter.
**
** The function should set both the effective uid and real uid (if
** either one isn't available, return -1 in that return variable)
** variables in the "struct kernel" argument.
**
** This function should return a 1 if the lookup was successful,
** a zero if the connection wasn't found or a -1 in case an error
** occured (the call to ka_lookup() will be retried if -1 
** is returned a configurable number of times, but will fail
** immediately in case of a 0).
*/
int
ka_lookup(void *vp, struct kernel *kp)
{
    kp->euid = 12;
    kp->ruid = 121;
    
    return 1;
}
