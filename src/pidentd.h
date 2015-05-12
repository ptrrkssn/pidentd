/*
** pidentd.h - Definitions needing global visibility
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

#ifndef PIDENTD_H
#define PIDENTD_H

#include "s_pthread.h"

#include "buffer.h"
#include "avail.h"
#include "daemon.h"
#include "sockaddr.h"
#include "kernel.h"
#include "request.h"
#include "server.h"
#include "send.h"
#include "safeio.h"
#include "support.h"
#include "conf.h"
#include "str2.h"
#include "timeout.h"

#ifdef HAVE_LIBDES
#include "pdes.h"
#endif

#include "system.h"

#ifndef PATH_SYSCONFDIR
#define PATH_SYSCONFDIR "/etc"
#endif

#ifndef PATH_PIDFILE
#define PATH_PIDFILE "/etc/identd.pid"
#endif

#ifndef PATH_CFGFILE
#define PATH_CFGFILE PATH_SYSCONFDIR "/identd.conf"
#endif

#define NO_PID ((pid_t) -1)
#define INIT_PID 1

#define NO_UID ((uid_t) -1)
#define ROOT_UID 0
#define ROOT_GID 0

extern int debug;
extern uid_t server_uid;
extern gid_t server_gid;
extern char *argv0;

#ifdef HAVE_LIBDES

#ifndef PATH_KEYFILE
#define PATH_KEYFILE PATH_SYSCONFDIR "/identd.key"
#endif

extern int encrypt_flag;
extern char *encrypt_keyfile;

#endif

extern char *pidfile_path;
extern char server_version[];
extern pthread_attr_t cattr_detached;

#endif
