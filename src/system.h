/*
** system.h - Compatibility definitions for various systems.
**
** Copyright (c) 1998 Rainer Orth <ro@TechFak.Uni-Bielefeld.DE>
**		 1997 Peter Eriksson <pen@lysator.liu.se>
**
** This program is free software; you can redistribute it and/or
** modify it as you wish - as long as you don't claim that you wrote
** it.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#ifndef PIDENTD_SYSTEM_H
#define PIDENTD_SYSTEM_H

#ifndef F_OK
#define F_OK 0
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7F000001U
#endif

#ifndef IPPORT_IDENT
#define IPPORT_IDENT 113
#endif

#ifndef LOG_ODELAY
#define LOG_ODELAY 0
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#endif
