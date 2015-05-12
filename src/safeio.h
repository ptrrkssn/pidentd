/*
** safeio.h - Signal/Async safe wrapper functions
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

#ifndef PIDENTD_SAFEIO_H
#define PIDENTD_SAFEIO_H

extern void s_abort(void);

extern int s_open(const char *path, int oflag, ...);

extern ssize_t s_write(int fd, const char *buf, size_t len);
extern ssize_t s_read(int fd, char *buf, size_t len);
extern int s_close(int fd);

extern int s_accept(int fd, struct sockaddr *, socklen_t *len);
extern int s_getsockname(int fd, struct sockaddr *sin, socklen_t *len);
extern int s_getpeername(int fd, struct sockaddr *sin, socklen_t *len);

extern void *s_malloc(size_t size);
extern void s_free(void *p);
extern char *s_strdup(const char *s);

extern long s_random(void);

extern int s_snprintf(char *buf,
		      size_t bufsize,
		      const char *format, ...);

#endif
