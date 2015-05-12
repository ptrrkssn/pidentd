/*
** pkvm.h - Partial Kernel "Virtual" Memory access function emulation.
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

#ifndef KVM_H
#define KVM_H

typedef struct
{
    int fd;
    char *namelist;
} kvm_t;


extern kvm_t *kvm_open(const char *namelist,
		       const char *corefile,
		       const char *swapfile,
		       int flag,
		       const char *errstr);

extern int kvm_close(kvm_t *kd);

struct nlist;
extern int kvm_nlist(kvm_t *kd, struct nlist *nl);

extern ssize_t kvm_read(kvm_t *kd,
			off_t addr,
			void *buf,
			size_t len);
#endif
