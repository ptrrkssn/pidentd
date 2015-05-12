/*
** idecrypt.c - Encrypted IDENT response decryption utility.
**
** Copyright (c) 1997-2000 Peter Eriksson <pen@lysator.liu.se>
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

#include <string.h>

#ifdef HAVE_LIBDES

#include <stdio.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/time.h>

#ifdef HAVE_DES_H
#include <des.h>
#elif HAVE_OPENSSL_DES_H
#include <openssl/des.h>
#endif

#include "pidentd.h"

int debug = 0; /* for linking with safeio.o */

static char *keyfile_path = PATH_KEYFILE;

static char
is_base_64 [] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static unsigned char
to_bin[] =
{
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x3e, 0x80, 0x80, 0x80, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x80, 0x80, 0x80, 0x80, 0x80,
};




static char *
decrypt_packet(unsigned char *packet)
{
    union data r;
    int i, j;
    time_t date_in_sec;
    char *date_in_ascii;
    char keybuf[1024+1];
    char buf1[32], buf2[32];
    struct sockaddr_gen ip_local, ip_remote;
    int keyfile_fd;
    des_cblock key_bin;
    des_key_schedule sched;
    static char readable[256];
    

    keyfile_fd = open(keyfile_path, O_RDONLY);
    if (keyfile_fd < 0)
    {
	fprintf(stderr, "open: ");
	perror(keyfile_path);
	exit(1);
    }

    /* Try to decrypt with each key found in the key file */
    
    while (read(keyfile_fd, keybuf, sizeof(keybuf)-1) == sizeof(keybuf)-1)
    {
	keybuf[sizeof(keybuf)-1] = '\0';
	des_string_to_key(keybuf, &key_bin);
	des_set_key(&key_bin, sched);
	
	
	for (i = 0, j = 0; i < 24; i += 3, j += 4)
	{
	    r.chars[i  ] = (to_bin[packet[j  ]] << 2) + (to_bin[packet[j+1]] >> 4);
	    r.chars[i+1] = (to_bin[packet[j+1]] << 4) + (to_bin[packet[j+2]] >> 2);
	    r.chars[i+2] = (to_bin[packet[j+2]] << 6) + (to_bin[packet[j+3]]);
	}
    
	des_ecb_encrypt((des_cblock *)&(r.longs[4]),
			(des_cblock *)&(r.longs[4]),
			sched, DES_DECRYPT);
	r.longs[4] ^= r.longs[2];
	r.longs[5] ^= r.longs[3];
	
	des_ecb_encrypt((des_cblock *)&(r.longs[2]),
			(des_cblock *)&(r.longs[2]),
			sched, DES_DECRYPT);
	
	r.longs[2] ^= r.longs[0];
	r.longs[3] ^= r.longs[1]; 
	des_ecb_encrypt((des_cblock *)&(r.longs[0]),
			(des_cblock *)&(r.longs[0]),
			sched, DES_DECRYPT);

	for (i = 1; i < 6; i++)
	{
	    r.longs[0] ^= r.longs[i];
	}
	
	if (r.fields.checksum == 0)
	    goto GoodKey;
    }
    close(keyfile_fd);
    return NULL;
    
  GoodKey:
    date_in_sec = ntohl(r.fields.date);
    date_in_ascii = ctime(&date_in_sec);
    
    memcpy(SGADDRP(ip_local), &(r.fields.ip_local), sizeof(ip_local));
    memcpy(SGADDRP(ip_remote), &(r.fields.ip_remote), sizeof(ip_remote));

    /* FIXME: uid_t isn't necessarily short.  */
#ifdef HAVE_SNPRINTF
    snprintf(readable, sizeof(readable),
#else
    sprintf(readable,
#endif
            "%24.24s %u %s %u %s %u",
	    date_in_ascii,
	    ntohs(r.fields.uid),
	    s_inet_ntox(&ip_local, buf1, sizeof(buf1)),
	    (unsigned) ntohs(r.fields.port_local),
	    s_inet_ntox(&ip_remote, buf2, sizeof(buf2)),
	    (unsigned) ntohs(r.fields.port_remote));
    
    close(keyfile_fd);
    return readable;
}


static void
decrypt_file(FILE *f)
{
    int c;
    int i;
    char buf[32];
    char *result;

    
    while (1)
    {
	c = getc(f);
	
      Same:
	if (c == EOF)
	    return;
	
	if (c != '[')
	{
	    putchar(c);
	    continue;
	}
	
	for (i = 0; i < 32; i++)
	{
	    c = getc(f);
	    if (c == EOF || c < 0 || c > 255)
		break;
	    if (!is_base_64[c])
		break;
	    buf[i] = c;
	}
	
	if (i == 32)
	    c = getc(f);
	
	if (i < 32 || c != ']')
	{
	    putchar('[');
	    fwrite(buf, 1, i, stdout);
	    goto Same;
	}
	
	
	if ((result = decrypt_packet((unsigned char *) buf)) == NULL)
	{
	    putchar('[');
	    fwrite(buf, 1, 32, stdout);
	    putchar(']');
	}
	else
	{
	    fputs(result, stdout);
	}
    }
}


int
main(int argc,
     char *argv[])
{
    int i;
    FILE *f;


    if (argc < 2)
	decrypt_file(stdin);
    else
    {
	for (i = 1; i < argc; i++)
	{
	    if (!strcmp(argv[i], "-"))
	    {
		decrypt_file(stdin);
		continue;
	    }
	    
	    f = fopen(argv[i], "r");
	    if (f == NULL)
	    {
		perror(argv[i]);
		continue;
	    }
	    
	    decrypt_file(f);
	    fclose(f);
	}
    }
    
    exit(0);
}

#else /* no HAVE_LIBDES */

#error Need a DES library to compile Idecrupt.

#endif
