/*
** ikeygen.c - Generate a random DES key
**
** Copyright (c) 1999 Peter Eriksson <pen@lysator.liu.se>
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

#ifdef HAVE_LIBDES

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_RAND_H
#include <rand.h>
#elif HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#include "pidentd.h"

static int verbose = 0;
static char *keyfile_path = PATH_KEYFILE;
static int crypto_v0_bugfix = 1;

static void
read_dev_random(unsigned char *keybuf, int length)
{
  int dev_random;
  int bytes_read = 0;
  int total_bytes_read = 0;
  int bytes_to_read = length;
  unsigned char *index;

  if ( (dev_random = open("/dev/random", O_RDONLY)) == -1 ) {
    perror("unable to read /dev/random");
    exit(1);
  }
  while (index < keybuf + length) {
    bytes_read = read(dev_random, keybuf, bytes_to_read);
    if (bytes_read < 0) {
      perror("error reading /dev/random");
      exit(1);
    } else {
      index += bytes_read;
      bytes_to_read -= bytes_read;
      total_bytes_read += bytes_read;
      if (verbose) 
	printf("Got %d bytes from /dev/random (%d out of %d done).\n",
	       bytes_read, total_bytes_read, length);
    }
  }
}

static void
make_random_key(unsigned char *keybuf)
{
    int i;
    
#ifdef HAVE_RAND_BYTES
    RAND_bytes(keybuf, 1024);
#elif HAVE_DEV_RANDOM
    read_dev_random(keybuf, 1024);
#else

    /* This is a BAD BAD BAD key generator */
    for (i = 0; i < 1024; i++)
	keybuf[i] = random() & 0xFF;
#endif

    if (crypto_v0_bugfix)
    {
	/* Yuk! The code assumes that the key buf contains a NUL
	   terminated string! */
	for (i = 0; i < 1024; i++)
	    while (keybuf[i] == 0)
		keybuf[i] = random() & 0xFF;
    }
}


static void
usage(FILE *fp)
{
    fputs("Usage: ikeygen [-h] [-V] [-v] [-iFILE] [KEYFILE]\n", fp);
    fputs("\t-h\tDisplay this information.\n", fp);
    fputs("\t-V\tPrint version and build information.\n", fp);
    fputs("\t-v\tBe verbose.\n", fp);
    fputs("\t-iFILE\tFile to copy DES key from.\n", fp);
}

void
program_header(FILE *fp)
{
    fprintf(fp, "[Ikeygen, version %s - %s %s]\n",
	    server_version, __DATE__, __TIME__);
}
    

int
main(int argc,
     char *argv[])
{
    int i, res;
    int keyfile_fd, fd;
    unsigned char key[1024];
    char *input_key_file = NULL;
    off_t keyfile_end_pos = 0;
    
    
    for (i = 1; i < argc && argv[i][0] == '-'; i++)
	switch (argv[i][1])
	{
	  case 'V':
	    program_header(stdout);
	    exit(EXIT_SUCCESS);
	    
	  case 'i':
	    input_key_file = argv[i]+2;
	    break;
	    
	  case 'v':
	    program_header(stdout);
	    verbose = 1;
	    break;
	    
	  case 'h':
	    usage(stdout);
	    exit(0);

	  default:
	    usage(stderr);
	    exit(1);
	}

    if (i < argc)
	keyfile_path = argv[i++];
    
    if (verbose)
	printf("Using key file: %s\n", keyfile_path);
    
    if (input_key_file)
    {
	if (verbose)
	    printf("Copying 1024 byte key from: %s\n", input_key_file);
	
	fd = open(input_key_file, O_RDONLY);
	if (fd < 0)
	{
	    fprintf(stderr, "open: ");
	    perror(input_key_file);
	    exit(1);
	}
	
	res = read(fd, key, sizeof(key));
	if (res < 0)
	{
	    perror("read(input_key_file)");
	    exit(1);
	}
	if (res != sizeof(key))
	{
	    fprintf(stderr, "read(input_key_file): too short\n");
	    exit(1);
	}
	close(fd);
    }
    else
    {
	if (verbose)
	    printf("Making random input key\n");
	
	make_random_key(key);
    }

    keyfile_fd = open(keyfile_path, O_RDWR|O_CREAT, 0600);
    if (keyfile_fd < 0)
    {
	fprintf(stderr, "ikeygen: open: ");
	perror(keyfile_path);
	exit(1);
    }

    keyfile_end_pos = lseek(keyfile_fd, 0, SEEK_END);
    if (keyfile_end_pos % 1024 != 0)
    {
	fprintf(stderr, "ikeygen: key file is corrupt\n");
	exit(1);
    }
    
    res = write(keyfile_fd, key, sizeof(key));
    if (res < 0)
    {
	perror("ikeygen: write(keyfile)");
	close(keyfile_fd);
	exit(1);
    }
    if (res != sizeof(key))
    {
#ifdef HAVE_FTRUNCATE
	ftruncate(keyfile_fd, keyfile_end_pos);
#endif
	fprintf(stderr,
		"ikeygen: write(keyfile): could not write a complete key\n");
	
	close(keyfile_fd);
	exit(1);
    }
    
    close(keyfile_fd);
    
    if (verbose)
	printf("Key file now contains %lu keys\n",
	       ((unsigned long) keyfile_end_pos / 1024)+1);
    exit(0);
}

#else

#error This program needs a usable DES library

#endif
