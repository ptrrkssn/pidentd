/*
** gen_osinfo.c - Generate the compile-time OS information.
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
#include <stdlib.h>

#include "pidentd.h"


int debug = 0;

int
main(int argc,
     char *argv[])
{
    char buf[256];
    
    printf("char osinfo_build[] = \"%s\";\n", osinfo_get(buf));
    return EXIT_SUCCESS;
}

