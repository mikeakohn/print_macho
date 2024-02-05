/*
  print_macho - The MachO file format analyzer.

  Copyright 2024 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the MIT license.

*/

#ifndef FILEIO_H
#define FILEIO_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "fileio.h"

uint64_t read_uint64(FILE *in)
{
  uint64_t c;

  c = (uint64_t)getc(in);
  c |= (uint64_t)getc(in) << 8;
  c |= (uint64_t)getc(in) << 16;
  c |= (uint64_t)getc(in) << 24;
  c |= (uint64_t)getc(in) << 32;
  c |= (uint64_t)getc(in) << 40;
  c |= (uint64_t)getc(in) << 48;
  c |= (uint64_t)getc(in) << 56;

  return c;
}

int read_uint32(FILE *in)
{
  int c;

  c = getc(in);
  c |= getc(in) << 8;
  c |= getc(in) << 16;
  c |= getc(in) << 24;

  return c;
}

int read_uint16(FILE *in)
{
  int c;

  c = getc(in);
  c |= getc(in) << 8;

  return c;
}

int read_uint8(FILE *in)
{
  int c;

  c = getc(in);

  return c;
}

#endif

