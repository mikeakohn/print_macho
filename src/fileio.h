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

uint64_t read_uint64(FILE *in);
int read_uint32(FILE *in);
int read_uint16(FILE *in);
int read_uint8(FILE *in);

#endif

