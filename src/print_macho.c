/*
  print_macho - The MachO file format analyzer.

  Copyright 2024 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the MIT license.

*/

#include <stdio.h>
#include <stdlib.h>

#include "macho.h"

int parse_macho(FILE *fp)
{
  MachoHeader macho_header;

  if (macho_read_header(&macho_header, fp) != 0)
  {
    printf("Error: Not a MachO file.\n");
    return -1;
  }

  macho_print_header(&macho_header);

  MachoLoadCommand macho_load_command;
  MachoSegmentLoad macho_segment_load;
  MachoSection macho_section;
  MachoSymtab macho_symtab;
  MachoDysymtab macho_dysymtab;

  int bits = (macho_header.cpu_type & 0x01000000) == 0x01000000 ? 64 : 32;
  int i, n;

  for (i = 0; i < macho_header.load_command_count; i++)
  {
    // printf("0x%04lx\n", ftell(fp));
    macho_read_load_command(&macho_load_command, fp);
    macho_print_load_command(&macho_load_command);

    switch (macho_load_command.type)
    {
      case 0x00000001:
      case 0x00000019:
        // LC_SEGMENT_32
        // LC_SEGMENT_64
        macho_read_segment_load(&macho_segment_load, fp, bits);
        macho_print_segment_load(&macho_segment_load);

        for (n = 0; n < macho_segment_load.section_count; n++)
        {
          macho_read_section(&macho_section, fp, bits);
          macho_print_section(&macho_section);
        }
        break;
      case 0x00000002:
        // LC_SYMTAB
        macho_read_symtab(&macho_symtab, fp);
        macho_print_symtab(&macho_symtab, fp, bits);
        break;
      case 0x0000000b:
        // LC_DYSYMTAB
        macho_read_dysymtab(&macho_dysymtab, fp);
        macho_print_dysymtab(&macho_dysymtab, fp);
        break;
      case 0x00000032:
        // build version?
        printf(" -- Build Version ? --\n");
        for (n = 0; n < macho_load_command.size - 8; n++)
        {
          if ((n % 8) == 0) { printf("\n"); }
          printf(" %02x", getc(fp));
        }
        printf("\n\n");
        break;
      default:
        fseek(fp, macho_load_command.size - 8, SEEK_CUR);
        break;
    }
  }

  printf("file offset: 0x%lx\n", ftell(fp));

  return 0;
}

int main(int argc, char *argv[])
{
  FILE *fp;

  printf(
    "\nprint_macho - Copyright 2024 by Michael Kohn <mike@mikekohn.net>\n"
    "https://www.mikekohn.net/\n"
    "Version: February 4, 2024\n\n");

  if (argc != 2)
  {
    printf("Usage: print_macho <filename.o>\n");
    exit(0);
  }

  fp = fopen(argv[1], "rb");

  if (fp == NULL)
  {
    printf("Error: Couldn't open %s\n", argv[1]);
    exit(1);
  }

  parse_macho(fp);

  fclose(fp);

  return 0;
}

