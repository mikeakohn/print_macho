/*
  print_macho - The MachO file format analyzer.

  Copyright 2024 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the MIT license.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "fileio.h"
#include "macho.h"

const char *cpu_type[] =
{
  "???",
  "VAX",
  "ROMP",
  "???",
  "NS32032",
  "NS32332",
  "MC680x0",
  "x86",
  "MIPS",
  "NS32352",
  "MC98000",
  "HP-PA",
  "ARM",
  "MC88000",
  "SPARC",
  "I860/BE",
  "I860/LE",
  "RS/6000",
  "PowerPC",
};

const char *cpu_subtype_arm[] =
{
  "All ARM processors.",
  "Optimized for ARM-A500 ARCH or newer.",
  "Optimized for ARM-A500 or newer.",
  "Optimized for ARM-A440 or newer.",
  "Optimized for ARM-M4 or newer.",
  "Optimized for ARM-V4T or newer.",
  "Optimized for ARM-V6 or newer.",
  "Optimized for ARM-V5TEJ or newer.",
  "Optimized for ARM-XSCALE or newer.",
  "Optimized for ARM-V7 or newer.",
  "Optimized for ARM-V7F (Cortex A9) or newer.",
  "Optimized for ARM-V7S (Swift) or newer.",
  "Optimized for ARM-V7K (Kirkwood40) or newer.",
  "Optimized for ARM-V8 or newer.",
  "Optimized for ARM-V6M or newer.",
  "Optimized for ARM-V7M or newer.",
  "Optimized for ARM-V7EM or newer.",
};

const char *file_type[] =
{
  "???",
  "Relocatable object",
  "Demand paged executable",
  "Fixed VM shared library",
  "Core",
  "Preloaded executable",
  "Dynamically bound shared library",
  "Dynamic link editor",
  "Dynamically bound bundle",
  "Shared library stub for static linking",
  "Companion file with only debug sections",
  "x86_64 kexts",
  "Composite MachOs",
};

const char *get_cpu_type(int value)
{
  int max = sizeof(cpu_type) / sizeof(char *);

  if ((value & 0x01000000) == 0x01000000) { value = value ^ 0x01000000; }
  if (value >= max) { return "???"; }

  return cpu_type[value];
}

const char *get_cpu_subtype_arm(int value)
{
  int max = sizeof(cpu_subtype_arm) / sizeof(char *);
  if (value >= max) { return "???"; }

  return cpu_subtype_arm[value];
}

const char *get_cpu_subtype_x86(int value)
{
  switch (value)
  {
    case 0x03: return "All x86 processors.";
    case 0x04: return "Optimized for 486 or newer.";
    case 0x84: return "Optimized for 486SX or newer.";
    case 0x56: return "Optimized for Pentium M5 or newer.";
    case 0x67: return "Optimized for Celeron or newer.";
    case 0x77: return "Optimized for Celeron Mobile.";
    case 0x08: return "Optimized for Pentium 3 or newer.";
    case 0x18: return "Optimized for Pentium 3-M or newer.";
    case 0x28: return "Optimized for Pentium 3-XEON or newer.";
    case 0x0a: return "Optimized for Pentium-4 or newer.";
    case 0x0b: return "Optimized for Itanium or newer.";
    case 0x1b: return "Optimized for Itanium-2 or newer.";
    case 0x0c: return "Optimized for XEON or newer.";
    case 0x1c: return "Optimized for XEON-MP or newer.";
    default: return "???";
  }
}

const char *get_cpu_subtype(int cpu_type, int cpu_subtype)
{
  switch (cpu_type)
  {
    case MACHO_ARM: return get_cpu_subtype_arm(cpu_subtype);
    case MACHO_X86: return get_cpu_subtype_x86(cpu_subtype);
    default: return "";
  }
}

const char *get_file_type(int value)
{
  int max = sizeof(file_type) / sizeof(char *);
  if (value >= max) { return "???"; }

  return file_type[value];
}

int macho_read_header(MachoHeader *macho_header, FILE *fp)
{
  memset(macho_header, 0, sizeof(MachoHeader));

  macho_header->magic_number = read_uint32(fp);

  if (macho_header->magic_number != 0xfeedface &&
      macho_header->magic_number != 0xfeedfacf)
  {
    return -1;
  }

  macho_header->cpu_type = read_uint32(fp);
  macho_header->cpu_subtype = read_uint32(fp);
  macho_header->file_type = read_uint32(fp);
  macho_header->load_command_count = read_uint32(fp);
  macho_header->load_command_size = read_uint32(fp);
  macho_header->flags = read_uint32(fp);

  // 64 bit files have 4 extra bytes (probably for alignment).
  if (macho_header->magic_number == 0xfeedfacf)
  {
    macho_header->reserved = read_uint32(fp);
  }

  return 0;
}

int macho_read_load_command(MachoLoadCommand *macho_load_command, FILE *fp)
{
  macho_load_command->type = read_uint32(fp);
  macho_load_command->size = read_uint32(fp);

  return 0;
}

int macho_read_segment_load(MachoSegmentLoad *macho_segment_load, FILE *fp, int bits)
{
  if (fread(macho_segment_load->name, 1, 16, fp) != 16) { return -1; }

  if (bits == 32)
  {
    macho_segment_load->address = read_uint32(fp);
    macho_segment_load->address_size = read_uint32(fp);
    macho_segment_load->file_offset = read_uint32(fp);
    macho_segment_load->file_size = read_uint32(fp);
  }
    else
  {
    macho_segment_load->address = read_uint64(fp);
    macho_segment_load->address_size = read_uint64(fp);
    macho_segment_load->file_offset = read_uint64(fp);
    macho_segment_load->file_size = read_uint64(fp);
  }

  macho_segment_load->protection_max = read_uint32(fp);
  macho_segment_load->protection_initial = read_uint32(fp);
  macho_segment_load->section_count = read_uint32(fp);
  macho_segment_load->flag = read_uint32(fp);

  return 0;
}

int macho_read_section(MachoSection *macho_section, FILE *fp, int bits)
{
  if (fread(macho_section->section_name, 1, 16, fp) != 16) { return -1; }
  if (fread(macho_section->segment_name, 1, 16, fp) != 16) { return -1; }

  if (bits == 32)
  {
    macho_section->address = read_uint32(fp);
    macho_section->size = read_uint32(fp);
  }
    else
  {
    macho_section->address = read_uint64(fp);
    macho_section->size = read_uint64(fp);
  }

  macho_section->offset = read_uint32(fp);
  macho_section->align = read_uint32(fp);
  macho_section->relocation_offset = read_uint32(fp);
  macho_section->relocation_count = read_uint32(fp);
  macho_section->flags = read_uint32(fp);
  macho_section->reserved1 = read_uint32(fp);
  macho_section->reserved2 = read_uint32(fp);
  macho_section->reserved3 = read_uint32(fp);

  return 0;
}

int macho_read_symtab(MachoSymtab *macho_symtab, FILE *fp)
{
  macho_symtab->symbol_table_offset = read_uint32(fp);
  macho_symtab->symbol_count = read_uint32(fp);
  macho_symtab->string_table_offset = read_uint32(fp);
  macho_symtab->string_table_size = read_uint32(fp);

  return 0;
}

int macho_read_symbol(MachoSymbol *macho_symbol, FILE *fp, int bits)
{
  macho_symbol->string_index = read_uint32(fp);
  macho_symbol->type = read_uint8(fp);
  macho_symbol->section = read_uint8(fp);
  macho_symbol->desc = read_uint16(fp);

  if (bits == 32)
  {
    macho_symbol->value = read_uint32(fp);
  }
    else
  {
    macho_symbol->value = read_uint64(fp);
  }

  return 0;
}

int macho_read_dysymtab(MachoDysymtab *macho_dysymtab, FILE *fp)
{
  macho_dysymtab->local_sym_index = read_uint32(fp);
  macho_dysymtab->local_sym_count = read_uint32(fp);
  macho_dysymtab->external_sym_index = read_uint32(fp);
  macho_dysymtab->external_sym_count = read_uint32(fp);
  macho_dysymtab->undefined_sym_index = read_uint32(fp);
  macho_dysymtab->undefined_sym_count = read_uint32(fp);
  macho_dysymtab->toc_offset = read_uint32(fp);
  macho_dysymtab->toc_count = read_uint32(fp);
  macho_dysymtab->mod_table_offset = read_uint32(fp);
  macho_dysymtab->mod_count = read_uint32(fp);
  macho_dysymtab->ref_sym_offset = read_uint32(fp);
  macho_dysymtab->ref_sym_count = read_uint32(fp);
  macho_dysymtab->indirect_sym_index = read_uint32(fp);
  macho_dysymtab->indirect_sym_count = read_uint32(fp);
  macho_dysymtab->external_reloc_offset = read_uint32(fp);
  macho_dysymtab->external_reloc_count = read_uint32(fp);
  macho_dysymtab->local_reloc_offset = read_uint32(fp);
  macho_dysymtab->local_reloc_count = read_uint32(fp);

  return 0;
}

void macho_print_header(MachoHeader *macho_header)
{
  printf(" -- MachO Header --\n");
  printf("        magic_number: 0x%x\n", macho_header->magic_number);
  printf("            cpu_type: 0x%04x (%s%s)\n",
    macho_header->cpu_type,
    get_cpu_type(macho_header->cpu_type),
    (macho_header->cpu_type & 0x01000000) == 0x01000000 ? " 64bit" : "");
  printf("         cpu_subtype: 0x%04x (%s)\n",
    macho_header->cpu_subtype,
    get_cpu_subtype(macho_header->cpu_type, macho_header->cpu_subtype));
  printf("           file_type: %d (%s)\n",
    macho_header->file_type,
    get_file_type(macho_header->file_type));
  printf("  load_command_count: %d\n", macho_header->load_command_count);
  printf("   load_command_size: %d\n", macho_header->load_command_size);
  printf("               flags: %d\n", macho_header->flags);
  printf("            reserved: %d\n", macho_header->reserved);
  printf("\n");
}

void macho_print_load_command(MachoLoadCommand *macho_load_command)
{
  printf("  %08x %08x\n",
    macho_load_command->type,
    macho_load_command->size);
}

void macho_print_segment_load(MachoSegmentLoad *macho_segment_load)
{
  printf(" -- Segment Load --\n");
  printf("              name: %-16s\n", macho_segment_load->name);
  printf("           address: 0x%lx\n", macho_segment_load->address);
  printf("      address_size: %ld\n", macho_segment_load->address_size);
  printf("       file_offset: 0x%lx\n", macho_segment_load->file_offset);
  printf("         file_size: %ld\n", macho_segment_load->file_size);
  printf("    protection_max: %d\n", macho_segment_load->protection_max);
  printf("protection_initial: %d\n", macho_segment_load->protection_initial);
  printf("     section_count: %d\n", macho_segment_load->section_count);
  printf("              flag: %d\n", macho_segment_load->flag);
  printf("\n");
}

void macho_print_section(MachoSection *macho_section)
{
  printf(" -- Section --\n");

  printf("section_name: %-16s\n", macho_section->section_name);
  printf("segment_name: %-16s\n", macho_section->segment_name);
  printf("          address: 0x%04lx\n", macho_section->address);
  printf("             size: %ld\n", macho_section->size);
  printf("           offset: %d\n", macho_section->offset);
  printf("            align: %d\n", macho_section->align);
  printf("relocation_offset: %d\n", macho_section->relocation_offset);
  printf(" relocation_count: %d\n", macho_section->relocation_count);
  printf("            flags: %d\n", macho_section->flags);
  printf("        reserved1: %d\n", macho_section->reserved1);
  printf("        reserved2: %d\n", macho_section->reserved2);
  printf("        reserved3: %d\n", macho_section->reserved3);
  printf("\n");
}

void macho_print_symtab(MachoSymtab *macho_symtab, FILE *fp, int bits)
{
  printf(" -- Symbol Table --\n");

  printf("symbol_table_offset: 0x%04x\n", macho_symtab->symbol_table_offset);
  printf("       symbol_count: %d\n", macho_symtab->symbol_count);
  printf("string_table_offset: 0x%04x\n", macho_symtab->string_table_offset);
  printf("  string_table_size: %d\n", macho_symtab->string_table_size);
  printf("\n");

  long marker;
  int n;

  marker = ftell(fp);
  fseek(fp, macho_symtab->string_table_offset + 1, SEEK_SET);
  int length = 0;

  for (n = 1; n < macho_symtab->string_table_size; n++)
  {
    int ch = getc(fp);

    if (ch == 0)
    {
      printf("\n");
      if (length == 0) { break; }
      length = 0;
    }
      else
    {
      if (length == 0)
      {
        printf("%d) ", n);
      }

      printf("%c", ch);
      length++;
    }
  }

  fseek(fp, macho_symtab->symbol_table_offset, SEEK_SET);

  MachoSymbol macho_symbol;

  for (n = 0; n < macho_symtab->symbol_count; n++)
  {
    macho_read_symbol(&macho_symbol, fp, bits);
    macho_print_symbol(&macho_symbol, fp, macho_symtab->string_table_offset);
  }

  printf("\n");

  fseek(fp, marker, SEEK_SET);
}

void macho_print_symbol(MachoSymbol *macho_symbol, FILE *fp, long symtab)
{
  printf("0x%04x 0x%02x 0x%02x 0x%04x 0x%08lx ",
    macho_symbol->string_index,
    macho_symbol->type,
    macho_symbol->section,
    macho_symbol->desc,
    macho_symbol->value);

  long marker = ftell(fp);
  fseek(fp, symtab + macho_symbol->string_index, SEEK_SET);

  while (1)
  {
    int ch = getc(fp);
    if (ch == 0 || ch == EOF) { break; }
    printf("%c", ch);
  }

  fseek(fp, marker, SEEK_SET);

  printf("\n");
}

void macho_print_dysymtab(MachoDysymtab *macho_dysymtab, FILE *fp)
{
  printf(" -- Dysymtab --\n");
  printf("      local_sym_index: %d\n", macho_dysymtab->local_sym_index);
  printf("      local_sym_count: %d\n", macho_dysymtab->local_sym_count);
  printf("   external_sym_index: %d\n", macho_dysymtab->external_sym_index);
  printf("   external_sym_count: %d\n", macho_dysymtab->external_sym_count);
  printf("  undefined_sym_index: %d\n", macho_dysymtab->undefined_sym_index);
  printf("  undefined_sym_count: %d\n", macho_dysymtab->undefined_sym_count);
  printf("           toc_offset: 0x%04x\n", macho_dysymtab->toc_offset);
  printf("            toc_count: %d\n", macho_dysymtab->toc_count);
  printf("     mod_table_offset: 0x%04x\n", macho_dysymtab->mod_table_offset);
  printf("            mod_count: %d\n", macho_dysymtab->mod_count);
  printf("       ref_sym_offset: 0x%04x\n", macho_dysymtab->ref_sym_offset);
  printf("        ref_sym_count: %d\n", macho_dysymtab->ref_sym_count);
  printf("   indirect_sym_index: %d\n", macho_dysymtab->indirect_sym_index);
  printf("   indirect_sym_count: %d\n", macho_dysymtab->indirect_sym_count);
  printf("external_reloc_offset: 0x%04x\n", macho_dysymtab->external_reloc_offset);
  printf(" external_reloc_count: %d\n", macho_dysymtab->external_reloc_count);
  printf("   local_reloc_offset: 0x%04x\n", macho_dysymtab->local_reloc_offset);
  printf("    local_reloc_count: %d\n", macho_dysymtab->local_reloc_count);
  printf("\n");
}

