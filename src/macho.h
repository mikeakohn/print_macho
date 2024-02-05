/*
  print_macho - The MachO file format analyzer.

  Copyright 2024 - Michael Kohn (mike@mikekohn.net)
  https://www.mikekohn.net/

  This program falls under the MIT license.

*/

#ifndef MACHO_H
#define MACHO_H

#include <stdint.h>

#define MACHO_VAX     0x00000001
#define MACHO_ROMP    0x00000002
#define MACHO_NS32032 0x00000004
#define MACHO_NS32332 0x00000005
#define MACHO_MC680X0 0x00000006
#define MACHO_X86     0x00000007
#define MACHO_MIPS    0x00000008
#define MACHO_NS32352 0x00000009
#define MACHO_MC98000 0x0000000a
#define MACHO_HP_PA   0x0000000b
#define MACHO_ARM     0x0000000c
#define MACHO_MC88000 0x0000000d
#define MACHO_SPARC   0x0000000e
#define MACHO_I860_BE 0x0000000f
#define MACHO_I860_LE 0x00000010
#define MACHO_RS6000  0x00000011
#define MACHO_POWERPC 0x00000012

typedef struct MachoHeader
{
  uint32_t magic_number;
  uint32_t cpu_type;
  uint32_t cpu_subtype;
  uint32_t file_type;
  uint32_t load_command_count;
  uint32_t load_command_size;
  uint32_t flags;
  uint32_t reserved;
} MachoHeader;

typedef struct MachoLoadCommand
{
  uint32_t type;
  uint32_t size;
} MachoLoadCommand;

typedef struct MachoSegmentLoad
{
  char name[16];
  uint64_t address;
  uint64_t address_size;
  uint64_t file_offset;
  uint64_t file_size;
  uint32_t protection_max;
  uint32_t protection_initial;
  uint32_t section_count;
  uint32_t flag;
} MachoSegmentLoad;

typedef struct MachoSection
{
  char section_name[16];
  char segment_name[16];
  uint64_t address;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t relocation_offset;
  uint32_t relocation_count;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
} MachoSection;

typedef struct MachoSymtab
{
  uint32_t symbol_table_offset;
  uint32_t symbol_count;
  uint32_t string_table_offset;
  uint32_t string_table_size;
} MachoSymtab;

typedef struct MachoSymbol
{
  uint32_t string_index;
  uint8_t type;
  uint8_t section;
  uint16_t desc;
  uint64_t value;
} MachoSymbol;

typedef struct MachoDysymtab
{
  uint32_t local_sym_index;
  uint32_t local_sym_count;
  uint32_t external_sym_index;
  uint32_t external_sym_count;
  uint32_t undefined_sym_index;
  uint32_t undefined_sym_count;
  uint32_t toc_offset;
  uint32_t toc_count;
  uint32_t mod_table_offset;
  uint32_t mod_count;
  uint32_t ref_sym_offset;
  uint32_t ref_sym_count;
  uint32_t indirect_sym_index;
  uint32_t indirect_sym_count;
  uint32_t external_reloc_offset;
  uint32_t external_reloc_count;
  uint32_t local_reloc_offset;
  uint32_t local_reloc_count;
} MachoDysymtab;

int macho_read_header(MachoHeader *macho_header, FILE *fp);
int macho_read_load_command(MachoLoadCommand *macho_load_command, FILE *fp);
int macho_read_segment_load(MachoSegmentLoad *macho_segement_load, FILE *fp, int bits);
int macho_read_section(MachoSection *macho_section, FILE *fp, int bits);
int macho_read_symtab(MachoSymtab *macho_symtab, FILE *fp);
int macho_read_symbol(MachoSymbol *macho_symbol, FILE *fp, int bits);
int macho_read_dysymtab(MachoDysymtab *macho_symtab, FILE *fp);

void macho_print_header(MachoHeader *macho_header);
void macho_print_load_command(MachoLoadCommand *macho_load_command);
void macho_print_segment_load(MachoSegmentLoad *macho_segment_load);
void macho_print_section(MachoSection *macho_section);
void macho_print_symtab(MachoSymtab *macho_symtab, FILE *fp, int bits);
void macho_print_symbol(MachoSymbol *macho_symbol, FILE *fp, long symtab);
void macho_print_dysymtab(MachoDysymtab *macho_dysymtab, FILE *fp);

#endif

