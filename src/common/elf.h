/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 */

#ifndef _UST_COMMON_ELF_H
#define _UST_COMMON_ELF_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

struct lttng_ust_elf_ehdr {
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct lttng_ust_elf_phdr {
	uint32_t p_type;
	uint64_t p_offset;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
	uint64_t p_vaddr;
};

struct lttng_ust_elf_shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
};

struct lttng_ust_elf_nhdr {
	uint32_t n_namesz;
	uint32_t n_descsz;
	uint32_t n_type;
};

struct lttng_ust_elf {
	/* Offset in bytes to start of section names string table. */
	off_t section_names_offset;
	/* Size in bytes of section names string table. */
	size_t section_names_size;
	char *path;
	int fd;
	struct lttng_ust_elf_ehdr *ehdr;
	uint8_t bitness;
	uint8_t endianness;
};

struct lttng_ust_elf *lttng_ust_elf_create(const char *path);
void lttng_ust_elf_destroy(struct lttng_ust_elf *elf);
uint8_t lttng_ust_elf_is_pic(struct lttng_ust_elf *elf);
int lttng_ust_elf_get_memsz(struct lttng_ust_elf *elf, uint64_t *memsz);
int lttng_ust_elf_get_build_id(struct lttng_ust_elf *elf, uint8_t **build_id,
			size_t *length, int *found);
int lttng_ust_elf_get_debug_link(struct lttng_ust_elf *elf, char **filename,
			uint32_t *crc, int *found);

#endif	/* _UST_COMMON_ELF_H */
