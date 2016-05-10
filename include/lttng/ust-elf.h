#ifndef _LTTNG_UST_ELF_H
#define _LTTNG_UST_ELF_H
/*
 * Copyright (C) 2015  Antoine Busque <abusque@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <byteswap.h>
#include <elf.h>
#include <lttng/ust-endian.h>

/*
 * Determine native endianness in order to convert when reading an ELF
 * file if there is a mismatch.
 */
#if BYTE_ORDER == LITTLE_ENDIAN
#define NATIVE_ELF_ENDIANNESS ELFDATA2LSB
#else
#define NATIVE_ELF_ENDIANNESS ELFDATA2MSB
#endif

/*
 * The size in bytes of the debug link CRC as contained in an ELF
 * section.
 */
#define ELF_CRC_SIZE		4
/*
 * ELF notes are aligned on 4 bytes. ref: ELF specification version
 * 1.1 p. 2-5.
 */
#define ELF_NOTE_ENTRY_ALIGN	4
/*
 * Within an ELF note, the `desc` field is also aligned on 4
 * bytes. ref: ELF specification version 1.1 p. 2-5.
 */
#define ELF_NOTE_DESC_ALIGN	4

#define bswap(x)				\
	do {					\
		switch (sizeof(x)) {		\
		case 8:				\
			x = bswap_64(x);	\
			break;			\
		case 4:				\
			x = bswap_32(x);	\
			break;			\
		case 2:				\
			x = bswap_16(x);	\
			break;			\
		case 1:				\
			break;			\
		default:			\
			abort();		\
		}				\
	} while (0)

#define bswap_phdr(phdr)		\
	do {				\
		bswap((phdr).p_type);	\
		bswap((phdr).p_offset); \
		bswap((phdr).p_filesz); \
		bswap((phdr).p_memsz);	\
		bswap((phdr).p_align);	\
		bswap((phdr).p_vaddr);	\
	} while (0)

#define bswap_shdr(shdr)		    \
	do {				    \
		bswap((shdr).sh_name);	    \
		bswap((shdr).sh_type);	    \
		bswap((shdr).sh_flags);	    \
		bswap((shdr).sh_addr);	    \
		bswap((shdr).sh_offset);    \
		bswap((shdr).sh_size);	    \
		bswap((shdr).sh_link);	    \
		bswap((shdr).sh_info);	    \
		bswap((shdr).sh_addralign); \
		bswap((shdr).sh_entsize);   \
	} while (0)

#define bswap_ehdr(ehdr)				\
	do {						\
		bswap((ehdr).e_type);			\
		bswap((ehdr).e_machine);		\
		bswap((ehdr).e_version);		\
		bswap((ehdr).e_entry);			\
		bswap((ehdr).e_phoff);			\
		bswap((ehdr).e_shoff);			\
		bswap((ehdr).e_flags);			\
		bswap((ehdr).e_ehsize);			\
		bswap((ehdr).e_phentsize);		\
		bswap((ehdr).e_phnum);			\
		bswap((ehdr).e_shentsize);		\
		bswap((ehdr).e_shnum);			\
		bswap((ehdr).e_shstrndx);		\
	} while (0)

#define copy_phdr(src_phdr, dst_phdr)				\
	do {							\
		(dst_phdr).p_type = (src_phdr).p_type;		\
		(dst_phdr).p_offset = (src_phdr).p_offset;	\
		(dst_phdr).p_filesz = (src_phdr).p_filesz;	\
		(dst_phdr).p_memsz = (src_phdr).p_memsz;	\
		(dst_phdr).p_align = (src_phdr).p_align;	\
		(dst_phdr).p_vaddr = (src_phdr).p_vaddr;	\
	} while (0)

#define copy_shdr(src_shdr, dst_shdr)					\
	do {								\
		(dst_shdr).sh_name = (src_shdr).sh_name;		\
		(dst_shdr).sh_type = (src_shdr).sh_type;		\
		(dst_shdr).sh_flags = (src_shdr).sh_flags;		\
		(dst_shdr).sh_addr = (src_shdr).sh_addr;		\
		(dst_shdr).sh_offset = (src_shdr).sh_offset;		\
		(dst_shdr).sh_size = (src_shdr).sh_size;		\
		(dst_shdr).sh_link = (src_shdr).sh_link;		\
		(dst_shdr).sh_info = (src_shdr).sh_info;		\
		(dst_shdr).sh_addralign = (src_shdr).sh_addralign;	\
		(dst_shdr).sh_entsize = (src_shdr).sh_entsize;		\
	} while (0)

#define copy_ehdr(src_ehdr, dst_ehdr)					\
	do {								\
		(dst_ehdr).e_type = (src_ehdr).e_type;			\
		(dst_ehdr).e_machine = (src_ehdr).e_machine;		\
		(dst_ehdr).e_version = (src_ehdr).e_version;		\
		(dst_ehdr).e_entry = (src_ehdr).e_entry;		\
		(dst_ehdr).e_phoff = (src_ehdr).e_phoff;		\
		(dst_ehdr).e_shoff = (src_ehdr).e_shoff;		\
		(dst_ehdr).e_flags = (src_ehdr).e_flags;		\
		(dst_ehdr).e_ehsize = (src_ehdr).e_ehsize;		\
		(dst_ehdr).e_phentsize = (src_ehdr).e_phentsize;	\
		(dst_ehdr).e_phnum = (src_ehdr).e_phnum;		\
		(dst_ehdr).e_shentsize = (src_ehdr).e_shentsize;	\
		(dst_ehdr).e_shnum = (src_ehdr).e_shnum;		\
		(dst_ehdr).e_shstrndx = (src_ehdr).e_shstrndx;		\
	} while (0)

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

static inline
int is_elf_32_bit(struct lttng_ust_elf *elf)
{
	return elf->bitness == ELFCLASS32;
}

static inline
int is_elf_native_endian(struct lttng_ust_elf *elf)
{
	return elf->endianness == NATIVE_ELF_ENDIANNESS;
}

struct lttng_ust_elf *lttng_ust_elf_create(const char *path);
void lttng_ust_elf_destroy(struct lttng_ust_elf *elf);
uint8_t lttng_ust_elf_is_pic(struct lttng_ust_elf *elf);
int lttng_ust_elf_get_memsz(struct lttng_ust_elf *elf, uint64_t *memsz);
int lttng_ust_elf_get_build_id(struct lttng_ust_elf *elf, uint8_t **build_id,
			size_t *length, int *found);
int lttng_ust_elf_get_debug_link(struct lttng_ust_elf *elf, char **filename,
			uint32_t *crc, int *found);

#endif	/* _LTTNG_UST_ELF_H */
