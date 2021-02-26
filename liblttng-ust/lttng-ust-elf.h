/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 */

#ifndef _LIB_LTTNG_UST_ELF_H
#define _LIB_LTTNG_UST_ELF_H

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

#endif
