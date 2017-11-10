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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <helper.h>
#include <string.h>
#include <lttng/align.h>
#include <lttng/ust-elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <ust-fd.h>
#include "lttng-tracer-core.h"

#define BUF_LEN	4096

#ifndef NT_GNU_BUILD_ID
# define NT_GNU_BUILD_ID	3
#endif

/*
 * Retrieve the nth (where n is the `index` argument) phdr (program
 * header) from the given elf instance.
 *
 * A pointer to the phdr is returned on success, NULL on failure.
 */
static
struct lttng_ust_elf_phdr *lttng_ust_elf_get_phdr(struct lttng_ust_elf *elf,
						uint16_t index)
{
	struct lttng_ust_elf_phdr *phdr = NULL;
	off_t offset;

	if (!elf) {
		goto error;
	}

	if (index >= elf->ehdr->e_phnum) {
		goto error;
	}

	phdr = zmalloc(sizeof(struct lttng_ust_elf_phdr));
	if (!phdr) {
		goto error;
	}

	offset = (off_t) elf->ehdr->e_phoff
			+ (off_t) index * elf->ehdr->e_phentsize;
	if (lseek(elf->fd, offset, SEEK_SET) < 0) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Phdr elf_phdr;

		if (lttng_ust_read(elf->fd, &elf_phdr, sizeof(elf_phdr))
				< sizeof(elf_phdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_phdr(elf_phdr);
		}
		copy_phdr(elf_phdr, *phdr);
	} else {
		Elf64_Phdr elf_phdr;

		if (lttng_ust_read(elf->fd, &elf_phdr, sizeof(elf_phdr))
				< sizeof(elf_phdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_phdr(elf_phdr);
		}
		copy_phdr(elf_phdr, *phdr);
	}

	return phdr;

error:
	free(phdr);
	return NULL;
}

/*
 * Retrieve the nth (where n is the `index` argument) shdr (section
 * header) from the given elf instance.
 *
 * A pointer to the shdr is returned on success, NULL on failure.
 */
static
struct lttng_ust_elf_shdr *lttng_ust_elf_get_shdr(struct lttng_ust_elf *elf,
						uint16_t index)
{
	struct lttng_ust_elf_shdr *shdr = NULL;
	off_t offset;

	if (!elf) {
		goto error;
	}

	if (index >= elf->ehdr->e_shnum) {
		goto error;
	}

	shdr = zmalloc(sizeof(struct lttng_ust_elf_shdr));
	if (!shdr) {
		goto error;
	}

	offset = (off_t) elf->ehdr->e_shoff
			+ (off_t) index * elf->ehdr->e_shentsize;
	if (lseek(elf->fd, offset, SEEK_SET) < 0) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Shdr elf_shdr;

		if (lttng_ust_read(elf->fd, &elf_shdr, sizeof(elf_shdr))
				< sizeof(elf_shdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_shdr(elf_shdr);
		}
		copy_shdr(elf_shdr, *shdr);
	} else {
		Elf64_Shdr elf_shdr;

		if (lttng_ust_read(elf->fd, &elf_shdr, sizeof(elf_shdr))
				< sizeof(elf_shdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_shdr(elf_shdr);
		}
		copy_shdr(elf_shdr, *shdr);
	}

	return shdr;

error:
	free(shdr);
	return NULL;
}

/*
 * Lookup a section's name from a given offset (usually from an shdr's
 * sh_name value) in bytes relative to the beginning of the section
 * names string table.
 *
 * If no name is found, NULL is returned.
 */
static
char *lttng_ust_elf_get_section_name(struct lttng_ust_elf *elf, off_t offset)
{
	char *name = NULL;
	size_t len = 0, to_read;	/* len does not include \0 */

	if (!elf) {
		goto error;
	}

	if (offset >= elf->section_names_size) {
		goto error;
	}

	if (lseek(elf->fd, elf->section_names_offset + offset, SEEK_SET) < 0) {
		goto error;
	}

	to_read = elf->section_names_size - offset;

	/* Find first \0 after or at current location, remember len. */
	for (;;) {
		char buf[BUF_LEN];
		ssize_t read_len;
		size_t i;

		if (!to_read) {
			goto error;
		}
		read_len = lttng_ust_read(elf->fd, buf,
			min_t(size_t, BUF_LEN, to_read));
		if (read_len <= 0) {
			goto error;
		}
		for (i = 0; i < read_len; i++) {
			if (buf[i] == '\0') {
				len += i;
				goto end;
			}
		}
		len += read_len;
		to_read -= read_len;
	}
end:
	name = zmalloc(sizeof(char) * (len + 1));	/* + 1 for \0 */
	if (!name) {
		goto error;
	}
	if (lseek(elf->fd, elf->section_names_offset + offset,
		SEEK_SET) < 0) {
		goto error;
	}
	if (lttng_ust_read(elf->fd, name, len + 1) < len + 1) {
		goto error;
	}

	return name;

error:
	free(name);
	return NULL;
}

/*
 * Create an instance of lttng_ust_elf for the ELF file located at
 * `path`.
 *
 * Return a pointer to the instance on success, NULL on failure.
 */
struct lttng_ust_elf *lttng_ust_elf_create(const char *path)
{
	uint8_t e_ident[EI_NIDENT];
	struct lttng_ust_elf_shdr *section_names_shdr;
	struct lttng_ust_elf *elf = NULL;

	elf = zmalloc(sizeof(struct lttng_ust_elf));
	if (!elf) {
		goto error;
	}


	elf->path = strdup(path);
	if (!elf->path) {
		goto error;
	}

	lttng_ust_lock_fd_tracker();
	elf->fd = open(elf->path, O_RDONLY | O_CLOEXEC);
	if (elf->fd < 0) {
		lttng_ust_unlock_fd_tracker();
		goto error;
	}
	lttng_ust_add_fd_to_tracker(elf->fd);
	lttng_ust_unlock_fd_tracker();

	if (lttng_ust_read(elf->fd, e_ident, EI_NIDENT) < EI_NIDENT) {
		goto error;
	}
	elf->bitness = e_ident[EI_CLASS];
	elf->endianness = e_ident[EI_DATA];

	if (lseek(elf->fd, 0, SEEK_SET) < 0) {
		goto error;
	}

	elf->ehdr = zmalloc(sizeof(struct lttng_ust_elf_ehdr));
	if (!elf->ehdr) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Ehdr elf_ehdr;

		if (lttng_ust_read(elf->fd, &elf_ehdr, sizeof(elf_ehdr))
				< sizeof(elf_ehdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_ehdr(elf_ehdr);
		}
		copy_ehdr(elf_ehdr, *(elf->ehdr));
	} else {
		Elf64_Ehdr elf_ehdr;

		if (lttng_ust_read(elf->fd, &elf_ehdr, sizeof(elf_ehdr))
				< sizeof(elf_ehdr)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_ehdr(elf_ehdr);
		}
		copy_ehdr(elf_ehdr, *(elf->ehdr));
	}

	section_names_shdr = lttng_ust_elf_get_shdr(elf, elf->ehdr->e_shstrndx);
	if (!section_names_shdr) {
		goto error;
	}

	elf->section_names_offset = section_names_shdr->sh_offset;
	elf->section_names_size = section_names_shdr->sh_size;

	free(section_names_shdr);
	return elf;

error:
	lttng_ust_elf_destroy(elf);
	return NULL;
}

/*
 * Test whether the ELF file is position independent code (PIC)
 */
uint8_t lttng_ust_elf_is_pic(struct lttng_ust_elf *elf)
{
	/*
	 * PIC has and e_type value of ET_DYN, see ELF specification
	 * version 1.1 p. 1-3.
	 */
	return elf->ehdr->e_type == ET_DYN;
}

/*
 * Destroy the given lttng_ust_elf instance.
 */
void lttng_ust_elf_destroy(struct lttng_ust_elf *elf)
{
	int ret;

	if (!elf) {
		return;
	}

	if (elf->fd >= 0) {
		lttng_ust_lock_fd_tracker();
		ret = close(elf->fd);
		if (!ret) {
			lttng_ust_delete_fd_from_tracker(elf->fd);
		} else {
			PERROR("close");
			abort();
		}
		lttng_ust_unlock_fd_tracker();
	}

	free(elf->ehdr);
	free(elf->path);
	free(elf);
}

/*
 * Compute the total in-memory size of the ELF file, in bytes.
 *
 * Returns 0 if successful, -1 if not. On success, the memory size is
 * returned through the out parameter `memsz`.
 */
int lttng_ust_elf_get_memsz(struct lttng_ust_elf *elf, uint64_t *memsz)
{
	uint16_t i;
	uint64_t low_addr = UINT64_MAX, high_addr = 0;

	if (!elf || !memsz) {
		goto error;
	}

	for (i = 0; i < elf->ehdr->e_phnum; ++i) {
		struct lttng_ust_elf_phdr *phdr;

		phdr = lttng_ust_elf_get_phdr(elf, i);
		if (!phdr) {
			goto error;
		}

		/*
		 * Only PT_LOAD segments contribute to memsz. Skip
		 * other segments.
		 */
		if (phdr->p_type != PT_LOAD) {
			goto next_loop;
		}

		low_addr = min_t(uint64_t, low_addr, phdr->p_vaddr);
		high_addr = max_t(uint64_t, high_addr,
				phdr->p_vaddr + phdr->p_memsz);
	next_loop:
		free(phdr);
	}

	if (high_addr < low_addr) {
		/* No PT_LOAD segments or corrupted data. */
		goto error;
	}

	*memsz = high_addr - low_addr;
	return 0;
error:
	return -1;
}

/*
 * Internal method used to try and get the build_id from a PT_NOTE
 * segment ranging from `offset` to `segment_end`.
 *
 * If the function returns successfully, the out parameter `found`
 * indicates whether the build id information was present in the
 * segment or not. If `found` is not 0, the out parameters `build_id`
 * and `length` will both have been set with the retrieved
 * information.
 *
 * Returns 0 on success, -1 if an error occurred.
 */
static
int lttng_ust_elf_get_build_id_from_segment(
	struct lttng_ust_elf *elf, uint8_t **build_id, size_t *length,
	off_t offset, off_t segment_end)
{
	uint8_t *_build_id = NULL;	/* Silence old gcc warning. */
	size_t _length = 0;		/* Silence old gcc warning. */

	while (offset < segment_end) {
		struct lttng_ust_elf_nhdr nhdr;
		size_t read_len;

		/* Align start of note entry */
		offset += offset_align(offset, ELF_NOTE_ENTRY_ALIGN);
		if (offset >= segment_end) {
			break;
		}
		/*
		 * We seek manually because if the note isn't the
		 * build id the data following the header will not
		 * have been read.
		 */
		if (lseek(elf->fd, offset, SEEK_SET) < 0) {
			goto error;
		}
		if (lttng_ust_read(elf->fd, &nhdr, sizeof(nhdr))
				< sizeof(nhdr)) {
			goto error;
		}

		if (!is_elf_native_endian(elf)) {
			nhdr.n_namesz = bswap_32(nhdr.n_namesz);
			nhdr.n_descsz = bswap_32(nhdr.n_descsz);
			nhdr.n_type = bswap_32(nhdr.n_type);
		}

		offset += sizeof(nhdr) + nhdr.n_namesz;
		/* Align start of desc entry */
		offset += offset_align(offset, ELF_NOTE_DESC_ALIGN);

		if (nhdr.n_type != NT_GNU_BUILD_ID) {
			/*
			 * Ignore non build id notes but still
			 * increase the offset.
			 */
			offset += nhdr.n_descsz;
			continue;
		}

		_length = nhdr.n_descsz;
		_build_id = zmalloc(sizeof(uint8_t) * _length);
		if (!_build_id) {
			goto error;
		}

		if (lseek(elf->fd, offset, SEEK_SET) < 0) {
			goto error;
		}
		read_len = sizeof(*_build_id) * _length;
		if (lttng_ust_read(elf->fd, _build_id, read_len) < read_len) {
			goto error;
		}

		break;
	}

	if (_build_id) {
		*build_id = _build_id;
		*length = _length;
	}

	return 0;
error:
	free(_build_id);
	return -1;
}

/*
 * Retrieve a build ID (an array of bytes) from the corresponding
 * section in the ELF file. The length of the build ID can be either
 * 16 or 20 bytes depending on the method used to generate it, hence
 * the length out parameter.
 *
 * If the function returns successfully, the out parameter `found`
 * indicates whether the build id information was present in the ELF
 * file or not. If `found` is not 0, the out parameters `build_id` and
 * `length` will both have been set with the retrieved information.
 *
 * Returns 0 on success, -1 if an error occurred.
 */
int lttng_ust_elf_get_build_id(struct lttng_ust_elf *elf, uint8_t **build_id,
			size_t *length, int *found)
{
	uint16_t i;
	uint8_t *_build_id = NULL;	/* Silence old gcc warning. */
	size_t _length = 0;		/* Silence old gcc warning. */

	if (!elf || !build_id || !length || !found) {
		goto error;
	}

	for (i = 0; i < elf->ehdr->e_phnum; ++i) {
		off_t offset, segment_end;
		struct lttng_ust_elf_phdr *phdr;
		int ret = 0;

		phdr = lttng_ust_elf_get_phdr(elf, i);
		if (!phdr) {
			goto error;
		}

		/* Build ID will be contained in a PT_NOTE segment. */
		if (phdr->p_type != PT_NOTE) {
			goto next_loop;
		}

		offset = phdr->p_offset;
		segment_end = offset + phdr->p_filesz;
		ret = lttng_ust_elf_get_build_id_from_segment(
			elf, &_build_id, &_length, offset, segment_end);
	next_loop:
		free(phdr);
		if (ret) {
			goto error;
		}
		if (_build_id) {
			break;
		}
	}

	if (_build_id) {
		*build_id = _build_id;
		*length = _length;
		*found = 1;
	} else {
		*found = 0;
	}

	return 0;
error:
	free(_build_id);
	return -1;
}

/*
 * Try to retrieve filename and CRC from given ELF section `shdr`.
 *
 * If the function returns successfully, the out parameter `found`
 * indicates whether the debug link information was present in the ELF
 * section or not. If `found` is not 0, the out parameters `filename` and
 * `crc` will both have been set with the retrieved information.
 *
 * Returns 0 on success, -1 if an error occurred.
 */
int lttng_ust_elf_get_debug_link_from_section(struct lttng_ust_elf *elf,
					char **filename, uint32_t *crc,
					struct lttng_ust_elf_shdr *shdr)
{
	char *_filename = NULL;		/* Silence old gcc warning. */
	size_t filename_len;
	char *section_name = NULL;
	uint32_t _crc = 0;		/* Silence old gcc warning. */

	if (!elf || !filename || !crc || !shdr) {
		goto error;
	}

	/*
	 * The .gnu_debuglink section is of type SHT_PROGBITS,
	 * skip the other sections.
	 */
	if (shdr->sh_type != SHT_PROGBITS) {
		goto end;
	}

	section_name = lttng_ust_elf_get_section_name(elf,
						shdr->sh_name);
	if (!section_name) {
		goto end;
	}
	if (strcmp(section_name, ".gnu_debuglink")) {
		goto end;
	}

	/*
	 * The length of the filename is the sh_size excluding the CRC
	 * which comes after it in the section.
	 */
	_filename = zmalloc(sizeof(char) * (shdr->sh_size - ELF_CRC_SIZE));
	if (!_filename) {
		goto error;
	}
	if (lseek(elf->fd, shdr->sh_offset, SEEK_SET) < 0) {
		goto error;
	}
	filename_len = sizeof(*_filename) * (shdr->sh_size - ELF_CRC_SIZE);
	if (lttng_ust_read(elf->fd, _filename, filename_len) < filename_len) {
		goto error;
	}
	if (lttng_ust_read(elf->fd, &_crc, sizeof(_crc)) < sizeof(_crc)) {
		goto error;
	}
	if (!is_elf_native_endian(elf)) {
		_crc = bswap_32(_crc);
	}

end:
	free(section_name);
	if (_filename) {
		*filename = _filename;
		*crc = _crc;
	}

	return 0;

error:
	free(_filename);
	free(section_name);
	return -1;
}

/*
 * Retrieve filename and CRC from ELF's .gnu_debuglink section, if any.
 *
 * If the function returns successfully, the out parameter `found`
 * indicates whether the debug link information was present in the ELF
 * file or not. If `found` is not 0, the out parameters `filename` and
 * `crc` will both have been set with the retrieved information.
 *
 * Returns 0 on success, -1 if an error occurred.
 */
int lttng_ust_elf_get_debug_link(struct lttng_ust_elf *elf, char **filename,
				uint32_t *crc, int *found)
{
	int ret;
	uint16_t i;
	char *_filename = NULL;		/* Silence old gcc warning. */
	uint32_t _crc = 0;		/* Silence old gcc warning. */

	if (!elf || !filename || !crc || !found) {
		goto error;
	}

	for (i = 0; i < elf->ehdr->e_shnum; ++i) {
		struct lttng_ust_elf_shdr *shdr = NULL;

		shdr = lttng_ust_elf_get_shdr(elf, i);
		if (!shdr) {
			goto error;
		}

		ret = lttng_ust_elf_get_debug_link_from_section(
			elf, &_filename, &_crc, shdr);
		free(shdr);

		if (ret) {
			goto error;
		}
		if (_filename) {
			break;
		}
	}

	if (_filename) {
		*filename = _filename;
		*crc = _crc;
		*found = 1;
	} else {
		*found = 0;
	}

	return 0;

error:
	free(_filename);
	return -1;
}
