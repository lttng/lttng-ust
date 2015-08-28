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

#include <helper.h>
#include <string.h>
#include <lttng/align.h>
#include <lttng/ust-elf.h>

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
	long offset;

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

	offset = elf->ehdr->e_phoff + index * elf->ehdr->e_phentsize;
	if (fseek(elf->file, offset, SEEK_SET)) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Phdr elf_phdr;

		if (!fread(&elf_phdr, sizeof(elf_phdr), 1, elf->file)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_phdr(elf_phdr);
		}
		copy_phdr(elf_phdr, *phdr);
	} else {
		Elf64_Phdr elf_phdr;

		if (!fread(&elf_phdr, sizeof(elf_phdr), 1, elf->file)) {
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
	long offset;

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

	offset = elf->ehdr->e_shoff + index * elf->ehdr->e_shentsize;
	if (fseek(elf->file, offset, SEEK_SET)) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Shdr elf_shdr;

		if (!fread(&elf_shdr, sizeof(elf_shdr), 1, elf->file)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_shdr(elf_shdr);
		}
		copy_shdr(elf_shdr, *shdr);
	} else {
		Elf64_Shdr elf_shdr;

		if (!fread(&elf_shdr, sizeof(elf_shdr), 1, elf->file)) {
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
char *lttng_ust_elf_get_section_name(struct lttng_ust_elf *elf, uint32_t offset)
{
	char *name = NULL;
	size_t len;

	if (!elf) {
		goto error;
	}

	if (offset >= elf->section_names_size) {
		goto error;
	}

	if (fseek(elf->file, elf->section_names_offset + offset, SEEK_SET)) {
		goto error;
	}
	/* Note that len starts at 1, it is not an index. */
	for (len = 1; offset + len <= elf->section_names_size; ++len) {
		switch (fgetc(elf->file)) {
		case EOF:
			goto error;
		case '\0':
			goto end;
		default:
			break;
		}
	}

	/* No name was found before the end of the table. */
	goto error;

end:
	name = zmalloc(sizeof(char) * len);
	if (!name) {
		goto error;
	}
	if (fseek(elf->file, elf->section_names_offset + offset,
		SEEK_SET)) {
		goto error;
	}
	if (!fgets(name, len, elf->file)) {
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
	struct lttng_ust_elf *elf;

	elf = zmalloc(sizeof(struct lttng_ust_elf));
	if (!elf) {
		goto error;
	}

	elf->path = strdup(path);
	if (!elf->path) {
		goto error;
	}

	elf->file = fopen(elf->path, "rb");
	if (!elf->file) {
		goto error;
	}

	if (!fread(e_ident, 1, EI_NIDENT, elf->file)) {
		goto error;
	}
	elf->bitness = e_ident[EI_CLASS];
	elf->endianness = e_ident[EI_DATA];
	rewind(elf->file);

	elf->ehdr = zmalloc(sizeof(struct lttng_ust_elf_ehdr));
	if (!elf->ehdr) {
		goto error;
	}

	if (is_elf_32_bit(elf)) {
		Elf32_Ehdr elf_ehdr;

		if (!fread(&elf_ehdr, sizeof(elf_ehdr), 1, elf->file)) {
			goto error;
		}
		if (!is_elf_native_endian(elf)) {
			bswap_ehdr(elf_ehdr);
		}
		copy_ehdr(elf_ehdr, *(elf->ehdr));
	} else {
		Elf64_Ehdr elf_ehdr;

		if (!fread(&elf_ehdr, sizeof(elf_ehdr), 1, elf->file)) {
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
	if (elf) {
		free(elf->ehdr);
		fclose(elf->file);
		free(elf->path);
	}
	free(elf);
	return NULL;
}

/*
 * Destroy the given lttng_ust_elf instance.
 */
void lttng_ust_elf_destroy(struct lttng_ust_elf *elf)
{
	if (!elf) {
		return;
	}

	free(elf->ehdr);
	fclose(elf->file);
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
	uint64_t _memsz = 0;

	if (!elf || !memsz) {
		goto error;
	}

	for (i = 0; i < elf->ehdr->e_phnum; ++i) {
		struct lttng_ust_elf_phdr *phdr;
		uint64_t align;

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

		/*
		 * A p_align of 0 means no alignment, i.e. aligned to
		 * 1 byte.
		 */
		align = phdr->p_align == 0 ? 1 : phdr->p_align;
		/* Align the start of the segment. */
		_memsz += offset_align(_memsz, align);
		_memsz += phdr->p_memsz;
		/*
		 * Add padding at the end of the segment, so it ends
		 * on a multiple of the align value (which usually
		 * means a page boundary). This makes the computation
		 * valid even in cases where p_align would change from
		 * one segment to the next.
		 */
		_memsz += offset_align(_memsz, align);
	next_loop:
		free(phdr);
	}

	*memsz = _memsz;
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
	uint64_t offset, uint64_t segment_end, int *found)
{
	uint8_t *_build_id;
	size_t _length;
	int _found = 0;

	while (offset < segment_end) {
		struct lttng_ust_elf_nhdr nhdr;

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
		if (fseek(elf->file, offset, SEEK_SET)) {
			goto error;
		}
		if (!fread(&nhdr, sizeof(nhdr), 1, elf->file)) {
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
		if (!build_id) {
			goto error;
		}

		if (fseek(elf->file, offset, SEEK_SET)) {
			goto error;
		}
		if (!fread(_build_id, sizeof(*_build_id), _length, elf->file)) {
			goto error;
		}

		_found = 1;
		break;
	}

	if (_found) {
		*build_id = _build_id;
		*length = _length;
	}

	*found = _found;
	return 0;
error:
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
	uint8_t *_build_id;
	size_t _length;
	int _found = 0;

	if (!elf || !build_id || !length || !found) {
		goto error;
	}

	for (i = 0; i < elf->ehdr->e_phnum; ++i) {
		uint64_t offset, segment_end;
		struct lttng_ust_elf_phdr *phdr;
		int ret;

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
			elf, &_build_id, &_length, offset, segment_end,
			&_found);
	next_loop:
		free(phdr);
		if (ret) {
			goto error;
		}
		if (_found) {
			break;
		}
	}

	if (_found) {
		*build_id = _build_id;
		*length = _length;
	}

	*found = _found;
	return 0;
error:
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
static
int lttng_ust_elf_get_debug_link_from_section(struct lttng_ust_elf *elf,
					char **filename, uint32_t *crc,
					int *found,
					struct lttng_ust_elf_shdr *shdr)
{
	int _found = 0;
	char *_filename;
	char *section_name = NULL;
	uint32_t _crc;

	if (!elf || !filename || !crc || !found || !shdr) {
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
	if (fseek(elf->file, shdr->sh_offset, SEEK_SET)) {
		goto error;
	}
	if (!fread(_filename, sizeof(*_filename), shdr->sh_size - ELF_CRC_SIZE,
		elf->file)) {
		goto error;
	}
	if (!fread(&_crc, sizeof(_crc), 1, elf->file)) {
		goto error;
	}
	if (!is_elf_native_endian(elf)) {
		_crc = bswap_32(_crc);
	}

	_found = 1;

end:
	free(section_name);
	if (_found) {
		*filename = _filename;
		*crc = _crc;
	}
	*found = _found;

	return 0;

error:
	if (section_name) {
		free(section_name);
	}

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
	int _found = 0;
	char *_filename;
	uint32_t _crc;

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
			elf, &_filename, &_crc, &_found, shdr);
		free(shdr);

		if (ret) {
			goto error;
		}
		if (_found) {
			break;
		}
	}

	if (_found) {
		*filename = _filename;
		*crc = _crc;
	}

	*found = _found;
	return 0;
error:
	return -1;
}
