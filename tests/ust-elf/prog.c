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

#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lttng/ust-elf.h>
#include "tap.h"

#define NUM_ARCH 4
#define NUM_TESTS_PER_ARCH 11
#define NUM_TESTS (NUM_ARCH * NUM_TESTS_PER_ARCH)

/*
 * Expected memsz were computed using libelf, build ID and debug link
 * were determined through readelf.
 */
#define X86_MEMSZ 8192
#define X86_64_MEMSZ 4194304
#define ARMEB_MEMSZ 65536
#define AARCH64_BE_MEMSZ 131072

#define X86_CRC 0x1531f73c
#define X86_64_CRC 0xa048a98f
#define ARMEB_CRC 0x9d40261b
#define AARCH64_BE_CRC 0x2b8cedce

#define BUILD_ID_LEN 20
#define DBG_FILE "main.elf.debug"

static
void test_elf(const char *test_dir, const char *arch, uint64_t exp_memsz,
		uint8_t *exp_build_id, uint32_t exp_crc)
{
	char path[PATH_MAX];
	struct lttng_ust_elf *elf = NULL;
	int ret = 0;
	uint64_t memsz = 0;
	int has_build_id = 0;
	uint8_t *build_id = NULL;
	size_t build_id_len = 0;
	int has_debug_link = 0;
	char *dbg_file = NULL;
	uint32_t crc = 0;

	diag("Testing %s support", arch);

	snprintf(path, PATH_MAX, "%s/data/%s/main.elf", test_dir, arch);
	elf = lttng_ust_elf_create(path);
	ok(elf != NULL, "lttng_ust_elf_create");

	ret = lttng_ust_elf_get_memsz(elf, &memsz);
	ok(ret == 0, "lttng_ust_elf_get_memsz returned successfully");
	ok(memsz == exp_memsz,
		"memsz - expected: %lu, got: %lu",
		exp_memsz, memsz);

	ret = lttng_ust_elf_get_build_id(elf, &build_id, &build_id_len,
					&has_build_id);
	ok(ret == 0, "lttng_ust_elf_get_build_id returned successfully");
	ok(has_build_id == 1, "build id marked as found");
	ok(build_id_len == BUILD_ID_LEN,
		"build_id_len - expected: %u, got: %u",
		BUILD_ID_LEN, build_id_len);
	ok(memcmp(build_id, exp_build_id, build_id_len) == 0,
		"build_id has expected value");

	ret = lttng_ust_elf_get_debug_link(elf, &dbg_file, &crc,
					&has_debug_link);
	ok(ret == 0, "lttng_ust_elf_get_debug_link returned successfully");
	ok(has_debug_link == 1, "debug link marked as found");
	ok(strcmp(dbg_file, DBG_FILE) == 0,
		"debug link filename - expected: %s, got: %s",
		DBG_FILE, dbg_file);
	ok(crc == exp_crc,
		"debug link crc - expected: %#x, got: %#x",
		exp_crc, crc);

	free(build_id);
	free(dbg_file);
	lttng_ust_elf_destroy(elf);
}

int main(int argc, char **argv)
{
	uint8_t X86_BUILD_ID[BUILD_ID_LEN] = {
		0x27, 0x79, 0x2a, 0xe7, 0xaa, 0xef, 0x72, 0x5c, 0x9c, 0x52,
		0x80, 0xec, 0x1e, 0x18, 0xd8, 0x09, 0x02, 0xba, 0xbc, 0x82
	};
	uint8_t X86_64_BUILD_ID[BUILD_ID_LEN] = {
		0x0f, 0x87, 0xb2, 0xe2, 0x24, 0x9c, 0xe1, 0xc2, 0x24, 0xb1,
		0xf8, 0xb6, 0x65, 0x83, 0xa3, 0xc1, 0xcb, 0x30, 0x5c, 0x63
	};
	uint8_t ARMEB_BUILD_ID[BUILD_ID_LEN] = {
		0x60, 0x5d, 0x26, 0xa0, 0x0e, 0x30, 0xa4, 0x29, 0xf4, 0xf1,
		0x85, 0x53, 0xda, 0x90, 0x68, 0xe1, 0xf5, 0x67, 0xbe, 0x42
	};
	uint8_t AARCH64_BE_BUILD_ID[BUILD_ID_LEN] = {
		0xb9, 0x0a, 0xa0, 0xed, 0xd1, 0x41, 0x42, 0xc3, 0x34, 0x85,
		0xfa, 0x27, 0x2e, 0xa9, 0x2f, 0xd2, 0xe4, 0xf7, 0xb6, 0x60
	};
	const char *TEST_DIR = argv[1];

	plan_tests(NUM_TESTS);

	test_elf(TEST_DIR, "x86", X86_MEMSZ, X86_BUILD_ID, X86_CRC);
	test_elf(TEST_DIR, "x86_64", X86_64_MEMSZ, X86_64_BUILD_ID, X86_64_CRC);
	test_elf(TEST_DIR, "armeb", ARMEB_MEMSZ, ARMEB_BUILD_ID, ARMEB_CRC);
	test_elf(TEST_DIR, "aarch64_be", AARCH64_BE_MEMSZ, AARCH64_BE_BUILD_ID,
		AARCH64_BE_CRC);

	return 0;
}
