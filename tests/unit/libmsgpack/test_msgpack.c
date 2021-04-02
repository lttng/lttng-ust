/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tap.h"

#include "common/msgpack/msgpack.h"

#define BUFFER_SIZE 4096
#define NUM_TESTS 23


/*
 * echo 'null' | json2msgpack | xxd -i
 */
static const uint8_t NIL_EXPECTED[] = { 0xc0 };

/*
 * echo '"bye"' | json2msgpack | xxd -i
 */
static const uint8_t STRING_BYE_EXPECTED[] = { 0xa3, 0x62, 0x79, 0x65 };

/*
 * echo '1337' | json2msgpack | xxd -i
 */
static const uint8_t UINT_1337_EXPECTED[] = { 0xcd, 0x05, 0x39 };

/*
 * echo '127' | json2msgpack | xxd -i
 */
static const uint8_t UINT_127_EXPECTED[] = { 0x7f };

/*
 * echo '128' | json2msgpack | xxd -i
 */
static const uint8_t UINT_128_EXPECTED[] = { 0xcc, 0x80 };

/*
 * echo '256' | json2msgpack | xxd -i
 */
static const uint8_t UINT_256_EXPECTED[] = { 0xcd, 0x01, 0x00 };

/*
 * echo '65535' | json2msgpack | xxd -i
 */
static const uint8_t UINT_65535_EXPECTED[] = { 0xcd, 0xff, 0xff };

/*
 * echo '65536' | json2msgpack | xxd -i
 */
static const uint8_t UINT_65536_EXPECTED[] = { 0xce, 0x00, 0x01, 0x00, 0x00 };

/*
 * echo '4294967295' | json2msgpack | xxd -i
 */
static const uint8_t UINT_4294967295_EXPECTED[] = { 0xce, 0xff, 0xff, 0xff, 0xff };

/*
 * echo '4294967296' | json2msgpack | xxd -i
 */
static const uint8_t UINT_4294967296_EXPECTED[] = { 0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };

/*
 * echo '-32' | json2msgpack | xxd -i
 */
static const uint8_t INT_NEG_32_EXPECTED[] = { 0xe0 };

/*
 * echo '-33' | json2msgpack | xxd -i
 */
static const uint8_t INT_NEG_33_EXPECTED[] = { 0xd0, 0xdf };

/*
 * echo '-129' | json2msgpack | xxd -i
 */
static const uint8_t INT_NEG_129_EXPECTED[] = { 0xd1, 0xff, 0x7f};

/*
 * echo '-32768' | json2msgpack | xxd -i
 */
static const uint8_t INT_NEG_32768_EXPECTED[] = { 0xd1, 0x80, 0x00 };

/*
 * echo '-32769' | json2msgpack | xxd -i
 */
static const uint8_t INT_NEG_32769_EXPECTED[] = { 0xd2, 0xff, 0xff, 0x7f,
		0xff };

/*
 * echo '-2147483648' | json2msgpack | xxd -i
 */
static const uint8_t INT_NEG_2147483648_EXPECTED[] = { 0xd2, 0x80, 0x00, 0x00,
		0x00 };

/*
 * echo '-2147483649' | json2msgpack | xxd -i
 */
static const uint8_t INT_NEG_2147483649_EXPECTED[] = { 0xd3, 0xff, 0xff, 0xff,
		0xff, 0x7f, 0xff, 0xff, 0xff };
/*
 * echo '0.0' | json2msgpack | xxd -i
 */
static const uint8_t DOUBLE_ZERO_EXPECTED[] = { 0xcb, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00 };

/*
 * echo '3.14159265' | json2msgpack | xxd -i
 */
static const uint8_t DOUBLE_PI_EXPECTED[] = { 0xcb, 0x40, 0x09, 0x21, 0xfb, 0x53,
		0xc8, 0xd4, 0xf1 };

/*
 * echo '3.14159265' | json2msgpack | xxd -i
 */
static const uint8_t DOUBLE_NEG_PI_EXPECTED[] = { 0xcb, 0xc0, 0x09, 0x21, 0xfb,
		0x53, 0xc8, 0xd4, 0xf1 };

/*
 * echo [1.1, 2.3, -12345.2] | json2msgpack | xxd -i
 */
static const uint8_t ARRAY_DOUBLE_EXPECTED[] = { 0x93, 0xcb, 0x3f, 0xf1, 0x99,
		0x99, 0x99, 0x99, 0x99, 0x9a, 0xcb, 0x40, 0x02, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0xcb, 0xc0, 0xc8, 0x1c, 0x99, 0x99,
		0x99, 0x99, 0x9a };

/*
 * echo '{"type":"enum","value":117}' | json2msgpack | xxd -i
 */
static const uint8_t MAP_EXPECTED[] = {
  0x82, 0xa4, 0x74, 0x79, 0x70, 0x65, 0xa4, 0x65, 0x6e, 0x75, 0x6d, 0xa5,
  0x76, 0x61, 0x6c, 0x75, 0x65, 0x75 };

/*
 * echo '["meow mix", 18, null, 14.197, [1980, 1995]]' | json2msgpack | xxd -i
 */
static const uint8_t COMPLETE_CAPTURE_EXPECTED[] = { 0x95, 0xa8, 0x6d, 0x65,
		0x6f, 0x77, 0x20, 0x6d, 0x69, 0x78, 0x12, 0xc0, 0xcb, 0x40,
		0x2c, 0x64, 0xdd, 0x2f, 0x1a, 0x9f, 0xbe, 0x92, 0xcd, 0x07,
		0xbc, 0xcd, 0x07, 0xcb };

static void string_test(uint8_t *buf, const char *value)
{
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);
	lttng_msgpack_write_str(&writer, value);
	lttng_msgpack_writer_fini(&writer);
}

static void int_test(uint8_t *buf, int64_t value)
{
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);
	lttng_msgpack_write_signed_integer(&writer, value);

	lttng_msgpack_writer_fini(&writer);
}

static void uint_test(uint8_t *buf, uint64_t value)
{
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);
	lttng_msgpack_write_unsigned_integer(&writer, value);
	lttng_msgpack_writer_fini(&writer);
}

static void double_test(uint8_t *buf, double value)
{
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);
	lttng_msgpack_write_double(&writer, value);
	lttng_msgpack_writer_fini(&writer);
}

static void array_double_test(uint8_t *buf, double *values, size_t nb_values)
{
	int i = 0;
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);
	lttng_msgpack_begin_array(&writer, nb_values);

	for (i = 0; i < nb_values; i++) {
		lttng_msgpack_write_double(&writer, values[i]);
	}

	lttng_msgpack_end_array(&writer);
	lttng_msgpack_writer_fini(&writer);
}

static void map_test(uint8_t *buf)
{
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);

	lttng_msgpack_begin_map(&writer, 2);

	lttng_msgpack_write_str(&writer, "type");
	lttng_msgpack_write_str(&writer, "enum");

	lttng_msgpack_write_str(&writer, "value");
	lttng_msgpack_write_unsigned_integer(&writer, 117);

	lttng_msgpack_end_map(&writer);
	lttng_msgpack_writer_fini(&writer);
}

static void complete_capture_test(uint8_t *buf)
{
	/*
	 * This testcase tests the following json representation:
	 * "meow mix",18, null, 14.197,[1980, 1995]]
	 */
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);

	lttng_msgpack_begin_array(&writer, 5);

	lttng_msgpack_write_str(&writer, "meow mix");
	lttng_msgpack_write_signed_integer(&writer, 18);
	lttng_msgpack_write_nil(&writer);
	lttng_msgpack_write_double(&writer, 14.197);

	lttng_msgpack_begin_array(&writer, 2);

	lttng_msgpack_write_unsigned_integer(&writer, 1980);
	lttng_msgpack_write_unsigned_integer(&writer, 1995);

	lttng_msgpack_end_array(&writer);

	lttng_msgpack_end_array(&writer);

	lttng_msgpack_writer_fini(&writer);
}

static void nil_test(uint8_t *buf)
{
	struct lttng_msgpack_writer writer;

	lttng_msgpack_writer_init(&writer, buf, BUFFER_SIZE);
	lttng_msgpack_write_nil(&writer);
	lttng_msgpack_writer_fini(&writer);
}

int main(void)
{
	uint8_t buf[BUFFER_SIZE] = {0};
	double arr_double[] = {1.1, 2.3, -12345.2};

	plan_tests(NUM_TESTS);

	diag("Testing msgpack implementation");

	/*
	 * Expected outputs were produced using the `json2msgpack` tool.
	 * https://github.com/ludocode/msgpack-tools
	 * For example, here is the command to produce the null test expected
	 * output:
	 *  echo 'null' | json2msgpack | hexdump -v -e '"\\\x" 1/1 "%02x"'
	 *
	 * The only exception is that we always produce 64bits integer to
	 * represent integers even if they would fit into smaller objects so
	 * they need to be manually crafted in 64bits two's complement (if
	 * signed) big endian.
	 */
	nil_test(buf);
	ok(memcmp(buf, NIL_EXPECTED, sizeof(NIL_EXPECTED)) == 0,
		"NIL object");

	string_test(buf, "bye");
	ok(memcmp(buf, STRING_BYE_EXPECTED, sizeof(STRING_BYE_EXPECTED)) == 0,
		"String \"bye\" object");

	uint_test(buf, 1337);
	ok(memcmp(buf, UINT_1337_EXPECTED, sizeof(UINT_1337_EXPECTED)) == 0,
		"Unsigned integer \"1337\" object");

	uint_test(buf, 127);
	ok(memcmp(buf, UINT_127_EXPECTED, sizeof(UINT_127_EXPECTED)) == 0,
		"Unsigned integer \"127\" object");

	uint_test(buf, 128);
	ok(memcmp(buf, UINT_128_EXPECTED, sizeof(UINT_128_EXPECTED)) == 0,
		"Unsigned integer \"128\" object");

	uint_test(buf, 256);
	ok(memcmp(buf, UINT_256_EXPECTED, sizeof(UINT_256_EXPECTED)) == 0,
		"Unsigned integer \"256\" object");

	uint_test(buf, 65536);
	ok(memcmp(buf, UINT_65536_EXPECTED, sizeof(UINT_65536_EXPECTED)) == 0,
		"Unsigned integer \"65536\" object");

	uint_test(buf, 65535);
	ok(memcmp(buf, UINT_65535_EXPECTED, sizeof(UINT_65535_EXPECTED)) == 0,
		"Unsigned integer \"65535\" object");

	uint_test(buf, 4294967295);
	ok(memcmp(buf, UINT_4294967295_EXPECTED, sizeof(UINT_4294967295_EXPECTED)) == 0,
		"Unsigned integer \"4294967295\" object");

	uint_test(buf, 4294967296);
	ok(memcmp(buf, UINT_4294967296_EXPECTED, sizeof(UINT_4294967296_EXPECTED)) == 0,
		"Unsigned integer \"4294967296\" object");

	int_test(buf, -32);
	ok(memcmp(buf, INT_NEG_32_EXPECTED, sizeof(INT_NEG_32_EXPECTED)) == 0,
		"Signed integer \"-32\" object");

	int_test(buf, -33);
	ok(memcmp(buf, INT_NEG_33_EXPECTED, sizeof(INT_NEG_33_EXPECTED)) == 0,
		"Signed integer \"-33\" object");

	int_test(buf, -129);
	ok(memcmp(buf, INT_NEG_129_EXPECTED, sizeof(INT_NEG_129_EXPECTED)) == 0,
		"Signed integer \"-129\" object");

	int_test(buf, -32768);
	ok(memcmp(buf, INT_NEG_32768_EXPECTED, sizeof(INT_NEG_32768_EXPECTED)) == 0,
		"Signed integer \"-32768\" object");

	int_test(buf, -32769);
	ok(memcmp(buf, INT_NEG_32769_EXPECTED, sizeof(INT_NEG_32769_EXPECTED)) == 0,
		"Signed integer \"-32769\" object");

	int_test(buf, -2147483648);
	ok(memcmp(buf, INT_NEG_2147483648_EXPECTED, sizeof(INT_NEG_2147483648_EXPECTED)) == 0,
		"Signed integer \"-2147483648\" object");

	int_test(buf, -2147483649);
	ok(memcmp(buf, INT_NEG_2147483649_EXPECTED, sizeof(INT_NEG_2147483649_EXPECTED)) == 0,
		"Signed integer \"-2147483649\" object");

	double_test(buf, 0.0);
	ok(memcmp(buf, DOUBLE_ZERO_EXPECTED, sizeof(DOUBLE_ZERO_EXPECTED)) == 0,
		"double \"0.0\" object");

	double_test(buf, 3.14159265);
	ok(memcmp(buf, DOUBLE_PI_EXPECTED, sizeof(DOUBLE_PI_EXPECTED)) == 0,
		"double \"PI\" object");

	double_test(buf, -3.14159265);
	ok(memcmp(buf, DOUBLE_NEG_PI_EXPECTED, sizeof(DOUBLE_NEG_PI_EXPECTED)) == 0,
		"double \"-PI\" object");

	array_double_test(buf, arr_double, 3);
	ok(memcmp(buf, ARRAY_DOUBLE_EXPECTED, sizeof(ARRAY_DOUBLE_EXPECTED)) == 0,
		"Array of double object");

	map_test(buf);
	ok(memcmp(buf, MAP_EXPECTED, sizeof(MAP_EXPECTED)) == 0,
		"Map object");

	complete_capture_test(buf);
	ok(memcmp(buf, COMPLETE_CAPTURE_EXPECTED, sizeof(COMPLETE_CAPTURE_EXPECTED)) == 0,
		"Complete capture object");

	return EXIT_SUCCESS;
}
