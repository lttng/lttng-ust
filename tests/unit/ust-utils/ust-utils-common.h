/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include "tap.h"

#define NUM_TESTS 94

static
void test_ust_stringify(void)
{
	ok(strcmp(lttng_ust_stringify(1), "1") == 0, "lttng_ust_stringify - literal integer");
	ok(strcmp(lttng_ust_stringify(random_identifier), "random_identifier") == 0, "lttng_ust_stringify - identifier");
}

#define ok_is_signed(_type) \
	ok(lttng_ust_is_signed_type(_type) == true, "lttng_ust_is_signed_type - '" lttng_ust_stringify(_type) "' is signed")

#define ok_is_unsigned(_type) \
	ok(lttng_ust_is_signed_type(_type) == false, "lttng_ust_is_signed_type - '" lttng_ust_stringify(_type) "' is unsigned")

static
void test_ust_is_signed(void)
{
	/*
	 * Signed types
	 */

	ok_is_signed(signed char);
	ok_is_signed(short);
	ok_is_signed(int);
	ok_is_signed(long);
	ok_is_signed(long long);
	ok_is_signed(float);
	ok_is_signed(double);
	ok_is_signed(long double);

	ok_is_signed(int8_t);
	ok_is_signed(int16_t);
	ok_is_signed(int32_t);
	ok_is_signed(int64_t);
	ok_is_signed(intmax_t);

	ok_is_signed(ssize_t);
	ok_is_signed(ptrdiff_t);
	ok_is_signed(intptr_t);

	/*
	 * Unsigned types
	 */

	ok_is_unsigned(unsigned char);
	ok_is_unsigned(unsigned short);
	ok_is_unsigned(unsigned int);
	ok_is_unsigned(unsigned long);
	ok_is_unsigned(unsigned long long);

	ok_is_unsigned(uint8_t);
	ok_is_unsigned(uint16_t);
	ok_is_unsigned(uint32_t);
	ok_is_unsigned(uint64_t);
	ok_is_unsigned(uintmax_t);

	ok_is_unsigned(bool);
	ok_is_unsigned(size_t);

	ok_is_unsigned(void *);
}


#define ok_is_integer_type(_type) \
	ok(lttng_ust_is_integer_type(_type) == true, "lttng_ust_is_integer_type - '" lttng_ust_stringify(_type) "' is an integer")

#define ok_is_not_integer_type(_type) \
	ok(lttng_ust_is_integer_type(_type) == false, "lttng_ust_is_integer_type - '" lttng_ust_stringify(_type) "' is not an integer")

static
void test_ust_is_integer_type(void)
{
	ok_is_integer_type(char);
	ok_is_integer_type(short);
	ok_is_integer_type(int);
	ok_is_integer_type(long);
	ok_is_integer_type(long long);

	ok_is_integer_type(signed char);
	ok_is_integer_type(signed short);
	ok_is_integer_type(signed int);
	ok_is_integer_type(signed long);
	ok_is_integer_type(signed long long);

	ok_is_integer_type(unsigned char);
	ok_is_integer_type(unsigned short);
	ok_is_integer_type(unsigned int);
	ok_is_integer_type(unsigned long);
	ok_is_integer_type(unsigned long long);

	ok_is_integer_type(int8_t);
	ok_is_integer_type(int16_t);
	ok_is_integer_type(int32_t);
	ok_is_integer_type(int64_t);
	ok_is_integer_type(intmax_t);

	ok_is_integer_type(uint8_t);
	ok_is_integer_type(uint16_t);
	ok_is_integer_type(uint32_t);
	ok_is_integer_type(uint64_t);
	ok_is_integer_type(uintmax_t);

	ok_is_not_integer_type(float);
	ok_is_not_integer_type(double);
	ok_is_not_integer_type(long double);

	ok_is_not_integer_type(void *);
}

#define ok_is_pointer_type(_type) \
	ok(lttng_ust_is_pointer_type(_type) == true, "lttng_ust_is_pointer_type - '" lttng_ust_stringify(_type) "' is a pointer")

#define ok_is_not_pointer_type(_type) \
	ok(lttng_ust_is_pointer_type(_type) == false, "lttng_ust_is_pointer_type - '" lttng_ust_stringify(_type) "' is not a pointer")

struct dummy {
	int a;
};

static
void test_ust_is_pointer_type(void)
{
	ok_is_not_pointer_type(char);
	ok_is_not_pointer_type(short);
	ok_is_not_pointer_type(int);
	ok_is_not_pointer_type(long);
	ok_is_not_pointer_type(long long);

	ok_is_not_pointer_type(signed char);
	ok_is_not_pointer_type(signed short);
	ok_is_not_pointer_type(signed int);
	ok_is_not_pointer_type(signed long);
	ok_is_not_pointer_type(signed long long);

	ok_is_not_pointer_type(unsigned char);
	ok_is_not_pointer_type(unsigned short);
	ok_is_not_pointer_type(unsigned int);
	ok_is_not_pointer_type(unsigned long);
	ok_is_not_pointer_type(unsigned long long);

	ok_is_not_pointer_type(int8_t);
	ok_is_not_pointer_type(int16_t);
	ok_is_not_pointer_type(int32_t);
	ok_is_not_pointer_type(int64_t);
	ok_is_not_pointer_type(intmax_t);

	ok_is_not_pointer_type(uint8_t);
	ok_is_not_pointer_type(uint16_t);
	ok_is_not_pointer_type(uint32_t);
	ok_is_not_pointer_type(uint64_t);
	ok_is_not_pointer_type(uintmax_t);

	ok_is_not_pointer_type(float);
	ok_is_not_pointer_type(double);
	ok_is_not_pointer_type(long double);

	ok_is_pointer_type(void *);
	ok_is_pointer_type(void **);
	ok_is_pointer_type(struct dummy *);
	ok_is_pointer_type(int *);
	ok_is_pointer_type(float *);
	ok_is_pointer_type(double *);
}

int main(void)
{
	plan_tests(NUM_TESTS);

	test_ust_stringify();
	test_ust_is_signed();
	test_ust_is_integer_type();
	test_ust_is_pointer_type();

	return exit_status();
}
