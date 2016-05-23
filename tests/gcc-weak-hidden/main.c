/*
 * Copyright (C) 2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED. ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program for any
 * purpose, provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is
 * granted, provided the above notices are retained, and a notice that
 * the code was modified is included with the above copyright notice.
 */

#include <stdbool.h>
#include "tap.h"

#define NUM_TESTS 2

int testint __attribute__((weak, visibility("hidden")));
void *testptr __attribute__((weak, visibility("hidden")));
struct {
	char a[24];
} testsym_24_bytes __attribute__((weak, visibility("hidden")));

void *testfct_int(void);
void *testfct_ptr(void);
void *testfct_24_bytes(void);

void *testlibfct1_int(void);
void *testlibfct1_ptr(void);
void *testlibfct1_24_bytes(void);

void *testlibfct2_int(void);
void *testlibfct2_ptr(void);
void *testlibfct2_24_bytes(void);

enum {
	MATCH_PROGRAM_INT,
	MATCH_PROGRAM_PTR,
	MATCH_PROGRAM_24_BYTES,
	MATCH_LIB_INT,
	MATCH_LIB_PTR,
	MATCH_LIB_24_BYTES,
	NR_MATCH,
};

static bool match_matrix[NR_MATCH];

int main()
{
	plan_tests(NUM_TESTS);

	if (testfct_int() == &testint)
		match_matrix[MATCH_PROGRAM_INT] = true;
	if (testfct_ptr() == &testptr)
		match_matrix[MATCH_PROGRAM_PTR] = true;
	if (testfct_24_bytes() == &testsym_24_bytes)
		match_matrix[MATCH_PROGRAM_24_BYTES] = true;

	if (testlibfct1_int() == testlibfct2_int())
		match_matrix[MATCH_LIB_INT] = true;
	if (testlibfct1_ptr() == testlibfct2_ptr())
		match_matrix[MATCH_LIB_PTR] = true;
	if (testlibfct1_24_bytes() == testlibfct2_24_bytes())
		match_matrix[MATCH_LIB_24_BYTES] = true;

	diag("Address of weak symbol with hidden visibility %s between compile units within same module for main program (4 bytes integer object)",
		match_matrix[MATCH_PROGRAM_INT] ? "match" : "MISMATCH");
	diag("Address of weak symbol with hidden visibility %s between compile units within same module for main program (pointer object)",
		match_matrix[MATCH_PROGRAM_PTR] ? "match" : "MISMATCH");
	diag("Address of weak symbol with hidden visibility %s between compile units within same module for main program (24 bytes structure object)",
		match_matrix[MATCH_PROGRAM_24_BYTES] ? "match" : "MISMATCH");

	diag("Address of weak symbol with hidden visibility %s between compile units within same module for shared library (4 bytes integer object)",
		match_matrix[MATCH_LIB_INT] ? "match" : "MISMATCH");
	diag("Address of weak symbol with hidden visibility %s between compile units within same module for shared library (pointer object)",
		match_matrix[MATCH_LIB_PTR] ? "match" : "MISMATCH");
	diag("Address of weak symbol with hidden visibility %s between compile units within same module for shared library (24 bytes structure object)",
		match_matrix[MATCH_LIB_24_BYTES] ? "match" : "MISMATCH");

	ok(match_matrix[MATCH_PROGRAM_INT] == match_matrix[MATCH_PROGRAM_PTR],
		"Weak-hidden behavior is the same for 4 bytes integer and pointer objects within main program");
	ok(match_matrix[MATCH_LIB_INT] == match_matrix[MATCH_LIB_PTR],
		"Weak-hidden behavior is the same for 4 bytes integer and pointer objects within shared library");
	return 0;
}
