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
#include "tap.h"

#define NUM_TESTS 2

char testsym[9] __attribute__((weak, visibility("hidden")));

void *fct1(void);
void *fctlib1(void);
void *fctlib2(void);

int main()
{
	plan_tests(NUM_TESTS);
	ok(fct1() == testsym,
		"Address of weak symbol with hidden visibility match between compile units within same module for main program");
	ok(fctlib1() == fctlib2(),
		"Address of weak symbol with hidden visibility match between compile units within same module for shared library");
	return 0;
}
