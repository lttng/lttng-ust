/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Sebastien Boisvert <sboisvert@gydle.com>
 */

#include "aligner-lib.h"
#include "tester-lib.h"

int main(void)
{
	/* Generate alignment */
	align_query("moleculeX");

	/* Test alignment */
	test_alignment("my-alignment");

	return 0;
}
