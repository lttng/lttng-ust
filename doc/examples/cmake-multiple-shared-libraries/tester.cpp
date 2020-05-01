/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Sebastien Boisvert <sboisvert@gydle.com>
 */

#include "aligner-lib.h"
#include "tester-lib.h"

int main(int argc, char **argv)
{
	/* Generate alignment */
	align_query("moleculeX");

	/* Test alignment */
	test_alignment("my-alignment");

	return 0;
}
