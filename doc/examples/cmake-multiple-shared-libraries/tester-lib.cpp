/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Sebastien Boisvert <sboisvert@gydle.com>
 */

#define LTTNG_UST_TRACEPOINT_DEFINE

#include "tester-lib.h"
#include "tracepoint-provider.h"

void test_alignment(const std::string &alignment)
{
	tracepoint(gydle_om, test_alignment, alignment.c_str());
}
