/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

#include <stdbool.h>
#include <stddef.h>

bool strutils_is_star_glob_pattern(const char *pattern)
	__attribute__((visibility("hidden")));

bool strutils_is_star_at_the_end_only_glob_pattern(const char *pattern)
	__attribute__((visibility("hidden")));

bool strutils_star_glob_match(const char *pattern, size_t pattern_len,
                const char *candidate, size_t candidate_len)
	__attribute__((visibility("hidden")));

#endif /* _STRING_UTILS_H */
