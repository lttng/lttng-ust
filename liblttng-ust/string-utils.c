/*
 * Copyright (C) 2017 - Philippe Proulx <pproulx@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _LGPL_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "string-utils.h"

enum star_glob_pattern_type_flags {
	STAR_GLOB_PATTERN_TYPE_FLAG_NONE = 0,
	STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN = 1,
	STAR_GLOB_PATTERN_TYPE_FLAG_END_ONLY = 2,
};

static
enum star_glob_pattern_type_flags strutils_test_glob_pattern(const char *pattern)
{
	enum star_glob_pattern_type_flags ret =
		STAR_GLOB_PATTERN_TYPE_FLAG_NONE;
	const char *p;

	assert(pattern);

	for (p = pattern; *p != '\0'; p++) {
		switch (*p) {
		case '*':
			ret = STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN;

			if (p[1] == '\0') {
				ret |= STAR_GLOB_PATTERN_TYPE_FLAG_END_ONLY;
			}

			goto end;
		case '\\':
			p++;

			if (*p == '\0') {
				goto end;
			}
			break;
		default:
			break;
		}
	}

end:
	return ret;
}

/*
 * Returns true if `pattern` is a star-only globbing pattern, that is,
 * it contains at least one non-escaped `*`.
 */
bool strutils_is_star_glob_pattern(const char *pattern)
{
	return strutils_test_glob_pattern(pattern) &
		STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN;
}

/*
 * Returns true if `pattern` is a globbing pattern with a globbing,
 * non-escaped star only at its very end.
 */
bool strutils_is_star_at_the_end_only_glob_pattern(const char *pattern)
{
	return strutils_test_glob_pattern(pattern) &
		STAR_GLOB_PATTERN_TYPE_FLAG_END_ONLY;
}

static inline
bool at_end_of_pattern(const char *p, const char *pattern, size_t pattern_len)
{
	return (p - pattern) == pattern_len || *p == '\0';
}

/*
 * Globbing matching function with the star feature only (`?` and
 * character sets are not supported). This matches `candidate` (plain
 * string) against `pattern`. A literal star can be escaped with `\` in
 * `pattern`.
 *
 * `pattern_len` or `candidate_len` can be greater than the actual
 * string length of `pattern` or `candidate` if the string is
 * null-terminated.
 */
bool strutils_star_glob_match(const char *pattern, size_t pattern_len,
		const char *candidate, size_t candidate_len) {
	const char *retry_c = candidate, *retry_p = pattern, *c, *p;
	bool got_a_star = false;

retry:
	c = retry_c;
	p = retry_p;

	/*
	 * The concept here is to retry a match in the specific case
	 * where we already got a star. The retry position for the
	 * pattern is just after the most recent star, and the retry
	 * position for the candidate is the character following the
	 * last try's first character.
	 *
	 * Example:
	 *
	 *     candidate: hi ev every onyx one
	 *                ^
	 *     pattern:   hi*every*one
	 *                ^
	 *
	 *     candidate: hi ev every onyx one
	 *                 ^
	 *     pattern:   hi*every*one
	 *                 ^
	 *
	 *     candidate: hi ev every onyx one
	 *                  ^
	 *     pattern:   hi*every*one
	 *                  ^
	 *
	 *     candidate: hi ev every onyx one
	 *                  ^
	 *     pattern:   hi*every*one
	 *                   ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                   ^
	 *     pattern:   hi*every*one
	 *                   ^
	 *
	 *     candidate: hi ev every onyx one
	 *                   ^^
	 *     pattern:   hi*every*one
	 *                   ^^
	 *
	 *     candidate: hi ev every onyx one
	 *                   ^ ^
	 *     pattern:   hi*every*one
	 *                   ^ ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                    ^
	 *     pattern:   hi*every*one
	 *                   ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                     ^
	 *     pattern:   hi*every*one
	 *                   ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                      ^
	 *     pattern:   hi*every*one
	 *                   ^
	 *
	 *     candidate: hi ev every onyx one
	 *                      ^^
	 *     pattern:   hi*every*one
	 *                   ^^
	 *
	 *     candidate: hi ev every onyx one
	 *                      ^ ^
	 *     pattern:   hi*every*one
	 *                   ^ ^
	 *
	 *     candidate: hi ev every onyx one
	 *                      ^  ^
	 *     pattern:   hi*every*one
	 *                   ^  ^
	 *
	 *     candidate: hi ev every onyx one
	 *                      ^   ^
	 *     pattern:   hi*every*one
	 *                   ^   ^
	 *
	 *     candidate: hi ev every onyx one
	 *                           ^
	 *     pattern:   hi*every*one
	 *                        ^
	 *
	 *     candidate: hi ev every onyx one
	 *                           ^
	 *     pattern:   hi*every*one
	 *                         ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                            ^
	 *     pattern:   hi*every*one
	 *                         ^
	 *
	 *     candidate: hi ev every onyx one
	 *                            ^^
	 *     pattern:   hi*every*one
	 *                         ^^
	 *
	 *     candidate: hi ev every onyx one
	 *                            ^ ^
	 *     pattern:   hi*every*one
	 *                         ^ ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                             ^
	 *     pattern:   hi*every*one
	 *                         ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                              ^
	 *     pattern:   hi*every*one
	 *                         ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                               ^
	 *     pattern:   hi*every*one
	 *                         ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                                ^
	 *     pattern:   hi*every*one
	 *                         ^ MISMATCH
	 *
	 *     candidate: hi ev every onyx one
	 *                                 ^
	 *     pattern:   hi*every*one
	 *                         ^
	 *
	 *     candidate: hi ev every onyx one
	 *                                 ^^
	 *     pattern:   hi*every*one
	 *                         ^^
	 *
	 *     candidate: hi ev every onyx one
	 *                                 ^ ^
	 *     pattern:   hi*every*one
	 *                         ^ ^
	 *
	 *     candidate: hi ev every onyx one
	 *                                 ^  ^
	 *     pattern:   hi*every*one
	 *                         ^  ^ SUCCESS
	 */
	while ((c - candidate) < candidate_len && *c != '\0') {
		assert(*c);

		if (at_end_of_pattern(p, pattern, pattern_len)) {
			goto end_of_pattern;
		}

		switch (*p) {
		case '*':
			got_a_star = true;

			/*
			 * Our first try starts at the current candidate
			 * character and after the star in the pattern.
			 */
			retry_c = c;
			retry_p = p + 1;

			if (at_end_of_pattern(retry_p, pattern, pattern_len)) {
				/*
				 * Star at the end of the pattern at
				 * this point: automatic match.
				 */
				return true;
			}

			goto retry;
		case '\\':
			/* Go to escaped character. */
			p++;

			/*
			 * Fall through the default case which will
			 * compare the escaped character now.
			 */
		default:
			if (at_end_of_pattern(p, pattern, pattern_len) ||
					*c != *p) {
end_of_pattern:
				/* Character mismatch OR end of pattern. */
				if (!got_a_star) {
					/*
					 * We didn't get any star yet,
					 * so this first mismatch
					 * automatically makes the whole
					 * test fail.
					 */
					return false;
				}

				/*
				 * Next try: next candidate character,
				 * original pattern character (following
				 * the most recent star).
				 */
				retry_c++;
				goto retry;
			}
			break;
		}

		/* Next pattern and candidate characters. */
		c++;
		p++;
	}

	/*
	 * We checked every candidate character and we're still in a
	 * success state: the only pattern character allowed to remain
	 * is a star.
	 */
	if (at_end_of_pattern(p, pattern, pattern_len)) {
		return true;
	}

	p++;
	return p[-1] == '*' && at_end_of_pattern(p, pattern, pattern_len);
}
